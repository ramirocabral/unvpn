//! Bring up and run the Fortinet SSL-VPN data plane: fetch the tunnel config, open
//! the PPP link — over **DTLS** (UDP) when the gateway offers it, else over TLS
//! (`GET /remote/sslvpn-tunnel`) — negotiate PPP, configure `tun`/routes/DNS, then
//! pump packets between the tun device and the link with a single `poll(2)` loop.
//!
//! DTLS is the fast path (no TCP-over-TCP head-of-line blocking), as in openconnect:
//! an ordinary certificate DTLS handshake on the TLS port, then the bespoke
//! `GFtype\0clthello\0SVPNCOOKIE\0<cookie>\0` hello answered by `…svrhello\0handshake\0ok`,
//! then PPP frames (same 6-byte Fortinet header), one per record. If any of it fails
//! the tunnel comes up over TLS instead; if DTLS dies later we reconnect over TLS.

use super::auth::Session;
use super::{config, http, ppp};
use crate::gnutls;
use crate::sysnet;
use crate::tun;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static FORTI_STOP: AtomicBool = AtomicBool::new(false);

const XML_PATH: &str = "/remote/fortisslvpn_xml?dual_stack=1";
const TUNNEL_PATH: &str = "/remote/sslvpn-tunnel";
const TUN_MTU: u32 = 1400;
/// Fortinet header (6) + `FF 03` + protocol (4) around each IP packet.
const PPP_OVERHEAD: usize = 10;
const MAX_RECONNECT_TRIES: u32 = 4;
/// Grace window for a fresh DTLS link to prove it forwards data before we fall back
/// to TLS (bounds the blackhole on a gateway whose DTLS data plane is broken).
const DTLS_TRIAL: Duration = Duration::from_secs(5);

const CLTHELLO: &[u8] = b"GFtype\0clthello\0SVPNCOOKIE\0";

type Link = ppp::PppConn<Box<dyn ppp::Transport>>;

struct Up {
    conn: Link,
    fd: i32,
    ipc: ppp::IpConfig,
    /// tun MTU this link carries (≤ the gateway's MRU, ≤ the DTLS record budget).
    mtu: u32,
    dtls: bool,
    /// The gateway address this link's socket reached (pinned outside the tunnel).
    gw: Option<Ipv4Addr>,
}

/// Blocks until the stop flag is set (SIGTERM / `disconnect` on stdin).
pub fn run(session: &mut Session, no_dtls: bool, no_routes: bool) -> Result<(), String> {
    if session.svpncookie().is_none() {
        return Err("no SVPNCOOKIE — not authenticated".into());
    }

    println!("# fetching tunnel config ({XML_PATH}) …");
    let resp = http::request(
        &session.host,
        session.port,
        "GET",
        XML_PATH,
        &mut session.cookies,
        &[],
        b"",
        Duration::from_secs(20),
    )?;
    if resp.status != 200 {
        return Err(format!("config request failed: HTTP {}", resp.status));
    }
    if let Ok(p) = std::env::var("UNVPN_FORTI_DUMP_XML") {
        let _ = std::fs::write(&p, &resp.body);
        println!("# (raw tunnel XML dumped to {p})");
    }
    let cfg = config::parse(&resp.body_str());
    println!(
        "# config: dtls={} heartbeat={}s idle={}s dns={:?} domains={:?} routes={} exclude={}",
        cfg.dtls, cfg.heartbeat, cfg.idle_timeout, cfg.dns, cfg.domains, cfg.routes.len(), cfg.exclude.len()
    );

    let mut want_dtls = cfg.dtls && !no_dtls;
    if cfg.dtls && no_dtls {
        println!("# --no-dtls: gateway offers DTLS but staying on TLS");
    }
    let mut up = open_link(session, want_dtls)?;
    let assigned = cfg.assigned_ip.unwrap_or(up.ipc.addr);
    let mut dns = cfg.dns.clone();
    if dns.is_empty() {
        dns = up.ipc.dns.clone();
    }
    println!("# PPP up over {} — IP {assigned}  DNS {dns:?}  (IPCP gave {})", path(up.dtls), up.ipc.addr);

    // Distinct name from the Check Point back-end ("unvpn0") so both tunnels can be
    // up at once without colliding.
    let (mut tun_file, tun_name) = tun::open_tun("cpfg0")?;
    tun::ip(&["addr", "add", &format!("{assigned}/32"), "dev", &tun_name])?;
    tun::ip(&["link", "set", "dev", &tun_name, "up", "mtu", &up.mtu.to_string()])?;
    println!("# tun {tun_name} up — {assigned}/32, mtu {}", up.mtu);

    // From here on every exit path must undo what we change, so signals (incl.
    // SIGHUP from a closed terminal) only raise the stop flag; and a disconnect the
    // GUI sent while we were still connecting means: don't touch routes/DNS at all.
    sysnet::install_stop_signals(&FORTI_STOP);
    if sysnet::stop_requested() || FORTI_STOP.load(Ordering::SeqCst) {
        return Err("disconnect requested before the tunnel came up".into());
    }

    let mut restore = sysnet::NetRestore::default();
    if no_routes {
        out!("# --no-routes: installing no routes/DNS (reach hosts with `ping -I {tun_name}`)");
    } else {
        let gw = match up.gw {
            Some(g) => Some(g),
            None => Some(resolve_v4(&session.host, session.port)?),
        };
        restore.routes = setup_routes(gw, &tun_name, &cfg);
        restore.dns = sysnet::set_dns(&dns, &cfg.domains);
    }

    sysnet::spawn_stdin_disconnect(&FORTI_STOP);
    tun::set_nonblocking(&tun_file);
    let hb = if cfg.heartbeat > 0 { cfg.heartbeat as u64 } else { 10 };
    let dead_secs = (hb * 6).max(60);

    out!("# TUNNEL UP over {}. (send 'disconnect' on stdin or SIGTERM to stop)", path(up.dtls));
    let result = 'session: loop {
        let outcome = data_loop(&mut up.conn, &mut tun_file, up.fd, hb, dead_secs, up.dtls);
        if FORTI_STOP.load(Ordering::SeqCst) {
            break Ok(());
        }
        let Err(e) = outcome else { break Ok(()) }; // peer terminated cleanly
        if up.dtls {
            // This DTLS link failed (UDP timeout, or the gateway's DTLS data plane
            // didn't forward): don't retry DTLS — the TLS link is the reliable path.
            want_dtls = false;
        }
        out!("# warning: link dropped ({e}) — reconnecting over TLS …");
        // Rebuild the link (no re-auth), retrying with a short backoff. Only once we
        // hold a fresh link do we loop back into data_loop — never re-run it on the
        // dead one.
        let mut attempt = 0u32;
        loop {
            if FORTI_STOP.load(Ordering::SeqCst) {
                break 'session Ok(());
            }
            attempt += 1;
            if attempt > MAX_RECONNECT_TRIES {
                break 'session Err(format!("tunnel lost ({e}); reconnect failed {MAX_RECONNECT_TRIES} times"));
            }
            if sleep_interruptible(attempt as u64) {
                break 'session Ok(());
            }
            match open_link(session, want_dtls) {
                Ok(new) if new.ipc.addr != up.ipc.addr && cfg.assigned_ip.is_none() => {
                    break 'session Err(format!(
                        "reconnected but the gateway assigned a new IP {} (was {})",
                        new.ipc.addr, up.ipc.addr
                    ));
                }
                Ok(new) => {
                    if new.mtu < up.mtu {
                        let _ = tun::ip(&["link", "set", "dev", &tun_name, "mtu", &new.mtu.to_string()]);
                    }
                    up = new;
                    out!("# reconnected over {}", path(up.dtls));
                    break;
                }
                Err(e2) => out!("# reconnect attempt {attempt}/{MAX_RECONNECT_TRIES} failed: {e2}"),
            }
        }
    };

    // NetRestore restores DNS and our routes when it drops.
    out!("# disconnecting — terminating PPP, restoring DNS/routes …");
    let _ = up.conn.send(ppp::PPP_LCP, &ppp::terminate_request(0xfe));
    drop(restore);
    result
}

fn path(dtls: bool) -> &'static str {
    if dtls {
        "DTLS"
    } else {
        "TLS"
    }
}

/// Sleep `secs`, waking early on a stop request. True if a stop was requested.
fn sleep_interruptible(secs: u64) -> bool {
    for _ in 0..secs * 10 {
        if FORTI_STOP.load(Ordering::SeqCst) || sysnet::stop_requested() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn open_link(session: &Session, try_dtls: bool) -> Result<Up, String> {
    if try_dtls {
        if !gnutls::available() {
            println!("# DTLS offered but libgnutls is not installed — using TLS");
        } else {
            match open_dtls(session) {
                Ok(up) => return Ok(up),
                Err(e) => println!("# DTLS unavailable ({e}) — using TLS"),
            }
        }
    }
    open_tls(session)
}

/// PPP over DTLS on the gateway's TLS port (openconnect: "DTLS always uses same port").
fn open_dtls(session: &Session) -> Result<Up, String> {
    let cookie = session.svpncookie().ok_or("no SVPNCOOKIE")?.to_string();
    let gw = resolve_v4(&session.host, session.port)?;
    println!("# trying DTLS (UDP {gw}:{}) …", session.port);
    let dtls = gnutls::DtlsSession::connect_cert(IpAddr::V4(gw), session.port, true, Duration::from_secs(4))?;
    let record_mtu = dtls.data_mtu();
    let mut st = gnutls::DtlsStream::new(dtls);

    // The tunnel "hello": resend every second until svrhello (or a PPP frame — the
    // ok can be lost while the gateway already talks PPP) arrives, up to 5 s.
    let hello = clthello(&cookie);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 2048];
    'hello: loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("no svrhello from the gateway".into());
        }
        if !st.session.send_oversized(&hello)? {
            println!("# (DTLS hello send would block — retrying)");
        }
        let resend_at = Instant::now() + Duration::from_secs(1);
        loop {
            let wait = resend_at.saturating_duration_since(Instant::now()).min(left);
            if wait.is_zero() {
                break;
            }
            st.set_read_timeout(Some(wait));
            match st.read(&mut buf) {
                Ok(n) => match parse_svrhello(&buf[..n]) {
                    Hello::Ok | Hello::Ppp => break 'hello,
                    Hello::Refused(why) => return Err(format!("svrhello status {why:?}")),
                    Hello::Other => println!("# (ignoring unexpected {}-byte DTLS record {:02x?}…)", n, &buf[..n.min(16)]),
                },
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                Err(e) => return Err(format!("DTLS: {e}")),
            }
        }
    }

    let fd = st.fd();
    st.set_read_timeout(Some(Duration::from_secs(5)));
    let mut conn = ppp::PppConn::new(st);
    conn.set_record_mode();
    println!("# DTLS tunnel accepted — negotiating PPP (LCP/IPCP) over UDP …");
    let ipc = ppp::negotiate(&mut conn)?;
    conn.get_mut().set_read_timeout(None);
    conn.set_poll_fd(fd);
    let mtu = link_mtu(ipc.peer_mru, Some(record_mtu));
    Ok(Up { conn: conn.boxed(), fd, ipc, mtu, dtls: true, gw: Some(gw) })
}


/// PPP over the TLS tunnel stream (`GET /remote/sslvpn-tunnel`).
fn open_tls(session: &Session) -> Result<Up, String> {
    println!("# opening tunnel ({TUNNEL_PATH}) …");
    let mut tls = http::connect_tls(&session.host, session.port, Duration::from_secs(20))?;
    // The address this very socket reached is the one to pin (a second DNS lookup
    // may pick another A record of a dual-WAN/HA gateway).
    let gw = match tls.get_ref().peer_addr().ok().map(|a| a.ip()) {
        Some(IpAddr::V4(v4)) => Some(v4),
        Some(IpAddr::V6(v6)) => v6.to_ipv4_mapped(), // a v6 transport can't loop into IPv4 routes
        None => None,
    };
    let req = http::build_request(
        "GET",
        "sslvpn", // Fortinet wants Host: sslvpn on the tunnel request
        TUNNEL_PATH,
        &session.cookies,
        &["Connection: Upgrade".to_string()],
        b"",
        true,
    );
    tls.write_all(&req).map_err(|e| format!("tunnel request: {e}"))?;
    tls.flush().ok();

    // Blocking reads with a timeout during negotiation.
    tls.get_ref().set_read_timeout(Some(Duration::from_secs(5))).ok();
    let fd = tls.get_ref().as_raw_fd();
    let mut conn = ppp::PppConn::new(tls);
    println!("# negotiating PPP (LCP/IPCP) …");
    let ipc = ppp::negotiate(&mut conn)?;
    // Non-blocking socket for the poll loop (TlsStream → inner TcpStream); sends
    // then wait for POLLOUT instead of failing when the send buffer is full.
    conn.get_ref().get_ref().set_nonblocking(true).ok();
    conn.set_poll_fd(fd);
    let mtu = link_mtu(ipc.peer_mru, None);
    Ok(Up { conn: conn.boxed(), fd, ipc, mtu, dtls: false, gw })
}

/// tun MTU for a link: our default, capped by the gateway's MRU (it drops larger
/// PPP payloads — a silent black hole for bulk TCP) and, over DTLS, by what fits in
/// one record after the PPP framing.
fn link_mtu(peer_mru: Option<u16>, record_mtu: Option<usize>) -> u32 {
    let mut mtu = TUN_MTU;
    if let Some(m) = peer_mru.filter(|&m| m >= 576) {
        mtu = mtu.min(m as u32);
    }
    if let Some(r) = record_mtu.filter(|&r| r > PPP_OVERHEAD + 576) {
        mtu = mtu.min((r - PPP_OVERHEAD) as u32);
    }
    mtu
}

/// `[be16 total_len]GFtype\0clthello\0SVPNCOOKIE\0<cookie>\0`.
fn clthello(cookie: &str) -> Vec<u8> {
    let len = 2 + CLTHELLO.len() + cookie.len() + 1;
    let mut v = Vec::with_capacity(len);
    v.extend_from_slice(&(len as u16).to_be_bytes());
    v.extend_from_slice(CLTHELLO);
    v.extend_from_slice(cookie.as_bytes());
    v.push(0);
    v
}

#[derive(Debug, PartialEq)]
enum Hello {
    Ok,
    Refused(String),
    /// A PPP frame: the gateway already switched to PPP (the "ok" got lost).
    Ppp,
    Other,
}

/// Classify a record received while waiting for `svrhello`. Parsed as FortiClient
/// does: `[be16 len]"GF"` then `key\0value\0` pairs — `type` must be `svrhello` (or
/// the newer `svrhello-tun`) and `handshake` must be `ok`.
fn parse_svrhello(rec: &[u8]) -> Hello {
    if rec.len() >= 4 && u16::from_be_bytes([rec[0], rec[1]]) as usize == rec.len() && &rec[2..4] == b"GF" {
        let mut fields = rec[4..].split(|&b| b == 0);
        let mut ty = None;
        let mut status = None;
        while let (Some(k), Some(v)) = (fields.next(), fields.next()) {
            match k {
                b"type" => ty = Some(v),
                b"handshake" => status = Some(v),
                _ => {}
            }
        }
        if matches!(ty, Some(b"svrhello") | Some(b"svrhello-tun")) {
            let st = status.unwrap_or(b"");
            return if st == b"ok" { Hello::Ok } else { Hello::Refused(String::from_utf8_lossy(st).into_owned()) };
        }
    }
    if rec.len() >= 6 && rec[2..4] == [0x50, 0x50] {
        return Hello::Ppp;
    }
    Hello::Other
}

/// The poll(2) packet pump. Returns Ok on a clean stop or peer termination, Err on
/// link failure (the caller reconnects).
fn data_loop(
    conn: &mut Link,
    tun_file: &mut std::fs::File,
    sock_fd: i32,
    heartbeat: u64,
    dead_secs: u64,
    dtls: bool,
) -> Result<(), String> {
    let tun_fd = tun_file.as_raw_fd();
    let mut echo_id = 1u8;
    let mut last_hb = Instant::now();
    let mut last_stats = Instant::now();
    let mut last_rx = Instant::now();
    // tin: IP packets delivered to tun; tout: IP packets sent to the tunnel;
    // rx: total PPP frames received (incl. LCP echo-replies → proves the return path).
    let (mut tin, mut tout, mut perr, mut rx) = (0u64, 0u64, 0u64, 0u64);
    // DTLS is opportunistic: FortiOS may hand out a DTLS session yet forward no IP
    // over it (control frames flow, data doesn't). So on a fresh DTLS link we run a
    // short trial — if we send data but none comes back within the window, treat the
    // path as dead and let the caller reconnect over TLS. `tin` (IP frames in) is the
    // only honest signal; LCP echo-replies must not count.
    let started = Instant::now();
    let mut buf = [0u8; 2048];

    loop {
        if FORTI_STOP.load(Ordering::SeqCst) {
            return Ok(());
        }
        if dtls && tin == 0 && tout >= 8 && started.elapsed() >= DTLS_TRIAL {
            return Err(format!("DTLS up but no data forwarded in {}s (gateway DTLS data plane broken)", DTLS_TRIAL.as_secs()));
        }
        let mut fds = [
            libc::pollfd { fd: tun_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: sock_fd, events: libc::POLLIN, revents: 0 },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, 1000) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("poll: {e}"));
        }

        // tun → tunnel: drain everything queued (bounded), sent as one batch.
        if fds[0].revents & libc::POLLIN != 0 {
            for _ in 0..64 {
                match tun_file.read(&mut buf) {
                    Ok(0) => return Err("tun closed".into()),
                    Ok(m) if tun::is_ipv4(&buf[..m]) => {
                        conn.queue(ppp::PPP_IPV4, &buf[..m])?;
                        tout += 1;
                    }
                    Ok(_) => {} // not IPv4 (the tunnel is IPv4-only) — drop
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(format!("tun read: {e}")),
                }
            }
            conn.flush_tx()?;
        }

        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            conn.fill()?;
            let rx_before = rx;
            loop {
                match conn.take_frame() {
                    Ok(Some((ppp::PPP_IPV4, payload))) => {
                        rx += 1;
                        if tun_file.write_all(&payload).is_ok() {
                            tin += 1;
                        }
                    }
                    Ok(Some((ppp::PPP_LCP, payload))) => {
                        rx += 1;
                        if ppp::handle_lcp_in(conn, &payload)? {
                            return Ok(());
                        }
                    }
                    Ok(Some((_other, _))) => rx += 1, // IPCP mid-session etc. — ignore
                    Ok(None) => break,
                    Err(e) => {
                        perr += 1;
                        if perr > 20 {
                            return Err(format!("tunnel framing error: {e}"));
                        }
                        break;
                    }
                }
            }
            if rx != rx_before {
                last_rx = Instant::now();
            }
        }

        // Keepalive (LCP echo) on the heartbeat interval; its reply also feeds the
        // dead-peer check below.
        if last_hb.elapsed().as_secs() >= heartbeat {
            echo_id = echo_id.wrapping_add(1);
            let _ = conn.send(ppp::PPP_LCP, &ppp::echo_request(echo_id));
            last_hb = Instant::now();
        }
        if last_rx.elapsed().as_secs() >= dead_secs {
            return Err(format!("no data from gateway for {}s (dead peer)", last_rx.elapsed().as_secs()));
        }
        if last_stats.elapsed().as_secs() >= 10 {
            out!("#  stats[{}]: rx_frames={rx} tun_in={tin} tun_out={tout} frame_err={perr}", path(dtls));
            last_stats = Instant::now();
        }
    }
}

fn resolve_v4(host: &str, port: u16) -> Result<Ipv4Addr, String> {
    use std::net::ToSocketAddrs;
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}: {e}"))?
        .find_map(|sa| match sa.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .ok_or_else(|| format!("no IPv4 address for {host}"))
}

/// Pin the gateway to its pre-VPN path, then install the tunnel's routes — all in
/// one `ip -batch` (big split-tunnels push hundreds of routes). Returns the
/// `route del …` lines for exactly the adds that succeeded: a route that already
/// existed (the LAN's own route in the exclude list, another session's gateway
/// pin) is not ours and must survive our teardown.
fn setup_routes(gw: Option<Ipv4Addr>, tun: &str, cfg: &config::TunnelConfig) -> Vec<String> {
    let mut add_lines: Vec<String> = Vec::new();
    let mut del_lines: Vec<String> = Vec::new();
    let pair = |net: String, suffix: &str, add: &mut Vec<String>, del: &mut Vec<String>| {
        add.push(format!("route add {net} {suffix}"));
        del.push(format!("route del {net} {suffix}"));
    };

    // 1) Keep the encrypted tunnel's own packets off the tun: pin gw/32 to the
    //    current path (so 0/1+128/1 or split routes don't loop it back).
    let mut pin: Option<(usize, String)> = None;
    if let Some((gw, (via, dev))) = gw.and_then(|g| original_path(g).map(|p| (g, p))) {
        let suffix = match &via {
            Some(v) => format!("via {v} dev {dev}"),
            None => format!("dev {dev}"),
        };
        pin = Some((add_lines.len(), format!("{gw}/32 ({suffix})")));
        pair(format!("{gw}/32"), &suffix, &mut add_lines, &mut del_lines);
    }

    // 2) Exclude routes (split-tunnel negate) also stay on the original path.
    for ex in &cfg.exclude {
        if let Some((via, dev)) = original_path(ex.net) {
            let prefix = tun::mask_to_prefix(ex.mask);
            let suffix = match &via {
                Some(v) => format!("via {v} dev {dev}"),
                None => format!("dev {dev}"),
            };
            pair(format!("{}/{}", ex.net, prefix), &suffix, &mut add_lines, &mut del_lines);
        }
    }

    // 3) Tunnel routes: split list, or a full tunnel via 0/1 + 128/1 (which beats
    //    the real default without deleting it, so the gateway pin above holds).
    let dev_suffix = format!("dev {tun}");
    if cfg.routes.is_empty() {
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            pair(net.to_string(), &dev_suffix, &mut add_lines, &mut del_lines);
        }
        out!("# full tunnel: 0.0.0.0/1 + 128.0.0.0/1 via {tun}");
    } else {
        for r in &cfg.routes {
            let prefix = tun::mask_to_prefix(r.mask);
            pair(format!("{}/{}", r.net, prefix), &dev_suffix, &mut add_lines, &mut del_lines);
        }
        out!("# split tunnel: {} route(s) via {tun}", cfg.routes.len());
    }

    let failed = tun::ip_batch_failed(&add_lines).unwrap_or_default();
    if let Some((i, what)) = pin {
        if failed.contains(&i) {
            out!("# gateway route {what} already present — left as is");
        } else {
            out!("# pinned gateway route {what}");
        }
    }
    if !failed.is_empty() {
        out!("# {} route(s) already existed — not ours, kept on disconnect", failed.len());
    }
    del_lines.into_iter().enumerate().filter(|(i, _)| !failed.contains(i)).map(|(_, d)| d).collect()
}

fn original_path(dst: Ipv4Addr) -> Option<(Option<String>, String)> {
    let out = std::process::Command::new("ip").args(["route", "get", &dst.to_string()]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next().unwrap_or("");
    let toks: Vec<&str> = first.split_whitespace().collect();
    let via = toks.windows(2).find(|w| w[0] == "via").map(|w| w[1].to_string());
    let dev = toks.windows(2).find(|w| w[0] == "dev").map(|w| w[1].to_string())?;
    Some((via, dev))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SVRHELLO: &[u8] = b"GFtype\0svrhello\0handshake\0";

    #[test]
    fn clthello_layout_matches_openconnect() {
        let h = clthello("abc");
        assert_eq!(u16::from_be_bytes([h[0], h[1]]) as usize, h.len());
        assert_eq!(&h[2..2 + CLTHELLO.len()], CLTHELLO);
        assert_eq!(&h[2 + CLTHELLO.len()..], b"abc\0");
    }

    #[test]
    fn svrhello_ok_fail_and_ppp() {
        let mk = |status: &[u8]| {
            let mut v = vec![0, 0];
            v.extend_from_slice(SVRHELLO);
            v.extend_from_slice(status);
            let n = v.len() as u16;
            v[..2].copy_from_slice(&n.to_be_bytes());
            v
        };
        assert_eq!(parse_svrhello(&mk(b"ok\0")), Hello::Ok);
        assert_eq!(parse_svrhello(&mk(b"ok")), Hello::Ok);
        assert_eq!(parse_svrhello(&mk(b"fail\0")), Hello::Refused("fail".into()));
        assert_eq!(parse_svrhello(&[0, 20, 0x50, 0x50, 0, 14, 0xff, 0x03, 0xc0, 0x21]), Hello::Ppp);
        assert_eq!(parse_svrhello(b"junk"), Hello::Other);
        // FortiOS 7.4 answers with the -tun variant.
        let mut v = b"\0\0GFtype\0svrhello-tun\0handshake\0ok\0".to_vec();
        let n = v.len() as u16;
        v[..2].copy_from_slice(&n.to_be_bytes());
        assert_eq!(parse_svrhello(&v), Hello::Ok);
    }

    #[test]
    fn mtu_respects_peer_mru_and_dtls_record() {
        assert_eq!(link_mtu(None, None), TUN_MTU);
        assert_eq!(link_mtu(Some(1354), None), 1354);
        assert_eq!(link_mtu(Some(1500), Some(1390)), 1380);
        assert_eq!(link_mtu(Some(100), None), TUN_MTU); // nonsense MRU ignored
    }
}
