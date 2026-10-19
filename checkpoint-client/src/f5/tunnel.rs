//! Bring up and run the F5 BIG-IP APM SSL-VPN data plane: fetch the VPN profile
//! and tunnel options, open `GET /myvpn?…`, read the assigned IP from the response
//! headers, negotiate PPP, configure `tun`/routes/DNS, then pump packets between
//! the tun device and the TLS tunnel with a single `poll(2)` loop.
//!
//! DTLS (UDP acceleration) is a later step; this path is TLS-only. `no_dtls` is
//! accepted for forward-compat.

use super::auth::Session;
use super::config::{self, F5Options};
use super::http;
use super::ppp::{self, Framing};
use crate::sysnet;
use crate::tun;
use native_tls::TlsStream;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static F5_STOP: AtomicBool = AtomicBool::new(false);

const PROFILE_PATH: &str = "/vdesk/vpn/index.php3?outform=xml&client_version=2.0";
const TUN_NAME: &str = "f5vpn0";
const TUN_MTU: u32 = 1400;
/// How many consecutive reconnect attempts before giving up (the APM session is
/// probably dead and needs a fresh login). Spread over a short backoff.
const MAX_RECONNECT_TRIES: u32 = 10;

/// The concrete PPP-over-TLS connection the data loop drives.
type F5Conn = ppp::PppConn<TlsStream<TcpStream>>;

/// Data-plane keepalive interval. F5's idle timer counts **data** packets, not LCP
/// control, so the LCP keepalive alone doesn't stop the gateway idle-resetting the
/// tunnel (~every 2 min on gw-f5). A small ICMP echo to an internal host every
/// this-many seconds keeps the idle timer reset — comfortably inside that window.
const DATA_KEEPALIVE_SECS: u64 = 45;

/// Liveness timing + the data-plane keepalive target for one data-loop run.
struct Keepalive {
    /// LCP Discard/Echo interval (keepalive + DPD).
    lcp_secs: u64,
    /// Declare the peer dead (→ reconnect) after this long with no inbound frame.
    dpd_dead_secs: u64,
    /// Data-plane keepalive interval (0 disables it).
    data_secs: u64,
    /// Source address for the keepalive ICMP (our current tunnel IP).
    src: Ipv4Addr,
    /// Destination for the keepalive ICMP (first internal DNS); `None` disables it.
    target: Option<Ipv4Addr>,
}

/// Options for [`run`].
pub struct RunOpts {
    /// Reserved for forward-compat (DTLS path); the data plane is TLS-only for now.
    pub no_dtls: bool,
    /// Bring the tunnel up but install no routes/DNS (safe data-plane test).
    pub no_routes: bool,
    /// Watch stdin for `disconnect`/EOF (the GUI and a TTY user drive teardown this
    /// way). Off for the `f5-vpn://` launch path, where stdin is `/dev/null` and an
    /// immediate EOF would otherwise tear the tunnel straight back down — there we
    /// stop on SIGTERM only.
    pub watch_stdin: bool,
    /// Optional path to a status file the browser-launch path writes so the GUI can
    /// detect and display this tunnel (pid/gateway/IP/DNS). Deleting the file is how
    /// the GUI stops the tunnel: a watcher sets the stop flag when it disappears (the
    /// GUI, running as the user, can't signal this root process directly). `None` for
    /// the GUI-driven `--connect` path, which the GUI already controls via stdin.
    pub status_file: Option<String>,
}

/// Full connect: authenticated `session` → live tunnel. Blocks until the stop flag
/// is set (SIGTERM / `disconnect` on stdin).
pub fn run(session: &mut Session, opts: RunOpts) -> Result<(), String> {
    // A valid MRHSession is enough to drive the tunnel: the form-login path only
    // returns here once F5_ST is also set, and the `--launch` handoff path obtains
    // a session that has already cleared the access policy in the browser.
    if session.cookies.get("MRHSession").map(|v| v.is_empty()).unwrap_or(true) {
        return Err("not authenticated (no MRHSession)".into());
    }
    let no_routes = opts.no_routes;
    let _ = opts.no_dtls;

    // 1) VPN profile → resource params.
    println!("# fetching VPN profile ({PROFILE_PATH}) …");
    let resp = http::request(
        &session.host, session.port, "GET", PROFILE_PATH,
        &mut session.cookies, &[], b"", session.timeout,
    )?;
    if resp.status != 200 {
        return Err(format!("profile request failed: HTTP {}", resp.status));
    }
    let params = config::parse_profile(&resp.body_str())
        .ok_or("no VPN resource found in profile (is a Network Access resource assigned?)")?;
    println!("# profile params: {params}");

    // 2) Tunnel options (session id, ur_Z, framing, DNS, routes, DTLS).
    let opt_path = format!("/vdesk/vpn/connect.php3?{params}&outform=xml&client_version=2.0");
    let resp = http::request(
        &session.host, session.port, "GET", &opt_path,
        &mut session.cookies, &[], b"", session.timeout,
    )?;
    if resp.status != 200 {
        return Err(format!("options request failed: HTTP {}", resp.status));
    }
    if let Ok(p) = std::env::var("CPVPN_F5_DUMP_XML") {
        let _ = std::fs::write(&p, &resp.body);
        println!("# (raw options XML dumped to {p})");
    }
    let cfg = config::parse_options(&resp.body_str());
    println!(
        "# options: ipv4={} ipv6={} hdlc={} dtls={}:{} dns={:?} domains={:?} routes={} exclude={} default_route={}",
        cfg.ipv4, cfg.ipv6, cfg.hdlc, cfg.dtls, cfg.dtls_port, cfg.dns, cfg.domains,
        cfg.routes.len(), cfg.exclude.len(), cfg.default_route
    );
    if cfg.session_id.is_empty() || cfg.ur_z.is_empty() {
        return Err("tunnel options missing Session_ID / ur_Z".into());
    }
    if !cfg.ipv4 {
        return Err("gateway did not offer IPv4 (IPv6-only not yet supported)".into());
    }

    // 3-5) Open the tunnel stream (GET /myvpn?…), read the assigned IP, negotiate PPP.
    println!("# opening tunnel (GET /myvpn?sess=…&Z=…) …");
    let (mut conn, mut sock_fd, mut assigned, dns, gw_peer) = open_channel(session, &cfg)?;

    // 6) tun device + addressing (distinct name so CP/Forti/F5 tunnels coexist). The
    // tun and its routes/DNS persist across reconnects — only the TLS/PPP channel is
    // rebuilt when the tunnel drops.
    let (mut tun_file, tun_name) = tun::open_tun(TUN_NAME)?;
    tun::ip(&["addr", "add", &format!("{assigned}/32"), "dev", &tun_name])?;
    tun::ip(&["link", "set", "dev", &tun_name, "up", "mtu", &TUN_MTU.to_string()])?;
    println!("# tun {tun_name} up — {assigned}/32, mtu {TUN_MTU}");

    // From here on every exit path must undo what we change: signals (incl. SIGHUP
    // from a closed terminal) only raise the stop flag, and a disconnect that came
    // in while we were connecting means we don't touch routes/DNS at all.
    F5_STOP.store(false, Ordering::SeqCst);
    sysnet::install_stop_signals(&F5_STOP);
    if sysnet::stop_requested() {
        return Err("disconnect requested before the tunnel came up".into());
    }

    // 7) Routing + 8) DNS — skipped entirely in --no-routes mode so the test cannot
    // disturb the host's live networking (verify the data plane with
    // `ping -I <tun> <internal-host>`, which uses the interface, not the route table).
    let mut restore = sysnet::NetRestore::default();
    if no_routes {
        out!("# --no-routes: NOT installing routes or DNS.");
        out!("#   test the data plane with:  ping -I {tun_name} {}", dns.first().map(|d| d.to_string()).unwrap_or_else(|| "<internal-host>".into()));
    } else {
        let gw = match gw_peer {
            Some(IpAddr::V4(v4)) => Some(v4),
            Some(IpAddr::V6(v6)) => v6.to_ipv4_mapped(), // a v6 transport can't loop into IPv4 routes
            None => Some(resolve_v4(&session.host, session.port)?),
        };
        restore.routes = setup_routes(gw, &tun_name, &cfg);
        restore.dns = sysnet::set_dns(&dns, &cfg.domains);
    }

    // 9) Data loop, wrapped in a reconnect loop. The F5 protocol expects the tunnel to
    // drop (idle timeout, server reset, network blip) and the client to transparently
    // reconnect — the gateway signals this with `autoreconnectifdropped`, and both
    // openconnect and the shipped client do it. We rebuild just the TLS/PPP channel,
    // reusing the same session (sess/Z + cookies) with no re-auth.
    if opts.watch_stdin {
        sysnet::spawn_stdin_disconnect(&F5_STOP);
    }
    // Keepalive/DPD interval: a fraction of the gateway's idle timeout, bounded so it
    // stays frequent even when the gateway sets a long (or no) idle timeout.
    let lcp_secs = if cfg.idle_timeout > 0 { (cfg.idle_timeout as u64 / 3).clamp(15, 30) } else { 20 };
    let mut ka = Keepalive {
        lcp_secs,
        dpd_dead_secs: (lcp_secs * 3).max(90),
        // Data-plane keepalive only makes sense with routes/DNS up and a reachable
        // internal target; skip it in --no-routes mode.
        data_secs: if no_routes { 0 } else { DATA_KEEPALIVE_SECS },
        src: assigned,
        target: cfg.dns.first().copied(),
    };
    if ka.data_secs > 0 {
        match ka.target {
            Some(t) => out!("# data-plane keepalive: ICMP → {t} every {}s (keeps F5's idle timer reset)", ka.data_secs),
            None => out!("# data-plane keepalive disabled (gateway pushed no DNS target)"),
        }
    }

    // Publish a status file so the GUI can detect this browser-launched tunnel and
    // offer a Disconnect (which deletes the file → the watcher below stops us).
    if let Some(ref sf) = opts.status_file {
        if write_status_file(sf, &session.host, assigned, &dns) {
            spawn_status_watch(sf.clone());
            out!("# status file {sf} (GUI can see + stop this tunnel)");
        } else {
            out!("# (status file {sf} not writable — GUI won't see this tunnel)");
        }
    }

    out!("# ✅ TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)");

    let mut fail_streak = 0u32;
    let final_result: Result<(), String> = 'session: loop {
        let outcome = data_loop(&mut conn, &mut tun_file, sock_fd, &ka);
        if F5_STOP.load(Ordering::SeqCst) {
            break 'session Ok(()); // user / SIGTERM asked to stop — not a drop
        }
        let reason = match outcome {
            Ok(()) => "closed by peer".to_string(),
            Err(e) => e,
        };
        out!("# tunnel dropped ({reason})");
        if !cfg.autoreconnect {
            break 'session Err(format!("tunnel dropped ({reason}); auto-reconnect disabled by gateway"));
        }

        // Rebuild the channel with a short backoff, keeping tun/routes/DNS in place.
        let mut reconnected = false;
        while fail_streak < MAX_RECONNECT_TRIES {
            if F5_STOP.load(Ordering::SeqCst) {
                break 'session Ok(());
            }
            fail_streak += 1;
            let delay = reconnect_delay(fail_streak);
            out!("# reconnecting in {delay}s (attempt {fail_streak}/{MAX_RECONNECT_TRIES}) …");
            if sleep_interruptible(delay) {
                break 'session Ok(()); // stop requested during the wait
            }
            match open_channel(session, &cfg) {
                Ok((c, fd, new_ip, _new_dns, _)) => {
                    conn = c;
                    sock_fd = fd;
                    if new_ip != assigned {
                        out!("# gateway reassigned IP {assigned} → {new_ip}");
                        let _ = tun::ip(&["addr", "del", &format!("{assigned}/32"), "dev", &tun_name]);
                        let _ = tun::ip(&["addr", "add", &format!("{new_ip}/32"), "dev", &tun_name]);
                        assigned = new_ip;
                        ka.src = new_ip; // keepalive ICMP must use the current tunnel IP
                        if let Some(ref sf) = opts.status_file {
                            write_status_file(sf, &session.host, assigned, &dns);
                        }
                    }
                    out!("# ✅ reconnected — tunnel back up (IP {assigned})");
                    reconnected = true;
                    break;
                }
                Err(e) => out!("# reconnect attempt {fail_streak} failed: {e}"),
            }
        }
        if !reconnected {
            break 'session Err(format!(
                "tunnel dropped ({reason}) and gave up after {MAX_RECONNECT_TRIES} reconnect attempts (session likely expired — reconnect)"
            ));
        }
        fail_streak = 0; // a clean reconnect resets the budget
    };

    // 10) Teardown (NetRestore restores DNS and our routes when it drops).
    out!("# disconnecting — terminating PPP, restoring DNS/routes …");
    let _ = conn.send(ppp::PPP_LCP, &ppp::terminate_request(0xfe));
    drop(conn); // close the tunnel socket before asking the gateway to hang up
    // Tell the gateway to drop the session server-side (openconnect `f5_bye`; the
    // /vdesk/hangup.php3 endpoint is confirmed in the shipped f5vpn.exe).
    let _ = http::request(
        &session.host, session.port, "GET", "/vdesk/hangup.php3?hangup_error=1",
        &mut session.cookies, &[], b"", session.timeout,
    );
    drop(restore);
    if let Some(ref sf) = opts.status_file {
        let _ = std::fs::remove_file(sf);
    }
    final_result
}

/// Open (or re-open) the TLS data channel: `GET /myvpn`, read the gateway-assigned IP
/// from the response headers, negotiate PPP (LCP + IPCP), and hand back a connection
/// ready for the poll loop (non-blocking, poll fd set). Reusable for the initial
/// connect and for reconnection — it reuses the same session tokens with no re-auth.
/// Returns `(conn, socket_fd, assigned_ipv4, dns, peer_addr_reached)`.
fn open_channel(
    session: &Session,
    cfg: &F5Options,
) -> Result<(F5Conn, i32, Ipv4Addr, Vec<Ipv4Addr>, Option<IpAddr>), String> {
    let myvpn = build_myvpn_path(cfg);
    let mut tls = http::connect_tls(&session.host, session.port, session.timeout)?;
    // Pin the address this very socket reached (not a second DNS answer).
    let gw_peer = tls.get_ref().peer_addr().ok().map(|a| a.ip());
    let empty = http::Cookies::new();
    let req = http::build_request("GET", &session.host, &myvpn, &empty, &[], b"", true);
    tls.write_all(&req).map_err(|e| format!("tunnel request: {e}"))?;
    tls.flush().ok();

    // Read the HTTP response: expect 200/201, carrying X-VPN-client-IP.
    tls.get_ref().set_read_timeout(Some(Duration::from_secs(20))).ok();
    let (status, headers, leftover) = read_http_response(&mut tls)?;
    if status != 200 && status != 201 {
        return Err(format!("tunnel setup failed: HTTP {status}"));
    }
    let header_ip = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("X-VPN-client-IP"))
        .and_then(|(_, v)| v.trim().parse::<Ipv4Addr>().ok());
    println!("# tunnel accepted (HTTP {status}); gateway-assigned IP {header_ip:?}");

    // PPP negotiation (LCP + IPCP), seeded with the header IP.
    let framing = if cfg.hdlc { Framing::Hdlc } else { Framing::F5 };
    tls.get_ref().set_read_timeout(Some(Duration::from_secs(5))).ok();
    let sock_fd = tls.get_ref().as_raw_fd();
    let mut conn = ppp::PppConn::new(tls, framing);
    conn.feed(&leftover);

    println!("# negotiating PPP (LCP/IPCP, framing {}) …", if cfg.hdlc { "HDLC" } else { "F5" });
    let ipc = ppp::negotiate(&mut conn, header_ip)?;
    let assigned = header_ip.unwrap_or(ipc.addr);
    let mut dns = cfg.dns.clone();
    if dns.is_empty() {
        dns = ipc.dns.clone();
    }
    println!("# ✅ PPP up — IP {assigned}  DNS {dns:?}  (IPCP gave {})", ipc.addr);

    // Non-blocking for the poll loop; sends wait for POLLOUT when the buffer is full.
    conn.get_ref().get_ref().set_nonblocking(true).ok();
    conn.set_poll_fd(sock_fd);
    Ok((conn, sock_fd, assigned, dns, gw_peer))
}

/// Backoff (seconds) for the Nth consecutive reconnect attempt.
fn reconnect_delay(attempt: u32) -> u64 {
    match attempt {
        1 => 1,
        2 => 2,
        3 => 5,
        _ => 10,
    }
}

/// Write the external-tunnel status file the GUI reads to detect a browser-launched
/// tunnel: pid (to confirm liveness) plus gateway/IP/DNS (to display). Best-effort;
/// returns whether the write succeeded (so the caller only arms the delete-watcher
/// when the file actually exists — a failed write must not look like a stop request).
fn write_status_file(path: &str, gateway: &str, ip: Ipv4Addr, dns: &[Ipv4Addr]) -> bool {
    let dns_s = dns.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(", ");
    let body = format!("pid={}\ngateway={}\nip={}\ndns={}\n", std::process::id(), gateway, ip, dns_s);
    std::fs::write(path, body).is_ok()
}

/// Watch the status file for deletion: the GUI (running as the user) stops a
/// browser-launched tunnel by removing it, since it cannot signal this root process
/// directly. When it disappears, raise the stop flag for a clean teardown.
fn spawn_status_watch(path: String) {
    std::thread::spawn(move || loop {
        if F5_STOP.load(Ordering::SeqCst) {
            return;
        }
        if !std::path::Path::new(&path).exists() {
            F5_STOP.store(true, Ordering::SeqCst);
            return;
        }
        std::thread::sleep(Duration::from_millis(800));
    });
}

/// Sleep up to `secs`, waking early if a stop is requested so `disconnect` stays
/// responsive during a reconnect backoff. Returns true if a stop was requested.
fn sleep_interruptible(secs: u64) -> bool {
    for _ in 0..(secs * 10) {
        if F5_STOP.load(Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    F5_STOP.load(Ordering::SeqCst)
}

/// Build the `/myvpn?…` path. Tokens are appended as openconnect does (sess/Z raw;
/// hostname base64). Cookies are deliberately not sent on this request.
fn build_myvpn_path(cfg: &F5Options) -> String {
    let yn = |b: bool| if b { "yes" } else { "no" };
    // `client_keepalive=yes` asks the gateway to run its side of the tunnel keepalive
    // (the shipped `svpn` client always sends it); openconnect omits it, but it is
    // harmless and matches the real client.
    format!(
        "/myvpn?sess={}&hdlc_framing={}&ipv4={}&ipv6={}&Z={}&hostname={}&client_keepalive=yes",
        cfg.session_id,
        yn(cfg.hdlc),
        yn(cfg.ipv4),
        yn(cfg.ipv6),
        cfg.ur_z,
        base64(local_hostname().as_bytes()),
    )
}

/// Read a full HTTP response (status line + headers) from a live stream, returning
/// `(status, headers, leftover_body_bytes)`. The leftover is any bytes already read
/// past the header terminator — the first PPP bytes of the tunnel.
fn read_http_response<S: Read>(s: &mut S) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let mut raw = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        match s.read(&mut tmp) {
            Ok(0) => return Err("tunnel closed before HTTP response".into()),
            Ok(n) => raw.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(format!("tunnel response read: {e}")),
        }
        if raw.len() > 1 << 16 {
            return Err("tunnel HTTP response headers too large".into());
        }
    };
    let text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("bad tunnel status line: {status_line:?}"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, headers, raw[header_end..].to_vec()))
}

/// The poll(2) packet pump. Returns Ok on clean stop, Err on tunnel failure.
fn data_loop<S: Read + Write>(
    conn: &mut ppp::PppConn<S>,
    tun_file: &mut std::fs::File,
    sock_fd: i32,
    ka: &Keepalive,
) -> Result<(), String> {
    let tun_fd = tun_file.as_raw_fd();
    let mut echo_id = 1u8;
    let mut ka_seq = 0u16;
    let mut last_hb = Instant::now();
    let mut last_data_ka = Instant::now();
    let mut last_stats = Instant::now();
    let mut last_rx = Instant::now();
    let dpd_dead = ka.dpd_dead_secs;
    let (mut tin, mut tout, mut perr, mut rx) = (0u64, 0u64, 0u64, 0u64);
    let mut buf = [0u8; 2048];

    loop {
        if F5_STOP.load(Ordering::SeqCst) {
            return Ok(());
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

        // tun → tunnel.
        if fds[0].revents & libc::POLLIN != 0 {
            match tun_file.read(&mut buf) {
                Ok(0) => return Err("tun closed".into()),
                Ok(m) if tun::is_ipv4(&buf[..m]) => {
                    conn.send(ppp::PPP_IPV4, &buf[..m])?;
                    tout += 1;
                }
                Ok(_) => {} // not IPv4 (the tunnel is IPv4-only) — drop
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("tun read: {e}")),
            }
        }

        // tunnel → tun (drain all complete frames).
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
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
                            return Ok(()); // peer terminated
                        }
                    }
                    Ok(Some((_other, _))) => rx += 1,
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
            // Any frame (data, echo-reply, LCP) proves the gateway is alive.
            if rx != rx_before {
                last_rx = Instant::now();
            }
        }

        // On the heartbeat interval send both of openconnect's liveness packets: an
        // LCP Discard-Request (keepalive) and an LCP Echo-Request (DPD — the reply
        // proves the link is still up).
        if last_hb.elapsed().as_secs() >= ka.lcp_secs {
            echo_id = echo_id.wrapping_add(1);
            let _ = conn.send(ppp::PPP_LCP, &ppp::discard_request(echo_id));
            echo_id = echo_id.wrapping_add(1);
            let _ = conn.send(ppp::PPP_LCP, &ppp::echo_request(echo_id));
            last_hb = Instant::now();
        }
        // Data-plane keepalive: a small ICMP echo to an internal host. F5's idle timer
        // counts data packets (not LCP control), so this — not the LCP keepalive above
        // — is what actually stops the gateway idle-resetting the tunnel.
        if ka.data_secs > 0 && last_data_ka.elapsed().as_secs() >= ka.data_secs {
            if let Some(dst) = ka.target {
                ka_seq = ka_seq.wrapping_add(1);
                let _ = conn.send(ppp::PPP_IPV4, &icmp_echo_packet(ka.src, dst, ka_seq));
                tout += 1;
            }
            last_data_ka = Instant::now();
        }
        // Dead-peer detection: if the gateway has sent nothing for too long, treat the
        // tunnel as dead so the caller reconnects — rather than waiting for the TCP
        // reset, which can lag well behind the gateway going silent.
        if last_rx.elapsed().as_secs() >= dpd_dead {
            return Err(format!("no data from gateway for {}s (dead peer)", last_rx.elapsed().as_secs()));
        }
        if last_stats.elapsed().as_secs() >= 10 {
            out!("#  stats: rx_frames={rx} tun_in={tin} tun_out={tout} frame_err={perr}");
            last_stats = Instant::now();
        }
    }
}

/// Build a minimal IPv4 + ICMP echo-request packet, used as the data-plane keepalive
/// that resets the gateway's (data-counting) idle timer. 8-byte ICMP payload.
fn icmp_echo_packet(src: Ipv4Addr, dst: Ipv4Addr, seq: u16) -> Vec<u8> {
    // ICMP: type 8 (echo), code 0, checksum, id, seq, payload.
    let mut icmp = vec![8u8, 0, 0, 0, 0, 0, (seq >> 8) as u8, seq as u8];
    icmp.extend_from_slice(b"cpvpn-ka");
    let csum = inet_checksum(&icmp);
    icmp[2] = (csum >> 8) as u8;
    icmp[3] = csum as u8;

    // IPv4 header (20 bytes, no options).
    let total_len = (20 + icmp.len()) as u16;
    let mut ip = Vec::with_capacity(total_len as usize);
    ip.push(0x45); // version 4, IHL 5
    ip.push(0); // DSCP/ECN
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&seq.to_be_bytes()); // identification
    ip.extend_from_slice(&0u16.to_be_bytes()); // flags/fragment = 0
    ip.push(64); // TTL
    ip.push(1); // protocol = ICMP
    ip.extend_from_slice(&0u16.to_be_bytes()); // header checksum (filled below)
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let ipcsum = inet_checksum(&ip);
    ip[10] = (ipcsum >> 8) as u8;
    ip[11] = ipcsum as u8;

    ip.extend_from_slice(&icmp);
    ip
}

/// The 16-bit one's-complement Internet checksum (RFC 1071).
fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Resolve `host` to its first IPv4 address (for the gateway bypass route).
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

/// Pin the gateway to its pre-VPN path, install exclude routes on that path, then
/// add the tunnel routes (default route and/or split includes) via the tun — all in
/// one `ip -batch`. Fills `del_lines` for a one-shot teardown.
fn setup_routes(gw: Option<Ipv4Addr>, tun: &str, cfg: &F5Options) -> Vec<String> {
    let mut add_lines: Vec<String> = Vec::new();
    let mut del_lines: Vec<String> = Vec::new();
    let pair = |net: String, suffix: &str, add: &mut Vec<String>, del: &mut Vec<String>| {
        add.push(format!("route add {net} {suffix}"));
        del.push(format!("route del {net} {suffix}"));
    };

    // 1) Keep the encrypted tunnel's own packets off the tun.
    let mut pin: Option<(usize, String)> = None;
    if let Some((gw, (via, dev))) = gw.and_then(|g| original_path(g).map(|p| (g, p))) {
        let suffix = match &via {
            Some(v) => format!("via {v} dev {dev}"),
            None => format!("dev {dev}"),
        };
        pin = Some((add_lines.len(), format!("{gw}/32 ({suffix})")));
        pair(format!("{gw}/32"), &suffix, &mut add_lines, &mut del_lines);
    }

    // 2) Exclude routes (split-exclude) stay on the original path.
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

    // 3) Tunnel routes.
    let dev_suffix = format!("dev {tun}");
    if cfg.default_route {
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            pair(net.to_string(), &dev_suffix, &mut add_lines, &mut del_lines);
        }
        out!("# full tunnel: 0.0.0.0/1 + 128.0.0.0/1 via {tun}");
    }
    for r in &cfg.routes {
        let prefix = tun::mask_to_prefix(r.mask);
        pair(format!("{}/{}", r.net, prefix), &dev_suffix, &mut add_lines, &mut del_lines);
    }
    if !cfg.routes.is_empty() {
        out!("# split tunnel: {} include route(s) via {tun}", cfg.routes.len());
    }
    if !cfg.default_route && cfg.routes.is_empty() {
        out!("# WARNING: no default route and no split includes — tunnel has no routes");
    }

    // Delete on teardown only what we actually added (see forti::tunnel::setup_routes).
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

/// Parse `ip route get <ip>` to find the current `via`/`dev` for a destination.
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

/// Local hostname for the `hostname=` tunnel parameter (base64 of this).
fn local_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "localhost".to_string())
}

/// Standard base64 (with padding).
fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { A[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[(n & 63) as usize] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"host1"), "aG9zdDE=");
    }

    #[test]
    fn myvpn_path_includes_client_keepalive() {
        let cfg = F5Options { session_id: "S".into(), ur_z: "Z".into(), ipv4: true, ..Default::default() };
        assert!(build_myvpn_path(&cfg).contains("&client_keepalive=yes"));
    }

    #[test]
    fn icmp_keepalive_packet_is_well_formed() {
        let src: Ipv4Addr = "10.80.176.167".parse().unwrap();
        let dst: Ipv4Addr = "10.60.175.134".parse().unwrap();
        let pkt = icmp_echo_packet(src, dst, 7);
        // IPv4/5, proto ICMP, correct total length, addresses.
        assert_eq!(pkt[0], 0x45);
        assert_eq!(pkt[9], 1); // protocol = ICMP
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]) as usize, pkt.len());
        assert_eq!(&pkt[12..16], &src.octets());
        assert_eq!(&pkt[16..20], &dst.octets());
        // ICMP echo request.
        assert_eq!(pkt[20], 8); // type = echo request
        assert_eq!(u16::from_be_bytes([pkt[26], pkt[27]]), 7); // seq
        // A valid checksum makes the one's-complement sum of the covered bytes zero.
        assert_eq!(inet_checksum(&pkt[..20]), 0); // IP header
        assert_eq!(inet_checksum(&pkt[20..]), 0); // ICMP message
    }

    #[test]
    fn myvpn_path_shape() {
        let cfg = F5Options {
            session_id: "SID".into(),
            ur_z: "URZ".into(),
            ipv4: true,
            ipv6: false,
            hdlc: false,
            ..Default::default()
        };
        let p = build_myvpn_path(&cfg);
        assert!(p.starts_with("/myvpn?sess=SID&hdlc_framing=no&ipv4=yes&ipv6=no&Z=URZ&hostname="));
    }

    #[test]
    fn parse_http_response_splits_leftover() {
        let mut stream = std::io::Cursor::new(
            b"HTTP/1.1 200 OK\r\nX-VPN-client-IP: 10.1.2.3\r\n\r\n\xf5\x00\x00\x06".to_vec(),
        );
        let (status, headers, leftover) = read_http_response(&mut stream).unwrap();
        assert_eq!(status, 200);
        assert_eq!(
            headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("x-vpn-client-ip")).map(|(_, v)| v.as_str()),
            Some("10.1.2.3")
        );
        assert_eq!(leftover, vec![0xf5, 0x00, 0x00, 0x06]);
    }
}
