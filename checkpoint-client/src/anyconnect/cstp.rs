//! The CSTP (Cisco SSL Tunneling Protocol) data plane.
//!
//! After authentication yields the `webvpn` cookie, the client sends
//! `CONNECT /CSCOSSLC/tunnel HTTP/1.1` with `X-CSTP-*` request headers; the
//! gateway answers `HTTP/1.1 200` plus `X-CSTP-*`/`X-DTLS-*` headers describing
//! the assigned IP, routes, DNS, MTU and timers (parsed by [`super::config`]).
//! From then on the same TLS stream carries length-prefixed frames:
//!
//! ```text
//!   'S' 'T' 'F' 0x01  <be16 payload-len>  <type>  0x00   <payload…>
//! ```
//!
//! type 0 = DATA (raw IPv4 packet), 3 = DPD request, 4 = DPD reply,
//! 5 = client disconnect, 7 = keepalive, 8 = compressed, 9 = server kick.
//! We advertise no compression, so only DATA/DPD/KEEPALIVE/DISCONN matter.
//!
//! Framing and packet types follow the real client as implemented by
//! openconnect `cstp.c`. DTLS acceleration is a later step — this path is
//! TLS-only (like the F5 back-end's first cut); DTLS options are parsed but the
//! data plane stays on CSTP, which every gateway supports.

use super::auth::Session;
use super::config::{self, TunnelConfig};
use super::dtls;
use super::http;
use crate::sysnet;
use crate::tun;
use native_tls::TlsStream;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static AC_STOP: AtomicBool = AtomicBool::new(false);

const TUN_NAME: &str = "cpac0";
const TUNNEL_PATH: &str = "/CSCOSSLC/tunnel";
const MAX_RECONNECT_TRIES: u32 = 10;

// CSTP packet types.
const AC_DATA: u8 = 0;
const AC_DPD_OUT: u8 = 3;
const AC_DPD_RESP: u8 = 4;
const AC_DISCONN: u8 = 5;
const AC_KEEPALIVE: u8 = 7;
const AC_COMPRESSED: u8 = 8;
const AC_TERM_SERVER: u8 = 9;

/// Options for [`run`].
pub struct RunOpts {
    pub no_routes: bool,
    pub watch_stdin: bool,
    /// Reserved for the DTLS path; the data plane is CSTP-only for now.
    pub no_dtls: bool,
}

/// A live CSTP channel over one TLS stream (non-blocking, with its poll fd).
struct Channel {
    tls: TlsStream<TcpStream>,
    fd: i32,
    /// Bytes read from the socket but not yet split into frames.
    rx: Vec<u8>,
    /// The 48-byte `X-DTLS-Master-Secret` sent in this channel's CONNECT — reused
    /// to resume the DTLS session (must match what the gateway got).
    dtls_master: [u8; 48],
}

impl Channel {
    fn send(&mut self, ty: u8, payload: &[u8]) -> Result<(), String> {
        let mut frame = Vec::with_capacity(8 + payload.len());
        frame.extend_from_slice(&[b'S', b'T', b'F', 1]);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.push(ty);
        frame.push(0);
        frame.extend_from_slice(payload);
        sysnet::write_all_polling(&mut self.tls, Some(self.fd), &frame)
    }

    /// Drain all currently-available ciphertext into the rx buffer. Returns false
    /// on a clean EOF with nothing read (the peer closed).
    ///
    /// Must loop until `WouldBlock`: TLS decrypts a whole record at once, so after
    /// one `read` OpenSSL can still hold several more frames in its own buffer with
    /// no new bytes on the socket — and `poll(fd)` would NOT wake us for those,
    /// stalling the tunnel up to a full poll interval. Reading to exhaustion each
    /// time keeps latency/throughput up (openconnect reads the same way).
    fn fill(&mut self) -> Result<bool, String> {
        let mut tmp = [0u8; 16384];
        let mut got_any = false;
        loop {
            match self.tls.read(&mut tmp) {
                Ok(0) => return Ok(got_any), // EOF: closed unless we just drained data
                Ok(n) => {
                    self.rx.extend_from_slice(&tmp[..n]);
                    got_any = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("tunnel read: {e}")),
            }
        }
    }

    /// Pull one complete frame `(type, payload)` from the rx buffer, if present.
    fn take_frame(&mut self) -> Result<Option<(u8, Vec<u8>)>, String> {
        take_frame(&mut self.rx)
    }
}

/// Split one complete CSTP frame off the front of `rx` (free function so the
/// framing is unit-testable without a live TLS stream). `None` = incomplete.
fn take_frame(rx: &mut Vec<u8>) -> Result<Option<(u8, Vec<u8>)>, String> {
    if rx.len() < 8 {
        return Ok(None);
    }
    if rx[0..4] != [b'S', b'T', b'F', 1] {
        return Err(format!("bad CSTP framing magic {:02x?} (tunnel desynced)", &rx[0..4]));
    }
    let len = u16::from_be_bytes([rx[4], rx[5]]) as usize;
    let ty = rx[6];
    if rx.len() < 8 + len {
        return Ok(None); // wait for the rest
    }
    let payload = rx[8..8 + len].to_vec();
    rx.drain(..8 + len);
    Ok(Some((ty, payload)))
}

/// Full connect: authenticated `session` → live tunnel. Blocks until stop.
pub fn run(session: &mut Session, opts: RunOpts) -> Result<(), String> {
    let _ = opts.no_dtls;
    if session.token.is_none() && session.cookies.get("webvpn").is_none() {
        return Err("not authenticated (no webvpn cookie)".into());
    }

    // 1) Open the tunnel and read the gateway config.
    println!("# opening CSTP tunnel (CONNECT {TUNNEL_PATH}) …");
    let (mut chan, cfg) = open_channel(session, None)?;
    let assigned = cfg.address.ok_or("gateway did not assign an IPv4 address")?;
    let mtu = if cfg.mtu >= 576 { cfg.mtu } else { 1390 };
    let dns = cfg.dns.clone();
    println!(
        "# CSTP options: mtu {mtu} routes {} exclude {} default_route {} keepalive {} dpd {} rekey {} dtls_port {} dtls_cipher {:?}",
        cfg.split_include.len(), cfg.split_exclude.len(), cfg.default_route, cfg.keepalive, cfg.dpd, cfg.rekey, cfg.dtls_port, cfg.dtls_cipher
    );
    // This exact "— IP <ip>  DNS [..]" shape is what the GUI's log parser reads.
    println!("# ✅ CSTP up — IP {assigned}  DNS {:?}  (mtu {mtu})", dns);
    if let Some(b) = &cfg.banner {
        println!("# banner: {}", super::auth::one_line(b));
    }

    // 2) tun device (distinct name so every back-end's tunnel coexists).
    let (mut tun_file, tun_name) = tun::open_tun(TUN_NAME)?;
    tun::ip(&["addr", "add", &format!("{assigned}/{}", cfg.prefix()), "dev", &tun_name])?;
    tun::ip(&["link", "set", "dev", &tun_name, "up", "mtu", &mtu.to_string()])?;
    println!("# tun {tun_name} up — {assigned}/{}, mtu {mtu}", cfg.prefix());

    // From here every exit path must undo what we changed; a disconnect that
    // arrived during connect means we skip routes/DNS entirely.
    AC_STOP.store(false, Ordering::SeqCst);
    sysnet::install_stop_signals(&AC_STOP);
    if sysnet::stop_requested() {
        return Err("disconnect requested before the tunnel came up".into());
    }

    // 3) Routes + DNS (skipped in --no-routes).
    let mut restore = sysnet::NetRestore::default();
    if opts.no_routes {
        out!("# --no-routes: NOT installing routes or DNS.");
        out!("#   test with:  ping -I {tun_name} {}", dns.first().map(|d| d.to_string()).unwrap_or_else(|| "<internal-host>".into()));
    } else {
        let gw = resolve_v4(&session.ep.host, session.ep.port).ok();
        restore.routes = setup_routes(gw, &tun_name, &cfg);
        restore.dns = sysnet::set_dns(&dns, &cfg.domains.join(" "));
    }

    if opts.watch_stdin {
        sysnet::spawn_stdin_disconnect(&AC_STOP);
    }

    // 4) Liveness: use the gateway's DPD/keepalive, bounded so they stay frequent.
    let dpd = clamp_secs(cfg.dpd, 30, 30, 90);
    let keepalive = clamp_secs(cfg.keepalive, 20, 20, 60);
    let ka = Liveness { dpd_secs: dpd, keepalive_secs: keepalive, dpd_dead_secs: (dpd * 2).max(90) };
    out!("# liveness: DPD {}s, keepalive {}s, dead-peer {}s", ka.dpd_secs, ka.keepalive_secs, ka.dpd_dead_secs);
    out!("# ✅ TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)");

    // 4b) DTLS fast path (best-effort): data on UDP, CSTP kept for control + fallback.
    let mut dtls = try_dtls(session, &chan, &cfg, opts.no_dtls);

    // 5) Data loop wrapped in transparent reconnection, like the F5 back-end.
    let mut fail_streak = 0u32;
    let final_result: Result<(), String> = 'session: loop {
        let outcome = data_loop(&mut chan, &mut dtls, &mut tun_file, &ka);
        if AC_STOP.load(Ordering::SeqCst) {
            break 'session Ok(());
        }
        let reason = outcome.err().unwrap_or_else(|| "closed by peer".into());
        out!("# tunnel dropped ({reason})");
        dtls = None; // the DTLS session is tied to this CSTP channel; rebuild after reconnect

        let mut reconnected = false;
        while fail_streak < MAX_RECONNECT_TRIES {
            if AC_STOP.load(Ordering::SeqCst) {
                break 'session Ok(());
            }
            fail_streak += 1;
            let delay = reconnect_delay(fail_streak);
            out!("# reconnecting in {delay}s (attempt {fail_streak}/{MAX_RECONNECT_TRIES}) …");
            if sleep_interruptible(delay) {
                break 'session Ok(());
            }
            match open_channel(session, Some(assigned)) {
                Ok((c, newcfg)) => {
                    chan = c;
                    let new_ip = newcfg.address.unwrap_or(assigned);
                    if new_ip != assigned {
                        out!("# gateway reassigned IP {assigned} → {new_ip}; re-addressing {tun_name}");
                        let _ = tun::ip(&["addr", "del", &format!("{assigned}/{}", cfg.prefix()), "dev", &tun_name]);
                        let _ = tun::ip(&["addr", "add", &format!("{new_ip}/{}", newcfg.prefix()), "dev", &tun_name]);
                    }
                    out!("# ✅ reconnected — tunnel back up (IP {new_ip})");
                    dtls = try_dtls(session, &chan, &newcfg, opts.no_dtls);
                    reconnected = true;
                    break;
                }
                Err(e) => out!("# reconnect attempt {fail_streak} failed: {e}"),
            }
        }
        if !reconnected {
            break 'session Err(format!(
                "tunnel dropped ({reason}) and gave up after {MAX_RECONNECT_TRIES} attempts (session likely expired — reconnect)"
            ));
        }
        fail_streak = 0;
    };

    // 6) Teardown: BYE frame, then logout, then NetRestore (DNS + routes) on drop.
    out!("# disconnecting — sending BYE, restoring DNS/routes …");
    if let Some(d) = &dtls {
        let _ = d.send(AC_DISCONN, &[0xb0]);
    }
    let _ = chan.send(AC_DISCONN, &[0xb0]);
    drop(dtls);
    drop(chan);
    let _ = http::request(&session.ep, "POST", "/+webvpn+/webvpn_logout.html", &mut session.cookies, None, b"");
    drop(restore);
    final_result
}

/// Open (or re-open) the CSTP tunnel: `CONNECT /CSCOSSLC/tunnel`, parse the reply
/// headers into a [`TunnelConfig`], and return a non-blocking channel ready for the
/// poll loop. `want_addr` asks the gateway for the same IP on reconnect.
fn open_channel(session: &Session, want_addr: Option<Ipv4Addr>) -> Result<(Channel, TunnelConfig), String> {
    let token = session
        .token
        .clone()
        .or_else(|| session.cookies.get("webvpn").map(str::to_string))
        .ok_or("no webvpn cookie for the tunnel")?;

    let mut tls = http::connect_tls(&session.ep.host, session.ep.port, session.ep.timeout)?;
    let fd = tls.get_ref().as_raw_fd();

    let mut req = format!("CONNECT {TUNNEL_PATH} HTTP/1.1\r\n");
    req.push_str(&format!("Host: {}\r\n", session.ep.host_header()));
    req.push_str(&format!("User-Agent: {}\r\n", session.ep.user_agent));
    req.push_str(&format!("Cookie: webvpn={token}\r\n"));
    req.push_str("X-CSTP-Version: 1\r\n");
    req.push_str(&format!("X-CSTP-Hostname: {}\r\n", local_hostname()));
    req.push_str("X-CSTP-Base-MTU: 1406\r\n");
    req.push_str("X-CSTP-MTU: 1406\r\n");
    req.push_str("X-CSTP-Address-Type: IPv4\r\n");
    req.push_str("X-CSTP-Full-IPv6-Capability: false\r\n");
    if let Some(a) = want_addr {
        req.push_str(&format!("X-CSTP-Address: {a}\r\n"));
    }
    // DTLS master secret must be 48 real random bytes (not zeros) or the ASA won't
    // offer DTLS. We keep these exact bytes to resume the DTLS session afterwards.
    let mut dtls_master = [0u8; 48];
    let _ = openssl::rand::rand_bytes(&mut dtls_master);
    let secret_hex: String = dtls_master.iter().map(|b| format!("{b:02X}")).collect();
    req.push_str(&format!("X-DTLS-Master-Secret: {secret_hex}\r\n"));
    req.push_str("X-DTLS-CipherSuite: DHE-RSA-AES256-SHA:AES256-SHA:AES128-SHA\r\n");
    // Offer DTLS 1.2 AEAD (ECDHE first) so a modern ASA gives us the DTLS1.2 resume;
    // the gateway echoes the chosen name back in X-DTLS12-CipherSuite. The names must
    // match what the GnuTLS resume expects (see dtls::DTLS12_CIPHERSUITES).
    req.push_str(&format!("X-DTLS12-CipherSuite: {}\r\n", dtls::DTLS12_CIPHERSUITES));
    req.push_str("\r\n");
    tls.write_all(req.as_bytes()).map_err(|e| format!("CONNECT write: {e}"))?;
    tls.flush().ok();

    // Read status + headers (no body for CONNECT); keep any trailing bytes.
    tls.get_ref().set_read_timeout(Some(session.ep.timeout)).ok();
    let resp = http::read_response(&mut tls, false)?;
    if resp.status != 200 {
        if resp.status == 503 {
            let reason = resp.header("x-reason").unwrap_or("service unavailable");
            return Err(format!("gateway refused the tunnel (HTTP 503: {reason})"));
        }
        return Err(format!("CONNECT failed: HTTP {}", resp.status));
    }
    let cfg = config::TunnelConfig::from_headers(&resp.headers);

    // Non-blocking for the poll loop; seed rx with any leftover body bytes.
    tls.get_ref().set_nonblocking(true).ok();
    Ok((Channel { tls, fd, rx: resp.body, dtls_master }, cfg))
}

/// Try to bring up the DTLS fast path for this channel (best-effort). Returns
/// `None` when the gateway offered no DTLS, `--no-dtls` was set, or the handshake
/// didn't complete — the caller just stays on CSTP, which always works.
fn try_dtls(session: &Session, chan: &Channel, cfg: &TunnelConfig, no_dtls: bool) -> Option<dtls::Dtls> {
    if no_dtls || cfg.dtls_port == 0 || cfg.dtls_session_id.is_empty() {
        return None;
    }
    // Prefer the DTLS 1.2 path when the gateway offered it (modern ASA); else the
    // classic DTLS1_BAD_VER resume.
    let dtls12 = cfg.dtls12_cipher.is_some();
    let cipher = if dtls12 {
        cfg.dtls12_cipher.clone().unwrap_or_default()
    } else {
        cfg.dtls_cipher.clone().unwrap_or_default()
    };
    let gw = match resolve_v4(&session.ep.host, session.ep.port) {
        Ok(ip) => ip,
        Err(_) => return None,
    };
    out!("# trying DTLS (UDP {} · {cipher} · {}) …", cfg.dtls_port, if dtls12 { "DTLSv1.2" } else { "DTLSv1-BAD" });
    match dtls::connect(gw, cfg.dtls_port, &cfg.dtls_session_id, &chan.dtls_master, &cipher, dtls12, Duration::from_secs(4)) {
        Ok(d) => {
            out!("# ✅ DTLS up — data plane on UDP {} (faster; CSTP kept for control + fallback)", cfg.dtls_port);
            Some(d)
        }
        Err(e) => {
            out!("# DTLS unavailable ({e}) — staying on CSTP/TCP");
            None
        }
    }
}

/// Liveness timers for one data-loop run.
struct Liveness {
    dpd_secs: u64,
    keepalive_secs: u64,
    dpd_dead_secs: u64,
}

/// The poll(2) packet pump. Ok on clean stop, Err on CSTP failure (→ reconnect).
///
/// When `dtls` is up it carries the DATA packets (UDP, no TCP head-of-line
/// blocking); the CSTP TCP stream still carries control (DPD/keepalive/disconnect)
/// and is the liveness anchor + reconnect trigger. If the DTLS path goes quiet
/// (UDP blocked mid-session) it's dropped and data silently falls back to CSTP —
/// the tunnel never dies just because UDP did.
fn data_loop(
    chan: &mut Channel,
    dtls: &mut Option<dtls::Dtls>,
    tun_file: &mut std::fs::File,
    ka: &Liveness,
) -> Result<(), String> {
    let tun_fd = tun_file.as_raw_fd();
    let sock_fd = chan.fd;
    let (mut tin, mut tout, mut rx) = (0u64, 0u64, 0u64);
    let now = Instant::now();
    let mut last_rx = now; // last CSTP frame (liveness anchor)
    let mut last_dpd = now;
    let mut last_tx = now;
    let mut last_stats = now;
    let mut last_dtls_rx = now;
    let mut last_dtls_dpd = now;
    let mut buf = [0u8; 2048];

    loop {
        if AC_STOP.load(Ordering::SeqCst) {
            return Ok(());
        }
        let dtls_fd = dtls.as_ref().map(|d| d.fd()).unwrap_or(-1);
        let mut fds = [
            libc::pollfd { fd: tun_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: sock_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: dtls_fd, events: libc::POLLIN, revents: 0 },
        ];
        let nfds = if dtls_fd >= 0 { 3 } else { 2 };
        let n = unsafe { libc::poll(fds.as_mut_ptr(), nfds, 1000) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("poll: {e}"));
        }

        // tun → tunnel: prefer DTLS; on a DTLS send error, drop to CSTP for good.
        if fds[0].revents & libc::POLLIN != 0 {
            match tun_file.read(&mut buf) {
                Ok(0) => return Err("tun closed".into()),
                Ok(m) if tun::is_ipv4(&buf[..m]) => {
                    let sent_dtls = match dtls.as_ref() {
                        Some(d) => match d.send(AC_DATA, &buf[..m]) {
                            Ok(()) => true,
                            Err(e) => {
                                out!("# DTLS send failed ({e}) — falling back to CSTP");
                                *dtls = None;
                                false
                            }
                        },
                        None => false,
                    };
                    if !sent_dtls {
                        chan.send(AC_DATA, &buf[..m])?;
                    }
                    tout += 1;
                    last_tx = Instant::now();
                }
                Ok(_) => {} // non-IPv4 dropped (tunnel is IPv4-only)
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("tun read: {e}")),
            }
        }

        // DTLS → tun (data + its own DPD). A read error disables DTLS, not the tunnel.
        if dtls_fd >= 0 && fds[2].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            loop {
                let Some(d) = dtls.as_ref() else { break };
                match d.recv() {
                    Ok(Some((AC_DATA, payload))) => {
                        last_dtls_rx = Instant::now();
                        if tun_file.write_all(&payload).is_ok() {
                            tin += 1;
                        }
                    }
                    Ok(Some((AC_DPD_OUT, _))) => {
                        last_dtls_rx = Instant::now();
                        let _ = d.send(AC_DPD_RESP, &[]);
                    }
                    Ok(Some((AC_DPD_RESP, _))) | Ok(Some((AC_KEEPALIVE, _))) => last_dtls_rx = Instant::now(),
                    Ok(Some((_other, _))) => last_dtls_rx = Instant::now(),
                    Ok(None) => break,
                    Err(e) => {
                        out!("# DTLS read error ({e}) — falling back to CSTP");
                        *dtls = None;
                        break;
                    }
                }
            }
        }

        // CSTP → tun (drain every complete frame). Control always lives here.
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            if !chan.fill()? {
                return Err("gateway closed the tunnel".into());
            }
            loop {
                match chan.take_frame()? {
                    Some((AC_DATA, payload)) => {
                        rx += 1;
                        last_rx = Instant::now();
                        if tun_file.write_all(&payload).is_ok() {
                            tin += 1;
                        }
                    }
                    Some((AC_DPD_OUT, _)) => {
                        rx += 1;
                        last_rx = Instant::now();
                        chan.send(AC_DPD_RESP, &[])?;
                    }
                    Some((AC_DPD_RESP, _)) | Some((AC_KEEPALIVE, _)) => {
                        rx += 1;
                        last_rx = Instant::now();
                    }
                    Some((AC_DISCONN, p)) => {
                        let why = disconnect_reason(&p);
                        return Err(format!("gateway sent disconnect{why}"));
                    }
                    Some((AC_TERM_SERVER, _)) => return Err("gateway kicked the session (terminate)".into()),
                    Some((AC_COMPRESSED, _)) => {
                        return Err("gateway sent a compressed packet (compression not negotiated)".into());
                    }
                    Some((_other, _)) => {
                        rx += 1;
                        last_rx = Instant::now();
                    }
                    None => break,
                }
            }
        }

        // CSTP DPD: prod the gateway if we've heard nothing for dpd_secs.
        if ka.dpd_secs > 0 && last_rx.elapsed().as_secs() >= ka.dpd_secs && last_dpd.elapsed().as_secs() >= ka.dpd_secs / 2 {
            chan.send(AC_DPD_OUT, &[])?;
            last_dpd = Instant::now();
            last_tx = Instant::now();
        }
        // CSTP keepalive: if we haven't *sent* anything for keepalive_secs.
        if ka.keepalive_secs > 0 && last_tx.elapsed().as_secs() >= ka.keepalive_secs {
            chan.send(AC_KEEPALIVE, &[])?;
            last_tx = Instant::now();
        }
        // DTLS DPD + dead-peer: keep the UDP path probed; if it goes quiet, drop to
        // CSTP (don't kill the tunnel — CSTP's own dead-peer check below does that).
        if let Some(d) = dtls.as_ref() {
            if ka.dpd_secs > 0 && last_dtls_dpd.elapsed().as_secs() >= ka.dpd_secs {
                let _ = d.send(AC_DPD_OUT, &[]);
                last_dtls_dpd = Instant::now();
            }
            if last_dtls_rx.elapsed().as_secs() >= ka.dpd_dead_secs {
                out!("# DTLS went quiet for {}s — falling back to CSTP", last_dtls_rx.elapsed().as_secs());
                *dtls = None;
            }
        }
        // CSTP dead peer → reconnect.
        if last_rx.elapsed().as_secs() >= ka.dpd_dead_secs {
            return Err(format!("no data from gateway for {}s (dead peer)", last_rx.elapsed().as_secs()));
        }
        if last_stats.elapsed().as_secs() >= 10 {
            let path = if dtls.is_some() { "DTLS" } else { "CSTP" };
            out!("#  stats: path={path} rx_frames={rx} tun_in={tin} tun_out={tout}");
            last_stats = Instant::now();
        }
    }
}

/// Decode a server DISCONN payload: `[reason-code][printable message…]`.
fn disconnect_reason(p: &[u8]) -> String {
    if p.len() < 2 {
        return String::new();
    }
    let msg: String = p[1..].iter().map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' }).collect();
    format!(": {}", msg.trim())
}

/// Clamp a gateway-supplied interval into `[min,max]`, or use `fallback` if unset.
fn clamp_secs(v: u32, fallback: u64, min: u64, max: u64) -> u64 {
    if v == 0 {
        fallback
    } else {
        (v as u64).clamp(min, max)
    }
}

fn reconnect_delay(attempt: u32) -> u64 {
    match attempt {
        1 => 1,
        2 => 2,
        3 => 5,
        _ => 10,
    }
}

fn sleep_interruptible(secs: u64) -> bool {
    for _ in 0..(secs * 10) {
        if AC_STOP.load(Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    AC_STOP.load(Ordering::SeqCst)
}

/// Pin the gateway to its pre-VPN path, install exclude routes there, then add the
/// tunnel routes — all in one `ip -batch`. Returns the `route del` lines for a
/// one-shot teardown, excluding any route that already existed (not ours).
fn setup_routes(gw: Option<Ipv4Addr>, tun: &str, cfg: &TunnelConfig) -> Vec<String> {
    let mut add: Vec<String> = Vec::new();
    let mut del: Vec<String> = Vec::new();
    fn pair(add: &mut Vec<String>, del: &mut Vec<String>, net: String, suffix: &str) {
        add.push(format!("route add {net} {suffix}"));
        del.push(format!("route del {net} {suffix}"));
    }

    // 1) Keep the encrypted tunnel's own packets off the tun.
    let mut pin: Option<(usize, String)> = None;
    if let Some((g, (via, dev))) = gw.and_then(|g| original_path(g).map(|p| (g, p))) {
        let suffix = via.map(|v| format!("via {v} dev {dev}")).unwrap_or_else(|| format!("dev {dev}"));
        pin = Some((add.len(), format!("{g}/32 ({suffix})")));
        pair(&mut add, &mut del, format!("{g}/32"), &suffix);
    }

    // 2) Split-exclude stays on the original path.
    for ex in &cfg.split_exclude {
        if let Some((via, dev)) = original_path(ex.net) {
            let suffix = via.map(|v| format!("via {v} dev {dev}")).unwrap_or_else(|| format!("dev {dev}"));
            pair(&mut add, &mut del, ex.to_cidr(), &suffix);
        }
    }

    // 3) Tunnel routes.
    let dev_suffix = format!("dev {tun}");
    if cfg.default_route {
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            pair(&mut add, &mut del, net.to_string(), &dev_suffix);
        }
        out!("# full tunnel: 0.0.0.0/1 + 128.0.0.0/1 via {tun}");
    }
    for r in &cfg.split_include {
        pair(&mut add, &mut del, r.to_cidr(), &dev_suffix);
    }
    if !cfg.split_include.is_empty() {
        out!("# split tunnel: {} include route(s) via {tun}", cfg.split_include.len());
    }
    if !cfg.default_route && cfg.split_include.is_empty() {
        out!("# WARNING: no default route and no split includes — tunnel has no routes");
    }

    let failed = tun::ip_batch_failed(&add).unwrap_or_default();
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
    del.into_iter().enumerate().filter(|(i, _)| !failed.contains(i)).map(|(_, d)| d).collect()
}

/// Parse `ip route get <ip>` for the current `via`/`dev` of a destination.
fn original_path(dst: Ipv4Addr) -> Option<(Option<String>, String)> {
    let out = std::process::Command::new("ip").args(["route", "get", &dst.to_string()]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let toks: Vec<&str> = text.lines().next().unwrap_or("").split_whitespace().collect();
    let via = toks.windows(2).find(|w| w[0] == "via").map(|w| w[1].to_string());
    let dev = toks.windows(2).find(|w| w[0] == "dev").map(|w| w[1].to_string())?;
    Some((via, dev))
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

fn local_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_split_from_buffer() {
        // DATA "abc", then KEEPALIVE, then a partial frame.
        let mut wire = vec![b'S', b'T', b'F', 1, 0, 3, AC_DATA, 0, b'a', b'b', b'c'];
        wire.extend_from_slice(&[b'S', b'T', b'F', 1, 0, 0, AC_KEEPALIVE, 0]);
        wire.extend_from_slice(&[b'S', b'T', b'F', 1, 0, 10, AC_DATA, 0, 1, 2]); // incomplete
        assert_eq!(take_frame(&mut wire).unwrap(), Some((AC_DATA, b"abc".to_vec())));
        assert_eq!(take_frame(&mut wire).unwrap(), Some((AC_KEEPALIVE, vec![])));
        assert_eq!(take_frame(&mut wire).unwrap(), None); // partial: wait for more
        assert_eq!(wire.len(), 10); // the partial frame is retained
    }

    #[test]
    fn frame_roundtrip_matches_header() {
        // A frame we'd build (STF|1|len|type|0|payload) parses back to itself.
        let payload = b"\x45\x00\x00\x1c".to_vec(); // a tiny IPv4 header
        let mut frame = vec![b'S', b'T', b'F', 1];
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.push(AC_DATA);
        frame.push(0);
        frame.extend_from_slice(&payload);
        assert_eq!(take_frame(&mut frame).unwrap(), Some((AC_DATA, payload)));
        assert!(frame.is_empty());
    }

    #[test]
    fn bad_magic_is_an_error() {
        let mut rx = vec![b'X', b'X', b'X', 1, 0, 0, AC_DATA, 0];
        assert!(take_frame(&mut rx).is_err());
    }

    #[test]
    fn disconnect_reason_decoded() {
        assert_eq!(disconnect_reason(&[0xb0, b'B', b'y', b'e']), ": Bye");
        assert_eq!(disconnect_reason(&[0xb0]), "");
    }

    #[test]
    fn clamp_intervals() {
        assert_eq!(clamp_secs(0, 30, 30, 90), 30); // unset → fallback
        assert_eq!(clamp_secs(5, 30, 30, 90), 30); // below min
        assert_eq!(clamp_secs(300, 30, 30, 90), 90); // above max
        assert_eq!(clamp_secs(45, 30, 30, 90), 45);
    }
}
