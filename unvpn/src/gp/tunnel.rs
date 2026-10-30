//! The GlobalProtect data plane: ESP over UDP, or the SSL tunnel.
//!
//! **ESP** (preferred): `getconfig.esp` hands over SPIs and keys; packets are
//! raw ESP in UDP to the gateway's `<udp-port>` (4501), no NAT-T marker. The
//! path is opened and kept alive with ICMP echo requests — sent *through* ESP
//! from our tunnel IP to `<gw-address>` with the magic payload
//! `"monitor\0\0pan ha "` — which the gateway answers the same way. No reply
//! within a few seconds ⇒ UDP is blocked; fall back to SSL.
//!
//! **SSL**: on a fresh TLS connection, `GET <ssl-tunnel-url>?authcookie=…&user=…`
//! (no headers) is answered by the 12 bytes `START_TUNNEL`; after that each
//! packet travels with a 16-byte header:
//!
//! ```text
//!   1a 2b 3c 4d | be16 ethertype | be16 len | 01 00 00 00 00 00 00 00 | payload
//! ```
//!
//! An all-zero tail with ethertype 0 and no payload is the keepalive/DPD frame,
//! which the gateway echoes. Opening the SSL tunnel invalidates the ESP keys, so
//! it is only used once ESP has been given up on.

use super::auth::Session;
use super::config::{self, GpConfig};
use super::hip;
use super::http;
use crate::ike::esp::EspSa;
use crate::sysnet;
use crate::tun;
use native_tls::TlsStream;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static GP_STOP: AtomicBool = AtomicBool::new(false);

pub const TUN_NAME: &str = "gpvpn0";
const MAX_RECONNECT_TRIES: u32 = 10;
/// DPD/keepalive interval: what the Windows client uses.
const DPD_SECS: u64 = 10;
/// No traffic at all for this long ⇒ the path is dead.
const DEAD_SECS: u64 = 35;
/// ESP probes (1/s) before giving up on UDP.
const ESP_PROBES: u32 = 5;
const DEFAULT_MTU: u32 = 1400;
/// Re-check the HIP posture this often when the portal didn't say.
const DEFAULT_HIP_INTERVAL: u64 = 3600;

const GPST_MAGIC: [u8; 4] = [0x1a, 0x2b, 0x3c, 0x4d];
const MAGIC_PING: &[u8; 16] = b"monitor\x00\x00pan ha ";

pub struct RunOpts {
    pub no_routes: bool,
    pub watch_stdin: bool,
    pub no_esp: bool,
    pub no_hip: bool,
}

/// Blocks until stop.
pub fn run(s: &mut Session, opts: RunOpts) -> Result<(), String> {
    let cfg = config::fetch(s, None)?;
    let assigned = cfg.address.ok_or("gateway did not assign an IPv4 address")?;
    let mtu = if cfg.mtu >= 576 { cfg.mtu } else { DEFAULT_MTU };
    let gw_ip = resolve_v4(&s.ep.host, s.ep.port)?;
    out!(
        "# GP config: routes {} exclude {} default_route {} timeout {}s lifetime {}s esp {}",
        cfg.include.len(),
        cfg.exclude.len(),
        cfg.default_route,
        cfg.timeout,
        cfg.lifetime,
        cfg.esp.as_ref().map(|e| format!("{}/{} udp {}", e.enc, e.hmac, e.udp_port)).unwrap_or_else(|| "no".into())
    );

    if !opts.no_hip {
        match hip::check_and_submit(s, assigned) {
            Ok(m) => out!("# {m}"),
            Err(e) => out!("# HIP check failed ({e}) — continuing; access may be limited by policy"),
        }
    }

    // This exact "— IP <ip> DNS [..]" shape is what the GUI's log parser reads.
    out!("# GP up — IP {assigned}  DNS {:?}  (mtu {mtu})", cfg.dns);

    let (mut tun_file, tun_name) = tun::open_tun(TUN_NAME)?;
    tun::set_nonblocking(&tun_file);
    tun::ip(&["addr", "add", &format!("{assigned}/{}", cfg.prefix()), "dev", &tun_name])?;
    tun::ip(&["link", "set", "dev", &tun_name, "up", "mtu", &mtu.to_string()])?;
    out!("# tun {tun_name} up — {assigned}/{}, mtu {mtu}", cfg.prefix());

    GP_STOP.store(false, Ordering::SeqCst);
    sysnet::install_stop_signals(&GP_STOP);
    if sysnet::stop_requested() {
        return Err("disconnect requested before the tunnel came up".into());
    }

    let mut restore = sysnet::NetRestore::default();
    if opts.no_routes {
        out!("# --no-routes: NOT installing routes or DNS.");
    } else {
        restore.routes = setup_routes(gw_ip, &tun_name, &cfg);
        restore.dns = sysnet::set_dns(&sysnet::tunnelled_dns(&cfg.dns, &tun_name), &cfg.domains.join(" "));
        restore.leak = crate::leakguard::enable(&tun_name, &[gw_ip])?;
    }
    if opts.watch_stdin {
        sysnet::spawn_stdin_disconnect(&GP_STOP);
    }

    let hip_every = Duration::from_secs(s.hip_interval.map(|i| i.saturating_sub(60).max(300)).unwrap_or(DEFAULT_HIP_INTERVAL));
    let mut hip_due = Instant::now() + hip_every;

    let mut cfg = cfg;
    let mut ip = assigned;
    let mut link = match establish(s, &cfg, gw_ip, opts.no_esp) {
        Ok(l) => l,
        Err(e) => {
            drop(restore);
            return Err(e);
        }
    };
    out!("# TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)");

    let mut fail_streak = 0u32;
    let result: Result<(), String> = 'session: loop {
        // Re-establish (fresh config + keys) before the gateway's tunnel timeout.
        let rekey_at = (cfg.timeout > 120).then(|| Instant::now() + Duration::from_secs(cfg.timeout - 60));
        let mut tick = || {
            if !opts.no_hip && Instant::now() >= hip_due {
                hip_due = Instant::now() + hip_every;
                let mut hs = s.clone();
                std::thread::spawn(move || match hip::check_and_submit(&mut hs, ip) {
                    Ok(m) => out!("# HIP re-check: {m}"),
                    Err(e) => out!("# HIP re-check failed: {e}"),
                });
            }
        };
        let end = match &mut link {
            Link::Esp(l) => esp_loop(l, &mut tun_file, rekey_at, &mut tick),
            Link::Ssl(l) => ssl_loop(l, &mut tun_file, rekey_at, &mut tick),
        };
        let reason = match end {
            End::Stop => break 'session Ok(()),
            End::Rekey => {
                out!("# tunnel timeout due — re-establishing with fresh keys");
                "rekey".to_string()
            }
            End::Dropped(r) => {
                out!("# tunnel dropped ({r})");
                r
            }
        };

        let mut back = false;
        while fail_streak < MAX_RECONNECT_TRIES {
            if GP_STOP.load(Ordering::SeqCst) {
                break 'session Ok(());
            }
            fail_streak += 1;
            if reason != "rekey" || fail_streak > 1 {
                let delay = reconnect_delay(fail_streak);
                out!("# reconnecting in {delay}s (attempt {fail_streak}/{MAX_RECONNECT_TRIES}) …");
                if sleep_interruptible(delay) {
                    break 'session Ok(());
                }
            }
            let attempt = config::fetch(s, Some(ip)).and_then(|c| {
                let l = establish(s, &c, gw_ip, opts.no_esp)?;
                Ok((c, l))
            });
            match attempt {
                Ok((c, l)) => {
                    let new_ip = c.address.unwrap_or(ip);
                    if new_ip != ip {
                        out!("# gateway reassigned IP {ip} → {new_ip}; re-addressing {tun_name}");
                        let _ = tun::ip(&["addr", "del", &format!("{ip}/{}", cfg.prefix()), "dev", &tun_name]);
                        let _ = tun::ip(&["addr", "add", &format!("{new_ip}/{}", c.prefix()), "dev", &tun_name]);
                        ip = new_ip;
                    }
                    cfg = c;
                    link = l;
                    out!("# reconnected — tunnel back up (IP {ip})");
                    back = true;
                    break;
                }
                Err(e) if is_fatal(&e) => break 'session Err(format!("session ended by the gateway: {e}")),
                Err(e) => out!("# reconnect attempt {fail_streak} failed: {e}"),
            }
        }
        if !back {
            break 'session Err(format!("tunnel dropped ({reason}) and gave up after {MAX_RECONNECT_TRIES} attempts"));
        }
        fail_streak = 0;
    };

    out!("# disconnecting — logging out, restoring DNS/routes …");
    drop(link);
    let mut quick = s.clone();
    quick.ep.timeout = Duration::from_secs(5);
    match quick.logout() {
        Ok(()) => out!("# logged out"),
        Err(e) => out!("# logout failed ({e}) — the session cookie expires on its own"),
    }
    drop(restore);
    result
}

/// Errors after which reconnecting cannot help (the session is gone).
fn is_fatal(e: &str) -> bool {
    ["Invalid authentication cookie", "Portal name not found", "Valid client certificate is required", "HTTP 502"]
        .iter()
        .any(|m| e.contains(m))
}

enum Link {
    Esp(EspLink),
    Ssl(SslLink),
}

enum End {
    Stop,
    Rekey,
    Dropped(String),
}

/// ESP when the gateway offered keys and the UDP path answers, else SSL.
fn establish(s: &Session, cfg: &GpConfig, gw: Ipv4Addr, no_esp: bool) -> Result<Link, String> {
    if !no_esp {
        match (&cfg.esp, cfg.gw_address, cfg.address) {
            (Some(p), Some(magic), Some(src)) => match EspLink::open(p, gw, src, magic) {
                Ok(l) => {
                    out!("# ESP up — data plane on UDP {gw}:{} ({}/{})", p.udp_port, p.enc, p.hmac);
                    return Ok(Link::Esp(l));
                }
                Err(e) => out!("# ESP unavailable ({e}) — using the SSL tunnel"),
            },
            (None, ..) => out!("# gateway offered no ESP keys — using the SSL tunnel"),
            _ => out!("# ESP config incomplete (no gw-address) — using the SSL tunnel"),
        }
    }
    let l = SslLink::open(s, cfg)?;
    out!("# SSL tunnel up ({})", cfg.tunnel_path);
    Ok(Link::Ssl(l))
}

struct EspLink {
    sock: UdpSocket,
    sa: EspSa,
    src: Ipv4Addr,
    magic: Ipv4Addr,
    seq: u16,
}

impl EspLink {
    fn open(p: &config::EspParams, gw: Ipv4Addr, src: Ipv4Addr, magic: Ipv4Addr) -> Result<Self, String> {
        let sa = p.sa()?;
        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("udp bind: {e}"))?;
        sock.connect((gw, p.udp_port)).map_err(|e| format!("udp connect: {e}"))?;
        sock.set_nonblocking(true).ok();
        let mut l = EspLink { sock, sa, src, magic, seq: 0 };
        for _ in 0..ESP_PROBES {
            l.probe();
            let deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < deadline {
                if GP_STOP.load(Ordering::SeqCst) || sysnet::stop_requested() {
                    return Err("stopped".into());
                }
                if !wait_readable(l.sock.as_raw_fd(), deadline.saturating_duration_since(Instant::now())) {
                    break;
                }
                while let Some(r) = l.recv() {
                    if matches!(r, EspIn::Probe) {
                        return Ok(l);
                    }
                }
            }
        }
        Err(format!("no reply to {ESP_PROBES} ESP probes on UDP {}", p.udp_port))
    }

    fn probe(&mut self) {
        self.seq = self.seq.wrapping_add(1);
        let pkt = probe_packet(self.src, self.magic, self.seq);
        if let Ok(esp) = self.sa.encode(&pkt) {
            let _ = self.sock.send(&esp);
        }
    }

    fn send(&self, pkt: &[u8]) -> Result<(), String> {
        let esp = self.sa.encode(pkt)?;
        match self.sock.send(&esp) {
            Ok(_) => Ok(()),
            // A transient ICMP error (port unreachable during a gateway blip) or a
            // full buffer: drop the packet, the liveness check decides.
            Err(e) if matches!(e.raw_os_error(), Some(libc::ECONNREFUSED | libc::ENOBUFS | libc::EAGAIN)) => Ok(()),
            Err(e) => Err(format!("ESP send: {e}")),
        }
    }

    /// One datagram, `None` when the socket is drained.
    fn recv(&self) -> Option<EspIn> {
        let mut buf = [0u8; 2048];
        match self.sock.recv(&mut buf) {
            Ok(n) => Some(match self.sa.decode(&buf[..n]) {
                Ok(inner) if is_probe_reply(&inner, self.magic) => EspIn::Probe,
                Ok(inner) => EspIn::Data(inner),
                Err(_) => EspIn::Junk,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
            Err(_) => Some(EspIn::Junk), // e.g. ECONNREFUSED from an ICMP error; keep draining
        }
    }
}

enum EspIn {
    Data(Vec<u8>),
    Probe,
    Junk,
}

fn esp_loop(l: &mut EspLink, tun_file: &mut std::fs::File, rekey_at: Option<Instant>, tick: &mut dyn FnMut()) -> End {
    let tun_fd = tun_file.as_raw_fd();
    let sock_fd = l.sock.as_raw_fd();
    let now = Instant::now();
    let (mut last_rx, mut last_probe, mut last_stats) = (now, now, now);
    let (mut tin, mut tout) = (0u64, 0u64);
    let mut buf = [0u8; 2048];
    let kick_fd = crate::netmon::kick_fd();
    loop {
        if GP_STOP.load(Ordering::SeqCst) {
            return End::Stop;
        }
        let mut fds = [
            libc::pollfd { fd: tun_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: sock_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: kick_fd, events: libc::POLLIN, revents: 0 },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), 3, 1000) } < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return End::Dropped(format!("poll: {e}"));
            }
            continue;
        }
        if let Some(why) = crate::netmon::took_kick() {
            return End::Dropped(format!("link kicked ({why})"));
        }
        if fds[0].revents & libc::POLLIN != 0 {
            for _ in 0..64 {
                match tun_file.read(&mut buf) {
                    Ok(0) => return End::Dropped("tun closed".into()),
                    Ok(m) if tun::is_ipv4(&buf[..m]) => {
                        if let Err(e) = l.send(&buf[..m]) {
                            return End::Dropped(e);
                        }
                        tout += 1;
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return End::Dropped(format!("tun read: {e}")),
                }
            }
        }
        if fds[1].revents & (libc::POLLIN | libc::POLLERR) != 0 {
            while let Some(r) = l.recv() {
                match r {
                    EspIn::Data(p) => {
                        last_rx = Instant::now();
                        if tun_file.write_all(&p).is_ok() {
                            tin += 1;
                        }
                    }
                    EspIn::Probe => last_rx = Instant::now(),
                    EspIn::Junk => {}
                }
            }
        }
        // The probes double as DPD: the gateway answers each one.
        if last_probe.elapsed().as_secs() >= DPD_SECS {
            l.probe();
            last_probe = Instant::now();
        }
        if last_rx.elapsed().as_secs() >= DEAD_SECS {
            return End::Dropped(format!("ESP: no reply from the gateway for {}s", last_rx.elapsed().as_secs()));
        }
        if rekey_at.is_some_and(|t| Instant::now() >= t) {
            return End::Rekey;
        }
        if last_stats.elapsed().as_secs() >= 10 {
            out!("#  stats: path=ESP tun_in={tin} tun_out={tout}");
            last_stats = Instant::now();
        }
        tick();
    }
}

struct SslLink {
    tls: TlsStream<TcpStream>,
    fd: i32,
    rx: Vec<u8>,
}

impl SslLink {
    fn open(s: &Session, cfg: &GpConfig) -> Result<Self, String> {
        let auth = s.auth.as_ref().ok_or("not authenticated")?;
        let mut tls = http::connect_tls(&s.ep.host, s.ep.port, s.ep.timeout)?;
        let fd = tls.get_ref().as_raw_fd();
        let q = format!("authcookie={}&user={}", http::urlencode(&auth.authcookie), http::urlencode(&auth.user));
        // The real client sends the bare request line, no headers.
        tls.write_all(format!("GET {}?{q} HTTP/1.1\r\n\r\n", cfg.tunnel_path).as_bytes())
            .map_err(|e| format!("tunnel GET: {e}"))?;
        tls.flush().ok();
        tls.get_ref().set_read_timeout(Some(s.ep.timeout)).ok();

        let mut head = Vec::new();
        let mut tmp = [0u8; 4096];
        while head.len() < 12 {
            match tls.read(&mut tmp) {
                Ok(0) => return Err("gateway closed the connection after the tunnel request".into()),
                Ok(n) => head.extend_from_slice(&tmp[..n]),
                Err(e) => return Err(format!("tunnel response: {e}")),
            }
        }
        if &head[..12] != b"START_TUNNEL" {
            let text = String::from_utf8_lossy(&head);
            let status = text.split_whitespace().nth(1).unwrap_or("?");
            if status == "502" {
                return Err("gateway rejected the session cookie (HTTP 502)".into());
            }
            return Err(format!("unexpected tunnel response: {}", super::one_line(&text).chars().take(120).collect::<String>()));
        }
        tls.get_ref().set_nonblocking(true).ok();
        Ok(SslLink { tls, fd, rx: head[12..].to_vec() })
    }

    fn send(&mut self, frame: &[u8]) -> Result<(), String> {
        sysnet::write_all_polling(&mut self.tls, Some(self.fd), frame)
    }

    /// Read everything available (TLS may hold several frames per record).
    fn fill(&mut self) -> Result<bool, String> {
        let mut tmp = [0u8; 16384];
        let mut got_any = false;
        loop {
            match self.tls.read(&mut tmp) {
                Ok(0) => return Ok(got_any),
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
}

/// Header + payload; an empty payload with ethertype 0 is the keepalive.
fn gpst_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(16 + payload.len());
    f.extend_from_slice(&GPST_MAGIC);
    if payload.is_empty() {
        f.extend_from_slice(&[0u8; 12]);
        return f;
    }
    let ethertype: u16 = if payload[0] >> 4 == 6 { 0x86dd } else { 0x0800 };
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    f.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
    f.extend_from_slice(payload);
    f
}

/// Next complete frame as `(ethertype, payload)`; `None` = incomplete.
fn take_frame(rx: &mut Vec<u8>) -> Result<Option<(u16, Vec<u8>)>, String> {
    if rx.len() < 16 {
        return Ok(None);
    }
    if rx[..4] != GPST_MAGIC {
        return Err(format!("bad GPST frame magic {:02x?} (tunnel desynced)", &rx[..4]));
    }
    let ethertype = u16::from_be_bytes([rx[4], rx[5]]);
    let len = u16::from_be_bytes([rx[6], rx[7]]) as usize;
    if rx.len() < 16 + len {
        return Ok(None);
    }
    let payload = rx[16..16 + len].to_vec();
    rx.drain(..16 + len);
    Ok(Some((ethertype, payload)))
}

fn ssl_loop(l: &mut SslLink, tun_file: &mut std::fs::File, rekey_at: Option<Instant>, tick: &mut dyn FnMut()) -> End {
    match ssl_pump(l, tun_file, rekey_at, tick) {
        Ok(e) => e,
        Err(e) => End::Dropped(e),
    }
}

fn ssl_pump(l: &mut SslLink, tun_file: &mut std::fs::File, rekey_at: Option<Instant>, tick: &mut dyn FnMut()) -> Result<End, String> {
    let tun_fd = tun_file.as_raw_fd();
    let now = Instant::now();
    let (mut last_rx, mut last_tx, mut last_stats) = (now, now, now);
    let (mut tin, mut tout) = (0u64, 0u64);
    let mut buf = [0u8; 2048];
    let kick_fd = crate::netmon::kick_fd();
    loop {
        if GP_STOP.load(Ordering::SeqCst) {
            return Ok(End::Stop);
        }
        let mut fds = [
            libc::pollfd { fd: tun_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: l.fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: kick_fd, events: libc::POLLIN, revents: 0 },
        ];
        if unsafe { libc::poll(fds.as_mut_ptr(), 3, 1000) } < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(format!("poll: {e}"));
            }
            continue;
        }
        if let Some(why) = crate::netmon::took_kick() {
            return Err(format!("link kicked ({why})"));
        }
        if fds[0].revents & libc::POLLIN != 0 {
            for _ in 0..64 {
                match tun_file.read(&mut buf) {
                    Ok(0) => return Err("tun closed".into()),
                    Ok(m) if tun::is_ipv4(&buf[..m]) => {
                        l.send(&gpst_frame(&buf[..m]))?;
                        tout += 1;
                        last_tx = Instant::now();
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(format!("tun read: {e}")),
                }
            }
        }
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            if !l.fill()? {
                return Err("gateway closed the tunnel".into());
            }
            while let Some((ethertype, payload)) = take_frame(&mut l.rx)? {
                last_rx = Instant::now();
                match ethertype {
                    0x0800 => {
                        if tun_file.write_all(&payload).is_ok() {
                            tin += 1;
                        }
                    }
                    0 | 0x86dd => {} // keepalive echo / IPv6 (not routed)
                    other => return Err(format!("unknown GPST frame type {other:#06x}")),
                }
            }
        }
        if last_rx.elapsed().as_secs() >= DPD_SECS && last_tx.elapsed().as_secs() >= DPD_SECS {
            l.send(&gpst_frame(&[]))?;
            last_tx = Instant::now();
        }
        if last_rx.elapsed().as_secs() >= DEAD_SECS {
            return Err(format!("no data from the gateway for {}s (dead peer)", last_rx.elapsed().as_secs()));
        }
        if rekey_at.is_some_and(|t| Instant::now() >= t) {
            return Ok(End::Rekey);
        }
        if last_stats.elapsed().as_secs() >= 10 {
            out!("#  stats: path=SSL tun_in={tin} tun_out={tout}");
            last_stats = Instant::now();
        }
        tick();
    }
}

/// IPv4 ICMP echo request `src → magic` with the payload the gateway answers.
fn probe_packet(src: Ipv4Addr, magic: Ipv4Addr, seq: u16) -> Vec<u8> {
    let total = 20 + 8 + MAGIC_PING.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[4..6].copy_from_slice(&0x4747u16.to_be_bytes()); // IP id, as the Windows client
    p[6] = 0x40; // DF
    p[8] = 64;
    p[9] = 1; // ICMP
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&magic.octets());
    let c = checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p[20] = 8; // echo request
    p[24..26].copy_from_slice(&0x4747u16.to_be_bytes());
    p[26..28].copy_from_slice(&seq.to_be_bytes());
    p[28..].copy_from_slice(MAGIC_PING);
    let c = checksum(&p[20..]);
    p[22..24].copy_from_slice(&c.to_be_bytes());
    p
}

fn is_probe_reply(p: &[u8], magic: Ipv4Addr) -> bool {
    if p.len() < 21 || p[0] >> 4 != 4 || p[9] != 1 || p[12..16] != magic.octets() {
        return false;
    }
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    p.len() >= ihl + 8 + MAGIC_PING.len() && p[ihl] == 0 && &p[ihl + 8..ihl + 8 + MAGIC_PING.len()] == MAGIC_PING
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data.chunks(2).map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32).sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn wait_readable(fd: i32, timeout: Duration) -> bool {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    unsafe { libc::poll(&mut p, 1, timeout.as_millis().min(i32::MAX as u128) as i32) > 0 }
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
        if GP_STOP.load(Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    GP_STOP.load(Ordering::SeqCst)
}

/// Pin the gateway to its pre-VPN path (ESP/TLS must not loop into the tun),
/// route excludes the same way, then the tunnel routes — one `ip -batch`.
/// Returns the `route del` lines for teardown, minus routes that pre-existed.
fn setup_routes(gw: Ipv4Addr, tun: &str, cfg: &GpConfig) -> Vec<String> {
    let mut add: Vec<String> = Vec::new();
    let mut del: Vec<String> = Vec::new();
    let mut pair = |net: String, suffix: &str| {
        add.push(format!("route add {net} {suffix}"));
        del.push(format!("route del {net} {suffix}"));
    };
    let via = |dst: Ipv4Addr| {
        original_path(dst).map(|(via, dev)| via.map(|v| format!("via {v} dev {dev}")).unwrap_or_else(|| format!("dev {dev}")))
    };
    if let Some(s) = via(gw) {
        pair(format!("{gw}/32"), &s);
    }
    for ex in &cfg.exclude {
        if let Some(s) = via(ex.net) {
            pair(ex.to_cidr(), &s);
        }
    }
    let dev = format!("dev {tun}");
    if cfg.default_route {
        pair("0.0.0.0/1".into(), &dev);
        pair("128.0.0.0/1".into(), &dev);
        out!("# full tunnel: 0.0.0.0/1 + 128.0.0.0/1 via {tun}");
    }
    for r in &cfg.include {
        pair(r.to_cidr(), &dev);
    }
    if !cfg.include.is_empty() {
        out!("# split tunnel: {} include route(s) via {tun}", cfg.include.len());
    }
    let failed = tun::ip_batch_failed(&add).unwrap_or_default();
    if !failed.is_empty() {
        out!("# {} route(s) already existed — not ours, kept on disconnect", failed.len());
    }
    del.into_iter().enumerate().filter(|(i, _)| !failed.contains(i)).map(|(_, d)| d).collect()
}

/// `ip route get <ip>` → current `via`/`dev`.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip_and_split() {
        let pkt = [0x45u8, 0, 0, 20, 1, 2, 3, 4];
        let mut wire = gpst_frame(&pkt);
        assert_eq!(&wire[..16], &[0x1a, 0x2b, 0x3c, 0x4d, 0x08, 0x00, 0, 8, 1, 0, 0, 0, 0, 0, 0, 0]);
        wire.extend(gpst_frame(&[]));
        wire.extend(&gpst_frame(&pkt)[..10]); // partial
        assert_eq!(take_frame(&mut wire).unwrap(), Some((0x0800, pkt.to_vec())));
        assert_eq!(take_frame(&mut wire).unwrap(), Some((0, vec![])));
        assert_eq!(take_frame(&mut wire).unwrap(), None);
        assert_eq!(wire.len(), 10);
    }

    #[test]
    fn keepalive_is_all_zero_after_magic() {
        assert_eq!(gpst_frame(&[]), vec![0x1a, 0x2b, 0x3c, 0x4d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn desync_is_an_error() {
        let mut rx = vec![0u8; 16];
        assert!(take_frame(&mut rx).is_err());
    }

    #[test]
    fn probe_is_valid_icmp_and_reply_is_recognised() {
        let src = Ipv4Addr::new(198, 51, 100, 7);
        let magic = Ipv4Addr::new(203, 0, 113, 10);
        let p = probe_packet(src, magic, 3);
        assert_eq!(p.len(), 44);
        assert_eq!(checksum(&p[..20]), 0, "IP header checksum verifies");
        assert_eq!(checksum(&p[20..]), 0, "ICMP checksum verifies");
        assert_eq!(&p[28..], MAGIC_PING);
        // The gateway's reply: swapped addresses, type 0, same payload.
        let mut r = p.clone();
        r[12..16].copy_from_slice(&magic.octets());
        r[16..20].copy_from_slice(&src.octets());
        r[20] = 0;
        assert!(is_probe_reply(&r, magic));
        assert!(!is_probe_reply(&p, magic), "our own request isn't a reply");
        r[30] ^= 1;
        assert!(!is_probe_reply(&r, magic), "payload must match");
    }
}
