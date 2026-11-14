//! The Ivanti data plane: IF-T/TLS data messages, or ESP over UDP.
//!
//! After the configuration, IP packets travel as Juniper data messages on the
//! authenticated IF-T/TLS connection. When the gateway handed out ESP keys, the
//! client probes the UDP path with ESP packets carrying a single zero byte, which
//! the gateway echoes; once answered, outgoing packets go over ESP. The TLS
//! connection stays open for control (ESP rekeys, fatal errors, the logout) and
//! takes the data back when ESP stops answering. Incoming packets may arrive on
//! either path.

use super::auth::{Session, COOKIE_REJECTED};
use super::config::{self, EspAlgs, IvantiConfig};
use super::ift::{self, IftConn};
use crate::ike::esp::EspSa;
use crate::sysnet;
use crate::tun;
use crate::tunnel_common::{self, resolve_v4, Reconnect, RoutePlan};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static IV_STOP: AtomicBool = AtomicBool::new(false);

pub const TUN_NAME: &str = "ivvpn0";
const MAX_RECONNECT_TRIES: u32 = 10;
const DEFAULT_MTU: u32 = 1400;
/// ESP keepalive probe while ESP carries the data.
const ESP_PROBE_SECS: u64 = 10;
/// No ESP reply for this long ⇒ back to the SSL tunnel (unless the gateway says).
const ESP_DEAD_SECS: u64 = 30;
/// Probes (1/s) per attempt to bring ESP up.
const ESP_PROBES: u32 = 5;
/// Pause between attempts once ESP didn't answer.
const ESP_RETRY_SECS: u64 = 60;

pub struct RunOpts {
    pub no_routes: bool,
    pub no_esp: bool,
    pub watch_stdin: bool,
}

/// Blocks until stop. `conn` is the connection the login authenticated.
pub fn run(s: &mut Session, conn: IftConn, opts: RunOpts) -> Result<(), String> {
    let mut conn = conn;
    let cfg = config::fetch(&mut conn, !opts.no_esp)?;
    let assigned = cfg
        .address
        .ok_or("gateway did not assign an IPv4 address")?;
    let mtu = if cfg.mtu >= 576 { cfg.mtu } else { DEFAULT_MTU };
    let gw_ip = resolve_v4(&s.ep.host, s.ep.port)?;
    out!(
        "# Ivanti config: routes {} exclude {} default_route {} esp {}",
        cfg.include.len(),
        cfg.exclude.len(),
        cfg.default_route(),
        match (&cfg.esp, &cfg.esp_algs) {
            (Some(_), Some(a)) => a.describe(),
            _ => "no".into(),
        }
    );
    if let Some(l) = s.lifetime {
        out!("# session lifetime {l}s");
    }
    if let Some(i) = s.idle_timeout {
        out!("# idle timeout {i}s");
    }
    out!(
        "# Ivanti up — IP {assigned}  DNS {:?}  (mtu {mtu})",
        cfg.dns
    );

    let (mut tun_file, tun_name) =
        tunnel_common::open_tun(TUN_NAME, (assigned, cfg.prefix()), mtu)?;
    tun::set_nonblocking(&tun_file);

    IV_STOP.store(false, Ordering::SeqCst);
    tunnel_common::arm_stop(&IV_STOP)?;
    let plan = (!opts.no_routes).then(|| route_plan(gw_ip, &cfg));
    let restore =
        tunnel_common::configure(&tun_name, plan.as_ref(), &cfg.dns, &cfg.domains.join(" "))?;
    if opts.watch_stdin {
        sysnet::spawn_stdin_disconnect(&IV_STOP);
    }

    let mut cfg = cfg;
    let mut ip = assigned;
    let mut link = match Link::open(conn, &cfg, gw_ip, opts.no_esp) {
        Ok(l) => l,
        Err(e) => {
            drop(restore);
            return Err(e);
        }
    };
    out!("# TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)");
    crate::report::up(&tun_name, Some(assigned.into()));

    let result: Result<(), String> = 'session: loop {
        let reason = match link.pump(&mut tun_file) {
            End::Stop => break 'session Ok(()),
            End::Fatal(e) => break 'session Err(e),
            End::Dropped(r) => r,
        };
        out!("# tunnel dropped ({reason})");
        crate::report::reconnecting();

        let opened =
            tunnel_common::reconnect(&IV_STOP, MAX_RECONNECT_TRIES, None, is_fatal, || {
                let mut c = s.resume()?;
                let cfg = config::fetch(&mut c, !opts.no_esp)?;
                let l = Link::open(c, &cfg, gw_ip, opts.no_esp)?;
                Ok((cfg, l))
            });
        let (c, l) = match opened {
            Reconnect::Up(up) => up,
            Reconnect::Stopped => break 'session Ok(()),
            Reconnect::Fatal(e) => break 'session Err(format!("session ended: {e}")),
            Reconnect::GaveUp => {
                break 'session Err(format!(
                    "tunnel dropped ({reason}) and gave up after {MAX_RECONNECT_TRIES} attempts"
                ))
            }
        };
        let new_ip = c.address.unwrap_or(ip);
        tunnel_common::readdress(&tun_name, (ip, cfg.prefix()), (new_ip, c.prefix()));
        ip = new_ip;
        cfg = c;
        link = l;
        out!("# reconnected — tunnel back up (IP {ip})");
        crate::report::recovered(Some(ip.into()));
    };

    out!("# disconnecting — logging out, restoring DNS/routes …");
    match link.logout() {
        Ok(()) => out!("# logged out"),
        Err(e) => out!("# logout failed ({e}) — the session expires on its own"),
    }
    drop(restore);
    result
}

/// Errors after which reconnecting cannot help (the session is gone).
fn is_fatal(e: &str) -> bool {
    e.contains(COOKIE_REJECTED) || e.contains("the gateway ended the session")
}

enum End {
    Stop,
    Fatal(String),
    Dropped(String),
}

struct Link {
    c: IftConn,
    esp: Option<Esp>,
}

impl Link {
    fn open(c: IftConn, cfg: &IvantiConfig, gw: Ipv4Addr, no_esp: bool) -> Result<Self, String> {
        c.tls.get_ref().set_nonblocking(true).ok();
        let esp = match (&cfg.esp, no_esp) {
            (_, true) => None,
            (None, false) => {
                out!("# gateway offered no ESP keys — using the SSL tunnel");
                None
            }
            (Some(p), false) => match Esp::open(p, gw) {
                Ok(e) => Some(e),
                Err(e) => {
                    out!("# ESP unavailable ({e}) — using the SSL tunnel");
                    None
                }
            },
        };
        Ok(Link { c, esp })
    }

    fn logout(&mut self) -> Result<(), String> {
        self.c.tls.get_ref().set_nonblocking(false).ok();
        self.c
            .tls
            .get_ref()
            .set_write_timeout(Some(Duration::from_secs(5)))
            .ok();
        Session::logout(&mut self.c).map_err(String::from)?;
        let _ = self.c.tls.shutdown();
        Ok(())
    }

    fn send_ssl(&mut self, pkt: &[u8]) -> Result<(), String> {
        self.c.send(ift::VENDOR_JUNIPER, ift::J_DATA, pkt)
    }

    fn pump(&mut self, tun_file: &mut std::fs::File) -> End {
        match self.pump_inner(tun_file) {
            Ok(e) => e,
            Err(e) => End::Dropped(e),
        }
    }

    fn pump_inner(&mut self, tun_file: &mut std::fs::File) -> Result<End, String> {
        let tun_fd = tun_file.as_raw_fd();
        let tls_fd = self.c.fd();
        let kick_fd = crate::netmon::kick_fd();
        let mut last_stats = Instant::now();
        let (mut tin, mut tout) = (0u64, 0u64);
        let mut buf = [0u8; 2048];
        loop {
            if IV_STOP.load(Ordering::SeqCst) {
                return Ok(End::Stop);
            }
            let udp_fd = self.esp.as_ref().map_or(-1, |e| e.sock.as_raw_fd());
            let mut fds = [tun_fd, tls_fd, udp_fd, kick_fd].map(|fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
            if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 1000) } < 0 {
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
                            match self.esp.as_mut().filter(|e| e.up) {
                                Some(e) => e.send(&buf[..m])?,
                                None => self.send_ssl(&buf[..m])?,
                            }
                            tout += 1;
                        }
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(format!("tun read: {e}")),
                    }
                }
            }
            if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                if !self.c.fill()? {
                    return Err("the gateway closed the IF-T/TLS connection".into());
                }
                while let Some(m) = self.c.take()? {
                    if m.vendor != ift::VENDOR_JUNIPER {
                        continue;
                    }
                    match m.msg_type {
                        ift::J_DATA => {
                            if tun::is_ipv4(&m.payload) && tun_file.write_all(&m.payload).is_ok() {
                                tin += 1;
                            }
                        }
                        ift::J_CONFIG if config::kind(&m.payload) == Some(config::KIND_ESP) => {
                            self.rekey(&m.payload)?
                        }
                        ift::J_FATAL => return Ok(End::Fatal(ift::fatal_reason(&m.payload))),
                        // Sent once the session is set up: a good moment to retry ESP.
                        ift::J_LICENSE => {
                            if let Some(e) = self.esp.as_mut().filter(|e| !e.up) {
                                e.probe();
                            }
                        }
                        _ => {}
                    }
                }
            }
            if fds[2].revents & (libc::POLLIN | libc::POLLERR) != 0 {
                if let Some(e) = self.esp.as_mut() {
                    while let Some(p) = e.recv() {
                        if tun_file.write_all(&p).is_ok() {
                            tin += 1;
                        }
                    }
                }
            }
            if let Some(e) = self.esp.as_mut() {
                e.tick();
            }
            if last_stats.elapsed().as_secs() >= 10 {
                let path = match &self.esp {
                    Some(e) if e.up => "ESP",
                    _ => "SSL",
                };
                out!("#  stats: path={path} tun_in={tin} tun_out={tout}");
                last_stats = Instant::now();
            }
        }
    }

    /// New ESP keys from the gateway: answer with ours and switch.
    fn rekey(&mut self, payload: &[u8]) -> Result<(), String> {
        let Some(e) = self.esp.as_mut() else {
            return Ok(());
        };
        match config::esp_answer(e.algs, payload) {
            Ok((params, reply)) => {
                self.c.send(ift::VENDOR_JUNIPER, ift::J_CONFIG, &reply)?;
                let sa = params.sa()?;
                e.old = Some(std::mem::replace(&mut e.sa, sa));
                out!("# ESP rekeyed");
            }
            Err(err) => {
                out!("# ESP rekey failed ({err}) — back to the SSL tunnel");
                self.esp = None;
            }
        }
        Ok(())
    }
}

struct Esp {
    sock: UdpSocket,
    sa: EspSa,
    /// The previous inbound SA after a rekey, for packets still in flight.
    old: Option<EspSa>,
    algs: EspAlgs,
    /// The gateway answered: data goes out over ESP.
    up: bool,
    dead_secs: u64,
    last_rx: Instant,
    last_probe: Instant,
    /// Probes left in the current attempt to bring ESP up.
    probes_left: u32,
    next_attempt: Instant,
}

impl Esp {
    fn open(p: &config::EspParams, gw: Ipv4Addr) -> Result<Self, String> {
        let sa = p.sa()?;
        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("udp bind: {e}"))?;
        sock.connect((gw, p.algs.port))
            .map_err(|e| format!("udp connect: {e}"))?;
        sock.set_nonblocking(true).ok();
        let now = Instant::now();
        let mut e = Esp {
            sock,
            sa,
            old: None,
            algs: p.algs,
            up: false,
            dead_secs: match p.algs.fallback_secs {
                0 => ESP_DEAD_SECS,
                s => u64::from(s).max(ESP_PROBE_SECS + 5),
            },
            last_rx: now,
            last_probe: now,
            probes_left: ESP_PROBES,
            next_attempt: now,
        };
        e.probe();
        out!(
            "# ESP probing UDP {gw}:{} ({})",
            p.algs.port,
            p.algs.describe()
        );
        Ok(e)
    }

    fn probe(&mut self) {
        if let Ok(esp) = self.sa.encode(&[0]) {
            let _ = self.sock.send(&esp);
        }
        self.last_probe = Instant::now();
    }

    fn send(&self, pkt: &[u8]) -> Result<(), String> {
        let esp = self.sa.encode(pkt)?;
        match self.sock.send(&esp) {
            Ok(_) => Ok(()),
            // A transient ICMP error or a full buffer: drop the packet, the
            // liveness check decides.
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ECONNREFUSED | libc::ENOBUFS | libc::EAGAIN)
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(format!("ESP send: {e}")),
        }
    }

    /// The next inbound IP packet; probe replies are absorbed. `None` when drained.
    fn recv(&mut self) -> Option<Vec<u8>> {
        let mut buf = [0u8; 2048];
        loop {
            let n = match self.sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return None,
                Err(_) => continue, // e.g. ECONNREFUSED from an ICMP error
            };
            let inner = self
                .sa
                .decode(&buf[..n])
                .or_else(|e| self.old.as_ref().ok_or(e)?.decode(&buf[..n]));
            let Ok(inner) = inner else { continue };
            self.last_rx = Instant::now();
            if !self.up {
                self.up = true;
                out!("# ESP up — data plane on UDP port {}", self.algs.port);
            }
            if inner != [0] && tun::is_ipv4(&inner) {
                return Some(inner);
            }
        }
    }

    /// Keepalive while up; fall back and retry later when it stops answering.
    fn tick(&mut self) {
        let now = Instant::now();
        if self.up {
            if self.last_probe.elapsed().as_secs() >= ESP_PROBE_SECS {
                self.probe();
            }
            if self.last_rx.elapsed().as_secs() >= self.dead_secs {
                self.up = false;
                self.probes_left = 0;
                self.next_attempt = now + Duration::from_secs(ESP_RETRY_SECS);
                out!(
                    "# ESP: no reply for {}s — data back on the SSL tunnel",
                    self.last_rx.elapsed().as_secs()
                );
            }
            return;
        }
        if self.probes_left == 0 && now >= self.next_attempt {
            self.probes_left = ESP_PROBES;
        }
        if self.probes_left > 0 && self.last_probe.elapsed() >= Duration::from_secs(1) {
            self.probes_left -= 1;
            self.probe();
            if self.probes_left == 0 {
                self.next_attempt = now + Duration::from_secs(ESP_RETRY_SECS);
            }
        }
    }
}

/// Excludes stay outside, the default route and includes go in.
fn route_plan(gw: Ipv4Addr, cfg: &IvantiConfig) -> RoutePlan {
    let net = |r: &crate::anyconnect::config::Route| (r.net, r.prefix);
    RoutePlan {
        gateway: Some(gw),
        exclude: cfg.exclude.iter().map(net).collect(),
        full: cfg.default_route(),
        include: cfg.include.iter().map(net).collect(),
    }
}
