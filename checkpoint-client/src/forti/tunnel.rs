//! Bring up and run the Fortinet SSL-VPN data plane: fetch the tunnel config,
//! open `GET /remote/sslvpn-tunnel`, negotiate PPP, configure `tun`/routes/DNS,
//! then pump packets between the tun device and the TLS tunnel with a single
//! `poll(2)` loop (the TLS stream can't be shared across threads).

use super::auth::Session;
use super::{config, http, ppp};
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

/// Full connect: authenticated `session` → live tunnel. Blocks until the stop
/// flag is set (SIGTERM / `disconnect` on stdin). `no_dtls` is accepted for
/// forward-compat (DTLS is F5; this path is TLS-only). `no_routes` brings the
/// tunnel up but installs no routes/DNS (safe data-plane test).
pub fn run(session: &mut Session, _no_dtls: bool, no_routes: bool) -> Result<(), String> {
    if session.svpncookie().is_none() {
        return Err("no SVPNCOOKIE — not authenticated".into());
    }

    // 1) Tunnel configuration (IP/DNS/domain/routes).
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
    // Optional raw-XML dump for debugging the parser (set CPVPN_FORTI_DUMP_XML=<path>).
    if let Ok(p) = std::env::var("CPVPN_FORTI_DUMP_XML") {
        let _ = std::fs::write(&p, &resp.body);
        println!("# (raw tunnel XML dumped to {p})");
    }
    let cfg = config::parse(&resp.body_str());
    println!(
        "# config: dtls={} heartbeat={}s idle={}s dns={:?} domains={:?} routes={} exclude={}",
        cfg.dtls, cfg.heartbeat, cfg.idle_timeout, cfg.dns, cfg.domains, cfg.routes.len(), cfg.exclude.len()
    );

    // 2) Open the tunnel stream and switch it to PPP.
    println!("# opening tunnel ({TUNNEL_PATH}) …");
    let mut tls = http::connect_tls(&session.host, session.port, Duration::from_secs(20))?;
    // The address this very socket reached is the one to pin (a second DNS lookup
    // may pick another A record of a dual-WAN/HA gateway).
    let gw_peer = tls.get_ref().peer_addr().ok().map(|a| a.ip());
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
    let sock_fd = tls.get_ref().as_raw_fd();
    let mut conn = ppp::PppConn::new(tls);

    // 3) PPP negotiation (LCP + IPCP) → assigned IP + DNS.
    println!("# negotiating PPP (LCP/IPCP) …");
    let ipc = ppp::negotiate(&mut conn)?;
    let assigned = cfg.assigned_ip.unwrap_or(ipc.addr);
    // Prefer DNS/domains from the XML config; fall back to IPCP-provided DNS.
    let mut dns = cfg.dns.clone();
    if dns.is_empty() {
        dns = ipc.dns.clone();
    }
    println!("# ✅ PPP up — IP {assigned}  DNS {dns:?}  (IPCP gave {})", ipc.addr);

    // 4) tun device + addressing. Distinct name from the Check Point back-end
    //    ("cpvpn0") so both tunnels can be up at once without colliding.
    let (tun_file, tun_name) = tun::open_tun("cpfg0")?;
    tun::ip(&["addr", "add", &format!("{assigned}/32"), "dev", &tun_name])?;
    tun::ip(&["link", "set", "dev", &tun_name, "up", "mtu", &TUN_MTU.to_string()])?;
    println!("# tun {tun_name} up — {assigned}/32, mtu {TUN_MTU}");

    // From here on every exit path must undo what we change, so signals (incl.
    // SIGHUP from a closed terminal) only raise the stop flag; and a disconnect the
    // GUI sent while we were still connecting means: don't touch routes/DNS at all.
    sysnet::install_stop_signals(&FORTI_STOP);
    if sysnet::stop_requested() || FORTI_STOP.load(Ordering::SeqCst) {
        return Err("disconnect requested before the tunnel came up".into());
    }

    // 5) Routing: pin the gateway via the original path, then install tunnel routes.
    let mut restore = sysnet::NetRestore::default();
    if no_routes {
        out!("# --no-routes: installing no routes/DNS (reach hosts with `ping -I {tun_name}`)");
    } else {
        let gw = match gw_peer {
            Some(IpAddr::V4(v4)) => Some(v4),
            Some(IpAddr::V6(v6)) => v6.to_ipv4_mapped(), // a v6 transport can't loop into IPv4 routes
            None => Some(resolve_v4(&session.host, session.port)?),
        };
        restore.routes = setup_routes(gw, &tun_name, &cfg);
        // 6) DNS.
        restore.dns = sysnet::set_dns(&dns, &cfg.domains);
    }

    // 7) Data loop.
    sysnet::spawn_stdin_disconnect(&FORTI_STOP);
    // Non-blocking socket for the poll loop (TlsStream → inner TcpStream); sends
    // then wait for POLLOUT instead of failing when the send buffer is full.
    conn.get_ref().get_ref().set_nonblocking(true).ok();
    conn.set_poll_fd(sock_fd);
    let hb = if cfg.heartbeat > 0 { cfg.heartbeat as u64 } else { 10 };

    out!("# ✅ TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)");
    let result = data_loop(&mut conn, tun_file, sock_fd, hb);

    // 8) Teardown (NetRestore restores DNS and our routes when it drops).
    out!("# disconnecting — terminating PPP, restoring DNS/routes …");
    let _ = conn.send(ppp::PPP_LCP, &ppp::terminate_request(0xfe));
    drop(restore);
    result
}

/// The poll(2) packet pump. Returns Ok on clean stop, Err on tunnel failure.
fn data_loop<S: Read + Write>(
    conn: &mut ppp::PppConn<S>,
    mut tun_file: std::fs::File,
    sock_fd: i32,
    heartbeat: u64,
) -> Result<(), String> {
    let tun_fd = tun_file.as_raw_fd();
    let mut echo_id = 1u8;
    let mut last_hb = Instant::now();
    let mut last_stats = Instant::now();
    // tin: IP packets delivered to tun; tout: IP packets sent to the tunnel;
    // rx: total PPP frames received (incl. LCP echo-replies → proves the return path).
    let (mut tin, mut tout, mut perr, mut rx) = (0u64, 0u64, 0u64, 0u64);
    let mut buf = [0u8; 2048];

    loop {
        if FORTI_STOP.load(Ordering::SeqCst) {
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
        }

        // Keepalive (LCP echo) on the heartbeat interval.
        if last_hb.elapsed().as_secs() >= heartbeat {
            echo_id = echo_id.wrapping_add(1);
            let _ = conn.send(ppp::PPP_LCP, &ppp::echo_request(echo_id));
            last_hb = Instant::now();
        }
        if last_stats.elapsed().as_secs() >= 10 {
            out!("#  stats: rx_frames={rx} tun_in={tin} tun_out={tout} frame_err={perr}");
            last_stats = Instant::now();
        }
    }
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
