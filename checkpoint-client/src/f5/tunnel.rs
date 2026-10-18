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
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static F5_STOP: AtomicBool = AtomicBool::new(false);

const PROFILE_PATH: &str = "/vdesk/vpn/index.php3?outform=xml&client_version=2.0";
const TUN_NAME: &str = "f5vpn0";
const TUN_MTU: u32 = 1400;

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

    // 3) Open the tunnel stream: GET /myvpn?… (no cookies; sess+Z authenticate it).
    let myvpn = build_myvpn_path(&cfg);
    println!("# opening tunnel (GET /myvpn?sess=…&Z=…) …");
    let mut tls = http::connect_tls(&session.host, session.port, session.timeout)?;
    let empty = http::Cookies::new();
    let req = http::build_request("GET", &session.host, &myvpn, &empty, &[], b"", true);
    tls.write_all(&req).map_err(|e| format!("tunnel request: {e}"))?;
    tls.flush().ok();

    // 4) Read the HTTP response: expect 200/201, carrying X-VPN-client-IP.
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

    // 5) PPP negotiation (LCP + IPCP), seeded with the header IP.
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

    // 6) tun device + addressing (distinct name so CP/Forti/F5 tunnels coexist).
    let (tun_file, tun_name) = tun::open_tun(TUN_NAME)?;
    tun::ip(&["addr", "add", &format!("{assigned}/32"), "dev", &tun_name])?;
    tun::ip(&["link", "set", "dev", &tun_name, "up", "mtu", &TUN_MTU.to_string()])?;
    println!("# tun {tun_name} up — {assigned}/32, mtu {TUN_MTU}");

    // 7) Routing + 8) DNS — skipped entirely in --no-routes mode so the test cannot
    // disturb the host's live networking (verify the data plane with
    // `ping -I <tun> <internal-host>`, which uses the interface, not the route table).
    let mut route_cleanup: Vec<String> = Vec::new();
    let dns_backup = if no_routes {
        println!("# --no-routes: NOT installing routes or DNS.");
        println!("#   test the data plane with:  ping -I {tun_name} {}", dns.first().map(|d| d.to_string()).unwrap_or_else(|| "<internal-host>".into()));
        None
    } else {
        let gw_ip = resolve_v4(&session.host, session.port)?;
        setup_routes(gw_ip, &tun_name, &cfg, &mut route_cleanup);
        sysnet::set_dns(&dns, &cfg.domains)
    };

    // 9) Data loop.
    F5_STOP.store(false, Ordering::SeqCst);
    sysnet::install_stop_signals(&F5_STOP);
    if opts.watch_stdin {
        sysnet::spawn_stdin_disconnect(&F5_STOP);
    }
    conn.get_ref().get_ref().set_nonblocking(true).ok();
    let hb = if cfg.idle_timeout > 0 { (cfg.idle_timeout as u64 / 3).clamp(10, 60) } else { 15 };

    println!("# ✅ TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)");
    let result = data_loop(&mut conn, tun_file, sock_fd, hb);

    // 10) Teardown.
    println!("# disconnecting — terminating PPP, restoring DNS/routes …");
    let _ = conn.send(ppp::PPP_LCP, &ppp::terminate_request(0xfe));
    drop(conn); // close the tunnel socket before asking the gateway to hang up
    // Tell the gateway to drop the session server-side (openconnect `f5_bye`; the
    // /vdesk/hangup.php3 endpoint is confirmed in the shipped f5vpn.exe).
    let _ = http::request(
        &session.host, session.port, "GET", "/vdesk/hangup.php3?hangup_error=1",
        &mut session.cookies, &[], b"", session.timeout,
    );
    sysnet::restore_dns(dns_backup);
    let _ = tun::ip_batch(&route_cleanup);
    result
}

/// Build the `/myvpn?…` path. Tokens are appended as openconnect does (sess/Z raw;
/// hostname base64). Cookies are deliberately not sent on this request.
fn build_myvpn_path(cfg: &F5Options) -> String {
    let yn = |b: bool| if b { "yes" } else { "no" };
    format!(
        "/myvpn?sess={}&hdlc_framing={}&ipv4={}&ipv6={}&Z={}&hostname={}",
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
    mut tun_file: std::fs::File,
    sock_fd: i32,
    heartbeat: u64,
) -> Result<(), String> {
    let tun_fd = tun_file.as_raw_fd();
    let mut echo_id = 1u8;
    let mut last_hb = Instant::now();
    let mut last_stats = Instant::now();
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
                Ok(m) => {
                    conn.send(ppp::PPP_IPV4, &buf[..m])?;
                    tout += 1;
                }
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
        }

        // Keepalive (LCP echo) on the heartbeat interval.
        if last_hb.elapsed().as_secs() >= heartbeat {
            echo_id = echo_id.wrapping_add(1);
            let _ = conn.send(ppp::PPP_LCP, &ppp::echo_request(echo_id));
            last_hb = Instant::now();
        }
        if last_stats.elapsed().as_secs() >= 10 {
            println!("#  stats: rx_frames={rx} tun_in={tin} tun_out={tout} frame_err={perr}");
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

/// Pin the gateway to its pre-VPN path, install exclude routes on that path, then
/// add the tunnel routes (default route and/or split includes) via the tun — all in
/// one `ip -batch`. Fills `del_lines` for a one-shot teardown.
fn setup_routes(gw: Ipv4Addr, tun: &str, cfg: &F5Options, del_lines: &mut Vec<String>) {
    let mut add_lines: Vec<String> = Vec::new();
    let pair = |net: String, suffix: &str, add: &mut Vec<String>, del: &mut Vec<String>| {
        add.push(format!("route add {net} {suffix}"));
        del.push(format!("route del {net} {suffix}"));
    };

    // 1) Keep the encrypted tunnel's own packets off the tun.
    if let Some((via, dev)) = original_path(gw) {
        let suffix = match &via {
            Some(v) => format!("via {v} dev {dev}"),
            None => format!("dev {dev}"),
        };
        pair(format!("{gw}/32"), &suffix, &mut add_lines, del_lines);
        println!("# pinned gateway route {gw}/32 ({suffix})");
    }

    // 2) Exclude routes (split-exclude) stay on the original path.
    for ex in &cfg.exclude {
        if let Some((via, dev)) = original_path(ex.net) {
            let prefix = tun::mask_to_prefix(ex.mask);
            let suffix = match &via {
                Some(v) => format!("via {v} dev {dev}"),
                None => format!("dev {dev}"),
            };
            pair(format!("{}/{}", ex.net, prefix), &suffix, &mut add_lines, del_lines);
        }
    }

    // 3) Tunnel routes.
    let dev_suffix = format!("dev {tun}");
    if cfg.default_route {
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            pair(net.to_string(), &dev_suffix, &mut add_lines, del_lines);
        }
        println!("# full tunnel: 0.0.0.0/1 + 128.0.0.0/1 via {tun}");
    }
    for r in &cfg.routes {
        let prefix = tun::mask_to_prefix(r.mask);
        pair(format!("{}/{}", r.net, prefix), &dev_suffix, &mut add_lines, del_lines);
    }
    if !cfg.routes.is_empty() {
        println!("# split tunnel: {} include route(s) via {tun}", cfg.routes.len());
    }
    if !cfg.default_route && cfg.routes.is_empty() {
        println!("# WARNING: no default route and no split includes — tunnel has no routes");
    }

    let _ = tun::ip_batch(&add_lines);
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
