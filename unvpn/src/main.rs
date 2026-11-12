//! unvpn — native Linux multi-vendor VPN client (Check Point, Fortinet, F5, AnyConnect, GlobalProtect, OpenVPN).

/// `println!` that never panics. Once the GUI is gone our stdout is a broken pipe,
/// and a panicking print on a teardown path would skip restoring DNS and routes.
macro_rules! out {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}

mod anyconnect;
mod ccc;
mod connect;
mod cpcert;
mod forti;
mod forti_ipsec;
mod gnutls;
mod f5;
mod gp;
mod ike;
mod ivanti;
mod leakguard;
mod net;
mod netmon;
mod openvpn;
mod replay;
mod sysnet;
mod tun;
mod wireguard;

use std::io::{Read, Write};
use std::time::Duration;

const USER_AGENT: &str = "Mozilla/5.0 (compatible; CPSC 5.0; Windows NT 5.0)";
const CCC_PATH: &str = "/clients/";

/// A non-zero request id. The gateway echoes it back in the response header;
/// Derived from the clock.
fn new_request_id() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1);
    (nanos % 100_000) as i64 + 1
}

/// Debug helper: deobfuscate hex secrets the gateway prints (prompt, error_*).
fn cmd_deob(args: &[String]) {
    for h in args {
        match ccc::deobfuscate(h) {
            Ok(b) => println!(
                "{h}\n  -> text: {:?}\n  -> hex : {}",
                String::from_utf8_lossy(&b),
                b.iter().map(|x| format!("{x:02x}")).collect::<String>()
            ),
            Err(e) => println!("{h}\n  -> error: {e}"),
        }
    }
}

/// Open the SSL data-plane tunnel and perform the `client_hello` /
/// `hello_reply` handshake to obtain the Office Mode IP + routes. Uses the
/// `active_key` (obfuscated hex) from a prior `login` as the session cookie, so
/// it can run against an existing 9h session without a fresh passcode.
/// Framing = "Slim": [u32 be len][u32 be type][payload]; type 1 = CONTROL
/// (S-expression + NUL), type 2 = DATA (raw IP packet).
fn cmd_tunnel(args: &[String]) {
    let mut gateway: Option<String> = None;
    let mut active_key: Option<String> = None;
    let mut om_ip = "0.0.0.0".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" => gateway = it.next().cloned(),
            "--active-key" | "-k" => active_key = it.next().cloned(),
            "--om-ip" => om_ip = it.next().cloned().unwrap_or(om_ip),
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let host = gateway.unwrap_or_else(|| {
        eprintln!("tunnel requires --gateway <host>");
        std::process::exit(2);
    });
    let akey = active_key.unwrap_or_else(|| {
        eprintln!("tunnel requires --active-key <obfuscated-hex>");
        std::process::exit(2);
    });

    // cookie = the DEOBFUSCATED active_key (a 64-char hex session key).
    let cookie = match ccc::deobfuscate(&akey) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => {
            eprintln!("bad --active-key: {e}");
            std::process::exit(1);
        }
    };

    let mut tls = net::tls::connect(&host, 443, Duration::from_secs(20)).unwrap_or_else(|e| {
        eprintln!("TLS failed: {e}");
        std::process::exit(1);
    });
    println!("# SSL tunnel: TLS connected to {host}:443");

    let hello = ccc::tunnel_client_hello(&cookie, &om_ip);
    let payload = hello.serialize();
    println!("# tunnel client_hello (cookie elided):");
    println!("{}\n", payload.replace(&cookie, "<SESSION_KEY>"));
    if let Err(e) = send_control(&mut tls, &payload) {
        eprintln!("send failed: {e}");
        std::process::exit(1);
    }

    match read_frame(&mut tls) {
        Ok((1, data)) => {
            let s = strip_nul(&data);
            match ccc::parse(&s) {
                Ok(p) => {
                    println!("# {} reply:\n{}\n", p.name, p.body.pretty(0));
                    if p.name == "hello_reply" {
                        let ip = p.path(&["OM", "ipaddr"]).and_then(|v| v.text()).unwrap_or_default();
                        let subnet = p
                            .path(&["optional", "subnet"])
                            .and_then(|v| v.text())
                            .unwrap_or_default();
                        println!("SSL TUNNEL UP — Office Mode IP: {ip}  subnet: {subnet}");
                    } else if p.name == "disconnect" {
                        println!("gateway sent disconnect (session invalid/expired?)");
                    }
                }
                Err(e) => println!("(could not parse control reply: {e})\n{s}"),
            }
        }
        Ok((2, data)) => println!("# unexpected DATA packet ({} bytes) during handshake", data.len()),
        Ok((t, _)) => println!("# unexpected packet type {t}"),
        Err(e) => {
            eprintln!("read failed: {e}");
            std::process::exit(1);
        }
    }
}

fn send_control(tls: &mut impl Write, payload: &str) -> std::io::Result<()> {
    let mut body = payload.as_bytes().to_vec();
    body.push(0);
    let mut frame = Vec::with_capacity(8 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes()); // PKT_CONTROL
    frame.extend_from_slice(&body);
    tls.write_all(&frame)
}

fn read_frame(tls: &mut impl Read) -> std::io::Result<(u32, Vec<u8>)> {
    let mut hdr = [0u8; 8];
    tls.read_exact(&mut hdr)?;
    let len = u32::from_be_bytes(hdr[0..4].try_into().unwrap()) as usize;
    let ptype = u32::from_be_bytes(hdr[4..8].try_into().unwrap());
    let mut payload = vec![0u8; len];
    tls.read_exact(&mut payload)?;
    Ok((ptype, payload))
}

fn strip_nul(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// Send an IKE message, then receive the reply that carries the expected
/// message_id — skipping retransmits of earlier exchanges (whose stale IVs would
/// otherwise decrypt to garbage). Reads only the header, never decrypting skips.
fn ike_send_recv_mid(
    udp: &ike::transport::IkeUdp,
    msg: &[u8],
    want_mid: u32,
) -> Result<Vec<u8>, String> {
    udp.send(msg)?;
    for _ in 0..8 {
        let r = udp.recv()?;
        if r.len() >= 24 {
            let mid = u32::from_be_bytes(r[20..24].try_into().unwrap());
            if mid == want_mid {
                return Ok(r);
            }
        }
    }
    Err(format!("no reply with message_id {want_mid:#x}"))
}

static TUNNEL_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Set when the control loop gives up recovering the tunnel (the IKE SA is gone and
/// re-auth needs a fresh passcode): the main loop turns this into an error exit so
/// the GUI shows the drop instead of a silent stop.
static TUNNEL_LOST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
extern "C" fn tunnel_sig_handler(_sig: libc::c_int) {
    TUNNEL_STOP.store(true, std::sync::atomic::Ordering::SeqCst);
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Check Point IPsec "tunnel-test" keepalive: a 12-byte UDP payload to the
/// gateway on port 18234, carried *inside* the tunnel. Check Point tears a tunnel
/// down after a few minutes of not seeing these, even if ESP data is flowing —
/// this is what kept the tunnel from surviving past ~20 min.
fn ipsec_keepalive_packet(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, counter: u32) -> Vec<u8> {
    let mut payload = [0u8; 12];
    payload[0..4].copy_from_slice(&counter.to_be_bytes());
    payload[4..6].copy_from_slice(&3u16.to_be_bytes());
    payload[6..8].copy_from_slice(&2u16.to_be_bytes());
    payload[8..10].copy_from_slice(&12u16.to_be_bytes());

    const PORT: u16 = 18234;
    let udp_len = (8 + payload.len()) as u16;
    let mut udp = Vec::with_capacity(udp_len as usize);
    udp.extend_from_slice(&PORT.to_be_bytes()); // sport
    udp.extend_from_slice(&PORT.to_be_bytes()); // dport
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum 0 (gateway ignores it)
    udp.extend_from_slice(&payload);

    let total_len = (20 + udp.len()) as u16;
    let mut ip = Vec::with_capacity(total_len as usize);
    ip.push(0x45); // IPv4, IHL 5
    ip.push(0x00);
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&(counter as u16).to_be_bytes()); // ID
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    ip.push(64); // TTL
    ip.push(17); // UDP
    ip.extend_from_slice(&[0, 0]); // header checksum placeholder
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let csum = ip_checksum(&ip);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    ip.extend_from_slice(&udp);
    ip
}

#[allow(clippy::too_many_arguments)]
fn run_tunnel(
    om_ip: std::net::Ipv4Addr,
    om_mask: std::net::Ipv4Addr,
    esp_sa: std::sync::Arc<ike::esp::EspSa>,
    sock: std::sync::Arc<std::net::UdpSocket>,
    dns: Vec<std::net::Ipv4Addr>,
    domains: String,
    rekey_secs: u32,
    lease_secs: u32,
    mac: Vec<u8>,
    session: Option<ike::session::Ikev1Session>,
    routes: Option<Vec<(std::net::Ipv4Addr, u8)>>,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{mpsc, Arc, RwLock};

    let prefix = tun::mask_to_prefix(om_mask);
    let (tun_rd, tun_name) = tun::open_tun("unvpn0")?;
    let tun_wr = tun_rd.try_clone().map_err(|e| e.to_string())?;
    tun::ip(&["addr", "add", &format!("{om_ip}/{prefix}"), "dev", &tun_name])?;
    tun::ip(&["link", "set", "dev", &tun_name, "up", "mtu", "1400"])?;
    crate::netmon::ignore_iface(&tun_name);
    println!("# tun {tun_name} up — {om_ip}/{prefix}");

    let _ = sock.send(&[0xff]); // NAT-T keepalive
    println!("# ESP on socket {:?} (same NAT-T port as IKE)", sock.local_addr().ok());

    // Restores DNS when dropped — also on an early return or a panic (e.g. a print
    // to the GUI's stdout pipe after the GUI is gone).
    let gw_v4 = sock.peer_addr().ok().and_then(|a| match a.ip() {
        std::net::IpAddr::V4(v) => Some(v),
        std::net::IpAddr::V6(_) => None,
    });
    let mut _restore = sysnet::NetRestore::default();
    match routes {
        None => out!("# --no-routes: installing no routes/DNS (reach hosts with `ping -I {tun_name}`)"),
        Some(nets) => {
            _restore.routes = cp_setup_routes(gw_v4, &tun_name, &nets);
            _restore.dns = sysnet::set_dns(&sysnet::tunnelled_dns(&dns, &tun_name), &domains);
            _restore.leak = leakguard::enable(&tun_name, &gw_v4.into_iter().collect::<Vec<_>>())?;
        }
    }
    TUNNEL_STOP.store(false, Ordering::SeqCst);
    TUNNEL_LOST.store(false, Ordering::SeqCst);
    unsafe {
        let h = tunnel_sig_handler as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGINT, h);
        libc::signal(libc::SIGHUP, h); // terminal closed (sudo relays it)
        libc::signal(libc::SIGQUIT, h);
    }
    // Disconnect when stdin gets "disconnect" or EOF (the GUI owns this pipe). Read
    // through the shared reader: a code prompt during login may have started it.
    std::thread::spawn(|| {
        while let sysnet::StdinEvent::Line(l) = sysnet::stdin_next(None) {
            if sysnet::is_disconnect(&l) {
                break;
            }
        }
        TUNNEL_STOP.store(true, Ordering::SeqCst);
    });

    // The current ESP SA, swappable so a rekey can replace it under the live
    // data-plane threads (they clone the Arc per packet; the swap is a brief write).
    let esp = Arc::new(RwLock::new(esp_sa));
    // IKE messages (NAT-T marker 0x00000000) arriving on the shared socket are
    // routed here for the control thread (rekey). Only wired up when we hold the
    // IKE session (the `--connect` path; the tunnel-up debug path can't rekey).
    let (ike_tx, ike_rx): (Option<mpsc::Sender<Vec<u8>>>, Option<mpsc::Receiver<Vec<u8>>>) =
        if session.is_some() {
            let (t, r) = mpsc::channel();
            (Some(t), Some(r))
        } else {
            (None, None)
        };

    let tin = Arc::new(AtomicU64::new(0));
    let eout = Arc::new(AtomicU64::new(0));
    let uin = Arc::new(AtomicU64::new(0));
    let tout = Arc::new(AtomicU64::new(0));
    let derr = Arc::new(AtomicU64::new(0));

    {
        let (sa, s, c1, c2) = (esp.clone(), sock.clone(), tin.clone(), eout.clone());
        let mut rd = tun_rd;
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            loop {
                match std::io::Read::read(&mut rd, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) if !tun::is_ipv4(&buf[..n]) => {} // ESP next-header is IPv4 — drop the rest
                    Ok(n) => {
                        c1.fetch_add(1, Ordering::Relaxed);
                        let cur = sa.read().unwrap().clone();
                        if let Ok(pkt) = cur.encode(&buf[..n]) {
                            if s.send(&pkt).is_ok() {
                                c2.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        });
    }
    {
        let (sa, s, c1, c2, ce) = (esp.clone(), sock.clone(), uin.clone(), tout.clone(), derr.clone());
        let itx = ike_tx;
        let mut wr = tun_wr;
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            loop {
                match s.recv(&mut buf) {
                    Ok(n) if n > 8 && buf[..4] != [0, 0, 0, 0] => {
                        c1.fetch_add(1, Ordering::Relaxed);
                        let cur = sa.read().unwrap().clone();
                        match cur.decode(&buf[..n]) {
                            Ok(ip) => {
                                let _ = std::io::Write::write_all(&mut wr, &ip);
                                c2.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => {
                                ce.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Ok(n) if n > 4 && buf[..4] == [0, 0, 0, 0] => {
                        if let Some(tx) = &itx {
                            let _ = tx.send(buf[4..n].to_vec());
                        }
                    }
                    Ok(_) => {}
                    Err(_) => continue,
                }
            }
        });
    }
    // NAT-T keepalive (keeps the UDP/NAT mapping fresh).
    {
        let s = sock.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(20));
            if TUNNEL_STOP.load(Ordering::SeqCst) {
                break;
            }
            let _ = s.send(&[0xff]);
        });
    }
    // Check Point IPsec tunnel-test keepalive (through the tunnel → gateway:18234).
    // Without this the gateway drops the tunnel after a few idle minutes.
    if let Some(std::net::IpAddr::V4(gw_ip)) = sock.peer_addr().ok().map(|a| a.ip()) {
        let (esp_c, sock_c) = (esp.clone(), sock.clone());
        std::thread::spawn(move || {
            let mut counter = 1u32;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(20));
                if TUNNEL_STOP.load(Ordering::SeqCst) {
                    break;
                }
                let pkt = ipsec_keepalive_packet(om_ip, gw_ip, counter);
                counter = counter.wrapping_add(1);
                let cur = esp_c.read().unwrap().clone();
                if let Ok(enc) = cur.encode(&pkt) {
                    let _ = sock_c.send(&enc);
                }
            }
        });
    }
    if let (Some(session), Some(ike_rx)) = (session, ike_rx) {
        let (esp_c, sock_c, uin_c) = (esp.clone(), sock.clone(), uin.clone());
        std::thread::spawn(move || {
            ike_control_loop(session, sock_c, esp_c, om_ip, ike_rx, rekey_secs, lease_secs, mac, uin_c)
        });
    }

    println!("# TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)");
    let mut ticks = 0u32;
    while !TUNNEL_STOP.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(500));
        ticks += 1;
        if ticks % 10 == 0 {
            out!(
                "#  stats: tun_in={} esp_out={} udp_in={} tun_out={} dec_err={}",
                tin.load(Ordering::Relaxed),
                eout.load(Ordering::Relaxed),
                uin.load(Ordering::Relaxed),
                tout.load(Ordering::Relaxed),
                derr.load(Ordering::Relaxed),
            );
        }
    }
    out!("# disconnecting — restoring DNS, tearing down tun/routes…");
    // `_restore` puts DNS/routes/leak back as it drops.
    if TUNNEL_LOST.load(Ordering::SeqCst) {
        return Err("tunnel lost and the IKE session could not be recovered — reconnect".into());
    }
    Ok(())
}

/// Used when the gateway's encryption domain can't be fetched.
const CP_FALLBACK_ROUTE: (std::net::Ipv4Addr, u8) = (std::net::Ipv4Addr::new(10, 0, 0, 0), 8);

/// The site's encryption domain as prefixes, from a CCC `ClientSettings` request
/// on the session Office Mode handed out.
fn fetch_encryption_domain(host: &str, session_id: &str) -> Result<Vec<(std::net::Ipv4Addr, u8)>, String> {
    let body = ccc::client_settings(new_request_id(), session_id).serialize();
    let raw = post(host, &http_request(host, CCC_PATH, &body))?;
    let pkt = ccc::parse(split_http_body(&raw)).map_err(|e| format!("bad ClientSettings answer: {e}"))?;
    let ranges = ccc::encryption_domain(&pkt)?;
    let mut nets: Vec<(std::net::Ipv4Addr, u8)> =
        ranges.into_iter().flat_map(|(f, t)| tun::range_to_prefixes(f, t)).collect();
    nets.sort();
    nets.dedup();
    Ok(nets)
}

/// The routes to send into the tunnel: the encryption domain, or the fallback.
fn cp_routes(host: &str, session_id: Option<&str>) -> Vec<(std::net::Ipv4Addr, u8)> {
    let got = match session_id {
        Some(sid) => fetch_encryption_domain(host, sid),
        None => Err("Office Mode gave no CCC session".into()),
    };
    match got {
        Ok(nets) if !nets.is_empty() => {
            let shown: Vec<String> = nets.iter().take(8).map(|(n, l)| format!("{n}/{l}")).collect();
            let more = if nets.len() > 8 { format!(" (+{} more)", nets.len() - 8) } else { String::new() };
            out!("# encryption domain: {}{more}", shown.join(" "));
            nets
        }
        Ok(_) => cp_fallback("the gateway listed no ranges"),
        Err(e) => cp_fallback(&e),
    }
}

fn cp_fallback(why: &str) -> Vec<(std::net::Ipv4Addr, u8)> {
    let (n, l) = CP_FALLBACK_ROUTE;
    out!("# encryption domain unavailable ({}) — routing {n}/{l} into the tunnel", sysnet::one_line(why));
    vec![CP_FALLBACK_ROUTE]
}

/// Pin the gateway to its pre-VPN path, then route `nets` into `tun` — one
/// `ip -batch`. Returns the `route del` lines for teardown, minus routes that
/// already existed. A `/0` goes in as 0/1 + 128/1 so the real default stays.
fn cp_setup_routes(gw: Option<std::net::Ipv4Addr>, tun: &str, nets: &[(std::net::Ipv4Addr, u8)]) -> Vec<String> {
    let mut add: Vec<String> = Vec::new();
    let mut del: Vec<String> = Vec::new();
    let mut pair = |net: String, suffix: &str| {
        add.push(format!("route add {net} {suffix}"));
        del.push(format!("route del {net} {suffix}"));
    };
    let mut pinned = None;
    if let Some((gw, (via, dev))) = gw.and_then(|g| sysnet::original_path(g).map(|p| (g, p))) {
        let suffix = match via {
            Some(v) => format!("via {v} dev {dev}"),
            None => format!("dev {dev}"),
        };
        pinned = Some(format!("{gw}/32 ({suffix})"));
        pair(format!("{gw}/32"), &suffix);
    }
    let dev = format!("dev {tun}");
    for &(net, len) in nets {
        if len == 0 {
            pair("0.0.0.0/1".into(), &dev);
            pair("128.0.0.0/1".into(), &dev);
        } else {
            pair(format!("{net}/{len}"), &dev);
        }
    }
    let failed = tun::ip_batch_failed(&add).unwrap_or_default();
    if let Some(what) = pinned {
        if failed.contains(&0) {
            out!("# gateway route {what} already present — left as is");
        } else {
            out!("# pinned gateway route {what}");
        }
    }
    out!("# {} route(s) via {tun}", nets.len());
    if !failed.is_empty() {
        out!("# {} route(s) already existed — not ours, kept on disconnect", failed.len());
    }
    del.into_iter().enumerate().filter(|(i, _)| !failed.contains(i)).map(|(_, d)| d).collect()
}

fn rekey_interval(lifetime_secs: u32) -> std::time::Duration {
    use std::time::Duration;
    if let Some(n) = std::env::var("UNVPN_REKEY_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        return Duration::from_secs(n.max(20));
    }
    let base = if lifetime_secs > 0 { lifetime_secs as u64 } else { 1200 };
    let at = (base * 85 / 100).min(base.saturating_sub(60)).max(60);
    Duration::from_secs(at)
}

fn lease_renew_at(lease_secs: u32) -> std::time::Duration {
    std::time::Duration::from_secs(lease_secs.saturating_sub(300).max(60) as u64)
}

/// Runs while connected: renegotiates the ESP SA via a fresh Quick Mode under
/// the existing IKE SA — no re-auth — before the Phase-2 lifetime expires, and
/// renews the Office Mode lease, so long sessions don't drop.
#[allow(clippy::too_many_arguments)]
fn ike_control_loop(
    mut session: ike::session::Ikev1Session,
    sock: std::sync::Arc<std::net::UdpSocket>,
    esp: std::sync::Arc<std::sync::RwLock<std::sync::Arc<ike::esp::EspSa>>>,
    om_ip: std::net::Ipv4Addr,
    ike_rx: std::sync::mpsc::Receiver<Vec<u8>>,
    mut lifetime_secs: u32,
    mut lease_secs: u32,
    mac: Vec<u8>,
    uin: std::sync::Arc<std::sync::atomic::AtomicU64>,
) {
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::{Duration, Instant};

    // No decrypted ESP for this long → probe the gateway with a Quick Mode exchange;
    // if that fails this many times in a row the IKE SA is gone (give up, no re-auth
    // — the passcode is single-use). A resume/network-change kick probes at once.
    const LIVENESS_STALE_SECS: u64 = 45;
    const MAX_RECOVER_FAILS: u32 = 2;
    let _ = crate::netmon::kick_fd(); // arm the resume / network-change watchers
    let mut last_uin = uin.load(Ordering::Relaxed);
    let mut last_progress = Instant::now();
    let mut recover_fails = 0u32;

    let mut esp_interval = rekey_interval(lifetime_secs);
    let mut esp_next = Instant::now() + esp_interval;
    // The Office Mode IP has a lease (e.g. 900s); not renewing it is what dropped
    // the tunnel at ~15 min. Renew it with a fresh OM config request (requesting
    // the current IP) under the IKE SA before it expires.
    let mut lease_next = (lease_secs > 0).then(|| Instant::now() + lease_renew_at(lease_secs));
    println!(
        "# IKE control up — ESP lifetime {lifetime_secs}s (rekey {}s), OM lease {lease_secs}s{}",
        esp_interval.as_secs(),
        lease_next.map(|_| format!(" (renew {}s)", lease_renew_at(lease_secs).as_secs())).unwrap_or_default()
    );

    loop {
        if TUNNEL_STOP.load(Ordering::SeqCst) {
            break;
        }

        // Liveness: track decrypted-ESP progress; on a stall or a resume/network
        // kick, probe-and-recover with a Quick Mode exchange under the live IKE SA.
        let cur_uin = uin.load(Ordering::Relaxed);
        if cur_uin != last_uin {
            last_uin = cur_uin;
            last_progress = Instant::now();
            recover_fails = 0;
        }
        let kicked = crate::netmon::took_kick();
        let stale = last_progress.elapsed() >= Duration::from_secs(LIVENESS_STALE_SECS);
        if kicked.is_some() || stale {
            match kicked {
                Some(why) => out!("# link event ({why}) — probing the gateway"),
                None => out!("# no data from the gateway for {}s — probing", last_progress.elapsed().as_secs()),
            }
            match do_rekey(&mut session, &sock, &esp, om_ip, &ike_rx) {
                Ok((si, so, life)) => {
                    if life > 0 {
                        lifetime_secs = life;
                        esp_interval = rekey_interval(lifetime_secs);
                    }
                    esp_next = Instant::now() + esp_interval;
                    recover_fails = 0;
                    last_progress = Instant::now();
                    out!("# tunnel recovered (ESP SA refreshed spi_in={si:#010x} spi_out={so:#010x})");
                }
                Err(e) => {
                    recover_fails += 1;
                    out!("# recovery attempt {recover_fails}/{MAX_RECOVER_FAILS} failed: {e}");
                    if recover_fails >= MAX_RECOVER_FAILS {
                        out!("# giving up — the IKE session is gone (reconnect to re-authenticate)");
                        TUNNEL_LOST.store(true, Ordering::SeqCst);
                        TUNNEL_STOP.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
            continue;
        }

        let mut wait = esp_next.saturating_duration_since(Instant::now());
        if let Some(ln) = lease_next {
            wait = wait.min(ln.saturating_duration_since(Instant::now()));
        }
        wait = wait.min(Duration::from_secs(1));

        match ike_rx.recv_timeout(wait) {
            Ok(raw) => {
                if raw.len() >= 20 {
                    println!("# IKE control: gateway sent IKE exchange {} (ignored)", raw[18]);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                // Office Mode lease renewal — and refresh the ESP SA alongside it.
                if lease_next.is_some_and(|ln| now >= ln) {
                    match do_lease_renew(&mut session, &sock, om_ip, &mac, &ike_rx) {
                        Ok(nl) => {
                            if nl > 0 {
                                lease_secs = nl;
                            }
                            println!("# OM lease renewed ({lease_secs}s)");
                        }
                        Err(e) => println!("# warning: OM lease renew failed: {e}"),
                    }
                    lease_next = Some(Instant::now() + lease_renew_at(lease_secs));
                    match do_rekey(&mut session, &sock, &esp, om_ip, &ike_rx) {
                        Ok((si, so, life)) => {
                            if life > 0 {
                                lifetime_secs = life;
                                esp_interval = rekey_interval(lifetime_secs);
                            }
                            println!("# ESP SA rekeyed (spi_in={si:#010x} spi_out={so:#010x})");
                        }
                        Err(e) => println!("# warning: ESP rekey failed: {e} — keeping current SA"),
                    }
                    esp_next = Instant::now() + esp_interval;
                } else if now >= esp_next {
                    match do_rekey(&mut session, &sock, &esp, om_ip, &ike_rx) {
                        Ok((si, so, life)) => {
                            if life > 0 {
                                lifetime_secs = life;
                                esp_interval = rekey_interval(lifetime_secs);
                            }
                            println!("# ESP SA rekeyed (spi_in={si:#010x} spi_out={so:#010x}, next {}s)", esp_interval.as_secs());
                        }
                        Err(e) => println!("# warning: ESP rekey failed: {e} — keeping current SA"),
                    }
                    esp_next = Instant::now() + esp_interval;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// Renew the Office Mode IP lease: re-send the OM config request (asking for the
/// current IP) under the IKE SA, in an ISAKMP-CFG Transaction, and read the fresh
/// lease back. Returns the new lease in seconds (0 if the reply didn't carry one).
fn do_lease_renew(
    session: &mut ike::session::Ikev1Session,
    sock: &std::net::UdpSocket,
    om_ip: std::net::Ipv4Addr,
    mac: &[u8],
    ike_rx: &std::sync::mpsc::Receiver<Vec<u8>>,
) -> Result<u32, String> {
    use ike::model::{ConfigAttributeType, ExchangeType};
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::{Duration, Instant};

    let (om_mid, _id, om_pl) = ike::service::build_om_request(session, mac, om_ip);
    let msg = ike::service::encrypt_message(session, u8::from(ExchangeType::Transaction), om_mid, &om_pl)?;

    let mut reply = None;
    'retx: for _ in 0..5u32 {
        send_natt(sock, &msg)?;
        let sub = Instant::now() + Duration::from_secs(3);
        while Instant::now() < sub {
            let left = sub.saturating_duration_since(Instant::now());
            match ike_rx.recv_timeout(left) {
                Ok(raw) => {
                    if raw.len() >= 24
                        && u32::from_be_bytes(raw[20..24].try_into().unwrap()) == om_mid
                    {
                        reply = Some(
                            ike::service::decrypt_message(session, &raw)
                                .map_err(|e| format!("OM renew decrypt: {e}"))?,
                        );
                        break 'retx;
                    }
                }
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => return Err("ike channel closed".into()),
            }
        }
    }
    let reply = reply.ok_or("no OM renew reply")?;
    let oma = ike::service::find_attributes(&reply).ok_or("no attributes in OM renew reply")?;
    let to_secs = |v: Vec<u8>| -> Option<u32> {
        match v.len() {
            4 => Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
            2 => Some(u16::from_be_bytes([v[0], v[1]]) as u32),
            _ => None,
        }
    };
    let lease = ike::service::get_long_attr(&oma, ConfigAttributeType::CccVariableLeaseTime)
        .and_then(to_secs)
        .or_else(|| ike::service::get_long_attr(&oma, ConfigAttributeType::AddressExpiry).and_then(to_secs))
        .unwrap_or(0);
    Ok(lease)
}

/// Prepend the NAT-T Non-ESP marker and send an IKE message on the shared socket.
fn send_natt(sock: &std::net::UdpSocket, msg: &[u8]) -> Result<(), String> {
    let mut buf = Vec::with_capacity(4 + msg.len());
    buf.extend_from_slice(&[0, 0, 0, 0]);
    buf.extend_from_slice(msg);
    sock.send(&buf).map(|_| ()).map_err(|e| e.to_string())
}

/// Run one Quick Mode exchange to replace the ESP SA, then hot-swap it in.
fn do_rekey(
    session: &mut ike::session::Ikev1Session,
    sock: &std::net::UdpSocket,
    esp: &std::sync::RwLock<std::sync::Arc<ike::esp::EspSa>>,
    om_ip: std::net::Ipv4Addr,
    ike_rx: &std::sync::mpsc::Receiver<Vec<u8>>,
) -> Result<(u32, u32, u32), String> {
    use ike::model::ExchangeType;
    use std::time::{Duration, Instant};

    let our_spi = ike::crypto::random_u32();
    let qm_nonce = ike::crypto::random(32);
    let qm_mid = ike::crypto::random_u32();
    let qm1 = ike::service::build_quick_mode(session, our_spi, &qm_nonce, om_ip, qm_mid, 3600);
    let qm1_msg = ike::service::encrypt_message(session, u8::from(ExchangeType::Quick), qm_mid, &qm1)?;
    // (Re)transmit QM1 until QM2 for our message-id arrives (the gateway can drop
    // the first one); skip retransmits / unsolicited informationals.
    use std::sync::mpsc::RecvTimeoutError;
    let mut qm2 = None;
    'retx: for _ in 0..5u32 {
        send_natt(sock, &qm1_msg)?;
        let sub = Instant::now() + Duration::from_secs(3);
        while Instant::now() < sub {
            let left = sub.saturating_duration_since(Instant::now());
            match ike_rx.recv_timeout(left) {
                Ok(raw) => {
                    if raw.len() >= 24
                        && u32::from_be_bytes(raw[20..24].try_into().unwrap()) == qm_mid
                    {
                        qm2 = Some(
                            ike::service::decrypt_message(session, &raw)
                                .map_err(|e| format!("QM2 decrypt: {e}"))?,
                        );
                        break 'retx;
                    }
                }
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => return Err("ike channel closed".into()),
            }
        }
    }
    let qm2 = qm2.ok_or("no QM2 reply")?;
    for p in &qm2.payloads {
        if let ike::wire::Payload::Notification(n) = p {
            return Err(format!("rekey rejected: NOTIFY {}", n.message_type));
        }
    }
    let chosen = ike::service::parse_esp_proposal(&qm2)?;
    let qm3 = ike::service::build_qm_ack(session, qm_mid, &qm_nonce, &chosen.nonce_r);
    send_natt(sock, &ike::service::encrypt_message(session, u8::from(ExchangeType::Quick), qm_mid, &qm3)?)?;

    let enc_len = if chosen.key_bits > 0 { chosen.key_bits / 8 } else { 24 };
    let auth_len = match chosen.auth_alg {
        a if a == ike::model::ESP_AUTH_HMAC_SHA96 || a == ike::model::ESP_AUTH_HMAC_SHA160 => 20,
        _ => 32,
    };
    let km_in = session.gen_esp_keymat(our_spi, &qm_nonce, &chosen.nonce_r, enc_len + auth_len);
    let km_out = session.gen_esp_keymat(chosen.gateway_spi, &qm_nonce, &chosen.nonce_r, enc_len + auth_len);
    let new_sa = std::sync::Arc::new(ike::esp::EspSa::new(
        chosen.transform_id,
        chosen.auth_alg,
        chosen.key_bits,
        our_spi,
        &km_in,
        chosen.gateway_spi,
        &km_out,
    )?);
    *esp.write().unwrap() = new_sa;
    Ok((our_spi, chosen.gateway_spi, chosen.lifetime_secs))
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn save_session_file(
    path: &str,
    host: &str,
    om_ip: std::net::Ipv4Addr,
    om_mask: std::net::Ipv4Addr,
    esp: &ike::service::ChosenEsp,
    our_spi: u32,
    km_in: &[u8],
    km_out: &[u8],
    dns: &[std::net::Ipv4Addr],
    domains: &str,
) -> Result<(), String> {
    let dns_str = dns.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(",");
    let data = format!(
        "gateway={host}\nom_ip={om_ip}\nom_mask={om_mask}\ntransform_id={}\nauth_alg={}\nkey_bits={}\nour_spi={}\ngw_spi={}\ndns={dns_str}\ndomains={domains}\nkm_in={}\nkm_out={}\n",
        esp.transform_id,
        esp.auth_alg,
        esp.key_bits,
        our_spi,
        esp.gateway_spi,
        hex_of(km_in),
        hex_of(km_out)
    );
    sysnet::write_user_file(path, data.as_bytes()).map_err(|e| format!("{path}: {e}"))
}

/// Debug: bring up the tunnel from a saved session file (no re-auth, so the
/// ESP data path can be iterated without burning a one-time passcode).
fn cmd_tunnel_up(args: &[String]) {
    let mut path = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--session" | "-s" => path = it.next().cloned(),
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let path = path.unwrap_or_else(|| {
        eprintln!("tunnel-up requires --session <file>");
        std::process::exit(2);
    });

    let run = || -> Result<(), String> {
        let text = sysnet::read_user_string(&path).map_err(|e| format!("{path}: {e}"))?;
        let mut m = std::collections::HashMap::new();
        for line in text.lines() {
            if let Some((k, v)) = line.split_once('=') {
                m.insert(k.to_string(), v.to_string());
            }
        }
        let get = |k: &str| -> Result<String, String> { m.get(k).cloned().ok_or(format!("missing {k}")) };
        let host = get("gateway")?;
        let om_ip: std::net::Ipv4Addr = get("om_ip")?.parse().map_err(|_| "bad om_ip")?;
        let om_mask: std::net::Ipv4Addr = get("om_mask")?.parse().map_err(|_| "bad om_mask")?;
        let transform_id: u8 = get("transform_id")?.parse().map_err(|_| "bad transform_id")?;
        let auth_alg: u16 = get("auth_alg")?.parse().map_err(|_| "bad auth_alg")?;
        let key_bits: usize = get("key_bits")?.parse().map_err(|_| "bad key_bits")?;
        let our_spi: u32 = get("our_spi")?.parse().map_err(|_| "bad our_spi")?;
        let gw_spi: u32 = get("gw_spi")?.parse().map_err(|_| "bad gw_spi")?;
        let km_in = unhex(&get("km_in")?);
        let km_out = unhex(&get("km_out")?);
        let dns: Vec<std::net::Ipv4Addr> = m
            .get("dns")
            .map(|s| s.split(',').filter_map(|x| x.parse().ok()).collect())
            .unwrap_or_default();
        let domains = m.get("domains").cloned().unwrap_or_default();
        let esp_sa = std::sync::Arc::new(ike::esp::EspSa::new(
            transform_id,
            auth_alg,
            key_bits,
            our_spi,
            &km_in,
            gw_spi,
            &km_out,
        )?);
        println!(
            "# loaded session: gw {host}, OM {om_ip}/{om_mask}, transform {transform_id} auth {auth_alg} our_spi {our_spi:#010x} gw_spi {gw_spi:#010x}"
        );
        let sock = std::sync::Arc::new(std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?);
        sock.connect((host.as_str(), 4500)).map_err(|e| e.to_string())?;
        run_tunnel(om_ip, om_mask, esp_sa, sock, dns, domains, 0, 0, Vec::new(), None, Some(vec![CP_FALLBACK_ROUTE]))
    };
    if let Err(e) = run() {
        eprintln!("tunnel-up failed: {e}");
        std::process::exit(1);
    }
}

/// A certificate login, prepared before IKE starts.
struct CertLogin {
    key: openssl::pkey::PKey<openssl::pkey::Private>,
    /// The user's certificate first, then the rest of the file's chain.
    chain: Vec<openssl::x509::X509>,
    realm: String,
    secondary_realm_hash: Option<String>,
    common_name: String,
}

/// Open the certificate file (password from stdin) and pick the login option.
fn prepare_cert_login(host: &str, path: &str, wanted_realm: Option<&str>) -> Result<CertLogin, String> {
    let pw = anyconnect::read_secret("Certificate password: ").ok_or("no certificate password given")?;
    let id = cpcert::p12::load(path, &pw)?;
    let subject = cpcert::p12::dn_string(id.cert.subject_name());
    let common_name = id
        .cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .map(|e| String::from_utf8_lossy(e.data().as_slice()).into_owned())
        .unwrap_or_default();
    let now = openssl::asn1::Asn1Time::days_from_now(0).map_err(|e| e.to_string())?;
    if id.cert.not_after() < now {
        println!("# warning: the certificate expired on {}", id.cert.not_after());
    }
    println!("# certificate: {subject} (valid until {})", id.cert.not_after());

    let info = match gateway_hello(host) {
        Ok(p) => cpcert::GatewayInfo::from_hello(&p),
        Err(e) if wanted_realm.is_some() => {
            println!("# warning: could not read the gateway's login options: {e}");
            cpcert::GatewayInfo::default()
        }
        Err(e) => return Err(format!("could not read the gateway's login options: {e}")),
    };
    let (realm, secondary_realm_hash) = match wanted_realm {
        Some(r) if info.login_options.is_empty() => (r.to_string(), None),
        w => {
            let o = info.certificate_option(w)?;
            println!("# login option: {} \"{}\" [{}]", o.id, o.display_name, o.factors.join(" + "));
            (o.id, Some(o.secondary_realm_hash).filter(|h| !h.is_empty()))
        }
    };
    if let Some(ca) = id.chain.first() {
        let fp = cpcert::enroll::ca_fingerprint(ca);
        if !info.ca_fingerprints.is_empty() && !info.ca_fingerprints.contains(&fp) {
            println!("# warning: the certificate's CA ({fp}) is not the gateway's internal CA");
        }
    }
    let mut chain = vec![id.cert];
    chain.extend(id.chain);
    Ok(CertLogin { key: id.key, chain, realm, secondary_realm_hash, common_name })
}

fn cmd_ike(args: &[String]) {
    let mut gateway: Option<String> = None;
    let mut user = String::new();
    let mut realm: Option<String> = None;
    let mut passcode: Option<String> = None;
    let mut cert: Option<String> = None;
    let mut probe_sig = false;
    let mut connect = false;
    let mut natt = false;
    let mut save_session: Option<String> = None;
    let mut no_routes = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" => gateway = it.next().cloned(),
            "--user" | "-u" => user = it.next().cloned().unwrap_or(user),
            "--realm" | "-r" => realm = it.next().cloned().filter(|r| !r.is_empty()),
            "--passcode" | "-p" => passcode = it.next().cloned(),
            "--cert" | "-c" => cert = it.next().cloned(),
            "--probe-sig" => probe_sig = true,
            "--connect" => connect = true,
            "--natt" => natt = true,
            "--save-session" => save_session = it.next().cloned(),
            "--no-routes" => no_routes = true,
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let host = gateway.unwrap_or_else(|| {
        eprintln!("ike requires --gateway <host>");
        std::process::exit(2);
    });
    if user.is_empty() && cert.is_none() && !probe_sig {
        eprintln!("ike requires --user <user> (or --cert <file.p12>)");
        std::process::exit(2);
    }

    let gw_ip: std::net::Ipv4Addr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("ike needs the gateway as an IPv4 address");
            std::process::exit(2);
        }
    };

    let cert_login = match &cert {
        Some(path) => match prepare_cert_login(&host, path, realm.as_deref()) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("IKE failed: {e}");
                std::process::exit(1);
            }
        },
        None => None,
    };
    let realm = cert_login.as_ref().map(|c| c.realm.clone()).or(realm).unwrap_or_else(|| "vpn".to_string());
    if user.is_empty() {
        if let Some(c) = &cert_login {
            user = c.common_name.clone();
        }
    }

    let mut run = || -> Result<(), String> {
        use ike::model::{AttributesPayloadType, ConfigAttributeType, ExchangeType};
        use ike::service;
        use ike::session::Ikev1Session;
        use ike::transport::IkeUdp;
        use ike::wire::{Attribute, IsakmpMessage, Payload};

        // ESP needs the same NAT-T mapping as IKE, so --connect does the whole
        // handshake on UDP 4500 and reuses that socket for ESP.
        let use_natt = connect || natt;
        let udp = IkeUdp::connect(&host, use_natt, Duration::from_secs(6))?;
        let local = udp.local_ipv4();
        let port = if use_natt { 4500 } else { 500 };
        println!("# IKEv1 Phase 1 to {host} over UDP {port} (local {local})");

        let mut session = Ikev1Session::new();

        // msg 1/2 — SA proposal / chosen transform.
        let auth_method = if cert_login.is_some() || probe_sig {
            ike::model::IKE_AUTH_RSA_SIG
        } else {
            ike::model::IKE_AUTH_HYBRID_INIT_RSA
        };
        let msg1 = service::build_sa_msg(&session, 28800, auth_method);
        session.set_sa_bytes(&service::sa_body(&msg1).ok_or("no SA body")?);
        let m2 = IsakmpMessage::decode(&udp.send_recv(&msg1.encode())?)?;
        let suite = service::parse_chosen_suite(&m2).map_err(|e| {
            let mut s = format!("SA rejected: {e}");
            for p in &m2.payloads {
                if let Payload::Notification(n) = p {
                    s.push_str(&format!("\n  NOTIFY {}: {}", n.message_type, String::from_utf8_lossy(&n.data)));
                }
            }
            s
        })?;
        println!(
            "# msg2 SA: enc={} hash={} group={} key_bits={} lifetime={}s responder_spi={:#018x}",
            suite.enc_alg, suite.hash_alg, suite.group, suite.key_bits, suite.lifetime, suite.responder_spi
        );
        session.responder_spi = suite.responder_spi;
        session.set_suite(suite.group, suite.hash_alg, suite.enc_alg, suite.key_bits)?;

        // msg 3/4 — KE + Nonce + NAT-D.
        let cert_requests: Vec<Vec<u8>> = match &cert_login {
            Some(c) => vec![c.chain[0].issuer_name().to_der().map_err(|e| e.to_string())?, Vec::new()],
            None if probe_sig => vec![Vec::new()],
            None => Vec::new(),
        };
        let msg3 = service::build_ke(&session, local, gw_ip, &cert_requests);
        let m4 = IsakmpMessage::decode(&udp.send_recv(&msg3.encode())?)?;
        let gw_pub = service::find_key_exchange(&m4).ok_or("no KE in msg4")?;
        let gw_nonce = service::find_nonce(&m4).ok_or("no nonce in msg4")?;
        println!(
            "# msg4: gateway KE {} bytes, nonce {} bytes, {} NAT-D payload(s)",
            gw_pub.len(),
            gw_nonce.len(),
            service::find_natds(&m4).len()
        );

        if probe_sig {
            let kinds: Vec<u8> = m4.payloads.iter().map(|p| p.payload_type()).collect();
            println!("# msg4 payload types: {kinds:?}");
            for p in &m4.payloads {
                if let Payload::CertificateRequest(d) = p {
                    let dn = d
                        .get(1..)
                        .filter(|b| !b.is_empty())
                        .and_then(|b| openssl::x509::X509Name::from_der(b).ok())
                        .map(|n| cpcert::p12::dn_string(&n))
                        .unwrap_or_else(|| "(any)".into());
                    println!("# gateway asks for a certificate (encoding {}) from: {dn}", d.first().copied().unwrap_or(0));
                }
            }
            println!("# the gateway accepts certificate (RSA signature) authentication; stopping before any identity is sent");
            return Ok(());
        }
        session.compute_keys(&gw_pub, &gw_nonce)?;
        println!(
            "# Phase 1 key material derived: SKEYID={}B d={}B a={}B e={}B",
            session.skeyid.len(),
            session.skeyid_d.len(),
            session.skeyid_a.len(),
            session.skeyid_e.len()
        );

        // msg 5/6 — ID protection + Check Point hybrid or certificate auth (encrypted).
        let auth_payloads = match &cert_login {
            Some(c) => service::build_cert_auth_payloads(
                &session,
                &service::auth_blob(&c.realm, c.secondary_realm_hash.as_deref()),
                &c.key,
                &c.chain,
            )?,
            None => service::build_auth_payloads(&session, &realm),
        };
        let msg5 = service::encrypt_message(
            &mut session,
            u8::from(ExchangeType::IdentityProtection),
            0,
            &auth_payloads,
        )?;
        let raw6 = udp.send_recv(&msg5)?;
        let m6 = service::decrypt_message(&mut session, &raw6)?;
        for p in &m6.payloads {
            if let Payload::Notification(n) = p {
                return Err(format!(
                    "msg6 NOTIFY {}: {}",
                    n.message_type,
                    String::from_utf8_lossy(&n.data)
                ));
            }
        }
        let id_r = service::find_identification_body(&m6).ok_or("no ID_R in msg6")?;
        let hash_r = session.hash_id_r(&id_r);
        match (service::find_signature(&m6), service::find_certificates(&m6).first().cloned()) {
            (Some(sig), Some(cert)) => match session.verify_rsa_signature(&hash_r, &sig, &cert) {
                Ok(()) => println!("# Phase 1 COMPLETE — gateway SIG_R verified against its certificate."),
                Err(e) => println!("# warning: gateway SIG_R did not verify: {e}"),
            },
            _ => match service::find_hash(&m6) {
                Some(h) if ike::crypto::ct_eq(&h, &hash_r) => println!("# Phase 1 COMPLETE — HASH_R matches."),
                _ => println!("# warning: msg6 had no SIG_R/cert and no matching HASH_R (payloads={})", m6.payloads.len()),
            },
        }

        // After msg6, skip any msg6 retransmits and drive the config-mode exchange
        // (SecurID, or the second factor of a certificate login; one message_id
        // throughout; reply with the requested attribute). A certificate login
        // without a second factor gets no config-mode request at all.
        if cert_login.is_some() {
            if let (Some(ca), Some(gw_cert)) = (
                cert_login.as_ref().and_then(|c| c.chain.get(1)),
                service::find_certificates(&m6).first().and_then(|d| openssl::x509::X509::from_der(d).ok()),
            ) {
                let ok = ca.public_key().ok().map(|k| gw_cert.verify(&k).unwrap_or(false)).unwrap_or(false);
                if !ok {
                    println!("# warning: the gateway certificate is not issued by the certificate's CA");
                }
            }
        }
        println!("# Phase 1 done; waiting for the gateway's authentication requests...");
        // Raw datagrams already handled: the gateway retransmits them while it waits
        // (e.g. for a code being typed), and decrypting one twice breaks the IV chain.
        let mut seen: Vec<Vec<u8>> = vec![raw6.clone()];
        let mut first = None;
        loop {
            match udp.recv() {
                Ok(r) if r == raw6 => continue, // msg6 retransmit while the gateway waits for us
                Ok(r) => {
                    seen.push(r.clone());
                    first = Some(service::decrypt_message(&mut session, &r)?);
                    break;
                }
                Err(e) if cert_login.is_some() => {
                    println!("# no further authentication requested ({e})");
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        let mut cfg_mid = 0u32;
        if let Some(mut req) = first {
            loop {
                let attrs = service::find_attributes(&req).ok_or("expected config attributes after Phase 1")?;
                let message_id = req.message_id;
                cfg_mid = message_id;
                let identifier = attrs.identifier;

                if let Some(status) = service::get_short_attr(&attrs, ConfigAttributeType::Status) {
                    if status == 1 {
                        let ack = service::build_config_payloads(
                            &session,
                            u8::from(AttributesPayloadType::Ack),
                            message_id,
                            identifier,
                            vec![Attribute::short(u16::from(ConfigAttributeType::Status), 1)],
                        );
                        let ack_msg = service::encrypt_message(
                            &mut session,
                            u8::from(ExchangeType::Transaction),
                            message_id,
                            &ack,
                        )?;
                        udp.send(&ack_msg)?;
                        println!("# AUTH SUCCEEDED via native IKE (Status=1).");
                        break;
                    }
                    return Err(format!("authentication failed (Status={status})"));
                }

                let ctype_raw = service::challenge_attr_type(&attrs);
                let ctype = ConfigAttributeType::from(ctype_raw);
                let prompt = service::get_long_attr(&attrs, ConfigAttributeType::Challenge)
                    .or_else(|| service::get_long_attr(&attrs, ConfigAttributeType::Message))
                    .map(|b| String::from_utf8_lossy(&b).replace('\0', " | "))
                    .unwrap_or_default();

                let input = match ctype {
                    ConfigAttributeType::UserName => {
                        println!("# gateway requests UserName → sending {user}");
                        user.clone()
                    }
                    _ if cert_login.is_some() => {
                        println!("# gateway challenge [{:?}]: {}", ctype, sysnet::one_line(&prompt));
                        // The text may be followed by its structured form after a NUL.
                        let text = prompt.split(" | ").next().unwrap_or("").trim();
                        let label = if text.is_empty() { "Verification code".to_string() } else { text.to_string() };
                        match passcode.take() {
                            Some(p) => p,
                            None => {
                                println!("# AUTH-PROMPT: code: {}", sysnet::one_line(&label));
                                match anyconnect::read_secret("Code: ") {
                                    Some(c) => c.trim().to_string(),
                                    None => {
                                        println!("# no code provided; stopping.");
                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        println!("# gateway challenge [{:?}]: {}", ctype, sysnet::one_line(&prompt));
                        match passcode.take() {
                            Some(p) => p,
                            None => match anyconnect::read_secret("Passcode (PIN+tokencode): ") {
                                Some(p) if !p.trim().is_empty() => p.trim().to_string(),
                                _ => {
                                    println!("# no passcode provided; stopping.");
                                    return Ok(());
                                }
                            },
                        }
                    }
                };

                let reply = service::build_config_payloads(
                    &session,
                    u8::from(AttributesPayloadType::Reply),
                    message_id,
                    identifier,
                    vec![
                        Attribute::short(u16::from(ConfigAttributeType::AuthType), 0),
                        Attribute::long(ctype_raw, input.into_bytes()),
                    ],
                );
                let reply_msg = service::encrypt_message(
                    &mut session,
                    u8::from(ExchangeType::Transaction),
                    message_id,
                    &reply,
                )?;
                let stale = udp.drain().into_iter().filter(|d| !seen.contains(d)).count();
                if stale > 0 {
                    println!("# discarded {stale} unexpected message(s) received while waiting for input");
                }
                udp.send(&reply_msg)?;
                let sent_at = std::time::Instant::now();
                let mut resent = 0;
                let raw = loop {
                    let r = udp.recv()?;
                    if seen.contains(&r) {
                        // The request again after our reply had time to arrive: it was lost.
                        if sent_at.elapsed() > std::time::Duration::from_secs(3) && resent < 3 {
                            udp.send(&reply_msg)?;
                            resent += 1;
                        }
                        continue;
                    }
                    break r;
                };
                seen.push(raw.clone());
                req = service::decrypt_message(&mut session, &raw)?;
            }
        }

        let mac = ike::crypto::random(6);
        let (om_mid, _om_id, om_pl) =
            service::build_om_request(&session, &mac, std::net::Ipv4Addr::UNSPECIFIED);
        let om_msg = service::encrypt_message(
            &mut session,
            u8::from(ExchangeType::Transaction),
            om_mid,
            &om_pl,
        )?;
        let om_raw = ike_send_recv_mid(&udp, &om_msg, om_mid)?;
        let om_reply = service::decrypt_message(&mut session, &om_raw)?;
        let oma = service::find_attributes(&om_reply).ok_or("no Office Mode reply")?;
        let to_ip = |v: Vec<u8>| -> Option<std::net::Ipv4Addr> {
            (v.len() == 4).then(|| std::net::Ipv4Addr::new(v[0], v[1], v[2], v[3]))
        };
        let om_ip = service::get_long_attr(&oma, ConfigAttributeType::Ipv4Address)
            .and_then(to_ip)
            .ok_or("no Office Mode IP assigned")?;
        let om_mask = service::get_long_attr(&oma, ConfigAttributeType::Ipv4Netmask)
            .and_then(to_ip)
            .unwrap_or(std::net::Ipv4Addr::new(255, 255, 255, 255));
        let dns: Vec<std::net::Ipv4Addr> = service::get_long_attrs(&oma, ConfigAttributeType::Ipv4Dns)
            .into_iter()
            .filter_map(to_ip)
            .collect();
        let domains = service::get_long_attr(&oma, ConfigAttributeType::InternalDomainName)
            .map(|v| String::from_utf8_lossy(&v).trim_matches('\0').to_string())
            .unwrap_or_default();
        let to_secs = |v: Vec<u8>| -> Option<u32> {
            match v.len() {
                4 => Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
                2 => Some(u16::from_be_bytes([v[0], v[1]]) as u32),
                _ => None,
            }
        };
        let lease_secs = service::get_long_attr(&oma, ConfigAttributeType::CccVariableLeaseTime)
            .and_then(to_secs)
            .or_else(|| service::get_long_attr(&oma, ConfigAttributeType::AddressExpiry).and_then(to_secs))
            .unwrap_or(0);
        println!("# Office Mode: IP {om_ip} / {om_mask}  DNS {dns:?}  domains \"{domains}\"  lease={lease_secs}s");
        let ccc_session = service::get_long_attr(&oma, ConfigAttributeType::CccSessionId)
            .map(|v| String::from_utf8_lossy(&v).trim_matches('\0').trim().to_string())
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic()));

        let our_spi = ike::crypto::random_u32();
        let qm_nonce = ike::crypto::random(32);
        let qm_mid = ike::crypto::random_u32();
        let qm1 = service::build_quick_mode(&session, our_spi, &qm_nonce, om_ip, qm_mid, 3600);
        let qm1_msg = service::encrypt_message(&mut session, u8::from(ExchangeType::Quick), qm_mid, &qm1)?;
        udp.send(&qm1_msg)?;
        let stale = [0u32, om_mid, cfg_mid];
        let mut qm2_opt: Option<ike::wire::IsakmpMessage> = None;
        for _ in 0..8 {
            let r = match udp.recv() {
                Ok(r) => r,
                Err(_) => break,
            };
            if r.len() < 28 {
                continue;
            }
            let rmid = u32::from_be_bytes(r[20..24].try_into().unwrap());
            if stale.contains(&rmid) {
                continue;
            }
            match service::decrypt_message(&mut session, &r) {
                Ok(m) => {
                    qm2_opt = Some(m);
                    break;
                }
                Err(e) => println!("#  decrypt failed: {e}"),
            }
        }
        let qm2 = qm2_opt.ok_or("no Quick Mode reply")?;
        for p in &qm2.payloads {
            if let ike::wire::Payload::Notification(n) = p {
                return Err(format!(
                    "Quick Mode rejected: NOTIFY {} (msg_id {:#x}): {}",
                    n.message_type,
                    qm2.message_id,
                    String::from_utf8_lossy(&n.data)
                ));
            }
        }
        let esp = service::parse_esp_proposal(&qm2)?;
        println!(
            "# Quick Mode ESP SA: transform={} auth={} key_bits={} encap={:#x} gw_spi={:#010x} our_spi={:#010x} lifetime={}s",
            esp.transform_id, esp.auth_alg, esp.key_bits, esp.encap, esp.gateway_spi, our_spi, esp.lifetime_secs
        );

        let qm3 = service::build_qm_ack(&session, qm_mid, &qm_nonce, &esp.nonce_r);
        udp.send(&service::encrypt_message(&mut session, u8::from(ExchangeType::Quick), qm_mid, &qm3)?)?;
        let enc_len = if esp.key_bits > 0 { esp.key_bits / 8 } else { 24 };
        let auth_len = match esp.auth_alg {
            a if a == ike::model::ESP_AUTH_HMAC_SHA96 || a == ike::model::ESP_AUTH_HMAC_SHA160 => 20,
            _ => 32,
        };
        let km_in = session.gen_esp_keymat(our_spi, &qm_nonce, &esp.nonce_r, enc_len + auth_len);
        let km_out = session.gen_esp_keymat(esp.gateway_spi, &qm_nonce, &esp.nonce_r, enc_len + auth_len);
        let esp_sa = std::sync::Arc::new(ike::esp::EspSa::new(
            esp.transform_id,
            esp.auth_alg,
            esp.key_bits,
            our_spi,
            &km_in,
            esp.gateway_spi,
            &km_out,
        )?);
        println!("# FULL IKE/IPSec HANDSHAKE COMPLETE — ESP SA ready.");

        if let Some(path) = &save_session {
            save_session_file(path, &host, om_ip, om_mask, &esp, our_spi, &km_in, &km_out, &dns, &domains)?;
            println!("# session saved to {path} (reuse: sudo unvpn tunnel-up --session {path})");
        }
        if connect {
            let routes = (!no_routes).then(|| cp_routes(&host, ccc_session.as_deref()));
            let sock = std::sync::Arc::new(udp.try_clone_socket().map_err(|e| e.to_string())?);
            return run_tunnel(
                om_ip, om_mask, esp_sa, sock, dns, domains,
                esp.lifetime_secs, lease_secs, mac, Some(session), routes,
            );
        }
        println!("# Office Mode IP {om_ip} ready. (--connect brings up the tunnel; needs sudo)");
        Ok(())
    };

    if let Err(e) = run() {
        eprintln!("IKE failed: {e}");
        std::process::exit(1);
    }
}

fn main() {
    // Session-wide leak protection, parsed out before the sub-command so every
    // back-end sees the same policy without each parsing these itself.
    //   --killswitch   fail-closed firewall (default off)
    //   --allow-ipv6   keep IPv6 egress (default: blocked, since the tunnels are v4)
    //   --pin [<host>:<port>=]sha256:<hex>   trust that gateway certificate (repeatable)
    //   --insecure     trust any gateway certificate
    let mut killswitch = false;
    let mut block_ipv6 = true;
    let mut tls_flags: Vec<String> = Vec::new();
    let mut pins: Vec<String> = Vec::new();
    let mut insecure = false;
    let mut args: Vec<String> = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--killswitch" => killswitch = true,
            "--allow-ipv6" => block_ipv6 = false,
            "--insecure" => {
                insecure = true;
                tls_flags.push(a);
            }
            "--pin" => {
                let Some(v) = it.next() else {
                    eprintln!("--pin needs a value: [<host>:<port>=]sha256:<hex>");
                    std::process::exit(2);
                };
                pins.push(v.clone());
                tls_flags.extend([a, v]);
            }
            _ => match a.strip_prefix("--pin=") {
                Some(v) => {
                    pins.push(v.to_string());
                    tls_flags.extend(["--pin".to_string(), v.to_string()]);
                }
                None => args.push(a),
            },
        }
    }
    leakguard::configure(killswitch, block_ipv6);
    if let Err(e) = net::trust::configure(&pins, insecure) {
        eprintln!("{e}");
        std::process::exit(2);
    }

    match args.first().map(String::as_str) {
        Some("connect") => connect::cmd_connect(&args[1..], killswitch, !block_ipv6, &tls_flags),
        Some("hello") => cmd_hello(&args[1..]),
        Some("login") => cmd_login(&args[1..]),
        Some("deob") => cmd_deob(&args[1..]),
        Some("tunnel") => cmd_tunnel(&args[1..]),
        Some("ike") => cmd_ike(&args[1..]),
        Some("cp-enroll") => cpcert::cmd_enroll(&args[1..]),
        Some("tunnel-up") => cmd_tunnel_up(&args[1..]),
        Some("forti") => forti::cmd_forti(&args[1..]),
        Some("forti-ipsec") | Some("fortiipsec") => forti_ipsec::cmd_forti_ipsec(&args[1..]),
        Some("f5") => f5::cmd_f5(&args[1..]),
        Some("anyconnect") => anyconnect::cmd_anyconnect(&args[1..]),
        Some("gp") | Some("globalprotect") => gp::cmd_gp(&args[1..]),
        Some("ivanti") | Some("pulse") => ivanti::cmd_ivanti(&args[1..]),
        Some("openvpn") => openvpn::cmd_openvpn(&args[1..]),
        Some("wireguard") | Some("wg") => wireguard::cmd_wireguard(&args[1..]),
        Some("--version" | "-V" | "version") => println!("unvpn {}", env!("CARGO_PKG_VERSION")),
        Some("--help" | "-h" | "help") => usage(&mut std::io::stdout()),
        _ => {
            usage(&mut std::io::stderr());
            std::process::exit(2);
        }
    }
}

fn usage(out: &mut dyn Write) {
    let _ = writeln!(out, "unvpn — native multi-vendor VPN client\n");
    let _ = writeln!(out, "usage:");
    let _ = writeln!(out, "  unvpn connect <profile>          # connect a profile saved in the app (run as your user)");
    let _ = writeln!(out, "  unvpn connect --list             # the saved profiles");
    let _ = writeln!(out, "  unvpn hello [--gateway <host>] [--send]");
    let _ = writeln!(out, "  unvpn login --gateway <host> [--user <u>] [--realm <r>] [--passcode <p>] [--probe]");
    let _ = writeln!(out, "  unvpn tunnel --gateway <host> --active-key <obfuscated-hex> [--om-ip <ip>]");
    let _ = writeln!(out, "  unvpn ike --gateway <host> [--passcode <PIN+tokencode>] [--connect [--no-routes]]");
    let _ = writeln!(out, "       # M3/M4: IKEv1 handshake; with --connect (sudo) brings up the tun tunnel");
    let _ = writeln!(out, "  unvpn ike --gateway <host> --cert <file.p12> [--realm <login-option>] [--connect]");
    let _ = writeln!(out, "       # certificate login; the file password is read from stdin");
    let _ = writeln!(out, "  unvpn cp-enroll -g <host> -r <registration-key> -o <file.p12>");
    let _ = writeln!(out, "       # get a Check Point user certificate with a one-time registration key");
    let _ = writeln!(out, "  unvpn forti -g <host[:port]> -u <user> [--connect]   # Fortinet SSL-VPN back-end");
    let _ = writeln!(out, "  unvpn forti-ipsec -g <host> -u <user> [--localid <group>] [--connect]  # FortiClient IPsec (IKEv2) back-end");
    let _ = writeln!(out, "  unvpn f5 -g <host[:port]> -u <user> [--connect]      # F5 BIG-IP APM SSL-VPN back-end");
    let _ = writeln!(out, "  unvpn anyconnect -g <url> -u <user> [--connect]       # Cisco AnyConnect SSL-VPN back-end");
    let _ = writeln!(out, "  unvpn gp -g <portal> -u <user> [--connect]            # Palo Alto GlobalProtect back-end");
    let _ = writeln!(out, "  unvpn ivanti -g <host> -u <user> [--connect]          # Ivanti Connect Secure (Pulse) back-end");
    let _ = writeln!(out, "  unvpn openvpn -c <profile.ovpn> [-u <user>] [--connect] # OpenVPN back-end");
    let _ = writeln!(out, "  unvpn wireguard -c <profile.conf> --connect            # WireGuard (kernel) back-end");
    let _ = writeln!(out, "  unvpn --version");
    let _ = writeln!(out, "\nglobal flags (any back-end):");
    let _ = writeln!(out, "  --killswitch   fail-closed firewall: block all egress but the tunnel, gateway, LAN and DHCP");
    let _ = writeln!(out, "  --allow-ipv6   keep IPv6 egress (default: blocked, since the tunnels are IPv4-only)");
    let _ = writeln!(out, "  --pin [<host>:<port>=]sha256:<hex>");
    let _ = writeln!(out, "                 trust this gateway certificate when no system CA vouches for it (repeatable);");
    let _ = writeln!(out, "                 without one, an unknown certificate is shown and you are asked");
    let _ = writeln!(out, "  --insecure     accept any gateway certificate without checking it");
}

fn cmd_hello(args: &[String]) {
    let mut gateway: Option<String> = None;
    let mut send = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" => gateway = it.next().cloned(),
            "--send" => send = true,
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let pkt = ccc::client_hello(new_request_id());
    let body = pkt.serialize();

    println!("# CCC ClientHello (body, {} bytes):", body.len());
    println!("{body}\n");

    let host = match gateway {
        Some(h) => h,
        None => {
            println!("(no --gateway given; not sending. Pass --gateway <host> --send to probe.)");
            return;
        }
    };

    let request = http_request(&host, CCC_PATH, &body);
    println!("# HTTP request that would be sent to {host}:443 :");
    println!("{}", preview(&request));

    if !send {
        println!("(dry run; add --send to actually POST to the gateway)");
        return;
    }

    match post(&host, &request) {
        Ok(resp) => {
            let parsed_body = split_http_body(&resp);
            println!("\n# raw response ({} bytes of body):", parsed_body.len());
            println!("{}\n", preview(parsed_body));
            match ccc::parse(parsed_body) {
                Ok(p) => {
                    println!("# parsed CCCserverResponse:");
                    println!("{} {}", p.name, p.body.pretty(0));
                }
                Err(e) => println!("(could not parse body as CCC: {e})"),
            }
        }
        Err(e) => {
            eprintln!("send failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Authenticate over CCC. UserPass (empty password) → challenge loop
/// (SecurID passcode via MultiChallange) → session. The initial UserPass
/// carries no passcode, so `--probe` validates the format and shows the real
/// gateway challenge WITHOUT consuming a one-time passcode. `--verbose` dumps
/// the full raw HTTP response at each step.
fn cmd_login(args: &[String]) {
    let mut gateway: Option<String> = None;
    let mut user = String::new();
    let mut realm = "vpn".to_string();
    let mut passcode: Option<String> = None;
    let mut probe = false;
    let mut verbose = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" => gateway = it.next().cloned(),
            "--user" | "-u" => user = it.next().cloned().unwrap_or(user),
            "--realm" | "-r" => realm = it.next().cloned().unwrap_or(realm),
            "--passcode" | "-p" => passcode = it.next().cloned(),
            "--probe" => probe = true,
            "--verbose" | "-v" => verbose = true,
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let host = match gateway {
        Some(h) => h,
        None => {
            eprintln!("login requires --gateway <host>");
            std::process::exit(2);
        }
    };
    if user.is_empty() {
        eprintln!("login requires --user <user>");
        std::process::exit(2);
    }

    let req = ccc::auth_userpass(new_request_id(), &user, &realm);
    println!("# UserPass request (user={user}, realm={realm}):");
    println!("{}\n", req.serialize());
    let (mut raw, mut resp) = post_ccc(&host, &req, verbose);

    loop {
        let rc = resp
            .path(&["ResponseHeader", "return_code"])
            .and_then(|v| v.text())
            .unwrap_or_default();
        let status = resp
            .path(&["ResponseData", "authn_status"])
            .and_then(|v| v.text())
            .unwrap_or_default();
        println!("# response: return_code={rc} authn_status={status}");
        if let Some(c) = extract_cookie(&raw, "CPCVPN_SESSION_ID") {
            println!("# Set-Cookie CPCVPN_SESSION_ID = {c}");
        }

        match status.as_str() {
            "done" => {
                if verbose {
                    println!("\n# ---- full 'done' response headers ----");
                    println!("{}", http_headers(&raw));
                    println!("\n# ---- full 'done' response body (parsed) ----");
                    println!("{}\n", resp.body.pretty(0));
                }
                let authed = resp
                    .path(&["ResponseData", "is_authenticated"])
                    .and_then(|v| v.text())
                    .unwrap_or_default();
                let sid = resp
                    .path(&["ResponseData", "session_id"])
                    .and_then(|v| v.text())
                    .unwrap_or_default();
                let cookie = extract_cookie(&raw, "CPCVPN_SESSION_ID");

                if authed == "true" {
                    println!("\nAUTH OK (is_authenticated=true).");
                    if !sid.is_empty() {
                        println!("   session_id : {sid}");
                    }
                    if let Some(c) = &cookie {
                        println!("   CPCVPN_SESSION_ID cookie: {c}");
                    }
                    if let Some(k) = resp.path(&["ResponseData", "active_key"]).and_then(|v| v.text()) {
                        let key = ccc::deobfuscate(&k).unwrap_or_default();
                        println!("   active_key : {} bytes (deobfuscated)", key.len());
                    }
                } else {
                    let err = resp
                        .path(&["ResponseData", "error_message"])
                        .and_then(|v| v.text())
                        .filter(|h| !h.is_empty())
                        .and_then(|h| ccc::deobfuscate(&h).ok())
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                        .unwrap_or_default();
                    let ecode = resp
                        .path(&["ResponseData", "error_code"])
                        .and_then(|v| v.text())
                        .unwrap_or_default();
                    println!("\nAUTH FAILED (is_authenticated=false, error_code={ecode}).");
                    if !err.is_empty() {
                        println!("   gateway says: \"{err}\"");
                    }
                    println!("   → passcode not accepted; re-run with a fresh passcode.");
                }
                return;
            }
            "continue" => {
                let sid = resp
                    .path(&["ResponseData", "session_id"])
                    .and_then(|v| v.text())
                    .unwrap_or_default();
                let prompt = resp
                    .path(&["ResponseData", "prompt"])
                    .and_then(|v| v.text())
                    .map(|h| {
                        ccc::deobfuscate(&h)
                            .map(|b| String::from_utf8_lossy(&b).into_owned())
                            .unwrap_or(h)
                    })
                    .unwrap_or_default();
                println!("\n# gateway challenge: \"{prompt}\"");
                println!("# auth session_id: {sid}");

                let input = if let Some(pc) = passcode.take() {
                    pc
                } else if probe {
                    println!(
                        "\n(--probe set: stopping before sending any passcode — UserPass format validated)"
                    );
                    return;
                } else {
                    match anyconnect::read_secret("Passcode: ") {
                        Some(l) if !l.trim().is_empty() => l.trim().to_string(),
                        _ => {
                            println!("(no passcode entered; stopping)");
                            return;
                        }
                    }
                };

                let chr = ccc::multi_challenge(new_request_id(), &sid, &input);
                let (r, p) = post_ccc(&host, &chr, verbose);
                raw = r;
                resp = p;
            }
            other => {
                println!("\n# ---- full response body (parsed) ----");
                println!("{}\n", resp.body.pretty(0));
                let err = resp
                    .path(&["ResponseData", "error_message"])
                    .and_then(|v| v.text())
                    .and_then(|h| ccc::deobfuscate(&h).ok())
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                println!("auth not completed (authn_status={other}). {err}");
                return;
            }
        }
    }
}

/// POST a CCC packet; return the raw HTTP response (headers+body) and the
/// parsed body. Exits on transport/parse failure.
fn post_ccc(host: &str, pkt: &ccc::Packet, verbose: bool) -> (String, ccc::Packet) {
    let body = pkt.serialize();
    let request = http_request(host, CCC_PATH, &body);
    let raw = post(host, &request).unwrap_or_else(|e| {
        eprintln!("send failed: {e}");
        std::process::exit(1);
    });
    if verbose {
        println!("# ---- raw HTTP response ----\n{raw}\n# ----");
    }
    let b = split_http_body(&raw);
    let parsed = ccc::parse(b).unwrap_or_else(|e| {
        eprintln!("parse failed: {e}\n--- raw body ---\n{b}");
        std::process::exit(1);
    });
    (raw, parsed)
}

fn http_headers(resp: &str) -> &str {
    match resp.find("\r\n\r\n") {
        Some(i) => &resp[..i],
        None => resp,
    }
}

fn extract_cookie(resp: &str, name: &str) -> Option<String> {
    let pat = format!("{name}=");
    for line in http_headers(resp).lines() {
        let l = line.trim();
        let rest = match l.strip_prefix("Set-Cookie:").or_else(|| l.strip_prefix("set-cookie:")) {
            Some(r) => r.trim(),
            None => continue,
        };
        if let Some(v) = rest.strip_prefix(&pat) {
            return Some(v.split(';').next().unwrap_or("").trim().to_string());
        }
    }
    None
}

fn http_request(host: &str, path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {USER_AGENT}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    )
}

/// One CCC request over TLS to the gateway's port 443.
fn post(host: &str, request: &str) -> Result<String, String> {
    let mut tls = net::tls::connect(host, 443, Duration::from_secs(15))?;
    tls.write_all(request.as_bytes()).map_err(|e| e.to_string())?;

    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// The gateway's CCC ClientHello answer (site information, login options).
pub(crate) fn gateway_hello(host: &str) -> Result<ccc::Packet, String> {
    let body = ccc::client_hello(new_request_id()).serialize();
    let raw = post(host, &http_request(host, CCC_PATH, &body))?;
    ccc::parse(split_http_body(&raw)).map_err(|e| format!("bad ClientHello answer: {e}"))
}

fn split_http_body(resp: &str) -> &str {
    match resp.find("\r\n\r\n") {
        Some(i) => &resp[i + 4..],
        None => resp,
    }
}

fn preview(s: &str) -> String {
    const MAX: usize = 1600;
    if s.len() <= MAX {
        s.to_string()
    } else {
        format!("{}\n... [{} more bytes]", &s[..MAX], s.len() - MAX)
    }
}
