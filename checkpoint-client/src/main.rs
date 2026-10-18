//! cpvpn — native Linux Check Point VPN client (work in progress).
//!
//! Milestone 1: build and (optionally) send the CCC `ClientHello`, then parse
//! the gateway's `login_options`. Reverse-engineered from Endpoint Security
//! VPN E84.30. See ../docs/protocol-notes.md.
//!
//! Usage:
//!   cpvpn hello                      # print the ClientHello request (no network)
//!   cpvpn hello --gateway <host>     # same, shows the full HTTP request preview
//!   cpvpn hello --gateway <host> --send   # actually POST to the gateway (TLS/443)
//!
//! `--send` is the only action that touches the network. Without it, cpvpn is
//! purely local.

mod ccc;
mod forti;
mod f5;
mod ike;
mod sysnet;
mod tun;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const USER_AGENT: &str = "Mozilla/5.0 (compatible; CPSC 5.0; Windows NT 5.0)";
const CCC_PATH: &str = "/clients/";

/// A non-zero request id. The gateway echoes it back in the response header;
/// snx-rs uses a fresh id per request (ours is derived from the clock).
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

/// M3a: open the SSL data-plane tunnel and perform the `client_hello` /
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

    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .expect("tls builder");
    let tcp = TcpStream::connect((host.as_str(), 443)).unwrap_or_else(|e| {
        eprintln!("connect failed: {e}");
        std::process::exit(1);
    });
    tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(20))).ok();
    let mut tls = connector.connect(&host, tcp).unwrap_or_else(|e| {
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
                        println!("✅ SSL TUNNEL UP — Office Mode IP: {ip}  subnet: {subnet}");
                    } else if p.name == "disconnect" {
                        println!("❌ gateway sent disconnect (session invalid/expired?)");
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

/// Send a CONTROL frame: [len][type=1][payload + NUL].
fn send_control(tls: &mut impl Write, payload: &str) -> std::io::Result<()> {
    let mut body = payload.as_bytes().to_vec();
    body.push(0);
    let mut frame = Vec::with_capacity(8 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes()); // PKT_CONTROL
    frame.extend_from_slice(&body);
    tls.write_all(&frame)
}

/// Read one Slim frame: returns (packet_type, payload).
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
        // else: retransmit of an earlier message_id — skip without decrypting.
    }
    Err(format!("no reply with message_id {want_mid:#x}"))
}

/// Bring up the tun device + ESP-over-UDP(4500) forwarding for an established SA.
/// Prints packet counters every 3s so the data path can be diagnosed.
static TUNNEL_STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
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
/// this is what kept the tunnel from surviving past ~20 min. (From snx-rs.)
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
) -> Result<(), String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{mpsc, Arc, RwLock};

    let prefix = tun::mask_to_prefix(om_mask);
    let (tun_rd, tun_name) = tun::open_tun("cpvpn0")?;
    let tun_wr = tun_rd.try_clone().map_err(|e| e.to_string())?;
    tun::ip(&["addr", "add", &format!("{om_ip}/{prefix}"), "dev", &tun_name])?;
    tun::ip(&["link", "set", "dev", &tun_name, "up", "mtu", "1400"])?;
    let _ = tun::ip(&["route", "add", "10.0.0.0/8", "dev", &tun_name]);
    println!("# tun {tun_name} up — {om_ip}/{prefix}, route 10.0.0.0/8 via {tun_name}");

    let _ = sock.send(&[0xff]); // NAT-T keepalive
    println!("# ESP on socket {:?} (same NAT-T port as IKE)", sock.local_addr().ok());

    let dns_backup = sysnet::set_dns(&dns, &domains);
    TUNNEL_STOP.store(false, Ordering::SeqCst);
    unsafe {
        let h = tunnel_sig_handler as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGINT, h);
    }
    // Disconnect when stdin gets "disconnect" or EOF (the GUI owns this pipe).
    std::thread::spawn(|| {
        let mut line = String::new();
        loop {
            line.clear();
            match std::io::stdin().read_line(&mut line) {
                Ok(0) => break, // EOF → disconnect
                Ok(_) if line.trim().eq_ignore_ascii_case("disconnect") => break,
                Ok(_) => continue,
                Err(_) => break,
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

    // Outbound: tun → ESP → socket.
    {
        let (sa, s, c1, c2) = (esp.clone(), sock.clone(), tin.clone(), eout.clone());
        let mut rd = tun_rd;
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            loop {
                match std::io::Read::read(&mut rd, &mut buf) {
                    Ok(0) | Err(_) => break,
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
    // Inbound: socket → demux (ESP → tun, IKE → control thread).
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
                            let _ = tx.send(buf[4..n].to_vec()); // IKE message
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
    // IKE control thread: ESP SA rekey before the Phase-2 lifetime expires.
    if let (Some(session), Some(ike_rx)) = (session, ike_rx) {
        let (esp_c, sock_c) = (esp.clone(), sock.clone());
        std::thread::spawn(move || {
            ike_control_loop(session, sock_c, esp_c, om_ip, ike_rx, rekey_secs, lease_secs, mac)
        });
    }

    println!("# ✅ TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)");
    let mut ticks = 0u32;
    while !TUNNEL_STOP.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(500));
        ticks += 1;
        if ticks % 10 == 0 {
            println!(
                "#  stats: tun_in={} esp_out={} udp_in={} tun_out={} dec_err={}",
                tin.load(Ordering::Relaxed),
                eout.load(Ordering::Relaxed),
                uin.load(Ordering::Relaxed),
                tout.load(Ordering::Relaxed),
                derr.load(Ordering::Relaxed),
            );
        }
    }
    println!("# disconnecting — restoring DNS, tearing down tun/routes…");
    sysnet::restore_dns(dns_backup);
    Ok(())
}

/// IKE control loop (runs while connected): renegotiates the ESP SA via a fresh
/// Quick Mode under the existing IKE SA — no re-auth — before the Phase-2
/// lifetime (3600s) expires, so long sessions don't drop. `CPVPN_REKEY_SECS`
/// overrides the interval (for testing).
/// When to rekey, given the Phase-2 lifetime (seconds). Rekey at 85% of it,
/// keeping ≥60s margin before expiry. `CPVPN_REKEY_SECS` overrides (for testing).
/// If the gateway didn't give a lifetime, assume a conservative 1200s.
fn rekey_interval(lifetime_secs: u32) -> std::time::Duration {
    use std::time::Duration;
    if let Some(n) = std::env::var("CPVPN_REKEY_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        return Duration::from_secs(n.max(20));
    }
    let base = if lifetime_secs > 0 { lifetime_secs as u64 } else { 1200 };
    let at = (base * 85 / 100).min(base.saturating_sub(60)).max(60);
    Duration::from_secs(at)
}

/// Renew at the Office Mode lease minus a 300s leeway (min 60s).
fn lease_renew_at(lease_secs: u32) -> std::time::Duration {
    std::time::Duration::from_secs(lease_secs.saturating_sub(300).max(60) as u64)
}

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
) {
    use std::sync::atomic::Ordering;
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::{Duration, Instant};

    let mut esp_interval = rekey_interval(lifetime_secs);
    let mut esp_next = Instant::now() + esp_interval;
    // The Office Mode IP has a lease (e.g. 900s); not renewing it is what dropped
    // the tunnel at ~15 min. Renew it with a fresh OM config request (requesting
    // the current IP) under the IKE SA before it expires. (From snx-rs.)
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
                // Office Mode lease renewal — and refresh the ESP SA alongside it,
                // the way snx-rs's session exchange does.
                if lease_next.is_some_and(|ln| now >= ln) {
                    match do_lease_renew(&mut session, &sock, om_ip, &mac, &ike_rx) {
                        Ok(nl) => {
                            if nl > 0 {
                                lease_secs = nl;
                            }
                            println!("# ✅ OM lease renewed ({lease_secs}s)");
                        }
                        Err(e) => println!("# ⚠ OM lease renew failed: {e}"),
                    }
                    lease_next = Some(Instant::now() + lease_renew_at(lease_secs));
                    match do_rekey(&mut session, &sock, &esp, om_ip, &ike_rx) {
                        Ok((si, so, life)) => {
                            if life > 0 {
                                lifetime_secs = life;
                                esp_interval = rekey_interval(lifetime_secs);
                            }
                            println!("# ✅ ESP SA rekeyed (spi_in={si:#010x} spi_out={so:#010x})");
                        }
                        Err(e) => println!("# ⚠ ESP rekey failed: {e} — keeping current SA"),
                    }
                    esp_next = Instant::now() + esp_interval;
                } else if now >= esp_next {
                    match do_rekey(&mut session, &sock, &esp, om_ip, &ike_rx) {
                        Ok((si, so, life)) => {
                            if life > 0 {
                                lifetime_secs = life;
                                esp_interval = rekey_interval(lifetime_secs);
                            }
                            println!("# ✅ ESP SA rekeyed (spi_in={si:#010x} spi_out={so:#010x}, next {}s)", esp_interval.as_secs());
                        }
                        Err(e) => println!("# ⚠ ESP rekey failed: {e} — keeping current SA"),
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
                    // else: retransmit or unsolicited (e.g. config) — ignore, keep waiting
                }
                Err(RecvTimeoutError::Timeout) => break, // resend QM1
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
    std::fs::write(path, data).map_err(|e| e.to_string())
}

/// M4 debug: bring up the tunnel from a saved session file (no re-auth, so the
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
        let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
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
        run_tunnel(om_ip, om_mask, esp_sa, sock, dns, domains, 0, 0, Vec::new(), None)
    };
    if let Err(e) = run() {
        eprintln!("tunnel-up failed: {e}");
        std::process::exit(1);
    }
}

/// M3 probe: send IKEv1 Main Mode msg 1 (SA proposal) and read the gateway's
/// chosen transform. Tries plain UDP :500 then NAT-T :4500. Benign — no auth,
/// no passcode — and tells us whether UDP is open or Visitor Mode is required.
fn cmd_ike(args: &[String]) {
    let mut gateway: Option<String> = None;
    let mut user = "u-123456".to_string();
    let mut realm = "vpn".to_string();
    let mut passcode: Option<String> = None;
    let mut connect = false;
    let mut natt = false;
    let mut save_session: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" => gateway = it.next().cloned(),
            "--user" | "-u" => user = it.next().cloned().unwrap_or(user),
            "--realm" | "-r" => realm = it.next().cloned().unwrap_or(realm),
            "--passcode" | "-p" => passcode = it.next().cloned(),
            "--connect" => connect = true,
            "--natt" => natt = true,
            "--save-session" => save_session = it.next().cloned(),
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

    let gw_ip: std::net::Ipv4Addr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("ike needs the gateway as an IPv4 address");
            std::process::exit(2);
        }
    };

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
        let msg1 = service::build_sa_msg(&session, 28800);
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
        let msg3 = service::build_ke(&session, local, gw_ip);
        let m4 = IsakmpMessage::decode(&udp.send_recv(&msg3.encode())?)?;
        let gw_pub = service::find_key_exchange(&m4).ok_or("no KE in msg4")?;
        let gw_nonce = service::find_nonce(&m4).ok_or("no nonce in msg4")?;
        println!(
            "# msg4: gateway KE {} bytes, nonce {} bytes, {} NAT-D payload(s)",
            gw_pub.len(),
            gw_nonce.len(),
            service::find_natds(&m4).len()
        );

        session.compute_keys(&gw_pub, &gw_nonce)?;
        println!(
            "# ✅ Phase 1 key material derived: SKEYID={}B d={}B a={}B e={}B",
            session.skeyid.len(),
            session.skeyid_d.len(),
            session.skeyid_a.len(),
            session.skeyid_e.len()
        );

        // msg 5/6 — ID protection + Check Point hybrid auth (encrypted).
        let auth_payloads = service::build_auth_payloads(&session, &realm);
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
                Ok(()) => println!("# ✅ Phase 1 COMPLETE — gateway SIG_R verified against its certificate."),
                Err(e) => println!("# ⚠ gateway SIG_R did not verify: {e}"),
            },
            _ => match service::find_hash(&m6) {
                Some(h) if h == hash_r => println!("# ✅ Phase 1 COMPLETE — HASH_R matches."),
                _ => println!("# ⚠ msg6 had no SIG_R/cert and no matching HASH_R (payloads={})", m6.payloads.len()),
            },
        }

        // After msg6, skip any msg6 retransmits and drive the config-mode SecurID
        // exchange (one message_id throughout; reply with the requested attribute).
        println!("# Phase 1 done; driving config-mode SecurID auth...");
        let mut req = loop {
            let r = udp.recv()?;
            if r == raw6 {
                continue; // msg6 retransmit while the gateway waits for us
            }
            break service::decrypt_message(&mut session, &r)?;
        };

        loop {
            let attrs = service::find_attributes(&req).ok_or("expected config attributes after Phase 1")?;
            let message_id = req.message_id;
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
                    println!("# ✅✅ SecurID AUTH SUCCEEDED via native IKE (Status=1).");

                    // Office Mode: internal IP + DNS + domains.
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
                    println!("# ✅ Office Mode: IP {om_ip} / {om_mask}  DNS {dns:?}  domains \"{domains}\"  lease={lease_secs}s");

                    // Quick Mode (Phase 2): negotiate the ESP SA.
                    let our_spi = ike::crypto::random_u32();
                    let qm_nonce = ike::crypto::random(32);
                    let qm_mid = ike::crypto::random_u32();
                    let qm1 = service::build_quick_mode(&session, our_spi, &qm_nonce, om_ip, qm_mid, 3600);
                    let qm1_msg = service::encrypt_message(&mut session, u8::from(ExchangeType::Quick), qm_mid, &qm1)?;
                    udp.send(&qm1_msg)?;
                    let stale = [0u32, om_mid, message_id];
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
                        "# ✅ Quick Mode ESP SA: transform={} auth={} key_bits={} encap={:#x} gw_spi={:#010x} our_spi={:#010x} lifetime={}s",
                        esp.transform_id, esp.auth_alg, esp.key_bits, esp.encap, esp.gateway_spi, our_spi, esp.lifetime_secs
                    );

                    // QM3 ack + ESP key derivation.
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
                    println!("# ✅✅✅ FULL IKE/IPSec HANDSHAKE COMPLETE — ESP SA ready.");

                    if let Some(path) = &save_session {
                        save_session_file(path, &host, om_ip, om_mask, &esp, our_spi, &km_in, &km_out, &dns, &domains)?;
                        println!("# session saved to {path} (reuse: sudo cpvpn tunnel-up --session {path})");
                    }
                    if connect {
                        let sock = std::sync::Arc::new(udp.try_clone_socket().map_err(|e| e.to_string())?);
                        return run_tunnel(
                            om_ip, om_mask, esp_sa, sock, dns, domains,
                            esp.lifetime_secs, lease_secs, mac, Some(session),
                        );
                    }
                    println!("# Office Mode IP {om_ip} ready. (--connect brings up the tunnel; needs sudo)");
                    break;
                }
                return Err(format!("SecurID auth failed (Status={status})"));
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
                _ => {
                    println!("# gateway challenge [{:?}]: {}", ctype, prompt);
                    match passcode.take() {
                        Some(p) => p,
                        None => {
                            // Read the passcode from stdin: the GUI pipes it; a TTY prompts.
                            eprint!("Passcode (PIN+tokencode): ");
                            let _ = std::io::stderr().flush();
                            let mut line = String::new();
                            if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0
                                || line.trim().is_empty()
                            {
                                println!("# no passcode provided; stopping.");
                                return Ok(());
                            }
                            line.trim().to_string()
                        }
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
            req = service::decrypt_message(&mut session, &udp.send_recv(&reply_msg)?)?;
        }
        Ok(())
    };

    if let Err(e) = run() {
        eprintln!("IKE failed: {e}");
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("hello") => cmd_hello(&args[1..]),
        Some("login") => cmd_login(&args[1..]),
        Some("deob") => cmd_deob(&args[1..]),
        Some("tunnel") => cmd_tunnel(&args[1..]),
        Some("ike") => cmd_ike(&args[1..]),
        Some("tunnel-up") => cmd_tunnel_up(&args[1..]),
        Some("forti") => forti::cmd_forti(&args[1..]),
        Some("f5") => f5::cmd_f5(&args[1..]),
        _ => {
            eprintln!("cpvpn — Check Point VPN client (M1/M2/M3)\n");
            eprintln!("usage:");
            eprintln!("  cpvpn hello [--gateway <host>] [--send]");
            eprintln!("  cpvpn login --gateway <host> [--user <u>] [--realm <r>] [--passcode <p>] [--probe]");
            eprintln!("  cpvpn tunnel --gateway <host> --active-key <obfuscated-hex> [--om-ip <ip>]");
            eprintln!("  cpvpn ike --gateway <host> [--passcode <PIN+tokencode>] [--connect]");
            eprintln!("       # M3/M4: IKEv1 handshake; with --connect (sudo) brings up the tun tunnel");
            eprintln!("  cpvpn forti -g <host[:port]> -u <user> [--connect]   # Fortinet SSL-VPN back-end");
            eprintln!("  cpvpn f5 -g <host[:port]> -u <user> [--connect]      # F5 BIG-IP APM SSL-VPN back-end");
            std::process::exit(2);
        }
    }
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

/// M2: authenticate over CCC. UserPass (empty password) → challenge loop
/// (SecurID passcode via MultiChallange) → session. The initial UserPass
/// carries no passcode, so `--probe` validates the format and shows the real
/// gateway challenge WITHOUT consuming a one-time passcode. `--verbose` dumps
/// the full raw HTTP response at each step.
fn cmd_login(args: &[String]) {
    let mut gateway: Option<String> = None;
    let mut user = "u-123456".to_string();
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

    // Step 1 — UserPass: username + empty password + selected realm.
    let req = ccc::auth_userpass(new_request_id(), &user, &realm);
    println!("# UserPass request (user={user}, realm={realm}):");
    println!("{}\n", req.serialize());
    let (mut raw, mut resp) = post_ccc(&host, &req, verbose);

    // Step 2 — drive the challenge loop until done / error.
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
                    println!("\n✅ AUTH OK (is_authenticated=true).");
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
                    println!("\n❌ AUTH FAILED (is_authenticated=false, error_code={ecode}).");
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
                    print!("Passcode: ");
                    std::io::stdout().flush().ok();
                    let mut line = String::new();
                    if std::io::stdin().read_line(&mut line).is_err() {
                        eprintln!("could not read passcode");
                        std::process::exit(1);
                    }
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        println!("(no passcode entered; stopping)");
                        return;
                    }
                    line
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
                println!("❌ auth not completed (authn_status={other}). {err}");
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

/// The header block of an HTTP response (everything before the blank line).
fn http_headers(resp: &str) -> &str {
    match resp.find("\r\n\r\n") {
        Some(i) => &resp[..i],
        None => resp,
    }
}

/// Extract a cookie value from `Set-Cookie` response headers, by name.
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

/// POST over TLS. The gateway presents an internal-CA certificate; for this
/// pre-auth probe we accept it and (later) pin it via internal_ca_sha1_hash.
fn post(host: &str, request: &str) -> Result<String, String> {
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|e| e.to_string())?;

    let tcp = TcpStream::connect((host, 443)).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(15))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(15))).ok();

    let mut tls = connector.connect(host, tcp).map_err(|e| e.to_string())?;
    tls.write_all(request.as_bytes()).map_err(|e| e.to_string())?;

    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Return the body part of an HTTP response (after the CRLFCRLF).
fn split_http_body(resp: &str) -> &str {
    match resp.find("\r\n\r\n") {
        Some(i) => &resp[i + 4..],
        None => resp,
    }
}

/// Truncate long blobs for console display.
fn preview(s: &str) -> String {
    const MAX: usize = 1600;
    if s.len() <= MAX {
        s.to_string()
    } else {
        format!("{}\n... [{} more bytes]", &s[..MAX], s.len() - MAX)
    }
}
