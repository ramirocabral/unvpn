//! The ESP data plane and the IKE control loop that keeps it alive (DPD,
//! rekey, Office Mode lease renewal).

use super::*;
use crate::{ike, report, sysnet, tun, tunnel_common};

/// Send an IKE message, then receive the reply that carries the expected
/// message_id — skipping retransmits of earlier exchanges (whose stale IVs would
/// otherwise decrypt to garbage). Reads only the header, never decrypting skips.
pub(super) fn ike_send_recv_mid(
    udp: &ike::transport::IkeUdp,
    msg: &[u8],
    want_mid: u32,
) -> Result<Vec<u8>, String> {
    udp.send(msg)?;
    for _ in 0..8 {
        let r = udp.recv()?;
        if ike::service::is_encrypted(&r) {
            let mid = u32::from_be_bytes(r[20..24].try_into().unwrap());
            if mid == want_mid {
                return Ok(r);
            }
        }
    }
    Err(format!("no reply with message_id {want_mid:#x}"))
}

pub(super) static TUNNEL_STOP: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Set when the control loop gives up recovering the tunnel (the IKE SA is gone and
/// re-auth needs a fresh passcode): the main loop turns this into an error exit so
/// the GUI shows the drop instead of a silent stop.
pub(super) static TUNNEL_LOST: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub(super) fn ip_checksum(header: &[u8]) -> u16 {
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
pub(super) fn ipsec_keepalive_packet(
    src: std::net::Ipv4Addr,
    dst: std::net::Ipv4Addr,
    counter: u32,
) -> Vec<u8> {
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
pub(super) fn run_tunnel(
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
    let (tun_rd, tun_name) = tunnel_common::open_tun("unvpn0", (om_ip, prefix), 1400)?;
    let tun_wr = tun_rd.try_clone().map_err(|e| e.to_string())?;

    let _ = sock.send(&[0xff]); // NAT-T keepalive
    println!(
        "# ESP on socket {:?} (same NAT-T port as IKE)",
        sock.local_addr().ok()
    );

    // From here every exit path must undo what we change; a disconnect asked for
    // while connecting means we touch no routes or DNS at all.
    TUNNEL_STOP.store(false, Ordering::SeqCst);
    TUNNEL_LOST.store(false, Ordering::SeqCst);
    tunnel_common::arm_stop(&TUNNEL_STOP)?;

    let gw_v4 = sock.peer_addr().ok().and_then(|a| match a.ip() {
        std::net::IpAddr::V4(v) => Some(v),
        std::net::IpAddr::V6(_) => None,
    });
    let plan = routes.map(|include| tunnel_common::RoutePlan {
        gateway: gw_v4,
        include,
        ..Default::default()
    });
    let _restore = tunnel_common::configure(&tun_name, plan.as_ref(), &dns, &domains)?;
    // Through the shared reader: a code prompt during login may have started it.
    sysnet::spawn_stdin_disconnect(&TUNNEL_STOP);

    // The current ESP SA, swappable so a rekey can replace it under the live
    // data-plane threads (they clone the Arc per packet; the swap is a brief write).
    let esp = Arc::new(RwLock::new(esp_sa));
    // IKE messages (NAT-T marker 0x00000000) arriving on the shared socket are
    // routed here for the control thread (rekey). Only wired up when we hold the
    // IKE session (the `--connect` path; the tunnel-up debug path can't rekey).
    let (ike_tx, ike_rx) = if session.is_some() {
        let (t, r) = mpsc::channel::<Vec<u8>>();
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
        let (sa, s, c1, c2, ce) = (
            esp.clone(),
            sock.clone(),
            uin.clone(),
            tout.clone(),
            derr.clone(),
        );
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
            ike_control_loop(
                session, sock_c, esp_c, om_ip, ike_rx, rekey_secs, lease_secs, mac, uin_c,
            )
        });
    }

    out!("# TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)");
    report::up(&tun_name, Some(om_ip.into()));
    let mut ticks = 0u32;
    while !TUNNEL_STOP.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(500));
        ticks += 1;
        if ticks.is_multiple_of(10) {
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

pub(super) fn rekey_interval(lifetime_secs: u32) -> std::time::Duration {
    use std::time::Duration;
    if let Some(n) = std::env::var("UNVPN_REKEY_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        return Duration::from_secs(n.max(20));
    }
    let base = if lifetime_secs > 0 {
        lifetime_secs as u64
    } else {
        1200
    };
    let at = (base * 85 / 100).min(base.saturating_sub(60)).max(60);
    Duration::from_secs(at)
}

pub(super) fn lease_renew_at(lease_secs: u32) -> std::time::Duration {
    std::time::Duration::from_secs(lease_secs.saturating_sub(300).max(60) as u64)
}

/// Runs while connected: renegotiates the ESP SA via a fresh Quick Mode under
/// the existing IKE SA — no re-auth — before the Phase-2 lifetime expires, and
/// renews the Office Mode lease, so long sessions don't drop.
#[allow(clippy::too_many_arguments)]
pub(super) fn ike_control_loop(
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
    // A link event was announced as a reconnect, still to be answered by a recovery.
    let mut reported = false;

    let mut esp_interval = rekey_interval(lifetime_secs);
    let mut esp_next = Instant::now() + esp_interval;
    // The Office Mode IP has a lease (e.g. 900s); not renewing it is what dropped
    // the tunnel at ~15 min. Renew it with a fresh OM config request (requesting
    // the current IP) under the IKE SA before it expires.
    let mut lease_next = (lease_secs > 0).then(|| Instant::now() + lease_renew_at(lease_secs));
    println!(
        "# IKE control up — ESP lifetime {lifetime_secs}s (rekey {}s), OM lease {lease_secs}s{}",
        esp_interval.as_secs(),
        lease_next
            .map(|_| format!(" (renew {}s)", lease_renew_at(lease_secs).as_secs()))
            .unwrap_or_default()
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
                Some(why) => {
                    out!("# link event ({why}) — probing the gateway");
                    if !reported {
                        report::reconnecting();
                        reported = true;
                    }
                }
                None => out!(
                    "# no data from the gateway for {}s — probing",
                    last_progress.elapsed().as_secs()
                ),
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
                    if std::mem::take(&mut reported) {
                        report::recovered(None);
                    }
                }
                Err(e) => {
                    recover_fails += 1;
                    out!("# recovery attempt {recover_fails}/{MAX_RECOVER_FAILS} failed: {e}");
                    if recover_fails >= MAX_RECOVER_FAILS {
                        out!(
                            "# giving up — the IKE session is gone (reconnect to re-authenticate)"
                        );
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
                    println!(
                        "# IKE control: gateway sent IKE exchange {} (ignored)",
                        raw[18]
                    );
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
                            println!(
                                "# ESP SA rekeyed (spi_in={si:#010x} spi_out={so:#010x}, next {}s)",
                                esp_interval.as_secs()
                            );
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
pub(super) fn do_lease_renew(
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
    let msg = ike::service::encrypt_message(
        session,
        u8::from(ExchangeType::Transaction),
        om_mid,
        &om_pl,
    )?;

    let mut reply = None;
    'retx: for _ in 0..5u32 {
        send_natt(sock, &msg)?;
        let sub = Instant::now() + Duration::from_secs(3);
        while Instant::now() < sub {
            let left = sub.saturating_duration_since(Instant::now());
            match ike_rx.recv_timeout(left) {
                Ok(raw) => {
                    if ike::service::is_encrypted(&raw)
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
        .or_else(|| {
            ike::service::get_long_attr(&oma, ConfigAttributeType::AddressExpiry).and_then(to_secs)
        })
        .unwrap_or(0);
    Ok(lease)
}

/// Prepend the NAT-T Non-ESP marker and send an IKE message on the shared socket.
pub(super) fn send_natt(sock: &std::net::UdpSocket, msg: &[u8]) -> Result<(), String> {
    let mut buf = Vec::with_capacity(4 + msg.len());
    buf.extend_from_slice(&[0, 0, 0, 0]);
    buf.extend_from_slice(msg);
    sock.send(&buf).map(|_| ()).map_err(|e| e.to_string())
}

/// Run one Quick Mode exchange to replace the ESP SA, then hot-swap it in.
pub(super) fn do_rekey(
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
    let qm1_msg =
        ike::service::encrypt_message(session, u8::from(ExchangeType::Quick), qm_mid, &qm1)?;
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
                    if ike::service::is_encrypted(&raw)
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
    send_natt(
        sock,
        &ike::service::encrypt_message(session, u8::from(ExchangeType::Quick), qm_mid, &qm3)?,
    )?;

    let enc_len = if chosen.key_bits > 0 {
        chosen.key_bits / 8
    } else {
        24
    };
    let auth_len = match chosen.auth_alg {
        a if a == ike::model::ESP_AUTH_HMAC_SHA96 || a == ike::model::ESP_AUTH_HMAC_SHA160 => 20,
        _ => 32,
    };
    let km_in = session.gen_esp_keymat(our_spi, &qm_nonce, &chosen.nonce_r, enc_len + auth_len);
    let km_out = session.gen_esp_keymat(
        chosen.gateway_spi,
        &qm_nonce,
        &chosen.nonce_r,
        enc_len + auth_len,
    );
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

pub(super) fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(super) fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn save_session_file(
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
    let dns_str = dns
        .iter()
        .map(|d| d.to_string())
        .collect::<Vec<_>>()
        .join(",");
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
pub fn cmd_tunnel_up(args: &[String]) {
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
        let get =
            |k: &str| -> Result<String, String> { m.get(k).cloned().ok_or(format!("missing {k}")) };
        let host = get("gateway")?;
        let om_ip: std::net::Ipv4Addr = get("om_ip")?.parse().map_err(|_| "bad om_ip")?;
        let om_mask: std::net::Ipv4Addr = get("om_mask")?.parse().map_err(|_| "bad om_mask")?;
        let transform_id: u8 = get("transform_id")?
            .parse()
            .map_err(|_| "bad transform_id")?;
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
        let sock =
            std::sync::Arc::new(std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?);
        sock.connect((host.as_str(), 4500))
            .map_err(|e| e.to_string())?;
        run_tunnel(
            om_ip,
            om_mask,
            esp_sa,
            sock,
            dns,
            domains,
            0,
            0,
            Vec::new(),
            None,
            Some(vec![CP_FALLBACK_ROUTE]),
        )
    };
    if let Err(e) = run() {
        report::fail("tunnel-up", &e);
    }
}
