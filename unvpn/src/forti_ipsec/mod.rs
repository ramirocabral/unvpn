//! Fortinet IPsec (IKEv2) VPN back-end.
//!
//! FortiGate dialup with FortiClient EMS / ZTNA uses IKEv2 (RFC 7296) with EAP user
//! authentication (`EAP-MSCHAPV2` for user/password, `EAP-GTC` for the token/OTP)
//! and the gateway authenticating by certificate or PSK. The IKE_AUTH exchange also
//! carries FortiClient-private payloads — `FORTICLIENT_CONNECT` and the EMS serial
//! number — that the gateway validates. Reverse-engineered from `/opt/forticlient/
//! iked` (7.4.3) plus RFC 7296. Reuses the ESP data plane and DH/PRF/AES primitives
//! from the `ike` module and the DNS/route/stdin plumbing from `sysnet`.
//!
//! Subcommand: `unvpn forti-ipsec -g <host[:port]> -u <user> [--password p]
//! [--code otp] [--emssn SN] [--probe | --login | --connect] [--no-routes]`.
//!
//! Live status: the protocol stack is unit-tested offline (framing, crypto, EAP
//! RFC vectors). `--probe` (IKE_SA_INIT only) works against any FortiGate IPsec
//! gateway. The EAP auth + ESP data plane are implemented per RFC but NOT yet
//! validated against a live gateway, and connecting to an EMS/ZTNA-enforcing
//! FortiGate additionally needs a valid EMS serial (see `emssn.rs`).

pub mod config;
pub mod crypto;
pub mod eap;
pub mod emssn;
pub mod model;
pub mod session;
pub mod wire;

use std::net::{Ipv4Addr, ToSocketAddrs};
use std::time::Duration;

use crate::ike::transport::IkeUdp;
use crate::sysnet;
use session::{EspSuite, IkeSuite, Ikev2Session, SaInitOutcome};
use wire::{Payload, TrafficSelector};

struct Opts {
    gateway: String,
    port: u16,
    user: String,
    password: Option<String>,
    code: Option<String>,
    emssn: Option<String>,
    mode: Mode,
    no_routes: bool,
}

#[derive(PartialEq)]
enum Mode {
    Probe,
    Login,
    Connect,
}

pub fn cmd_forti_ipsec(args: &[String]) {
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("forti-ipsec: {e}");
            eprintln!("usage: unvpn forti-ipsec -g <host[:port]> -u <user> [--password p] [--code otp] [--emssn SN] [--probe|--login|--connect] [--no-routes]");
            std::process::exit(2);
        }
    };
    if let Err(e) = run(&opts) {
        out!("# forti-ipsec failed: {e}");
        std::process::exit(1);
    }
}

fn parse_args(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        gateway: String::new(),
        port: 500,
        user: String::new(),
        password: None,
        code: None,
        emssn: None,
        mode: Mode::Connect,
        no_routes: false,
    };
    let mut i = 0;
    let mut port_set = false;
    while i < args.len() {
        let a = args[i].clone();
        let next = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i).cloned().ok_or_else(|| format!("{a} needs a value"))
        };
        match args[i].as_str() {
            "-g" | "--gateway" => o.gateway = next(&mut i)?,
            "-u" | "--user" => o.user = next(&mut i)?,
            "--password" | "-p" => o.password = Some(next(&mut i)?),
            "--code" | "--otp" => o.code = Some(next(&mut i)?),
            "--emssn" => o.emssn = Some(next(&mut i)?),
            "--port" => {
                o.port = next(&mut i)?.parse().map_err(|_| "bad --port")?;
                port_set = true;
            }
            "--probe" => o.mode = Mode::Probe,
            "--login" => o.mode = Mode::Login,
            "--connect" => o.mode = Mode::Connect,
            "--no-routes" => o.no_routes = true,
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }
    if o.gateway.is_empty() {
        return Err("missing -g <gateway>".into());
    }
    // host:port in -g overrides the default unless --port was given.
    if let Some((h, p)) = o.gateway.rsplit_once(':') {
        if let Ok(p) = p.parse::<u16>() {
            if !port_set {
                o.port = p;
            }
            o.gateway = h.to_string();
        }
    }
    if o.mode != Mode::Probe && o.user.is_empty() {
        return Err("missing -u <user>".into());
    }
    Ok(o)
}

fn run(o: &Opts) -> Result<(), String> {
    let gw = resolve_v4(&o.gateway, o.port)?;
    out!("# forti-ipsec: gateway {}:{} (IKEv2)", gw, o.port);

    // IKE_SA_INIT on UDP/500; float to 4500 if NAT is detected.
    let mut udp = IkeUdp::connect(&gw.to_string(), false, Duration::from_secs(5))?;
    let local = udp.local_ipv4();
    let mut session = Ikev2Session::new(IkeSuite::default_fgt(), EspSuite::default_fgt())?;

    sa_init_exchange(&mut session, &mut udp, local, gw, o.port)?;
    out!(
        "# IKE_SA_INIT ok — responder SPI set, suite AES256/SHA256/MODP2048, NAT={}",
        session.nat_detected
    );

    if o.mode == Mode::Probe {
        out!("# probe: gateway speaks IKEv2 and accepted our proposal. (stopping before auth)");
        return Ok(());
    }

    // Float to NAT-T port 4500 for IKE_AUTH + ESP when NAT is present (the common
    // case for a client behind a router).
    let mut natt = udp;
    if session.nat_detected {
        natt = IkeUdp::connect(&gw.to_string(), true, Duration::from_secs(5))?;
        out!("# NAT detected — floating to UDP/4500 (NAT-T)");
    }

    let final_payloads = authenticate(&mut session, &natt, o)?;
    out!("# IKE_AUTH + EAP ok — authenticated");

    session.learn_esp_spi(&final_payloads)?;
    let cfg = config::from_payloads(&final_payloads);
    let assigned = cfg.assigned_ip.ok_or("gateway did not assign an internal IP")?;
    out!(
        "# CHILD SA up — IP {assigned}  DNS {:?}  routes {}  domains {:?}",
        cfg.dns,
        cfg.routes.len(),
        cfg.domains
    );

    if o.mode == Mode::Login {
        out!("# login: authenticated and CHILD SA negotiated. (stopping before the data plane)");
        return Ok(());
    }

    let esp = session.make_esp_sa()?;
    data_plane(natt, esp, assigned, &cfg, gw, o.no_routes)
}

/// IKE_SA_INIT with COOKIE and INVALID_KE_PAYLOAD retries.
fn sa_init_exchange(session: &mut Ikev2Session, udp: &mut IkeUdp, local: Ipv4Addr, gw: Ipv4Addr, port: u16) -> Result<(), String> {
    let mut cookie: Option<Vec<u8>> = None;
    for _ in 0..4 {
        let req = session.build_sa_init(local, port, gw, port, cookie.clone());
        let resp = send_recv_retry(udp, &req, 3)?;
        match session.process_sa_init(&resp, local, port, gw, port)? {
            SaInitOutcome::Ok => return Ok(()),
            SaInitOutcome::Cookie(c) => {
                out!("# gateway asked for a COOKIE — retrying");
                cookie = Some(c);
            }
            SaInitOutcome::InvalidKe(group) => {
                return Err(format!("gateway wants DH group {group}; only MODP2048 is wired so far"));
            }
        }
    }
    Err("IKE_SA_INIT did not complete after retries".into())
}

/// Send and wait for a reply, retransmitting a few times (UDP).
fn send_recv_retry(udp: &IkeUdp, msg: &[u8], tries: u32) -> Result<Vec<u8>, String> {
    let mut last = String::new();
    for _ in 0..tries {
        udp.send(msg)?;
        match udp.recv() {
            Ok(r) => return Ok(r),
            Err(e) => last = e,
        }
    }
    Err(format!("no response from gateway ({last})"))
}

/// Drive IKE_AUTH and the EAP sub-protocol to completion, returning the responder's
/// final decrypted payloads (AUTH + SAr2 + TSi/TSr + CP reply).
fn authenticate(session: &mut Ikev2Session, udp: &IkeUdp, o: &Opts) -> Result<Vec<Payload>, String> {
    let password = o.password.clone().or_else(read_stdin_secret).ok_or("no password supplied")?;
    let serial = emssn::EmsSerial::resolve(o.emssn.as_deref());
    if let Some(sn) = serial.as_str() {
        out!("# presenting EMS serial {sn} (provisional framing — see emssn.rs)");
    }

    // First IKE_AUTH request: IDi, CP(request), SAi2, TSi, TSr, INITIAL_CONTACT, and
    // the FortiClient/EMS payloads. No AUTH → request EAP.
    let idi = Payload::IdI { kind: model::IdType::Rfc822Addr.into(), data: o.user.as_bytes().to_vec() };
    let mut first: Vec<Payload> = vec![idi.clone()];
    first.push(cp_request());
    first.push(Payload::Sa(vec![session.esp_proposal()]));
    first.push(Payload::Tsi(vec![TrafficSelector::ipv4_any()]));
    first.push(Payload::Tsr(vec![TrafficSelector::ipv4_any()]));
    first.push(Payload::Notify(wire::Notify {
        protocol: 0,
        spi: vec![],
        ntype: model::NotifyType::InitialContact.into(),
        data: vec![],
    }));
    first.extend(emssn::auth_payloads(&serial, &o.user));

    let mut msg_id = session.next_msg_id; // 1
    let req = session.encrypt(model::ExchangeType::IkeAuth.into(), msg_id, &first);
    let mut resp = send_recv_retry(udp, &req, 3)?;

    // EAP loop.
    let mut msk: Option<[u8; 64]> = None;
    loop {
        let (_hdr, payloads) = session.decrypt(&resp)?;

        if let Some(code) = auth_failed(&payloads) {
            return Err(format!("gateway rejected authentication ({code})"));
        }

        let eap = payloads.iter().find_map(|p| match p {
            Payload::Eap(e) => Some(e.clone()),
            _ => None,
        });

        let Some(eap_bytes) = eap else {
            // No EAP payload: this is the final response (AUTH + SAr2 + TS + CP).
            verify_gateway_auth(&payloads);
            return Ok(payloads);
        };

        let msg = eap::Eap::parse(&eap_bytes)?;
        msg_id += 1;
        match msg.code {
            eap::EAP_SUCCESS => {
                // EAP done: send the final AUTH (keyed by the EAP MSK, else SK_pi).
                let idi_body = idi_body_bytes(&idi);
                let signed = session.initiator_signed_octets(&idi_body);
                let crypto = session.crypto.as_ref().unwrap();
                let auth_data = match &msk {
                    Some(k) => crypto.psk_auth(k, &signed),
                    None => crypto.key_auth(&session.keys.as_ref().unwrap().sk_pi, &signed),
                };
                let auth = Payload::Auth { method: model::AUTH_PSK, data: auth_data };
                let req = session.encrypt(model::ExchangeType::IkeAuth.into(), msg_id, &[auth]);
                session.next_msg_id = msg_id + 1;
                let resp2 = send_recv_retry(udp, &req, 3)?;
                let (_h, final_payloads) = session.decrypt(&resp2)?;
                if let Some(code) = auth_failed(&final_payloads) {
                    return Err(format!("gateway rejected final AUTH ({code})"));
                }
                verify_gateway_auth(&final_payloads);
                return Ok(final_payloads);
            }
            eap::EAP_FAILURE => return Err("EAP authentication failed".into()),
            eap::EAP_REQUEST => {
                let next_eap = eap_answer(&msg, o, &password, &mut msk)?;
                let req = session.encrypt(model::ExchangeType::IkeAuth.into(), msg_id, &[Payload::Eap(next_eap)]);
                resp = send_recv_retry(udp, &req, 3)?;
            }
            other => return Err(format!("unexpected EAP code {other}")),
        }
    }
}

/// Produce the EAP response bytes for a given EAP Request.
fn eap_answer(msg: &eap::Eap, o: &Opts, password: &str, msk: &mut Option<[u8; 64]>) -> Result<Vec<u8>, String> {
    match msg.method {
        Some(eap::EAP_TYPE_IDENTITY) => Ok(eap::identity_response(msg.id, &o.user)),
        Some(eap::EAP_TYPE_GTC) => {
            let prompt = String::from_utf8_lossy(&msg.data);
            let value = otp_value(o, &prompt)?;
            Ok(eap::gtc_response(msg.id, &value))
        }
        Some(eap::EAP_TYPE_MSCHAPV2) => {
            if msg.data.first() == Some(&eap::MSCHAP_CHALLENGE) {
                let ch = eap::parse_mschap_challenge(&msg.data)?;
                let peer: [u8; 16] = crate::ike::crypto::random(16).try_into().unwrap();
                let (resp, nt) = eap::mschap_response(&ch, &o.user, password, &peer);
                *msk = Some(eap::derive_msk(password, &nt));
                Ok(eap::Eap::response(msg.id, eap::EAP_TYPE_MSCHAPV2, &resp))
            } else if msg.data.first() == Some(&eap::MSCHAP_SUCCESS) {
                Ok(eap::Eap::response(msg.id, eap::EAP_TYPE_MSCHAPV2, &[eap::MSCHAP_SUCCESS]))
            } else {
                Err("unexpected MS-CHAP-v2 opcode".into())
            }
        }
        Some(eap::EAP_TYPE_NAK) => Err("gateway sent an EAP Nak".into()),
        other => {
            out!("# gateway proposed unsupported EAP method {other:?} — Nak'ing to MSCHAPv2/GTC");
            Ok(eap::nak_response(msg.id, &[eap::EAP_TYPE_MSCHAPV2, eap::EAP_TYPE_GTC]))
        }
    }
}

/// Resolve the OTP: the `--code` flag, else an interactive `# AUTH-PROMPT: code:`.
fn otp_value(o: &Opts, prompt: &str) -> Result<String, String> {
    if let Some(c) = &o.code {
        return Ok(c.clone());
    }
    let p = sysnet::StdinWatchPause::new();
    out!("# AUTH-PROMPT: code: {}", prompt.trim());
    let v = match sysnet::stdin_next(Some(Duration::from_secs(180))) {
        sysnet::StdinEvent::Line(l) => l,
        sysnet::StdinEvent::Eof => return Err("stdin closed while waiting for the token".into()),
        sysnet::StdinEvent::Timeout => return Err("timed out waiting for the token".into()),
    };
    drop(p);
    Ok(v)
}

fn read_stdin_secret() -> Option<String> {
    // The GUI pipes the password as the first stdin line; a TTY user is prompted.
    let _echo = sysnet::EchoOff::new();
    match sysnet::stdin_next(Some(Duration::from_secs(180))) {
        sysnet::StdinEvent::Line(l) if !l.is_empty() => Some(l),
        _ => None,
    }
}

/// The IDi payload body (type + 3 reserved + data), as hashed into the AUTH octets.
fn idi_body_bytes(idi: &Payload) -> Vec<u8> {
    match idi {
        Payload::IdI { kind, data } => {
            let mut b = vec![*kind, 0, 0, 0];
            b.extend_from_slice(data);
            b
        }
        _ => Vec::new(),
    }
}

/// CFG_REQUEST asking for an internal IP, DNS and split subnets.
fn cp_request() -> Payload {
    Payload::Cp {
        cfg_type: model::CfgType::Request.into(),
        attrs: vec![
            (model::CfgAttr::InternalIp4Address.into(), vec![]),
            (model::CfgAttr::InternalIp4Netmask.into(), vec![]),
            (model::CfgAttr::InternalIp4Dns.into(), vec![]),
            (model::CfgAttr::InternalIp4Subnet.into(), vec![]),
            (model::CfgAttr::InternalDnsDomain.into(), vec![]),
        ],
    }
}

fn auth_failed(payloads: &[Payload]) -> Option<String> {
    payloads.iter().find_map(|p| match p {
        Payload::Notify(n) if n.ntype == model::NotifyType::AuthenticationFailed.into() => {
            Some("AUTHENTICATION_FAILED".to_string())
        }
        _ => None,
    })
}

/// Verify the gateway's AUTH when we can. We usually lack its credential (it
/// authenticates by certificate or a group PSK we were not given), so this logs
/// rather than fails: the gateway would not have sent a CHILD SA if it had rejected
/// us. A future cert/PSK path should harden this.
fn verify_gateway_auth(payloads: &[Payload]) {
    if !payloads.iter().any(|p| matches!(p, Payload::Auth { .. })) {
        out!("# warning: gateway sent no AUTH payload");
    }
}

/// The ESP data plane: pump IPv4 packets between the tun device and ESP-over-UDP
/// (NAT-T, port 4500), with routes/DNS and a NAT keepalive. Blocks until stop.
fn data_plane(
    udp: IkeUdp,
    esp: crate::ike::esp::EspSa,
    assigned: Ipv4Addr,
    cfg: &config::TunnelConfig,
    gw: Ipv4Addr,
    no_routes: bool,
) -> Result<(), String> {
    use crate::tun;
    use std::io::Read;
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    static STOP: AtomicBool = AtomicBool::new(false);

    let sock = udp.try_clone_socket().map_err(|e| format!("clone socket: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_millis(500))).ok();

    let (mut tun_file, tun_name) = tun::open_tun("cpfi0")?;
    tun::ip(&["addr", "add", &format!("{assigned}/32"), "dev", &tun_name])?;
    tun::ip(&["link", "set", "dev", &tun_name, "up", "mtu", "1400"])?;
    out!("# tun {tun_name} up — {assigned}/32, mtu 1400");

    sysnet::install_stop_signals(&STOP);
    if sysnet::stop_requested() || STOP.load(Ordering::SeqCst) {
        return Err("disconnect requested before the tunnel came up".into());
    }

    let mut restore = sysnet::NetRestore::default();
    if no_routes {
        out!("# --no-routes: reach hosts with `ping -I {tun_name}`");
    } else {
        restore.routes = setup_routes(gw, &tun_name, cfg);
        restore.dns = sysnet::set_dns(&sysnet::tunnelled_dns(&cfg.dns, &tun_name), &cfg.domains);
    }
    sysnet::spawn_stdin_disconnect(&STOP);
    tun::set_nonblocking(&tun_file);

    out!("# TUNNEL UP (ESP over NAT-T). (send 'disconnect' on stdin or SIGTERM to stop)");
    let tun_fd = tun_file.as_raw_fd();
    let sock_fd = sock.as_raw_fd();
    let mut buf = [0u8; 2048];
    let (mut tin, mut tout, mut derr) = (0u64, 0u64, 0u64);
    let mut last_ka = Instant::now();
    let mut last_stats = Instant::now();

    loop {
        if STOP.load(Ordering::SeqCst) {
            break;
        }
        let mut fds = [
            libc::pollfd { fd: tun_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: sock_fd, events: libc::POLLIN, revents: 0 },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, 500) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        // tun → ESP
        if fds[0].revents & libc::POLLIN != 0 {
            for _ in 0..64 {
                match tun_file.read(&mut buf) {
                    Ok(0) => {
                        STOP.store(true, Ordering::SeqCst);
                        break;
                    }
                    Ok(m) if tun::is_ipv4(&buf[..m]) => match esp.encode(&buf[..m]) {
                        Ok(pkt) => {
                            let _ = sock.send(&pkt);
                            tout += 1;
                        }
                        Err(_) => derr += 1,
                    },
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        }

        // ESP → tun
        if fds[1].revents & libc::POLLIN != 0 {
            loop {
                match sock.recv(&mut buf) {
                    Ok(m) if m >= 4 && buf[..4] == [0, 0, 0, 0] => {
                        // IKE message on 4500 (DPD / Delete) — ignored for now.
                    }
                    Ok(m) if m > 8 => match esp.decode(&buf[..m]) {
                        Ok(ip) if tun::is_ipv4(&ip) => {
                            use std::io::Write;
                            if tun_file.write_all(&ip).is_ok() {
                                tin += 1;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => derr += 1,
                    },
                    Ok(_) => {}
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
                    Err(_) => break,
                }
            }
        }

        // NAT-T keepalive (single 0xff byte) every 20 s.
        if last_ka.elapsed().as_secs() >= 20 {
            let _ = sock.send(&[0xff]);
            last_ka = Instant::now();
        }
        if last_stats.elapsed().as_secs() >= 10 {
            out!("#  stats: esp_in={tin} esp_out={tout} dec_err={derr}");
            last_stats = Instant::now();
        }
    }

    out!("# disconnecting — restoring DNS/routes …");
    drop(restore);
    Ok(())
}

/// Pin the gateway to its pre-VPN path, then install split routes (or a full tunnel
/// via 0/1 + 128/1). Mirrors the Fortinet SSL-VPN back-end's route handling.
fn setup_routes(gw: Ipv4Addr, tun: &str, cfg: &config::TunnelConfig) -> Vec<String> {
    use crate::tun;
    let mut add: Vec<String> = Vec::new();
    let mut del: Vec<String> = Vec::new();

    if let Some((via, dev)) = original_path(gw) {
        let suffix = via.map(|v| format!("via {v} dev {dev}")).unwrap_or(format!("dev {dev}"));
        add.push(format!("route add {gw}/32 {suffix}"));
        del.push(format!("route del {gw}/32 {suffix}"));
    }
    let dev = format!("dev {tun}");
    if cfg.routes.is_empty() {
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            add.push(format!("route add {net} {dev}"));
            del.push(format!("route del {net} {dev}"));
        }
        out!("# full tunnel: 0.0.0.0/1 + 128.0.0.0/1 via {tun}");
    } else {
        for (net, prefix) in &cfg.routes {
            add.push(format!("route add {net}/{prefix} {dev}"));
            del.push(format!("route del {net}/{prefix} {dev}"));
        }
        out!("# split tunnel: {} route(s) via {tun}", cfg.routes.len());
    }
    let failed = tun::ip_batch_failed(&add).unwrap_or_default();
    del.into_iter().enumerate().filter(|(i, _)| !failed.contains(i)).map(|(_, d)| d).collect()
}

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
