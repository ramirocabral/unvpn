//! Fortinet IPsec (IKEv2) VPN back-end.
//!
//! EMS-managed FortiGate dialup uses IKEv2 (RFC 7296) with EAP user authentication
//! (`EAP-MSCHAPV2` for user/password, `EAP-GTC` for the token/OTP) and the gateway
//! authenticating by certificate or PSK. The IKE_AUTH exchange also carries
//! FortiClient-private payloads (`FORTICLIENT_CONNECT` and the EMS serial) that a
//! managed gateway validates. Reuses the ESP data plane and DH/PRF/AES primitives
//! from the `ike` module and the DNS/route/stdin plumbing from `sysnet`.
//!
//! Subcommand: `unvpn forti-ipsec [-g <host[:port]>] [-u <user>] [--config f.xml]
//! [--password p] [--code otp] [--emssn SN] [--probe|--login|--connect]`.

pub mod config;
pub mod crypto;
pub mod eap;
pub mod emssn;
pub mod fctconfig;
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
    /// IKE local identity (IDi). FortiClient's `<localid>` — e.g. a dialup group
    /// name like `vpngroup` — which the FortiGate matches to select the phase1.
    /// When unset, the IDi is the username.
    localid: Option<String>,
    /// IDi payload type (RFC 7296 §3.5): 2 FQDN, 3 RFC822, 11 KEY_ID. A non-email
    /// `localid` (e.g. `vpngroup`) is sent as KEY_ID; a username as RFC822.
    id_type: u8,
    /// Group pre-shared key (FortiClient's `<preshared_key>`). Not needed to log in
    /// — the client's final AUTH is keyed by the EAP MSK — but when given we verify
    /// the *gateway's* AUTH with it, which authenticates the gateway to us (detects
    /// a wrong gateway / man-in-the-middle). A mismatch aborts the connection.
    psk: Option<String>,
    /// FortiClient version to report in the `FCTVER=` field of the FORTICLIENT_CONNECT
    /// blob. From the deployment's profile; `None` ⇒ the engine's built-in default.
    fctver: Option<String>,
    /// A FortiClient config file (`<forticlient_configuration>` XML) to import
    /// gateway/localid/PSK/version from. CLI flags still override its values.
    config: Option<String>,
    /// Print the de-obfuscated group PSK (a secret) in the `--import` summary.
    show_psk: bool,
}

#[derive(PartialEq)]
enum Mode {
    Probe,
    AuthProbe,
    Login,
    Connect,
    /// Parse a `--config` file and print the imported settings; do not connect.
    Import,
}

pub fn cmd_forti_ipsec(args: &[String]) {
    let mut opts = match parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("forti-ipsec: {e}");
            eprintln!("usage: unvpn forti-ipsec [-g <host[:port]>] [-u <user>] [--config file.xml [--import] [--show-psk]] [--password p] [--code otp] [--emssn SN] [--fctver V] [--localid id] [--id-type fqdn|rfc822|keyid] [--psk key] [--probe|--auth-probe|--login|--connect] [--no-routes]");
            std::process::exit(2);
        }
    };
    if let Err(e) = apply_config(&mut opts) {
        out!("# forti-ipsec failed: {e}");
        std::process::exit(1);
    }
    if opts.mode == Mode::Import {
        return; // apply_config already printed the parsed settings
    }
    if let Err(e) = run(&opts) {
        out!("# forti-ipsec failed: {e}");
        std::process::exit(1);
    }
}

/// Import a `--config` FortiClient file into `opts`, filling only the fields the CLI
/// did not set (CLI flags win). Prints what was imported; in `--import` mode this is
/// the whole output.
fn apply_config(opts: &mut Opts) -> Result<(), String> {
    let Some(path) = opts.config.clone() else {
        if opts.mode == Mode::Import {
            return Err("--import needs a --config <file.xml>".into());
        }
        return Ok(());
    };
    let xml = std::fs::read_to_string(&path).map_err(|e| format!("read {path}: {e}"))?;
    let p = fctconfig::parse(&xml)?;

    out!("# imported FortiClient config '{}' (connection '{}')", path, p.name);
    out!("#   gateway   {}:{}", p.server, p.udp_port);
    out!("#   localid   {}", p.localid);
    out!("#   auth      {} / EAP method {}", p.auth_method, p.eap_method);
    out!("#   version   {}", p.fctver);
    out!("#   proposals {}  DH {}", p.proposals.join(", "), p.dhgroup);
    out!("#   group PSK {}", if p.psk.is_empty() { "(none)".into() } else { format!("recovered ({} chars)", p.psk.len()) });
    if opts.show_psk && !p.psk.is_empty() {
        out!("#   PSK value {}", p.psk);
    }

    // Fill only what the CLI left unset.
    if opts.gateway.is_empty() {
        opts.gateway = p.server.clone();
        opts.port = p.udp_port;
    }
    if opts.localid.is_none() && !p.localid.is_empty() {
        opts.localid = Some(p.localid.clone());
        // A localid is an opaque group name, sent as KEY_ID (matches --localid).
        opts.id_type = model::IdType::KeyId.into();
    }
    if opts.psk.is_none() && !p.psk.is_empty() {
        opts.psk = Some(p.psk.clone());
    }
    if opts.fctver.is_none() && !p.fctver.is_empty() {
        opts.fctver = Some(p.fctver.clone());
    }
    Ok(())
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
        localid: None,
        fctver: None,
        config: None,
        show_psk: false,
        id_type: model::IdType::Rfc822Addr.into(),
        psk: None,
    };
    let mut i = 0;
    let mut port_set = false;
    let mut id_type_set = false;
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
            "--psk" => o.psk = Some(next(&mut i)?),
            "--fctver" => o.fctver = Some(next(&mut i)?),
            "--config" => o.config = Some(next(&mut i)?),
            "--import" => o.mode = Mode::Import,
            "--show-psk" => o.show_psk = true,
            "--localid" => {
                o.localid = Some(next(&mut i)?);
                // A localid is typically an opaque group name, not an email, so
                // default its IDi type to KEY_ID unless the caller overrides it.
                if !id_type_set {
                    o.id_type = model::IdType::KeyId.into();
                }
            }
            "--id-type" => {
                let v = next(&mut i)?;
                o.id_type = match v.as_str() {
                    "fqdn" => model::IdType::Fqdn.into(),
                    "rfc822" | "email" => model::IdType::Rfc822Addr.into(),
                    "keyid" => model::IdType::KeyId.into(),
                    _ => return Err(format!("bad --id-type {v} (fqdn|rfc822|keyid)")),
                };
                id_type_set = true;
            }
            "--port" => {
                o.port = next(&mut i)?.parse().map_err(|_| "bad --port")?;
                port_set = true;
            }
            "--probe" => o.mode = Mode::Probe,
            "--auth-probe" => o.mode = Mode::AuthProbe,
            "--login" => o.mode = Mode::Login,
            "--connect" => o.mode = Mode::Connect,
            "--no-routes" => o.no_routes = true,
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }
    // The gateway may instead come from a --config file (applied later). Import mode
    // never connects, so it needs neither.
    if o.gateway.is_empty() && o.config.is_none() {
        return Err("missing -g <gateway> (or --config <file.xml>)".into());
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
    // AuthProbe explores the gateway's IKE_AUTH behaviour with a throwaway identity
    // and no credentials, so a real username is not required (and deliberately not
    // used by default, to avoid touching a real account).
    if o.mode == Mode::AuthProbe && o.user.is_empty() {
        o.user = "probe@example.com".to_string();
    }
    if o.mode != Mode::Probe && o.mode != Mode::AuthProbe && o.mode != Mode::Import && o.user.is_empty() {
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
    // case for a client behind a router). Reuse the SAME socket (keep the source
    // port) so the gateway still matches the IKE SA from IKE_SA_INIT.
    let mut natt = udp;
    if session.nat_detected {
        natt.float_to_natt(&gw.to_string())?;
        out!("# NAT detected — floating to UDP/4500 (NAT-T)");
    }

    if o.mode == Mode::AuthProbe {
        return auth_probe(&mut session, &natt, o);
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
    data_plane(natt, session, esp, assigned, &cfg, gw, o.no_routes)
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
/// Send the first IKE_AUTH exactly as `authenticate` would (IDi, CP request, SAi2,
/// TSi/TSr, INITIAL_CONTACT, plus any EMS payload), but with NO AUTH payload and NO
/// credentials, then dump the gateway's (decrypted) reply and stop. This reveals,
/// without completing a login, which EAP method the gateway offers, whether it
/// authenticates by PSK or certificate, and whether the EMS/FortiClient gate fires
/// before the EAP exchange. Uses a throwaway identity by default so no real account
/// is touched.
fn auth_probe(session: &mut Ikev2Session, udp: &IkeUdp, o: &Opts) -> Result<(), String> {
    let serial = emssn::EmsSerial::resolve(o.emssn.as_deref());
    out!("# auth-probe: first IKE_AUTH as identity {:?}, no credentials, no EMS serial{}",
        o.user, if serial.as_str().is_some() { " (serial present)" } else { "" });

    let idi = build_idi(o);
    let mut first: Vec<Payload> = vec![idi];
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
    first.extend(emssn::auth_payloads(&serial, &o.user, &udp.local_ipv4().to_string(), o.fctver.as_deref().unwrap_or("")));

    let msg_id = session.next_msg_id;
    let req = session.encrypt(model::ExchangeType::IkeAuth.into(), msg_id, &first);
    let resp = send_recv_retry(udp, &req, 3)?;
    let (_hdr, payloads) = session.decrypt(&resp)?;

    session::dump_payloads("IKE_AUTH response (auth-probe)", &payloads);

    // Interpret the headline result.
    if let Some(code) = auth_failed(&payloads) {
        out!("# auth-probe: gateway returned AUTHENTICATION_FAILED ({code}) — rejected before/at EAP start");
    } else if payloads.iter().any(|p| matches!(p, Payload::Eap(_))) {
        out!("# auth-probe: gateway accepted the framing and started EAP (see the EAP payload above)");
    } else if let Some(Payload::Auth { method, .. }) = payloads.iter().find(|p| matches!(p, Payload::Auth { .. })) {
        out!("# auth-probe: gateway sent its AUTH (method {method}) without EAP — PSK/cert-only path");
    } else {
        out!("# auth-probe: gateway replied without EAP or AUTH — inspect the dump above");
    }
    Ok(())
}

fn authenticate(session: &mut Ikev2Session, udp: &IkeUdp, o: &Opts) -> Result<Vec<Payload>, String> {
    let password = o.password.clone().or_else(read_stdin_secret).ok_or("no password supplied")?;
    let serial = emssn::EmsSerial::resolve(o.emssn.as_deref());
    if let Some(sn) = serial.as_str() {
        out!("# presenting EMS serial {sn} in FORTICLIENT_CONNECT (0xF100)");
    }

    // First IKE_AUTH request: IDi, CP(request), SAi2, TSi, TSr, INITIAL_CONTACT, and
    // the FortiClient/EMS payloads. No AUTH → request EAP.
    let idi = build_idi(o);
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
    first.extend(emssn::auth_payloads(&serial, &o.user, &udp.local_ipv4().to_string(), o.fctver.as_deref().unwrap_or("")));

    let verbose = std::env::var("UNVPN_VERBOSE").is_ok();
    let mut msg_id = session.next_msg_id; // 1
    let req = session.encrypt(model::ExchangeType::IkeAuth.into(), msg_id, &first);
    let mut resp = send_recv_retry(udp, &req, 3)?;

    // EAP loop.
    let mut msk: Option<[u8; 64]> = None;
    let mut gw_auth_checked = false;
    loop {
        let (_hdr, payloads) = session.decrypt(&resp)?;
        if verbose {
            session::dump_payloads("IKE_AUTH response (authenticate)", &payloads);
        }
        // The gateway authenticates itself with a PSK AUTH (method 2) in the first
        // IKE_AUTH response. Verify it once against the group PSK — this is the real
        // gateway authentication (its post-EAP AUTH in the final message is keyed by
        // the EAP MSK instead, and is checked separately below).
        if !gw_auth_checked && payloads.iter().any(|p| matches!(p, Payload::Auth { .. })) {
            gw_auth_checked = true;
            verify_gateway_auth(session, o, &payloads)?;
        }

        if let Some(code) = auth_failed(&payloads) {
            return Err(format!("gateway rejected authentication ({code})"));
        }

        let eap = payloads.iter().find_map(|p| match p {
            Payload::Eap(e) => Some(e.clone()),
            _ => None,
        });

        let Some(eap_bytes) = eap else {
            // No EAP payload: this is the final response (AUTH + SAr2 + TS + CP).
            verify_gateway_auth(session, o, &payloads)?;
            return Ok(payloads);
        };

        let msg = eap::Eap::parse(&eap_bytes)?;
        if verbose {
            out!("# [verbose] EAP code={} id={} method={:?} data[{}]",
                msg.code, msg.id, msg.method, msg.data.len());
        }
        msg_id += 1;
        match msg.code {
            eap::EAP_SUCCESS => {
                // Final IKE_AUTH, keyed by the EAP MSK (RFC 7296 §2.16), or by SK_pi
                // for an EAP method that establishes no key.
                let idi_body = idi_body_bytes(&idi);
                let signed = session.initiator_signed_octets(&idi_body);
                let crypto = session.crypto.as_ref().unwrap();
                let sk_pi = &session.keys.as_ref().unwrap().sk_pi;
                let auth_data = match &msk {
                    Some(k) => crypto.psk_auth(k, &signed),
                    None => crypto.key_auth(sk_pi, &signed),
                };
                if verbose {
                    out!("# [verbose] EAP-Success; sending final AUTH");
                }
                let auth = Payload::Auth { method: model::AUTH_PSK, data: auth_data };
                let req = session.encrypt(model::ExchangeType::IkeAuth.into(), msg_id, &[auth]);
                session.next_msg_id = msg_id + 1;
                let resp2 = send_recv_retry(udp, &req, 3)?;
                let (_h, final_payloads) = session.decrypt(&resp2)?;
                if let Some(code) = auth_failed(&final_payloads) {
                    return Err(format!("gateway rejected final AUTH ({code})"));
                }
                // Post-EAP, the gateway's AUTH is keyed by the EAP MSK (RFC 7296
                // §2.16), NOT the group PSK — its PSK identity was already proven in
                // the first IKE_AUTH response. Verify this final AUTH against the MSK
                // (best-effort: authenticity is already established, so a mismatch
                // warns rather than aborts the otherwise-complete handshake).
                verify_gateway_msk_auth(session, &final_payloads, msk.as_ref(), verbose);
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

/// Build the IKE initiator identity (IDi). When `--localid` is given it is the
/// identity (e.g. the FortiGate dialup group `vpngroup`) with the configured type
/// (KEY_ID by default); otherwise the username as an RFC822 address. FortiGate
/// dialup selects the phase1-interface by this ID, so a wrong one is silently
/// dropped before any auth.
fn build_idi(o: &Opts) -> Payload {
    let id = o.localid.as_deref().unwrap_or(&o.user);
    Payload::IdI { kind: o.id_type, data: id.as_bytes().to_vec() }
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

/// Verify the gateway's AUTH. When a group PSK is supplied (`--psk`) and the
/// gateway authenticates by shared key (AUTH method 2), we recompute its AUTH from
/// our transcript and the PSK and compare — proving we are talking to the real
/// gateway, not an impostor. A mismatch aborts. Without a PSK (or against a
/// cert-authenticated gateway) we cannot check its credential, so we only note it:
/// the gateway would not have sent a CHILD SA had it rejected us.
/// Verify the gateway's post-EAP AUTH payload against the EAP MSK (RFC 7296 §2.16).
/// Non-fatal: the gateway's authenticity was already proven by its PSK AUTH in the
/// first IKE_AUTH response, so this only reports whether the MSK-keyed final AUTH
/// also checks out.
fn verify_gateway_msk_auth(
    session: &Ikev2Session,
    payloads: &[Payload],
    msk: Option<&[u8; 64]>,
    verbose: bool,
) {
    let Some(msk) = msk else { return };
    let auth = payloads.iter().find_map(|p| match p {
        Payload::Auth { data, .. } => Some(data.clone()),
        _ => None,
    });
    let idr = payloads.iter().find_map(|p| match p {
        Payload::IdR { kind, data } => Some((*kind, data.clone())),
        _ => None,
    });
    let (Some(data), Some((kind, id))) = (auth, idr) else { return };
    let mut idr_body = vec![kind, 0, 0, 0];
    idr_body.extend_from_slice(&id);
    if session.gateway_psk_auth_matches(msk, &idr_body, &data) {
        out!("# gateway final AUTH verified against the EAP MSK — mutual authentication complete");
    } else if verbose {
        out!("# [verbose] gateway final AUTH did not match the MSK (gateway already authenticated via PSK upfront)");
    }
}

fn verify_gateway_auth(session: &Ikev2Session, o: &Opts, payloads: &[Payload]) -> Result<(), String> {
    let auth = payloads.iter().find_map(|p| match p {
        Payload::Auth { method, data } => Some((*method, data.clone())),
        _ => None,
    });
    let Some((method, data)) = auth else {
        out!("# warning: gateway sent no AUTH payload");
        return Ok(());
    };

    match &o.psk {
        Some(psk) if method == model::AUTH_PSK => {
            let idr = payloads.iter().find_map(|p| match p {
                Payload::IdR { kind, data } => Some((*kind, data.clone())),
                _ => None,
            });
            let Some((kind, id)) = idr else {
                return Err("gateway AUTH is shared-key but it sent no IDr to bind it to".into());
            };
            let mut idr_body = vec![kind, 0, 0, 0];
            idr_body.extend_from_slice(&id);
            if session.gateway_psk_auth_matches(psk.as_bytes(), &idr_body, &data) {
                out!("# gateway AUTH verified against the group PSK (method 2) — authentic gateway");
                Ok(())
            } else {
                Err("gateway AUTH did NOT match the group PSK (wrong --psk or man-in-the-middle) — aborting".into())
            }
        }
        Some(_) => {
            out!("# note: gateway authenticated with method {method}, not shared-key — --psk cannot verify it (needs its certificate)");
            Ok(())
        }
        None => {
            out!("# note: gateway AUTH (method {method}) not verified — pass --psk <group-key> to authenticate the gateway");
            Ok(())
        }
    }
}

/// The ESP data plane: pump IPv4 packets between the tun device and ESP-over-UDP
/// (NAT-T, port 4500), with routes/DNS and a NAT keepalive. Blocks until stop.
fn data_plane(
    udp: IkeUdp,
    mut session: Ikev2Session,
    mut esp: crate::ike::esp::EspSa,
    assigned: Ipv4Addr,
    cfg: &config::TunnelConfig,
    gw: Ipv4Addr,
    no_routes: bool,
) -> Result<(), String> {
    use crate::tun;
    use std::io::Read;
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    static STOP: AtomicBool = AtomicBool::new(false);

    let sock = udp.try_clone_socket().map_err(|e| format!("clone socket: {e}"))?;
    // Non-blocking: the poll below waits for readiness, so the ESP→tun drain loop
    // must return immediately once the socket is empty. With a blocking read timeout
    // instead, every drain cycle ends in a ~500 ms blocking recv, inflating the RTT
    // to half a second and crippling TCP throughput (~10 KB/s).
    sock.set_nonblocking(true).ok();

    let (mut tun_file, tun_name) = tun::open_tun("cpfi0")?;
    tun::ip(&["addr", "add", &format!("{assigned}/32"), "dev", &tun_name])?;
    // 1280 matches FortiClient's IPsec default and leaves ample headroom for the
    // ESP + UDP(NAT-T) + outer IP overhead, avoiding PMTU black-holes on the path.
    tun::ip(&["link", "set", "dev", &tun_name, "up", "mtu", "1280"])?;
    out!("# tun {tun_name} up — {assigned}/32, mtu 1280");

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
        restore.leak = crate::leakguard::enable(&tun_name, &[gw])?;
    }
    sysnet::spawn_stdin_disconnect(&STOP);
    tun::set_nonblocking(&tun_file);

    out!("# TUNNEL UP (ESP over NAT-T). (send 'disconnect' on stdin or SIGTERM to stop)");
    let tun_fd = tun_file.as_raw_fd();
    let sock_fd = sock.as_raw_fd();
    let kick_fd = crate::netmon::kick_fd();
    let mut buf = [0u8; 2048];
    let (mut tin, mut tout, mut derr) = (0u64, 0u64, 0u64);
    let mut last_ka = Instant::now();
    let mut last_stats = Instant::now();
    // Liveness and recovery. A stall with outbound traffic, or a resume/network
    // kick, triggers a CREATE_CHILD_SA rekey (fresh ESP keys under the live IKE SA,
    // no re-auth); a quiet tunnel is probed with DPD instead of making a new SA. The
    // CHILD SA is also rekeyed on a timer so it doesn't expire. Only when the IKE SA
    // itself is gone (rekey/DPD unanswered) does the session end with an error.
    const PROBE_SECS: u64 = 45;
    const MAX_RECOVER_FAILS: u32 = 2;
    let child_rekey = Duration::from_secs(child_rekey_secs());
    let mut rekey_next = Instant::now() + child_rekey;
    let mut last_rx_at = Instant::now();
    let mut last_tin = 0u64;
    let mut recover_fails = 0u32;
    let mut lost: Option<String> = None;

    loop {
        if STOP.load(Ordering::SeqCst) {
            break;
        }
        let mut fds = [
            libc::pollfd { fd: tun_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: sock_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: kick_fd, events: libc::POLLIN, revents: 0 },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 3, 500) };
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
                        // A gateway-initiated IKE message (DPD request, or a Delete):
                        // answer DPD to stay alive; a Delete ends the session.
                        if let Some(why) = handle_inbound_ike(&udp, &session, &buf[4..m]) {
                            lost = Some(why);
                        }
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

        if lost.is_some() {
            break;
        }

        // A decrypted ESP packet is proof of life: reset the liveness timer.
        if tin > last_tin {
            last_tin = tin;
            last_rx_at = Instant::now();
            recover_fails = 0;
        }

        let kicked = crate::netmon::took_kick();
        let stale = last_rx_at.elapsed().as_secs() >= PROBE_SECS;

        if let Some(why) = kicked {
            // Resume / network change: the ESP path (NAT mapping) may be stale, so
            // rekey the CHILD SA to recover it under the live IKE SA (no re-auth).
            out!("# link event ({why}) — rekeying the CHILD SA");
            match rekey_child(&udp, &sock, &mut tun_file, &esp, &mut session) {
                Ok(new) => {
                    esp = new;
                    last_rx_at = Instant::now();
                    recover_fails = 0;
                    rekey_next = Instant::now() + child_rekey;
                    out!("# CHILD SA rekeyed — tunnel recovered");
                }
                Err(e) => {
                    recover_fails += 1;
                    out!("# recovery attempt {recover_fails}/{MAX_RECOVER_FAILS} failed: {e}");
                    if recover_fails >= MAX_RECOVER_FAILS {
                        lost = Some(format!("{why}; CHILD SA rekey failed"));
                        break;
                    }
                }
            }
        } else if stale {
            // No traffic for a while: probe liveness with DPD. This elicits a
            // guaranteed reply (unlike data, which may be one-way or just idle) and
            // makes no new SA, so it never churns a healthy tunnel.
            match dpd(&udp, &sock, &mut tun_file, &esp, &mut session) {
                Ok(()) => {
                    last_rx_at = Instant::now();
                    recover_fails = 0;
                }
                Err(e) => {
                    recover_fails += 1;
                    out!("# DPD {recover_fails}/{MAX_RECOVER_FAILS} unanswered: {e}");
                    if recover_fails >= MAX_RECOVER_FAILS {
                        lost = Some("gateway stopped answering DPD".to_string());
                        break;
                    }
                }
            }
        } else if Instant::now() >= rekey_next {
            match rekey_child(&udp, &sock, &mut tun_file, &esp, &mut session) {
                Ok(new) => {
                    esp = new;
                    out!("# CHILD SA rekeyed (lifetime)");
                }
                Err(e) => out!("# scheduled rekey failed: {e} — keeping the current SA"),
            }
            rekey_next = Instant::now() + child_rekey;
        }
    }

    out!("# disconnecting — restoring DNS/routes …");
    drop(restore);
    match lost {
        Some(why) => Err(format!("tunnel lost ({why}) — reconnect")),
        None => Ok(()),
    }
}

/// CHILD SA rekey interval (seconds), overridable for testing. Clamped to ≥ 20 s.
fn child_rekey_secs() -> u64 {
    std::env::var("UNVPN_REKEY_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(|n| n.max(20))
        .unwrap_or(1200)
}

/// Run one initiator IKE exchange over the NAT-T socket: (re)transmit `req`, and
/// while waiting keep forwarding ESP data both ways (a rekey must not stall user
/// traffic). Returns the decrypted response payloads for our `msg_id`.
#[allow(clippy::too_many_arguments)]
fn ike_exchange(
    udp: &IkeUdp,
    sock: &std::net::UdpSocket,
    tun_file: &mut std::fs::File,
    esp: &crate::ike::esp::EspSa,
    session: &Ikev2Session,
    req: &[u8],
    msg_id: u32,
    tries: u32,
) -> Result<Vec<Payload>, String> {
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;
    use std::time::{Duration, Instant};
    let (tun_fd, sock_fd) = (tun_file.as_raw_fd(), sock.as_raw_fd());
    let mut buf = [0u8; 2048];
    for _ in 0..tries {
        udp.send(req)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            let ms = deadline.saturating_duration_since(Instant::now()).as_millis().min(500) as i32;
            let mut fds = [
                libc::pollfd { fd: tun_fd, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: sock_fd, events: libc::POLLIN, revents: 0 },
            ];
            if unsafe { libc::poll(fds.as_mut_ptr(), 2, ms) } <= 0 {
                continue;
            }
            if fds[0].revents & libc::POLLIN != 0 {
                for _ in 0..64 {
                    match tun_file.read(&mut buf) {
                        Ok(m) if crate::tun::is_ipv4(&buf[..m]) => {
                            if let Ok(p) = esp.encode(&buf[..m]) {
                                let _ = sock.send(&p);
                            }
                        }
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
            }
            if fds[1].revents & libc::POLLIN != 0 {
                loop {
                    match sock.recv(&mut buf) {
                        Ok(m) if m >= 4 && buf[..4] == [0, 0, 0, 0] => {
                            if let Ok((hdr, payloads)) = session.decrypt(&buf[4..m]) {
                                if hdr.message_id == msg_id && hdr.flags & model::FLAG_RESPONSE != 0 {
                                    return Ok(payloads);
                                }
                            }
                        }
                        Ok(m) if m > 8 => {
                            if let Ok(ip) = esp.decode(&buf[..m]) {
                                if crate::tun::is_ipv4(&ip) {
                                    let _ = tun_file.write_all(&ip);
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
                        Err(_) => break,
                    }
                }
            }
        }
    }
    Err("no IKE response".into())
}

/// Rekey the ESP CHILD SA via CREATE_CHILD_SA under the live IKE SA (no re-auth),
/// returning the fresh ESP SA to swap in. Consumes a message id up front so a
/// failed attempt retries with a new one.
fn rekey_child(
    udp: &IkeUdp,
    sock: &std::net::UdpSocket,
    tun_file: &mut std::fs::File,
    esp: &crate::ike::esp::EspSa,
    session: &mut Ikev2Session,
) -> Result<crate::ike::esp::EspSa, String> {
    let new_spi_i = u32::from_be_bytes(crate::ike::crypto::random(4).try_into().unwrap()).max(0x1000);
    let ni_new = crate::ike::crypto::random(32);
    // PFS with the phase-1 D-H group (FortiGate phase-2 default). Without it the
    // gateway refuses the rekey with NO_PROPOSAL_CHOSEN.
    let dh = crypto::dh_new(model::DH_MODP2048)?;
    let msg_id = session.next_msg_id;
    session.next_msg_id = msg_id + 1;
    let payloads = session.rekey_child_payloads(new_spi_i, &ni_new, Some((model::DH_MODP2048, dh.public_key())));
    let req = session.encrypt(model::ExchangeType::CreateChildSa.into(), msg_id, &payloads);
    let resp = ike_exchange(udp, sock, tun_file, esp, session, &req, msg_id, 4)?;
    let (new_spi_r, nr, ke) = session.parse_child_response(&resp)?;
    let shared = match ke {
        Some(k) => Some(dh.shared_secret(&k)?),
        None => None,
    };
    let new_esp = session.rekeyed_esp_sa(new_spi_i, new_spi_r, shared.as_deref(), &ni_new, &nr)?;
    session.esp_spi_i = new_spi_i;
    session.esp_spi_r = new_spi_r;
    Ok(new_esp)
}

/// Liveness probe: an empty INFORMATIONAL request the gateway must answer.
fn dpd(
    udp: &IkeUdp,
    sock: &std::net::UdpSocket,
    tun_file: &mut std::fs::File,
    esp: &crate::ike::esp::EspSa,
    session: &mut Ikev2Session,
) -> Result<(), String> {
    let msg_id = session.next_msg_id;
    session.next_msg_id = msg_id + 1;
    let req = session.encrypt(model::ExchangeType::Informational.into(), msg_id, &[]);
    ike_exchange(udp, sock, tun_file, esp, session, &req, msg_id, 4).map(|_| ())
}

/// Handle a gateway-initiated IKE message: answer an INFORMATIONAL (DPD) request so
/// the gateway keeps the SA up, and report a Delete as the end of the session.
fn handle_inbound_ike(udp: &IkeUdp, session: &Ikev2Session, raw: &[u8]) -> Option<String> {
    let (hdr, payloads) = session.decrypt(raw).ok()?;
    let is_request = hdr.flags & model::FLAG_RESPONSE == 0;
    if is_request && hdr.exchange == u8::from(model::ExchangeType::Informational) {
        let resp = session.encrypt_resp(u8::from(model::ExchangeType::Informational), hdr.message_id, &[]);
        let _ = udp.send(&resp);
    }
    payloads
        .iter()
        .any(|p| matches!(p, Payload::Delete { .. }))
        .then(|| "gateway deleted the SA".to_string())
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
