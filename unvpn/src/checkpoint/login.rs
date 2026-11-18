//! `unvpn ike`: IKEv1 login (SecurID passcode or certificate), Office Mode, then
//! the tunnel.

use super::tunnel::*;
use super::*;
use crate::{anyconnect, ike, net, report, sysnet};

/// A certificate login, prepared before IKE starts.
pub(super) struct CertLogin {
    key: openssl::pkey::PKey<openssl::pkey::Private>,
    /// The user's certificate first, then the rest of the file's chain.
    chain: Vec<openssl::x509::X509>,
    realm: String,
    secondary_realm_hash: Option<String>,
    common_name: String,
}

/// Open the certificate file (password from stdin) and pick the login option.
pub(super) fn prepare_cert_login(
    host: &str,
    path: &str,
    wanted_realm: Option<&str>,
) -> Result<CertLogin, String> {
    let pw =
        anyconnect::read_secret("Certificate password: ").ok_or("no certificate password given")?;
    let id = cert::p12::load(path, &pw)?;
    let subject = cert::p12::dn_string(id.cert.subject_name());
    let common_name = id
        .cert
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .map(|e| String::from_utf8_lossy(e.data().as_slice()).into_owned())
        .unwrap_or_default();
    let now = openssl::asn1::Asn1Time::days_from_now(0).map_err(|e| e.to_string())?;
    if id.cert.not_after() < now {
        println!(
            "# warning: the certificate expired on {}",
            id.cert.not_after()
        );
    }
    println!(
        "# certificate: {subject} (valid until {})",
        id.cert.not_after()
    );

    let info = match gateway_hello(host) {
        Ok(p) => cert::GatewayInfo::from_hello(&p),
        Err(e) if wanted_realm.is_some() => {
            println!("# warning: could not read the gateway's login options: {e}");
            cert::GatewayInfo::default()
        }
        Err(e) => return Err(format!("could not read the gateway's login options: {e}")),
    };
    let (realm, secondary_realm_hash) = match wanted_realm {
        Some(r) if info.login_options.is_empty() => (r.to_string(), None),
        w => {
            let o = info.certificate_option(w)?;
            println!(
                "# login option: {} \"{}\" [{}]",
                o.id,
                o.display_name,
                o.factors.join(" + ")
            );
            (o.id, Some(o.secondary_realm_hash).filter(|h| !h.is_empty()))
        }
    };
    if let Some(ca) = id.chain.first() {
        let fp = cert::enroll::ca_fingerprint(ca);
        if !info.ca_fingerprints.is_empty() && !info.ca_fingerprints.contains(&fp) {
            println!("# warning: the certificate's CA ({fp}) is not the gateway's internal CA");
        }
    }
    let mut chain = vec![id.cert];
    chain.extend(id.chain);
    Ok(CertLogin {
        key: id.key,
        chain,
        realm,
        secondary_realm_hash,
        common_name,
    })
}

/// Login option (realm) and its secondary realm hash for a Check Point password
/// login. Without the gateway's list, falls back to `wanted` or `vpn`.
fn resolve_password_realm(
    host: &str,
    wanted: Option<&str>,
) -> Result<(String, Option<String>), String> {
    let info = match gateway_hello(host) {
        Ok(p) => cert::GatewayInfo::from_hello(&p),
        Err(e) => {
            println!("# warning: could not read the gateway's login options: {e}");
            cert::GatewayInfo::default()
        }
    };
    if info.login_options.is_empty() {
        return Ok((wanted.unwrap_or("vpn").to_string(), None));
    }
    let o = info.password_option(wanted)?;
    println!(
        "# login option: {} \"{}\" [{}]",
        o.id,
        o.display_name,
        o.factors.join(" + ")
    );
    Ok((o.id, Some(o.secondary_realm_hash).filter(|h| !h.is_empty())))
}

pub fn cmd_ike(args: &[String]) {
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
            Err(e) => report::fail("IKE", &e),
        },
        None => None,
    };
    // Password login: the gateway silently drops msg5 for a login option it
    // doesn't have, so pick (or check) it from the gateway's site information.
    let mut pw_realm_hash: Option<String> = None;
    let realm = match &cert_login {
        Some(c) => c.realm.clone(),
        // The probe stops before any login option is sent.
        None if probe_sig => realm.unwrap_or_default(),
        None => match resolve_password_realm(&host, realm.as_deref()) {
            Ok((r, h)) => {
                pw_realm_hash = h;
                r
            }
            Err(e) => report::fail("IKE", &e),
        },
    };
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
                    s.push_str(&format!(
                        "\n  NOTIFY {}: {}",
                        n.message_type,
                        String::from_utf8_lossy(&n.data)
                    ));
                }
            }
            s
        })?;
        println!(
            "# msg2 SA: enc={} hash={} group={} key_bits={} lifetime={}s responder_spi={:#018x}",
            suite.enc_alg,
            suite.hash_alg,
            suite.group,
            suite.key_bits,
            suite.lifetime,
            suite.responder_spi
        );
        session.responder_spi = suite.responder_spi;
        session.set_suite(suite.group, suite.hash_alg, suite.enc_alg, suite.key_bits)?;

        // msg 3/4 — KE + Nonce + NAT-D.
        let cert_requests: Vec<Vec<u8>> = match &cert_login {
            Some(c) => vec![
                c.chain[0]
                    .issuer_name()
                    .to_der()
                    .map_err(|e| e.to_string())?,
                Vec::new(),
            ],
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
                        .map(|n| cert::p12::dn_string(&n))
                        .unwrap_or_else(|| "(any)".into());
                    println!(
                        "# gateway asks for a certificate (encoding {}) from: {dn}",
                        d.first().copied().unwrap_or(0)
                    );
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
            None => service::build_auth_payloads(&session, &realm, pw_realm_hash.as_deref()),
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
        // The gateway signs HASH_R with its certificate's key in both the hybrid and
        // the certificate login; HASH_R alone proves nothing about who answered.
        let sig =
            service::find_signature(&m6).ok_or("the gateway sent no signature (SIG_R) in msg6")?;
        let gw_der = service::find_certificates(&m6)
            .into_iter()
            .next()
            .ok_or("the gateway sent no certificate in msg6")?;
        session
            .verify_rsa_signature(&hash_r, &sig, &gw_der)
            .map_err(|e| format!("the gateway's signature (SIG_R) does not verify: {e}"))?;
        let gw_cert = openssl::x509::X509::from_der(&gw_der)
            .map_err(|e| format!("gateway certificate: {e}"))?;
        // A certificate login carries the CA that issued the user's certificate; a
        // gateway certificate from that CA needs no other trust.
        let by_users_ca = cert_login
            .as_ref()
            .and_then(|c| c.chain.get(1))
            .and_then(|ca| ca.public_key().ok())
            .is_some_and(|k| gw_cert.verify(&k).unwrap_or(false));
        let ike_endpoint = format!("{host}:ike");
        if by_users_ca {
            net::trust::note_verified(&ike_endpoint, &gw_der);
        } else {
            net::trust::accept(
                &ike_endpoint,
                &gw_cert,
                "IKE certificate, not checked against any CA",
            )?;
        }
        println!("# Phase 1 COMPLETE — gateway SIG_R verified against its certificate.");

        println!("# Phase 1 done; waiting for the gateway's authentication requests...");
        // Raw datagrams already handled: the gateway retransmits them while it waits
        // (e.g. for a code being typed), and decrypting one twice breaks the IV chain.
        let mut seen: Vec<Vec<u8>> = vec![raw6.clone()];
        let mut first = None;
        loop {
            match udp.recv() {
                Ok(r) if r == raw6 => continue, // msg6 retransmit while the gateway waits for us
                Ok(r) if !service::is_encrypted(&r) => {
                    println!("# ignored an unencrypted message from the gateway's address");
                    continue;
                }
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
        // The password / PIN(+tokencode) answers the first challenge only.
        let mut secret_sent = false;
        if let Some(mut req) = first {
            loop {
                let attrs = service::find_attributes(&req)
                    .ok_or("expected config attributes after Phase 1")?;
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
                        println!(
                            "# gateway challenge [{:?}]: {}",
                            ctype,
                            sysnet::one_line(&prompt)
                        );
                        // The text may be followed by its structured form after a NUL.
                        let text = prompt.split(" | ").next().unwrap_or("").trim();
                        let label = if text.is_empty() {
                            "Verification code".to_string()
                        } else {
                            text.to_string()
                        };
                        match passcode.take() {
                            Some(p) => p,
                            None => {
                                report::prompt("code", &label);
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
                    // A later challenge (an e-mailed / SMS code the gateway sends only
                    // after checking the password, a SecurID next tokencode) can't have
                    // been supplied up front: ask for it, like the certificate path.
                    _ if secret_sent => {
                        println!(
                            "# gateway challenge [{:?}]: {}",
                            ctype,
                            sysnet::one_line(&prompt)
                        );
                        let text = prompt.split(" | ").next().unwrap_or("").trim();
                        let label = if text.is_empty() {
                            "Verification code".to_string()
                        } else {
                            text.to_string()
                        };
                        report::prompt("code", &label);
                        match anyconnect::read_secret("Code: ") {
                            Some(c) => c.trim().to_string(),
                            None => {
                                println!("# no code provided; stopping.");
                                return Ok(());
                            }
                        }
                    }
                    _ => {
                        println!(
                            "# gateway challenge [{:?}]: {}",
                            ctype,
                            sysnet::one_line(&prompt)
                        );
                        secret_sent = true;
                        match passcode.take() {
                            Some(p) => p,
                            None => {
                                match anyconnect::read_secret("Password / PIN (+tokencode): ") {
                                    Some(p) if !p.trim().is_empty() => p.trim().to_string(),
                                    _ => {
                                        println!("# no passcode provided; stopping.");
                                        return Ok(());
                                    }
                                }
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
                let stale = udp
                    .drain()
                    .into_iter()
                    .filter(|d| !seen.contains(d))
                    .count();
                if stale > 0 {
                    println!("# discarded {stale} unexpected message(s) received while waiting for input");
                }
                udp.send(&reply_msg)?;
                let sent_at = std::time::Instant::now();
                let mut resent = 0;
                let raw = loop {
                    let r = udp.recv()?;
                    if !service::is_encrypted(&r) {
                        println!("# ignored an unencrypted message from the gateway's address");
                        continue;
                    }
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
        let dns: Vec<std::net::Ipv4Addr> =
            service::get_long_attrs(&oma, ConfigAttributeType::Ipv4Dns)
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
            .or_else(|| {
                service::get_long_attr(&oma, ConfigAttributeType::AddressExpiry).and_then(to_secs)
            })
            .unwrap_or(0);
        println!("# Office Mode: IP {om_ip} / {om_mask}  DNS {dns:?}  domains \"{domains}\"  lease={lease_secs}s");
        let ccc_session = service::get_long_attr(&oma, ConfigAttributeType::CccSessionId)
            .map(|v| {
                String::from_utf8_lossy(&v)
                    .trim_matches('\0')
                    .trim()
                    .to_string()
            })
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic()));

        let our_spi = ike::crypto::random_u32();
        let qm_nonce = ike::crypto::random(32);
        let qm_mid = ike::crypto::random_u32();
        let qm1 = service::build_quick_mode(&session, our_spi, &qm_nonce, om_ip, qm_mid, 3600);
        let qm1_msg =
            service::encrypt_message(&mut session, u8::from(ExchangeType::Quick), qm_mid, &qm1)?;
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
        udp.send(&service::encrypt_message(
            &mut session,
            u8::from(ExchangeType::Quick),
            qm_mid,
            &qm3,
        )?)?;
        let enc_len = if esp.key_bits > 0 {
            esp.key_bits / 8
        } else {
            24
        };
        let auth_len = match esp.auth_alg {
            a if a == ike::model::ESP_AUTH_HMAC_SHA96 || a == ike::model::ESP_AUTH_HMAC_SHA160 => {
                20
            }
            _ => 32,
        };
        let km_in = session.gen_esp_keymat(our_spi, &qm_nonce, &esp.nonce_r, enc_len + auth_len);
        let km_out =
            session.gen_esp_keymat(esp.gateway_spi, &qm_nonce, &esp.nonce_r, enc_len + auth_len);
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
            save_session_file(
                path, &host, om_ip, om_mask, &esp, our_spi, &km_in, &km_out, &dns, &domains,
            )?;
            println!("# session saved to {path} (reuse: sudo unvpn tunnel-up --session {path})");
        }
        if connect {
            let routes = (!no_routes).then(|| cp_routes(&host, ccc_session.as_deref()));
            let sock = std::sync::Arc::new(udp.try_clone_socket().map_err(|e| e.to_string())?);
            return run_tunnel(
                om_ip,
                om_mask,
                esp_sa,
                sock,
                dns,
                domains,
                esp.lifetime_secs,
                lease_secs,
                mac,
                Some(session),
                routes,
            );
        }
        println!("# Office Mode IP {om_ip} ready. (--connect brings up the tunnel; needs sudo)");
        Ok(())
    };

    if let Err(e) = run() {
        report::fail("IKE", &e);
    }
}
