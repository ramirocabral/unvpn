//! IKEv1 Main Mode message construction/parsing for the Check Point initiator.
//! Transport-agnostic: the same messages ride UDP (NAT-T) or Visitor Mode (TLS).

use std::net::Ipv4Addr;

use super::model::*;
use super::session::Ikev1Session;
use super::wire::*;

/// The negotiated Phase-1 suite the gateway selected in msg 2.
#[derive(Debug, Clone, Copy)]
pub struct ChosenSuite {
    pub responder_spi: u64,
    pub enc_alg: u16,
    pub hash_alg: u16,
    pub group: u16,
    pub key_bits: usize,
    pub lifetime: u32,
}

/// Build Main Mode msg 1: the SA proposal (the single transform the Check Point
/// gateway selects — AES-256-CBC / SHA-256 / DH group 2 / Hybrid / 28800s) plus
/// the Check Point and NAT-T vendor IDs.
pub fn build_sa_msg(session: &Ikev1Session, lifetime_secs: u32) -> IsakmpMessage {
    // Offer a transform matrix (enc × hash × DH group, all Check Point hybrid
    // auth) for the gateway to pick from. A single transform drew
    // VPN_NO_COMMON_METHODS_MM.
    let mut transforms = Vec::new();
    for &(enc, keylens) in &[
        (IKE_ENC_AES_CBC, &[256u16, 128][..]),
        (IKE_ENC_3DES, &[0u16][..]),
    ] {
        for &hash in &[IKE_HASH_SHA512, IKE_HASH_SHA384, IKE_HASH_SHA256, IKE_HASH_SHA1] {
            for &group in &[IKE_GROUP_MODP2048, IKE_GROUP_MODP1024] {
                for &keylen in keylens {
                    let mut attributes = vec![
                        Attribute::short(IkeAttributeType::EncryptionAlgorithm.into(), enc),
                        Attribute::short(IkeAttributeType::HashAlgorithm.into(), hash),
                        Attribute::short(IkeAttributeType::GroupDescription.into(), group),
                        Attribute::short(
                            IkeAttributeType::AuthenticationMethod.into(),
                            IKE_AUTH_HYBRID_INIT_RSA,
                        ),
                        Attribute::short(IkeAttributeType::LifeType.into(), IKE_LIFE_SECONDS),
                        Attribute::short(IkeAttributeType::LifeDuration.into(), lifetime_secs as u16),
                    ];
                    if keylen != 0 {
                        attributes.push(Attribute::short(IkeAttributeType::KeyLength.into(), keylen));
                    }
                    transforms.push(Transform {
                        number: (transforms.len() + 1) as u8,
                        transform_id: TransformId::KeyIke.into(),
                        attributes,
                    });
                }
            }
        }
    }
    let sa = Payload::Sa(SaPayload {
        doi: 1,
        situation: Some(1), // SIT_IDENTITY_ONLY
        proposals: vec![Proposal {
            number: 1,
            protocol_id: ProtocolId::Isakmp.into(),
            spi: Vec::new(),
            transforms,
        }],
    });

    IsakmpMessage {
        initiator_spi: session.initiator_spi,
        responder_spi: 0,
        exchange_type: ExchangeType::IdentityProtection.into(),
        flags: 0,
        message_id: 0,
        payloads: vec![
            sa,
            Payload::VendorId(VID_CHECKPOINT.to_vec()),
            Payload::VendorId(VID_IPSEC_NAT_T.to_vec()),
        ],
    }
}

/// The SA payload *body* (SAi_b) that feeds HASH_I / HASH_R. Must be the exact
/// bytes sent in msg 1.
pub fn sa_body(msg: &IsakmpMessage) -> Option<Vec<u8>> {
    msg.payloads.iter().find_map(|p| match p {
        Payload::Sa(_) => {
            let (_t, encoded) = IsakmpMessage::encode_payloads(std::slice::from_ref(p));
            // strip the 4-byte generic payload header to get the body
            Some(encoded[PAYLOAD_HEADER_LEN..].to_vec())
        }
        _ => None,
    })
}

/// Parse the gateway's msg 2: the single transform it selected.
pub fn parse_chosen_suite(msg: &IsakmpMessage) -> Result<ChosenSuite, String> {
    let sa = msg
        .payloads
        .iter()
        .find_map(|p| match p {
            Payload::Sa(sa) => Some(sa),
            _ => None,
        })
        .ok_or("no SA payload in msg 2")?;
    let transform = sa
        .proposals
        .first()
        .and_then(|p| p.transforms.first())
        .ok_or("no transform in msg 2 SA")?;

    let attr = |ty: IkeAttributeType| -> Option<u16> {
        transform
            .attributes
            .iter()
            .find(|a| a.attr_type == u16::from(ty))
            .and_then(|a| a.as_u16())
    };
    let life_attr = || -> Option<u32> {
        transform
            .attributes
            .iter()
            .find(|a| a.attr_type == u16::from(IkeAttributeType::LifeDuration))
            .and_then(|a| match &a.value {
                AttrValue::Short(v) => Some(*v as u32),
                AttrValue::Long(b) if b.len() == 4 => Some(u32::from_be_bytes(b[..4].try_into().unwrap())),
                AttrValue::Long(b) if b.len() == 2 => Some(u16::from_be_bytes(b[..2].try_into().unwrap()) as u32),
                _ => None,
            })
    };

    let enc_alg = attr(IkeAttributeType::EncryptionAlgorithm).ok_or("no enc alg")?;
    let hash_alg = attr(IkeAttributeType::HashAlgorithm).ok_or("no hash alg")?;
    let group = attr(IkeAttributeType::GroupDescription).ok_or("no DH group")?;
    let key_bits = attr(IkeAttributeType::KeyLength).unwrap_or(if enc_alg == IKE_ENC_3DES { 192 } else { 0 }) as usize;
    let lifetime = life_attr().unwrap_or(28800);

    Ok(ChosenSuite {
        responder_spi: msg.responder_spi,
        enc_alg,
        hash_alg,
        group,
        key_bits,
        lifetime,
    })
}

/// Build Main Mode msg 3: KE + Nonce + two NAT-D payloads. Check Point hashes
/// the gateway address with port 4500 and the local address with port 0 — this
/// is what steers the connection onto NAT-T (ESP-in-UDP 4500).
pub fn build_ke(session: &Ikev1Session, local_ip: Ipv4Addr, gateway_ip: Ipv4Addr) -> IsakmpMessage {
    let gw: u32 = gateway_ip.into();
    let hash_r = session.hash(&[
        &session.initiator_spi.to_be_bytes(),
        &session.responder_spi.to_be_bytes(),
        &gw.to_be_bytes(),
        &4500u16.to_be_bytes(),
    ]);
    let loc: u32 = local_ip.into();
    let hash_i = session.hash(&[
        &session.initiator_spi.to_be_bytes(),
        &session.responder_spi.to_be_bytes(),
        &loc.to_be_bytes(),
        &[0, 0],
    ]);

    IsakmpMessage {
        initiator_spi: session.initiator_spi,
        responder_spi: session.responder_spi,
        exchange_type: ExchangeType::IdentityProtection.into(),
        flags: 0,
        message_id: 0,
        payloads: vec![
            Payload::KeyExchange(session.initiator_pubkey.clone()),
            Payload::Nonce(session.initiator_nonce.clone()),
            Payload::Natd(hash_r),
            Payload::Natd(hash_i),
        ],
    }
}

pub fn find_key_exchange(msg: &IsakmpMessage) -> Option<Vec<u8>> {
    msg.payloads.iter().find_map(|p| match p {
        Payload::KeyExchange(d) => Some(d.clone()),
        _ => None,
    })
}

pub fn find_nonce(msg: &IsakmpMessage) -> Option<Vec<u8>> {
    msg.payloads.iter().find_map(|p| match p {
        Payload::Nonce(d) => Some(d.clone()),
        _ => None,
    })
}

/// The gateway's NAT-D payloads (first = peer/self check, etc.), for NAT detection.
pub fn find_natds(msg: &IsakmpMessage) -> Vec<Vec<u8>> {
    msg.payloads
        .iter()
        .filter_map(|p| match p {
            Payload::Natd(d) => Some(d.clone()),
            _ => None,
        })
        .collect()
}

/// The Check Point hybrid-auth identity blob carried in the CccAuth notify of
/// Main Mode msg 5. A nameless CP S-expression naming the client + realm.
pub fn auth_blob(realm: &str) -> String {
    use crate::ccc::Value;
    let logging = Value::map(vec![
        ("client_name", Value::str("Check Point Mobile")),
        ("client_ver", Value::sym("1")),
        ("client_build_number", Value::sym("1")),
        ("os_name", Value::sym("Linux")),
        ("device_id", Value::str("cpvpn-linux")),
    ]);
    Value::map(vec![
        ("clientType", Value::sym("TRAC")),
        ("clientOS", Value::sym("Linux")),
        ("oldSessionId", Value::Empty),
        ("protocolVersion", Value::Num(100)),
        ("client_mode", Value::sym("endpoint_security")),
        ("selected_realm_id", Value::sym(realm)),
        ("client_logging_data", logging),
    ])
    .serialize_bare()
}

/// The raw body of an Identification payload (fed to HASH_I / HASH_R).
pub fn ident_body(id: &IdPayload) -> Vec<u8> {
    let mut b = vec![id.id_type, id.protocol_id];
    b.extend_from_slice(&id.port.to_be_bytes());
    b.extend_from_slice(&id.data);
    b
}

/// Main Mode msg 5 payloads for hybrid auth (no client certificate):
/// Hash(HASH_I), ID (empty UserFQDN), Notify(CccAuth, auth_blob). Encrypted.
pub fn build_auth_payloads(session: &Ikev1Session, realm: &str) -> Vec<Payload> {
    let id = IdPayload {
        id_type: IdentityType::UserFqdn.into(),
        protocol_id: 0,
        port: 0,
        data: Vec::new(),
    };
    let hash_i = session.hash_id_i(&ident_body(&id));

    let mut spi = session.initiator_spi.to_be_bytes().to_vec();
    spi.extend_from_slice(&session.responder_spi.to_be_bytes());
    let notify = NotifyPayload {
        doi: 0,
        protocol_id: ProtocolId::Isakmp.into(),
        spi,
        message_type: NotifyMessageType::CccAuth.into(),
        data: auth_blob(realm).into_bytes(),
    };

    vec![
        Payload::Hash(hash_i),
        Payload::Identification(id),
        Payload::Notification(notify),
    ]
}

/// Encode + encrypt an ISAKMP message (ISAKMP padding: 1..pad_len then pad_len).
pub fn encrypt_message(
    session: &mut Ikev1Session,
    exchange_type: u8,
    message_id: u32,
    payloads: &[Payload],
) -> Result<Vec<u8>, String> {
    let (first, mut chain) = IsakmpMessage::encode_payloads(payloads);
    let bs = session.block_size();
    let pad_len = (bs - ((chain.len() + 1) % bs)) % bs;
    for i in 1..=pad_len as u8 {
        chain.push(i);
    }
    chain.push(pad_len as u8);
    let ct = session.encrypt(message_id, &chain)?;

    let mut out = Vec::with_capacity(ISAKMP_HEADER_LEN + ct.len());
    out.extend_from_slice(&session.initiator_spi.to_be_bytes());
    out.extend_from_slice(&session.responder_spi.to_be_bytes());
    out.push(first);
    out.push(IKEV1_VERSION);
    out.push(exchange_type);
    out.push(FLAG_ENCRYPTION);
    out.extend_from_slice(&message_id.to_be_bytes());
    out.extend_from_slice(&((ISAKMP_HEADER_LEN + ct.len()) as u32).to_be_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt + parse an encrypted ISAKMP message received from the gateway.
pub fn decrypt_message(session: &mut Ikev1Session, raw: &[u8]) -> Result<IsakmpMessage, String> {
    if raw.len() < ISAKMP_HEADER_LEN {
        return Err("short ISAKMP header".into());
    }
    let initiator_spi = u64::from_be_bytes(raw[0..8].try_into().unwrap());
    let responder_spi = u64::from_be_bytes(raw[8..16].try_into().unwrap());
    let next_payload = raw[16];
    let exchange_type = raw[18];
    let flags = raw[19];
    let message_id = u32::from_be_bytes(raw[20..24].try_into().unwrap());

    let body = &raw[ISAKMP_HEADER_LEN..];
    let payloads = if flags & FLAG_ENCRYPTION != 0 {
        let pt = session.decrypt(message_id, body)?;
        IsakmpMessage::parse_payloads(next_payload, &pt)?
    } else {
        IsakmpMessage::parse_payloads(next_payload, body)?
    };
    Ok(IsakmpMessage {
        initiator_spi,
        responder_spi,
        exchange_type,
        flags,
        message_id,
        payloads,
    })
}

pub fn find_signature(msg: &IsakmpMessage) -> Option<Vec<u8>> {
    msg.payloads.iter().find_map(|p| match p {
        Payload::Signature(d) => Some(d.clone()),
        _ => None,
    })
}

pub fn find_hash(msg: &IsakmpMessage) -> Option<Vec<u8>> {
    msg.payloads.iter().find_map(|p| match p {
        Payload::Hash(d) => Some(d.clone()),
        _ => None,
    })
}

/// DER certificates from msg 6 (strip the 1-byte certificate-type prefix).
pub fn find_certificates(msg: &IsakmpMessage) -> Vec<Vec<u8>> {
    msg.payloads
        .iter()
        .filter_map(|p| match p {
            Payload::Certificate(d) if d.len() > 1 => Some(d[1..].to_vec()),
            _ => None,
        })
        .collect()
}

pub fn find_identification_body(msg: &IsakmpMessage) -> Option<Vec<u8>> {
    msg.payloads.iter().find_map(|p| match p {
        Payload::Identification(id) => Some(ident_body(id)),
        _ => None,
    })
}

pub fn find_attributes(msg: &IsakmpMessage) -> Option<AttributesPayload> {
    msg.payloads.iter().find_map(|p| match p {
        Payload::Attributes(a) => Some(a.clone()),
        _ => None,
    })
}

/// Quick-Mode / config HASH: prf(SKEYID_a, message_id | <payloads w/ generic hdrs>).
pub fn make_hash(session: &Ikev1Session, message_id: u32, payloads: &[Payload]) -> Vec<u8> {
    let (_, encoded) = IsakmpMessage::encode_payloads(payloads);
    session.prf(&session.skeyid_a, &[&message_id.to_be_bytes(), &encoded])
}

/// Build a config-mode (Transaction) payload chain: HASH over the Attributes
/// payload keyed with SKEYID_a, followed by the Attributes payload itself.
pub fn build_config_payloads(
    session: &Ikev1Session,
    kind: u8,
    message_id: u32,
    identifier: u16,
    attributes: Vec<Attribute>,
) -> Vec<Payload> {
    let attrs_payload = Payload::Attributes(AttributesPayload {
        kind,
        identifier,
        attributes,
    });
    let hash = make_hash(session, message_id, std::slice::from_ref(&attrs_payload));
    vec![Payload::Hash(hash), attrs_payload]
}

pub fn get_short_attr(ap: &AttributesPayload, ty: ConfigAttributeType) -> Option<u16> {
    ap.attributes
        .iter()
        .find(|a| a.attr_type == u16::from(ty))
        .and_then(|a| a.as_u16())
}

pub fn get_long_attr(ap: &AttributesPayload, ty: ConfigAttributeType) -> Option<Vec<u8>> {
    ap.attributes.iter().find_map(|a| {
        if a.attr_type == u16::from(ty) {
            match &a.value {
                AttrValue::Long(b) => Some(b.clone()),
                _ => None,
            }
        } else {
            None
        }
    })
}

/// All long-valued attributes of a given type (e.g. multiple DNS servers).
pub fn get_long_attrs(ap: &AttributesPayload, ty: ConfigAttributeType) -> Vec<Vec<u8>> {
    ap.attributes
        .iter()
        .filter_map(|a| {
            if a.attr_type == u16::from(ty) {
                match &a.value {
                    AttrValue::Long(b) => Some(b.clone()),
                    _ => None,
                }
            } else {
                None
            }
        })
        .collect()
}

/// The attribute the gateway wants filled (not AuthType/Challenge/Status).
pub fn challenge_attr_type(ap: &AttributesPayload) -> u16 {
    for a in &ap.attributes {
        let t = ConfigAttributeType::from(a.attr_type);
        if t != ConfigAttributeType::AuthType
            && t != ConfigAttributeType::Challenge
            && t != ConfigAttributeType::Status
        {
            return a.attr_type;
        }
    }
    0
}

// --- Office Mode -----------------------------------------------------------

/// Build the Office Mode config Request (asks for an internal IP, DNS, domains,
/// CCC session id, lease). Returns (message_id, identifier, payloads).
pub fn build_om_request(
    session: &Ikev1Session,
    mac: &[u8],
    requested_ip: std::net::Ipv4Addr,
) -> (u32, u16, Vec<Payload>) {
    let message_id = super::crypto::random_u32();
    let identifier = u16::from_be_bytes(super::crypto::random(2).try_into().unwrap());
    let empties = [
        ConfigAttributeType::Ipv4Dns,
        ConfigAttributeType::AddressExpiry,
        ConfigAttributeType::InternalDomainName,
        ConfigAttributeType::CccSessionId,
        ConfigAttributeType::CccVariableLeaseTime,
        ConfigAttributeType::CccOfficeModeAllowed,
        ConfigAttributeType::CccConnectAllowed,
    ];
    let mut attrs: Vec<Attribute> = empties
        .iter()
        .map(|t| Attribute::long(u16::from(*t), vec![0, 0, 0, 0]))
        .collect();
    attrs.push(Attribute::long(u16::from(ConfigAttributeType::MacAddress), mac.to_vec()));
    attrs.push(Attribute::long(
        u16::from(ConfigAttributeType::Ipv4Address),
        requested_ip.octets().to_vec(),
    ));
    attrs.push(Attribute::long(u16::from(ConfigAttributeType::Ipv4Netmask), vec![0, 0, 0, 0]));
    let payloads = build_config_payloads(
        session,
        u8::from(AttributesPayloadType::Request),
        message_id,
        identifier,
        attrs,
    );
    (message_id, identifier, payloads)
}

// --- Quick Mode (Phase 2, ESP SA) ------------------------------------------

#[derive(Debug, Clone)]
pub struct ChosenEsp {
    pub gateway_spi: u32,
    pub nonce_r: Vec<u8>,
    pub transform_id: u8,
    pub auth_alg: u16,
    pub key_bits: usize,
    pub encap: u16,
    /// Phase-2 SA lifetime the gateway settled on, in seconds (0 if KB-based or
    /// absent). We must rekey before this elapses or the gateway drops the SA.
    pub lifetime_secs: u32,
}

/// Build Quick Mode msg 1: Hash(1) + ESP SA proposal + Nonce + IDci(our IP) +
/// IDcr(subnet 0). `our_spi` is the inbound ESP SPI we pick.
pub fn build_quick_mode(
    session: &Ikev1Session,
    our_spi: u32,
    nonce: &[u8],
    our_ip: Ipv4Addr,
    message_id: u32,
    lifetime_secs: u32,
) -> Vec<Payload> {
    let mut transforms = Vec::new();
    for &(tid, keylens) in &[
        (u8::from(TransformId::EspAesCbc), &[256u16, 128][..]),
        (u8::from(TransformId::Esp3Des), &[0u16][..]),
    ] {
        for &auth in &[
            ESP_AUTH_HMAC_SHA256,
            ESP_AUTH_HMAC_SHA256_V2,
            ESP_AUTH_HMAC_SHA160,
            ESP_AUTH_HMAC_SHA96,
        ] {
            for &encap in &[ESP_ENCAP_UDP_TUNNEL, ESP_ENCAP_CHECKPOINT_ESP_IN_UDP] {
                for &keylen in keylens {
                    let mut attributes = vec![
                        Attribute::short(u16::from(EspAttributeType::LifeType), 1),
                        Attribute::long(
                            u16::from(EspAttributeType::LifeDuration),
                            lifetime_secs.to_be_bytes().to_vec(),
                        ),
                        Attribute::short(u16::from(EspAttributeType::AuthenticationAlgorithm), auth),
                        Attribute::short(u16::from(EspAttributeType::EncapsulationMode), encap),
                    ];
                    if keylen != 0 {
                        attributes.push(Attribute::short(u16::from(EspAttributeType::KeyLength), keylen));
                    }
                    transforms.push(Transform {
                        number: (transforms.len() + 1) as u8,
                        transform_id: tid,
                        attributes,
                    });
                }
            }
        }
    }
    let sa = Payload::Sa(SaPayload {
        // This gateway rejects a DOI-0/no-situation Phase-2 SA with
        // SITUATION_NOT_SUPPORTED, so use the IPSEC DOI + SIT_IDENTITY_ONLY,
        // exactly as the accepted Phase-1 SA.
        doi: 1,
        situation: Some(1),
        proposals: vec![Proposal {
            number: 1,
            protocol_id: ProtocolId::IpsecEsp.into(),
            spi: our_spi.to_be_bytes().to_vec(),
            transforms,
        }],
    });
    let nonce_p = Payload::Nonce(nonce.to_vec());
    let idci = Payload::Identification(IdPayload {
        id_type: IdentityType::Ipv4Address.into(),
        protocol_id: 0,
        port: 0,
        data: u32::from(our_ip).to_be_bytes().to_vec(),
    });
    let idcr = Payload::Identification(IdPayload {
        id_type: IdentityType::Ipv4Subnet.into(),
        protocol_id: 0,
        port: 0,
        data: vec![0u8; 8],
    });
    let hash = make_hash(session, message_id, &[sa.clone(), nonce_p.clone(), idci.clone(), idcr.clone()]);
    vec![Payload::Hash(hash), sa, nonce_p, idci, idcr]
}

/// Parse the gateway's Quick Mode reply (QM2): chosen ESP transform + SPI + nonce.
pub fn parse_esp_proposal(msg: &IsakmpMessage) -> Result<ChosenEsp, String> {
    let sa = msg
        .payloads
        .iter()
        .find_map(|p| match p {
            Payload::Sa(sa) => Some(sa),
            _ => None,
        })
        .ok_or("no SA in QM2")?;
    let proposal = sa.proposals.first().ok_or("no proposal in QM2")?;
    let transform = proposal.transforms.first().ok_or("no transform in QM2")?;
    let gateway_spi = {
        let s = &proposal.spi;
        if s.len() == 4 {
            u32::from_be_bytes([s[0], s[1], s[2], s[3]])
        } else {
            return Err(format!("unexpected ESP SPI size {}", s.len()));
        }
    };
    let attr = |ty: EspAttributeType| -> Option<u16> {
        transform
            .attributes
            .iter()
            .find(|a| a.attr_type == u16::from(ty))
            .and_then(|a| a.as_u16())
    };
    let auth_alg = attr(EspAttributeType::AuthenticationAlgorithm).ok_or("no ESP auth alg")?;
    let encap = attr(EspAttributeType::EncapsulationMode).unwrap_or(ESP_ENCAP_UDP_TUNNEL);
    let key_bits = attr(EspAttributeType::KeyLength).unwrap_or(0) as usize;
    // Phase-2 lifetime the gateway settled on. LifeType 1 = seconds, 2 = KB.
    let life_type = attr(EspAttributeType::LifeType).unwrap_or(1);
    let life_dur = transform
        .attributes
        .iter()
        .find(|a| a.attr_type == u16::from(EspAttributeType::LifeDuration))
        .and_then(|a| a.as_u32());
    let lifetime_secs = if life_type == 1 { life_dur.unwrap_or(0) } else { 0 };
    let nonce_r = find_nonce(msg).ok_or("no nonce in QM2")?;
    Ok(ChosenEsp {
        gateway_spi,
        nonce_r,
        transform_id: transform.transform_id,
        auth_alg,
        key_bits,
        encap,
        lifetime_secs,
    })
}

/// Build Quick Mode msg 3 (ack): HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b).
pub fn build_qm_ack(session: &Ikev1Session, message_id: u32, nonce_i: &[u8], nonce_r: &[u8]) -> Vec<Payload> {
    let hash = session.prf(
        &session.skeyid_a,
        &[&[0u8], &message_id.to_be_bytes(), nonce_i, nonce_r],
    );
    vec![Payload::Hash(hash)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sa_msg_roundtrips_and_parses() {
        let session = Ikev1Session::new();
        let msg = build_sa_msg(&session, 28800);
        let bytes = msg.encode();
        let back = IsakmpMessage::decode(&bytes).unwrap();
        assert_eq!(back.encode(), bytes);

        // Parsing our own proposal as if it were the response yields our suite.
        // parse_chosen_suite reads the first transform (SHA-512 / group 14 here).
        let suite = parse_chosen_suite(&back).unwrap();
        assert_eq!(suite.enc_alg, IKE_ENC_AES_CBC);
        assert_eq!(suite.hash_alg, IKE_HASH_SHA512);
        assert_eq!(suite.group, IKE_GROUP_MODP2048);
        assert_eq!(suite.key_bits, 256);
        assert_eq!(suite.lifetime, 28800);

        // SAi_b is non-empty and begins with DOI=1, situation=1.
        let body = sa_body(&msg).unwrap();
        assert_eq!(&body[0..8], &[0, 0, 0, 1, 0, 0, 0, 1]);
    }
}
