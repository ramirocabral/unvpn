//! IKEv2 initiator session (RFC 7296): IKE_SA_INIT, the SK (Encrypted) message
//! framing used by every later exchange, and the key schedule that feeds AUTH and
//! the CHILD SA. The IKE_AUTH + EAP orchestration lives in `mod.rs` (it needs the
//! interactive prompt plumbing); this module provides the protocol primitives.

#![allow(dead_code)]

use super::crypto::{self, Ikev2Crypto, SaKeys};
use super::model::*;
use super::wire::{self, Message, Notify, Payload, Proposal, Transform};
use crate::ike::crypto::{random, IkeCrypto};
use openssl::hash::{Hasher, MessageDigest};
use std::net::Ipv4Addr;

/// The IKE SA transforms we offer and, once chosen, run with.
#[derive(Debug, Clone, Copy)]
pub struct IkeSuite {
    pub encr: u16,
    pub encr_key_bits: usize,
    pub prf: u16,
    pub integ: u16,
    pub dh: u16,
}

impl IkeSuite {
    /// FortiGate's common dialup default.
    pub fn default_fgt() -> Self {
        IkeSuite { encr: ENCR_AES_CBC, encr_key_bits: 256, prf: PRF_HMAC_SHA256, integ: INTEG_HMAC_SHA256_128, dh: DH_MODP2048 }
    }
}

/// The ESP (CHILD SA) transforms we propose.
#[derive(Debug, Clone, Copy)]
pub struct EspSuite {
    pub encr: u16,
    pub encr_key_bits: usize,
    pub integ: u16,
}

impl EspSuite {
    pub fn default_fgt() -> Self {
        EspSuite { encr: ENCR_AES_CBC, encr_key_bits: 256, integ: INTEG_HMAC_SHA256_128 }
    }
    /// ESP key material per direction = enc_key || integ_key.
    pub fn key_bytes(&self) -> usize {
        self.encr_key_bits / 8 + esp_integ_key_len(self.integ)
    }
}

fn esp_integ_key_len(integ: u16) -> usize {
    match integ {
        INTEG_HMAC_SHA1_96 => 20,
        INTEG_HMAC_SHA256_128 => 32,
        INTEG_HMAC_SHA384_192 => 48,
        INTEG_HMAC_SHA512_256 => 64,
        _ => 20,
    }
}

pub struct Ikev2Session {
    pub spi_i: [u8; 8],
    pub spi_r: [u8; 8],
    dh: IkeCrypto,
    suite: IkeSuite,
    pub crypto: Option<Ikev2Crypto>,
    pub keys: Option<SaKeys>,
    pub ni: Vec<u8>,
    pub nr: Vec<u8>,
    /// The IKE_SA_INIT request exactly as sent (RealMessage1 for AUTH).
    pub real_msg1: Vec<u8>,
    /// Message id for the next initiator exchange (IKE_AUTH starts at 1).
    pub next_msg_id: u32,
    /// ESP SPI we propose (gateway's SPI learned from its SA response).
    pub esp_spi_i: u32,
    pub esp_spi_r: u32,
    pub esp: EspSuite,
    pub nat_detected: bool,
}

impl Ikev2Session {
    pub fn new(suite: IkeSuite, esp: EspSuite) -> Result<Self, String> {
        let mut spi_i = [0u8; 8];
        spi_i.copy_from_slice(&random(8));
        if spi_i.iter().all(|&b| b == 0) {
            spi_i[7] = 1;
        }
        let dh = crypto::dh_new(suite.dh)?;
        let esp_spi = u32::from_be_bytes(random(4).try_into().unwrap()).max(0x1000);
        Ok(Ikev2Session {
            spi_i,
            spi_r: [0u8; 8],
            dh,
            suite,
            crypto: None,
            keys: None,
            ni: random(32),
            nr: Vec::new(),
            real_msg1: Vec::new(),
            next_msg_id: 1,
            esp_spi_i: esp_spi,
            esp_spi_r: 0,
            esp: esp,
            nat_detected: false,
        })
    }

    fn ike_proposal(&self) -> Proposal {
        let mut transforms = vec![Transform::with_key_len(TransformType::Encryption, self.suite.encr, self.suite.encr_key_bits as u16)];
        transforms.push(Transform::new(TransformType::Prf, self.suite.prf));
        transforms.push(Transform::new(TransformType::Integrity, self.suite.integ));
        transforms.push(Transform::new(TransformType::DiffieHellman, self.suite.dh));
        Proposal { num: 1, protocol: PROTO_IKE, spi: vec![], transforms }
    }

    /// The ESP proposal carried in IKE_AUTH's SA payload (CHILD SA).
    pub fn esp_proposal(&self) -> Proposal {
        let transforms = vec![
            Transform::with_key_len(TransformType::Encryption, self.esp.encr, self.esp.encr_key_bits as u16),
            Transform::new(TransformType::Integrity, self.esp.integ),
            Transform::new(TransformType::Esn, ESN_NONE),
        ];
        Proposal { num: 1, protocol: PROTO_ESP, spi: self.esp_spi_i.to_be_bytes().to_vec(), transforms }
    }

    /// Build the IKE_SA_INIT request (SA, KEi, Ni, NAT-D), storing it as RealMessage1.
    pub fn build_sa_init(&mut self, local: Ipv4Addr, local_port: u16, gw: Ipv4Addr, gw_port: u16, cookie: Option<Vec<u8>>) -> Vec<u8> {
        let mut payloads: Vec<Payload> = Vec::new();
        if let Some(c) = cookie {
            payloads.push(Payload::Notify(Notify { protocol: 0, spi: vec![], ntype: NotifyType::Cookie.into(), data: c }));
        }
        payloads.push(Payload::Sa(vec![self.ike_proposal()]));
        payloads.push(Payload::Ke { group: self.suite.dh, data: self.dh.public_key() });
        payloads.push(Payload::Nonce(self.ni.clone()));
        // NAT detection: hashes of our and the gateway's address/port.
        let src = nat_hash(&self.spi_i, &self.spi_r, local, local_port);
        let dst = nat_hash(&self.spi_i, &self.spi_r, gw, gw_port);
        payloads.push(Payload::Notify(Notify { protocol: 0, spi: vec![], ntype: NotifyType::NatDetectionSourceIp.into(), data: src }));
        payloads.push(Payload::Notify(Notify { protocol: 0, spi: vec![], ntype: NotifyType::NatDetectionDestinationIp.into(), data: dst }));

        let msg = Message {
            init_spi: self.spi_i,
            resp_spi: self.spi_r,
            exchange: ExchangeType::IkeSaInit.into(),
            flags: FLAG_INITIATOR,
            message_id: 0,
            payloads,
        };
        let bytes = msg.encode(None);
        self.real_msg1 = bytes.clone();
        bytes
    }

    /// Process the IKE_SA_INIT response: learn the responder SPI, DH, nonce, chosen
    /// transforms, NAT state; derive the SA keys. Returns `Retry` signals for COOKIE
    /// and INVALID_KE, else `Ok`.
    pub fn process_sa_init(&mut self, raw: &[u8], local: Ipv4Addr, local_port: u16, gw: Ipv4Addr, gw_port: u16) -> Result<SaInitOutcome, String> {
        let (hdr, rest) = wire::parse_header(raw)?;
        let payloads = wire::parse_payloads(hdr.first_payload, rest)?;

        // COOKIE request → caller resends IKE_SA_INIT with the cookie.
        if let Some(c) = find_notify(&payloads, NotifyType::Cookie.into()) {
            return Ok(SaInitOutcome::Cookie(c.to_vec()));
        }
        if let Some(d) = find_notify(&payloads, NotifyType::InvalidKePayload.into()) {
            let group = if d.len() >= 2 { u16::from_be_bytes([d[0], d[1]]) } else { 0 };
            return Ok(SaInitOutcome::InvalidKe(group));
        }
        if find_notify(&payloads, NotifyType::NoProposalChosen.into()).is_some() {
            return Err("gateway rejected the IKE proposal (NO_PROPOSAL_CHOSEN)".into());
        }

        self.spi_r = hdr.resp_spi;
        let ker = payloads.iter().find_map(|p| match p {
            Payload::Ke { data, .. } => Some(data.clone()),
            _ => None,
        }).ok_or("IKE_SA_INIT response without KE")?;
        self.nr = payloads.iter().find_map(|p| match p {
            Payload::Nonce(n) => Some(n.clone()),
            _ => None,
        }).ok_or("IKE_SA_INIT response without Nonce")?;

        // Confirm the responder echoed a usable suite (we offered exactly one).
        verify_chosen_suite(&payloads, &self.suite)?;

        let shared = self.dh.shared_secret(&ker)?;
        let c = Ikev2Crypto::new(self.suite.prf, self.suite.integ, self.suite.encr, self.suite.encr_key_bits)?;
        let keys = c.derive_sa_keys(&shared, &self.ni, &self.nr, self.spi_i, self.spi_r);
        self.keys = Some(keys);
        self.crypto = Some(c);

        // NAT detection: if either of the responder's NAT-D hashes differs from what
        // we compute, there is NAT on that side → float ESP/IKE to UDP-encap (4500).
        let our_src = nat_hash(&self.spi_i, &self.spi_r, local, local_port);
        let our_dst = nat_hash(&self.spi_i, &self.spi_r, gw, gw_port);
        let r_src = find_notify(&payloads, NotifyType::NatDetectionSourceIp.into());
        let r_dst = find_notify(&payloads, NotifyType::NatDetectionDestinationIp.into());
        // Responder's SOURCE hash is of the gateway; its DESTINATION hash is of us.
        let nat_there = r_src.map(|h| h != our_dst.as_slice()).unwrap_or(false);
        let nat_here = r_dst.map(|h| h != our_src.as_slice()).unwrap_or(false);
        self.nat_detected = nat_there || nat_here;

        Ok(SaInitOutcome::Ok)
    }

    fn crypto(&self) -> &Ikev2Crypto {
        self.crypto.as_ref().expect("crypto set after SA_INIT")
    }
    fn keys(&self) -> &SaKeys {
        self.keys.as_ref().expect("keys set after SA_INIT")
    }

    /// Wrap `inner` payloads into an SK-protected message for the given exchange and
    /// message id, as the initiator.
    pub fn encrypt(&self, exchange: u8, message_id: u32, inner: &[Payload]) -> Vec<u8> {
        encrypt_message(
            self.crypto(),
            &self.keys().sk_ei,
            &self.keys().sk_ai,
            self.spi_i,
            self.spi_r,
            exchange,
            FLAG_INITIATOR,
            message_id,
            inner,
        )
    }

    /// Verify + decrypt an SK-protected response from the responder.
    pub fn decrypt(&self, raw: &[u8]) -> Result<(wire::Header, Vec<Payload>), String> {
        decrypt_message(self.crypto(), &self.keys().sk_er, &self.keys().sk_ar, raw)
    }

    /// Initiator's signed octets for the AUTH payload.
    pub fn initiator_signed_octets(&self, idi_body: &[u8]) -> Vec<u8> {
        self.crypto().initiator_signed_octets(&self.real_msg1, &self.nr, &self.keys().sk_pi, idi_body)
    }

    /// Learn the gateway's ESP SPI from its CHILD SA proposal in the IKE_AUTH reply.
    pub fn learn_esp_spi(&mut self, payloads: &[Payload]) -> Result<(), String> {
        for p in payloads {
            if let Payload::Sa(props) = p {
                if let Some(prop) = props.iter().find(|p| p.protocol == PROTO_ESP) {
                    if prop.spi.len() == 4 {
                        self.esp_spi_r = u32::from_be_bytes(prop.spi[..4].try_into().unwrap());
                        return Ok(());
                    }
                }
            }
        }
        Err("IKE_AUTH reply without an ESP SPI".into())
    }

    /// Build the ESP SA from the CHILD SA key material (RFC 7296 §2.17).
    pub fn make_esp_sa(&self) -> Result<crate::ike::esp::EspSa, String> {
        let per_dir = self.esp.key_bytes();
        let (i2r, r2i) = self.crypto().child_keymat(&self.keys().sk_d, &self.ni, &self.nr, per_dir);
        // EspSa::new wants (transform_id, auth_alg, key_bits, spi_in, km_in, spi_out, km_out).
        let transform_id = u8::from(crate::ike::model::TransformId::EspAesCbc);
        let esp_auth = esp_auth_alg(self.esp.integ);
        crate::ike::esp::EspSa::new(
            transform_id,
            esp_auth,
            self.esp.encr_key_bits,
            self.esp_spi_r, // inbound packets carry the gateway's SPI? No: inbound SPI is OURS.
            &r2i,
            self.esp_spi_i,
            &i2r,
        )

    }
}

/// Map an IKEv2 INTEG id to the ike::esp auth-alg constant.
fn esp_auth_alg(integ: u16) -> u16 {
    use crate::ike::model::{ESP_AUTH_HMAC_SHA256, ESP_AUTH_HMAC_SHA96};
    match integ {
        INTEG_HMAC_SHA1_96 => ESP_AUTH_HMAC_SHA96,
        INTEG_HMAC_SHA256_128 => ESP_AUTH_HMAC_SHA256,
        _ => ESP_AUTH_HMAC_SHA256,
    }
}

pub enum SaInitOutcome {
    Ok,
    Cookie(Vec<u8>),
    InvalidKe(u16),
}

fn find_notify<'a>(payloads: &'a [Payload], ntype: u16) -> Option<&'a [u8]> {
    payloads.iter().find_map(|p| match p {
        Payload::Notify(n) if n.ntype == ntype => Some(n.data.as_slice()),
        _ => None,
    })
}

/// Confirm the responder's SA payload names the suite we offered.
fn verify_chosen_suite(payloads: &[Payload], suite: &IkeSuite) -> Result<(), String> {
    let sa = payloads.iter().find_map(|p| match p {
        Payload::Sa(props) => Some(props),
        _ => None,
    }).ok_or("IKE_SA_INIT response without SA")?;
    let prop = sa.first().ok_or("empty SA proposal")?;
    let has = |tt: TransformType, id: u16| prop.transforms.iter().any(|t| t.ttype == u8::from(tt) && t.id == id);
    if has(TransformType::Encryption, suite.encr)
        && has(TransformType::Prf, suite.prf)
        && has(TransformType::Integrity, suite.integ)
        && has(TransformType::DiffieHellman, suite.dh)
    {
        Ok(())
    } else {
        Err("gateway chose transforms we did not offer".into())
    }
}

/// NAT-D hash: SHA1(SPIi | SPIr | ip | port) (RFC 7296 §2.23).
fn nat_hash(spi_i: &[u8; 8], spi_r: &[u8; 8], ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut h = Hasher::new(MessageDigest::sha1()).expect("sha1");
    h.update(spi_i).unwrap();
    h.update(spi_r).unwrap();
    h.update(&ip.octets()).unwrap();
    h.update(&port.to_be_bytes()).unwrap();
    h.finish().unwrap().to_vec()
}

/// Encode header + SK payload (IV | ciphertext | ICV) for `inner` payloads.
pub fn encrypt_message(
    crypto: &Ikev2Crypto,
    sk_e: &[u8],
    sk_a: &[u8],
    spi_i: [u8; 8],
    spi_r: [u8; 8],
    exchange: u8,
    flags: u8,
    message_id: u32,
    inner: &[Payload],
) -> Vec<u8> {
    let (first_inner, plain) = wire::encode_payloads(inner);
    let iv_ct = crypto.sk_encrypt(sk_e, &plain).expect("sk encrypt");
    let sk_body_len = iv_ct.len() + crypto.integ_icv_len();
    let total_len = IKE_HEADER_LEN + 4 + sk_body_len;

    let mut msg = Vec::with_capacity(total_len);
    msg.extend_from_slice(&spi_i);
    msg.extend_from_slice(&spi_r);
    msg.push(PayloadType::Encrypted.into()); // next payload = SK
    msg.push(IKEV2_VERSION);
    msg.push(exchange);
    msg.push(flags);
    msg.extend_from_slice(&message_id.to_be_bytes());
    msg.extend_from_slice(&(total_len as u32).to_be_bytes());
    // SK generic payload header: next = first inner payload type.
    msg.push(first_inner);
    msg.push(0);
    msg.extend_from_slice(&((4 + sk_body_len) as u16).to_be_bytes());
    msg.extend_from_slice(&iv_ct);
    let icv = crypto.integ_icv(sk_a, &msg);
    msg.extend_from_slice(&icv);
    msg
}

/// Verify + decrypt an SK-protected message, returning the header and inner payloads.
pub fn decrypt_message(crypto: &Ikev2Crypto, sk_e: &[u8], sk_a: &[u8], raw: &[u8]) -> Result<(wire::Header, Vec<Payload>), String> {
    let (hdr, rest) = wire::parse_header(raw)?;
    if PayloadType::from(hdr.first_payload) != PayloadType::Encrypted {
        return Err(format!("expected SK payload, got type {}", hdr.first_payload));
    }
    if rest.len() < 4 {
        return Err("truncated SK payload".into());
    }
    let sk_first_inner = rest[0];
    let sk_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
    if sk_len < 4 || sk_len > rest.len() {
        return Err("bad SK payload length".into());
    }
    let icv_len = crypto.integ_icv_len();
    let body = &rest[4..sk_len];
    if body.len() < icv_len {
        return Err("SK body shorter than ICV".into());
    }
    let (iv_ct, icv) = body.split_at(body.len() - icv_len);

    // ICV covers the whole message from the IKE header through the ciphertext.
    let associated = &raw[..raw.len() - icv_len];
    // (associated spans header + SK header + iv_ct; equals raw minus the trailing ICV
    // only when the SK payload is the last thing in the message, which it always is.)
    let expect = crypto.integ_icv(sk_a, associated);
    if expect != icv {
        return Err("SK ICV mismatch (bad integrity key or tampered message)".into());
    }
    let plain = crypto.sk_decrypt(sk_e, iv_ct)?;
    let payloads = wire::parse_payloads(sk_first_inner, &plain)?;
    Ok((hdr, payloads))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ike_proposal_has_all_four_transform_types() {
        let s = Ikev2Session::new(IkeSuite::default_fgt(), EspSuite::default_fgt()).unwrap();
        let p = s.ike_proposal();
        assert_eq!(p.protocol, PROTO_IKE);
        assert_eq!(p.transforms.len(), 4);
        assert_eq!(p.transforms[0].key_len, Some(256));
    }

    #[test]
    fn sa_init_request_parses_back() {
        let mut s = Ikev2Session::new(IkeSuite::default_fgt(), EspSuite::default_fgt()).unwrap();
        let b = s.build_sa_init(Ipv4Addr::new(192, 168, 1, 10), 500, Ipv4Addr::new(187, 214, 28, 2), 500, None);
        let (hdr, rest) = wire::parse_header(&b).unwrap();
        assert_eq!(hdr.exchange, u8::from(ExchangeType::IkeSaInit));
        assert_eq!(hdr.flags, FLAG_INITIATOR);
        let ps = wire::parse_payloads(hdr.first_payload, rest).unwrap();
        // SA, KE, Nonce, NAT-D source, NAT-D destination.
        assert!(matches!(ps[0], Payload::Sa(_)));
        assert!(ps.iter().any(|p| matches!(p, Payload::Ke { .. })));
        assert_eq!(ps.iter().filter(|p| matches!(p, Payload::Notify(_))).count(), 2);
    }

    #[test]
    fn sk_message_roundtrips_with_matching_keys() {
        // Framing self-check: encrypt as initiator, decrypt with the same keys read
        // as the initiator direction (sk_ei/sk_ai), proving header+SK+IV+ICV layout.
        let crypto = Ikev2Crypto::new(PRF_HMAC_SHA256, INTEG_HMAC_SHA256_128, ENCR_AES_CBC, 256).unwrap();
        let sk_e = [0x11u8; 32];
        let sk_a = [0x22u8; 32];
        let inner = vec![
            Payload::IdI { kind: IdType::Rfc822Addr.into(), data: b"user@example.com".to_vec() },
            Payload::Nonce(vec![0x33; 24]),
            Payload::Notify(Notify { protocol: 0, spi: vec![], ntype: NotifyType::InitialContact.into(), data: vec![] }),
        ];
        let msg = encrypt_message(&crypto, &sk_e, &sk_a, [1; 8], [2; 8], ExchangeType::IkeAuth.into(), FLAG_INITIATOR, 1, &inner);
        let (hdr, out) = decrypt_message(&crypto, &sk_e, &sk_a, &msg).unwrap();
        assert_eq!(hdr.exchange, u8::from(ExchangeType::IkeAuth));
        assert_eq!(out, inner);
    }

    #[test]
    fn sk_message_rejects_tampered_icv() {
        let crypto = Ikev2Crypto::new(PRF_HMAC_SHA256, INTEG_HMAC_SHA256_128, ENCR_AES_CBC, 256).unwrap();
        let (sk_e, sk_a) = ([0x11u8; 32], [0x22u8; 32]);
        let inner = vec![Payload::Nonce(vec![0x33; 24])];
        let mut msg = encrypt_message(&crypto, &sk_e, &sk_a, [1; 8], [2; 8], ExchangeType::IkeAuth.into(), FLAG_INITIATOR, 1, &inner);
        let n = msg.len();
        msg[n - 1] ^= 0xff;
        assert!(decrypt_message(&crypto, &sk_e, &sk_a, &msg).is_err());
    }
}
