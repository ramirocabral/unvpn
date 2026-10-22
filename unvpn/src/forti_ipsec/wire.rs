//! IKEv2 message wire format (RFC 7296 §3): the fixed header and the generic
//! payload chain, where each payload names the type of the next. Encryption of
//! the `SK` (Encrypted) payload is done one layer up in `crypto`/`session`; this
//! module serialises and parses the *plaintext* payload list so both the cleartext
//! IKE_SA_INIT and the inner payloads of an SK payload share one codec.

#![allow(dead_code)]

use super::model::*;

fn err<T>(msg: impl Into<String>) -> Result<T, String> {
    Err(msg.into())
}

/// One transform inside a proposal (RFC 7296 §3.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub ttype: u8,
    pub id: u16,
    /// Key-length attribute in bits (AES), when present.
    pub key_len: Option<u16>,
}

impl Transform {
    pub fn new(ttype: TransformType, id: u16) -> Self {
        Transform { ttype: ttype.into(), id, key_len: None }
    }
    pub fn with_key_len(ttype: TransformType, id: u16, bits: u16) -> Self {
        Transform { ttype: ttype.into(), id, key_len: Some(bits) }
    }
}

/// One proposal (RFC 7296 §3.3.1): a protocol plus its transform set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub num: u8,
    pub protocol: u8,
    /// Empty for the IKE SA; a 4-byte ESP SPI for a CHILD SA.
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

/// One traffic selector (RFC 7296 §3.13.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSelector {
    pub ts_type: u8,
    pub ip_protocol: u8,
    pub start_port: u16,
    pub end_port: u16,
    pub start_addr: Vec<u8>,
    pub end_addr: Vec<u8>,
}

impl TrafficSelector {
    /// The "everything" IPv4 selector (0.0.0.0-255.255.255.255, all ports/protos),
    /// which FortiGate narrows in its response to the pushed subnets.
    pub fn ipv4_any() -> Self {
        TrafficSelector {
            ts_type: TS_IPV4_ADDR_RANGE,
            ip_protocol: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: vec![0, 0, 0, 0],
            end_addr: vec![255, 255, 255, 255],
        }
    }
}

/// A Notify payload (RFC 7296 §3.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notify {
    pub protocol: u8,
    pub spi: Vec<u8>,
    pub ntype: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Sa(Vec<Proposal>),
    Ke { group: u16, data: Vec<u8> },
    Nonce(Vec<u8>),
    IdI { kind: u8, data: Vec<u8> },
    IdR { kind: u8, data: Vec<u8> },
    Cert { encoding: u8, data: Vec<u8> },
    CertReq { encoding: u8, data: Vec<u8> },
    Auth { method: u8, data: Vec<u8> },
    Notify(Notify),
    Delete { protocol: u8, spi_size: u8, spis: Vec<Vec<u8>> },
    VendorId(Vec<u8>),
    Tsi(Vec<TrafficSelector>),
    Tsr(Vec<TrafficSelector>),
    Cp { cfg_type: u8, attrs: Vec<(u16, Vec<u8>)> },
    Eap(Vec<u8>),
    /// Any payload we don't model structurally; preserved verbatim.
    Raw(u8, Vec<u8>),
}

impl Payload {
    fn payload_type(&self) -> u8 {
        match self {
            Payload::Sa(_) => PayloadType::SecurityAssociation.into(),
            Payload::Ke { .. } => PayloadType::KeyExchange.into(),
            Payload::Nonce(_) => PayloadType::Nonce.into(),
            Payload::IdI { .. } => PayloadType::IdInitiator.into(),
            Payload::IdR { .. } => PayloadType::IdResponder.into(),
            Payload::Cert { .. } => PayloadType::Certificate.into(),
            Payload::CertReq { .. } => PayloadType::CertRequest.into(),
            Payload::Auth { .. } => PayloadType::Authentication.into(),
            Payload::Notify(_) => PayloadType::Notify.into(),
            Payload::Delete { .. } => PayloadType::Delete.into(),
            Payload::VendorId(_) => PayloadType::VendorId.into(),
            Payload::Tsi(_) => PayloadType::TrafficSelectorI.into(),
            Payload::Tsr(_) => PayloadType::TrafficSelectorR.into(),
            Payload::Cp { .. } => PayloadType::Configuration.into(),
            Payload::Eap(_) => PayloadType::Eap.into(),
            Payload::Raw(t, _) => *t,
        }
    }

    /// Serialise just this payload's body (without the 4-byte generic header).
    fn encode_body(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Payload::Sa(props) => encode_proposals(props, &mut b),
            Payload::Ke { group, data } => {
                b.extend_from_slice(&group.to_be_bytes());
                b.extend_from_slice(&[0, 0]); // reserved
                b.extend_from_slice(data);
            }
            Payload::Nonce(n) => b.extend_from_slice(n),
            Payload::IdI { kind, data } | Payload::IdR { kind, data } => {
                b.push(*kind);
                b.extend_from_slice(&[0, 0, 0]); // reserved
                b.extend_from_slice(data);
            }
            Payload::Cert { encoding, data } | Payload::CertReq { encoding, data } => {
                b.push(*encoding);
                b.extend_from_slice(data);
            }
            Payload::Auth { method, data } => {
                b.push(*method);
                b.extend_from_slice(&[0, 0, 0]); // reserved
                b.extend_from_slice(data);
            }
            Payload::Notify(n) => {
                b.push(n.protocol);
                b.push(n.spi.len() as u8);
                b.extend_from_slice(&n.ntype.to_be_bytes());
                b.extend_from_slice(&n.spi);
                b.extend_from_slice(&n.data);
            }
            Payload::Delete { protocol, spi_size, spis } => {
                b.push(*protocol);
                b.push(*spi_size);
                b.extend_from_slice(&(spis.len() as u16).to_be_bytes());
                for s in spis {
                    b.extend_from_slice(s);
                }
            }
            Payload::VendorId(v) => b.extend_from_slice(v),
            Payload::Tsi(ts) | Payload::Tsr(ts) => encode_traffic_selectors(ts, &mut b),
            Payload::Cp { cfg_type, attrs } => {
                b.push(*cfg_type);
                b.extend_from_slice(&[0, 0, 0]); // reserved
                for (t, v) in attrs {
                    // Top bit (AF) reserved/0 for CP attributes; type in low 15 bits.
                    b.extend_from_slice(&(t & 0x7fff).to_be_bytes());
                    b.extend_from_slice(&(v.len() as u16).to_be_bytes());
                    b.extend_from_slice(v);
                }
            }
            Payload::Eap(e) => b.extend_from_slice(e),
            Payload::Raw(_, d) => b.extend_from_slice(d),
        }
        b
    }
}

fn encode_proposals(props: &[Proposal], out: &mut Vec<u8>) {
    for (i, p) in props.iter().enumerate() {
        let last = i + 1 == props.len();
        let mut body = Vec::new();
        body.push(p.num);
        body.push(p.protocol);
        body.push(p.spi.len() as u8);
        body.push(p.transforms.len() as u8);
        body.extend_from_slice(&p.spi);
        for (j, t) in p.transforms.iter().enumerate() {
            let t_last = j + 1 == p.transforms.len();
            let mut tb = Vec::new();
            tb.push(t.ttype);
            tb.push(0); // reserved
            tb.extend_from_slice(&t.id.to_be_bytes());
            if let Some(bits) = t.key_len {
                // TV attribute: AF=1 | type=14 → 0x800e, then the 2-byte value.
                tb.extend_from_slice(&(0x8000u16 | ATTR_KEY_LENGTH).to_be_bytes());
                tb.extend_from_slice(&bits.to_be_bytes());
            }
            let tlen = (tb.len() + 4) as u16;
            body.push(if t_last { 0 } else { 3 });
            body.push(0); // reserved
            body.extend_from_slice(&tlen.to_be_bytes());
            body.extend_from_slice(&tb);
        }
        let plen = (body.len() + 4) as u16;
        out.push(if last { 0 } else { 2 });
        out.push(0); // reserved
        out.extend_from_slice(&plen.to_be_bytes());
        out.extend_from_slice(&body);
    }
}

fn encode_traffic_selectors(ts: &[TrafficSelector], out: &mut Vec<u8>) {
    out.push(ts.len() as u8);
    out.extend_from_slice(&[0, 0, 0]); // reserved
    for t in ts {
        let sel_len = (8 + t.start_addr.len() + t.end_addr.len()) as u16;
        out.push(t.ts_type);
        out.push(t.ip_protocol);
        out.extend_from_slice(&sel_len.to_be_bytes());
        out.extend_from_slice(&t.start_port.to_be_bytes());
        out.extend_from_slice(&t.end_port.to_be_bytes());
        out.extend_from_slice(&t.start_addr);
        out.extend_from_slice(&t.end_addr);
    }
}

/// Serialise a payload chain, returning `(first_payload_type, bytes)`. The caller
/// (header builder or SK wrapper) stores `first_payload_type` as its own
/// next-payload field. An empty list yields `(None=0, [])`.
pub fn encode_payloads(payloads: &[Payload]) -> (u8, Vec<u8>) {
    if payloads.is_empty() {
        return (0, Vec::new());
    }
    let first = payloads[0].payload_type();
    let mut out = Vec::new();
    for (i, p) in payloads.iter().enumerate() {
        let next = payloads.get(i + 1).map(|n| n.payload_type()).unwrap_or(0);
        let body = p.encode_body();
        out.push(next);
        out.push(0); // critical bit clear + reserved
        out.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        out.extend_from_slice(&body);
    }
    (first, out)
}

/// A whole IKEv2 message (header + cleartext payload list). When the message is
/// protected, `payloads` holds the SK's *inner* payloads and the codec at the
/// session layer handles the SK wrap/unwrap; here `payloads` is what goes on the
/// wire directly (IKE_SA_INIT) or inside SK.
#[derive(Debug, Clone)]
pub struct Message {
    pub init_spi: [u8; 8],
    pub resp_spi: [u8; 8],
    pub exchange: u8,
    pub flags: u8,
    pub message_id: u32,
    pub payloads: Vec<Payload>,
}

impl Message {
    /// Encode header + the given cleartext payload chain. `first_payload` overrides
    /// the header's next-payload field (used when the chain starts with an SK
    /// payload whose type the caller sets); pass `None` to derive it from
    /// `self.payloads`.
    pub fn encode(&self, first_payload_override: Option<u8>) -> Vec<u8> {
        let (first, body) = encode_payloads(&self.payloads);
        let first = first_payload_override.unwrap_or(first);
        let mut out = Vec::with_capacity(IKE_HEADER_LEN + body.len());
        out.extend_from_slice(&self.init_spi);
        out.extend_from_slice(&self.resp_spi);
        out.push(first);
        out.push(IKEV2_VERSION);
        out.push(self.exchange);
        out.push(self.flags);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&((IKE_HEADER_LEN + body.len()) as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }
}

/// Parse an IKEv2 header, returning the fields and the first-payload type plus the
/// remaining bytes (the payload chain, possibly a single SK payload).
pub struct Header {
    pub init_spi: [u8; 8],
    pub resp_spi: [u8; 8],
    pub first_payload: u8,
    pub exchange: u8,
    pub flags: u8,
    pub message_id: u32,
    pub length: u32,
}

pub fn parse_header(msg: &[u8]) -> Result<(Header, &[u8]), String> {
    if msg.len() < IKE_HEADER_LEN {
        return err("IKE message shorter than header");
    }
    let mut init_spi = [0u8; 8];
    let mut resp_spi = [0u8; 8];
    init_spi.copy_from_slice(&msg[0..8]);
    resp_spi.copy_from_slice(&msg[8..16]);
    let h = Header {
        init_spi,
        resp_spi,
        first_payload: msg[16],
        exchange: msg[18],
        flags: msg[19],
        message_id: u32::from_be_bytes(msg[20..24].try_into().unwrap()),
        length: u32::from_be_bytes(msg[24..28].try_into().unwrap()),
    };
    if msg[17] >> 4 != 2 {
        return err(format!("not IKEv2 (version byte {:#x})", msg[17]));
    }
    Ok((h, &msg[IKE_HEADER_LEN..]))
}

/// Walk a cleartext payload chain starting with type `first`, returning the parsed
/// payloads. Unknown types are kept as `Raw`. Stops at `None`(0) or end of input.
pub fn parse_payloads(first: u8, mut data: &[u8]) -> Result<Vec<Payload>, String> {
    let mut out = Vec::new();
    let mut next = first;
    while next != 0 {
        if data.len() < 4 {
            return err("truncated payload header");
        }
        let this_next = data[0];
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if len < 4 || len > data.len() {
            return err(format!("bad payload length {len} (have {})", data.len()));
        }
        let body = &data[4..len];
        out.push(parse_body(next, body)?);
        data = &data[len..];
        next = this_next;
    }
    Ok(out)
}

fn parse_body(ptype: u8, body: &[u8]) -> Result<Payload, String> {
    Ok(match PayloadType::from(ptype) {
        PayloadType::SecurityAssociation => Payload::Sa(parse_proposals(body)?),
        PayloadType::KeyExchange => {
            if body.len() < 4 {
                return err("short KE payload");
            }
            Payload::Ke { group: u16::from_be_bytes([body[0], body[1]]), data: body[4..].to_vec() }
        }
        PayloadType::Nonce => Payload::Nonce(body.to_vec()),
        PayloadType::IdInitiator => {
            if body.is_empty() {
                return err("short IDi");
            }
            Payload::IdI { kind: body[0], data: body[4.min(body.len())..].to_vec() }
        }
        PayloadType::IdResponder => {
            if body.is_empty() {
                return err("short IDr");
            }
            Payload::IdR { kind: body[0], data: body[4.min(body.len())..].to_vec() }
        }
        PayloadType::Certificate => {
            if body.is_empty() {
                return err("short CERT");
            }
            Payload::Cert { encoding: body[0], data: body[1..].to_vec() }
        }
        PayloadType::CertRequest => {
            if body.is_empty() {
                return err("short CERTREQ");
            }
            Payload::CertReq { encoding: body[0], data: body[1..].to_vec() }
        }
        PayloadType::Authentication => {
            if body.len() < 4 {
                return err("short AUTH");
            }
            Payload::Auth { method: body[0], data: body[4..].to_vec() }
        }
        PayloadType::Notify => {
            if body.len() < 4 {
                return err("short Notify");
            }
            let spi_size = body[1] as usize;
            if body.len() < 4 + spi_size {
                return err("Notify SPI overruns payload");
            }
            Payload::Notify(Notify {
                protocol: body[0],
                spi: body[4..4 + spi_size].to_vec(),
                ntype: u16::from_be_bytes([body[2], body[3]]),
                data: body[4 + spi_size..].to_vec(),
            })
        }
        PayloadType::Delete => {
            if body.len() < 4 {
                return err("short Delete");
            }
            let spi_size = body[1] as usize;
            let count = u16::from_be_bytes([body[2], body[3]]) as usize;
            let mut spis = Vec::new();
            let mut off = 4;
            for _ in 0..count {
                if spi_size == 0 || off + spi_size > body.len() {
                    break;
                }
                spis.push(body[off..off + spi_size].to_vec());
                off += spi_size;
            }
            Payload::Delete { protocol: body[0], spi_size: body[1], spis }
        }
        PayloadType::VendorId => Payload::VendorId(body.to_vec()),
        PayloadType::TrafficSelectorI => Payload::Tsi(parse_traffic_selectors(body)?),
        PayloadType::TrafficSelectorR => Payload::Tsr(parse_traffic_selectors(body)?),
        PayloadType::Configuration => {
            if body.len() < 4 {
                return err("short CP");
            }
            Payload::Cp { cfg_type: body[0], attrs: parse_cfg_attrs(&body[4..])? }
        }
        PayloadType::Eap => Payload::Eap(body.to_vec()),
        _ => Payload::Raw(ptype, body.to_vec()),
    })
}

fn parse_proposals(mut data: &[u8]) -> Result<Vec<Proposal>, String> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data.len() < 4 {
            return err("short proposal header");
        }
        let plen = u16::from_be_bytes([data[2], data[3]]) as usize;
        if plen < 8 || plen > data.len() {
            return err(format!("bad proposal length {plen}"));
        }
        let num = data[4];
        let protocol = data[5];
        let spi_size = data[6] as usize;
        let ntrans = data[7] as usize;
        if 8 + spi_size > plen {
            return err("proposal SPI overruns");
        }
        let spi = data[8..8 + spi_size].to_vec();
        let mut toff = 8 + spi_size;
        let mut transforms = Vec::new();
        for _ in 0..ntrans {
            if toff + 8 > plen {
                return err("transform overruns proposal");
            }
            let tlen = u16::from_be_bytes([data[toff + 2], data[toff + 3]]) as usize;
            if tlen < 8 || toff + tlen > plen {
                return err(format!("bad transform length {tlen}"));
            }
            let ttype = data[toff + 4];
            let id = u16::from_be_bytes([data[toff + 6], data[toff + 7]]);
            // Parse a single Key-Length TV attribute if present.
            let mut key_len = None;
            let mut aoff = toff + 8;
            while aoff + 4 <= toff + tlen {
                let af_type = u16::from_be_bytes([data[aoff], data[aoff + 1]]);
                let val = u16::from_be_bytes([data[aoff + 2], data[aoff + 3]]);
                if af_type == (0x8000 | ATTR_KEY_LENGTH) {
                    key_len = Some(val);
                    aoff += 4;
                } else if af_type & 0x8000 != 0 {
                    aoff += 4; // other TV attribute
                } else {
                    // TLV attribute: length in `val`.
                    aoff += 4 + val as usize;
                }
            }
            transforms.push(Transform { ttype, id, key_len });
            toff += tlen;
        }
        out.push(Proposal { num, protocol, spi, transforms });
        data = &data[plen..];
    }
    Ok(out)
}

fn parse_traffic_selectors(body: &[u8]) -> Result<Vec<TrafficSelector>, String> {
    if body.len() < 4 {
        return err("short TS payload");
    }
    let count = body[0] as usize;
    let mut out = Vec::new();
    let mut off = 4;
    for _ in 0..count {
        if off + 8 > body.len() {
            return err("TS overruns payload");
        }
        let ts_type = body[off];
        let ip_protocol = body[off + 1];
        let sel_len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        if sel_len < 8 || off + sel_len > body.len() {
            return err(format!("bad TS selector length {sel_len}"));
        }
        let start_port = u16::from_be_bytes([body[off + 4], body[off + 5]]);
        let end_port = u16::from_be_bytes([body[off + 6], body[off + 7]]);
        let addr_len = (sel_len - 8) / 2;
        let a0 = off + 8;
        out.push(TrafficSelector {
            ts_type,
            ip_protocol,
            start_port,
            end_port,
            start_addr: body[a0..a0 + addr_len].to_vec(),
            end_addr: body[a0 + addr_len..a0 + 2 * addr_len].to_vec(),
        });
        off += sel_len;
    }
    Ok(out)
}

fn parse_cfg_attrs(mut data: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, String> {
    let mut out = Vec::new();
    while data.len() >= 4 {
        let t = u16::from_be_bytes([data[0], data[1]]) & 0x7fff;
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if 4 + len > data.len() {
            return err("CP attribute overruns payload");
        }
        out.push((t, data[4..4 + len].to_vec()));
        data = &data[4 + len..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let m = Message {
            init_spi: [1, 2, 3, 4, 5, 6, 7, 8],
            resp_spi: [0; 8],
            exchange: ExchangeType::IkeSaInit.into(),
            flags: FLAG_INITIATOR,
            message_id: 0,
            payloads: vec![Payload::Nonce(vec![0xaa; 32])],
        };
        let bytes = m.encode(None);
        let (h, rest) = parse_header(&bytes).unwrap();
        assert_eq!(h.init_spi, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(h.exchange, ExchangeType::IkeSaInit.into());
        assert_eq!(h.length as usize, bytes.len());
        assert_eq!(h.first_payload, u8::from(PayloadType::Nonce));
        let ps = parse_payloads(h.first_payload, rest).unwrap();
        assert_eq!(ps, vec![Payload::Nonce(vec![0xaa; 32])]);
    }

    #[test]
    fn sa_proposal_roundtrip() {
        let prop = Proposal {
            num: 1,
            protocol: PROTO_IKE,
            spi: vec![],
            transforms: vec![
                Transform::with_key_len(TransformType::Encryption, ENCR_AES_CBC, 256),
                Transform::new(TransformType::Prf, PRF_HMAC_SHA256),
                Transform::new(TransformType::Integrity, INTEG_HMAC_SHA256_128),
                Transform::new(TransformType::DiffieHellman, DH_MODP2048),
            ],
        };
        let (first, bytes) = encode_payloads(&[Payload::Sa(vec![prop.clone()])]);
        assert_eq!(first, u8::from(PayloadType::SecurityAssociation));
        let ps = parse_payloads(first, &bytes).unwrap();
        assert_eq!(ps, vec![Payload::Sa(vec![prop])]);
    }

    #[test]
    fn esp_proposal_with_spi_and_keylen() {
        let prop = Proposal {
            num: 1,
            protocol: PROTO_ESP,
            spi: vec![0xde, 0xad, 0xbe, 0xef],
            transforms: vec![
                Transform::with_key_len(TransformType::Encryption, ENCR_AES_CBC, 128),
                Transform::new(TransformType::Integrity, INTEG_HMAC_SHA1_96),
                Transform::new(TransformType::Esn, ESN_NONE),
            ],
        };
        let (first, bytes) = encode_payloads(&[Payload::Sa(vec![prop.clone()])]);
        let ps = parse_payloads(first, &bytes).unwrap();
        match &ps[0] {
            Payload::Sa(props) => {
                assert_eq!(props[0].spi, vec![0xde, 0xad, 0xbe, 0xef]);
                assert_eq!(props[0].transforms[0].key_len, Some(128));
            }
            _ => panic!("expected SA"),
        }
    }

    #[test]
    fn notify_and_nat_detection_roundtrip() {
        let n = Payload::Notify(Notify {
            protocol: 0,
            spi: vec![],
            ntype: NotifyType::NatDetectionSourceIp.into(),
            data: vec![0x11; 20],
        });
        let (first, bytes) = encode_payloads(&[n.clone()]);
        assert_eq!(parse_payloads(first, &bytes).unwrap(), vec![n]);
    }

    #[test]
    fn traffic_selector_roundtrip() {
        let tsi = Payload::Tsi(vec![TrafficSelector::ipv4_any()]);
        let (first, bytes) = encode_payloads(&[tsi.clone()]);
        assert_eq!(parse_payloads(first, &bytes).unwrap(), vec![tsi]);
    }

    #[test]
    fn cp_reply_attrs_roundtrip() {
        let cp = Payload::Cp {
            cfg_type: CfgType::Reply.into(),
            attrs: vec![
                (CfgAttr::InternalIp4Address.into(), vec![10, 1, 2, 3]),
                (CfgAttr::InternalIp4Dns.into(), vec![10, 0, 0, 53]),
                (CfgAttr::InternalIp4Subnet.into(), vec![10, 0, 0, 0, 255, 0, 0, 0]),
            ],
        };
        let (first, bytes) = encode_payloads(&[cp.clone()]);
        assert_eq!(parse_payloads(first, &bytes).unwrap(), vec![cp]);
    }

    #[test]
    fn multi_payload_chain_links_next() {
        let chain = vec![
            Payload::IdI { kind: IdType::Rfc822Addr.into(), data: b"user@example.com".to_vec() },
            Payload::Auth { method: AUTH_PSK, data: vec![0x22; 20] },
            Payload::Nonce(vec![0x33; 16]),
        ];
        let (first, bytes) = encode_payloads(&chain);
        assert_eq!(first, u8::from(PayloadType::IdInitiator));
        assert_eq!(parse_payloads(first, &bytes).unwrap(), chain);
    }
}
