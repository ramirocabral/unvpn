//! IKEv1 / ISAKMP wire codec (RFC 2408 §3). Encodes and decodes the ISAKMP
//! header and the payload chain. Encryption (Main Mode msgs 5-6, Quick Mode,
//! Transaction) is a crypto-layer concern: the service decrypts a message body
//! before `parse_payloads`, and encrypts after `encode_payloads`.

use super::model::*;

// ---------------------------------------------------------------------------
// Small big-endian reader over a byte slice (avoids a byteorder dependency).
// ---------------------------------------------------------------------------
struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, i: 0 }
    }
    fn rem(&self) -> usize {
        self.b.len() - self.i
    }
    fn u8(&mut self) -> Result<u8, String> {
        let v = *self.b.get(self.i).ok_or("eof(u8)")?;
        self.i += 1;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16, String> {
        if self.rem() < 2 {
            return Err("eof(u16)".into());
        }
        let v = u16::from_be_bytes([self.b[self.i], self.b[self.i + 1]]);
        self.i += 2;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32, String> {
        if self.rem() < 4 {
            return Err("eof(u32)".into());
        }
        let v = u32::from_be_bytes(self.b[self.i..self.i + 4].try_into().unwrap());
        self.i += 4;
        Ok(v)
    }
    fn u64(&mut self) -> Result<u64, String> {
        if self.rem() < 8 {
            return Err("eof(u64)".into());
        }
        let v = u64::from_be_bytes(self.b[self.i..self.i + 8].try_into().unwrap());
        self.i += 8;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.rem() < n {
            return Err(format!("eof(take {n}, have {})", self.rem()));
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
}

// ---------------------------------------------------------------------------
// Data attribute TLV (RFC 2408 §3.3): short (value in the length field) or long.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrValue {
    Short(u16),
    Long(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    pub attr_type: u16,
    pub value: AttrValue,
}

impl Attribute {
    pub fn short(attr_type: u16, value: u16) -> Self {
        Attribute {
            attr_type,
            value: AttrValue::Short(value),
        }
    }
    pub fn long(attr_type: u16, value: Vec<u8>) -> Self {
        Attribute {
            attr_type,
            value: AttrValue::Long(value),
        }
    }
    pub fn as_u16(&self) -> Option<u16> {
        match &self.value {
            AttrValue::Short(v) => Some(*v),
            AttrValue::Long(b) if b.len() == 2 => Some(u16::from_be_bytes([b[0], b[1]])),
            _ => None,
        }
    }

    /// Read the attribute value as a u32 (SA lifetimes can be 2 or 4 bytes).
    pub fn as_u32(&self) -> Option<u32> {
        match &self.value {
            AttrValue::Short(v) => Some(*v as u32),
            AttrValue::Long(b) => match b.len() {
                1 => Some(b[0] as u32),
                2 => Some(u16::from_be_bytes([b[0], b[1]]) as u32),
                3 => Some(u32::from_be_bytes([0, b[0], b[1], b[2]])),
                4 => Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
                _ => None,
            },
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match &self.value {
            AttrValue::Short(v) => {
                out.extend_from_slice(&(self.attr_type | 0x8000).to_be_bytes());
                out.extend_from_slice(&v.to_be_bytes());
            }
            AttrValue::Long(b) => {
                out.extend_from_slice(&self.attr_type.to_be_bytes());
                out.extend_from_slice(&(b.len() as u16).to_be_bytes());
                out.extend_from_slice(b);
            }
        }
    }

    fn parse(r: &mut Reader) -> Result<Attribute, String> {
        let t = r.u16()?;
        if t & 0x8000 != 0 {
            Ok(Attribute {
                attr_type: t & 0x7fff,
                value: AttrValue::Short(r.u16()?),
            })
        } else {
            let len = r.u16()? as usize;
            Ok(Attribute {
                attr_type: t,
                value: AttrValue::Long(r.take(len)?.to_vec()),
            })
        }
    }
}

fn parse_attributes(body: &[u8]) -> Result<Vec<Attribute>, String> {
    let mut r = Reader::new(body);
    let mut v = Vec::new();
    while r.rem() > 0 {
        v.push(Attribute::parse(&mut r)?);
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// SA payload nesting: SA -> Proposal(s) -> Transform(s) -> Attributes.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub number: u8,
    pub transform_id: u8,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub number: u8,
    pub protocol_id: u8,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaPayload {
    pub doi: u32,
    /// Present for the IPSEC DOI (1); absent for the DOI-0 SA used in Quick Mode.
    pub situation: Option<u32>,
    pub proposals: Vec<Proposal>,
}

impl Transform {
    fn body(&self) -> Vec<u8> {
        let mut out = vec![self.number, self.transform_id, 0, 0];
        for a in &self.attributes {
            a.encode(&mut out);
        }
        out
    }
    fn parse(body: &[u8]) -> Result<Transform, String> {
        let mut r = Reader::new(body);
        let number = r.u8()?;
        let transform_id = r.u8()?;
        r.u16()?; // reserved
        let attributes = parse_attributes(&body[4..])?;
        Ok(Transform {
            number,
            transform_id,
            attributes,
        })
    }
}

impl Proposal {
    fn body(&self) -> Vec<u8> {
        let mut out = vec![
            self.number,
            self.protocol_id,
            self.spi.len() as u8,
            self.transforms.len() as u8,
        ];
        out.extend_from_slice(&self.spi);
        for (i, t) in self.transforms.iter().enumerate() {
            let next = if i + 1 < self.transforms.len() {
                u8::from(PayloadType::Transform)
            } else {
                0
            };
            let b = t.body();
            out.push(next);
            out.push(0);
            out.extend_from_slice(&((PAYLOAD_HEADER_LEN + b.len()) as u16).to_be_bytes());
            out.extend_from_slice(&b);
        }
        out
    }
    fn parse(body: &[u8]) -> Result<Proposal, String> {
        let mut r = Reader::new(body);
        let number = r.u8()?;
        let protocol_id = r.u8()?;
        let spi_size = r.u8()? as usize;
        let num_transforms = r.u8()? as usize;
        let spi = r.take(spi_size)?.to_vec();
        let mut transforms = Vec::new();
        for _ in 0..num_transforms {
            let _next = r.u8()?;
            let _res = r.u8()?;
            let len = r.u16()? as usize;
            let tbody = r.take(len - PAYLOAD_HEADER_LEN)?;
            transforms.push(Transform::parse(tbody)?);
        }
        Ok(Proposal {
            number,
            protocol_id,
            spi,
            transforms,
        })
    }
}

impl SaPayload {
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.doi.to_be_bytes());
        if let Some(s) = self.situation {
            out.extend_from_slice(&s.to_be_bytes());
        }
        for (i, p) in self.proposals.iter().enumerate() {
            let next = if i + 1 < self.proposals.len() {
                u8::from(PayloadType::Proposal)
            } else {
                0
            };
            let b = p.body();
            out.push(next);
            out.push(0);
            out.extend_from_slice(&((PAYLOAD_HEADER_LEN + b.len()) as u16).to_be_bytes());
            out.extend_from_slice(&b);
        }
        out
    }
    fn parse(body: &[u8]) -> Result<SaPayload, String> {
        let mut r = Reader::new(body);
        let doi = r.u32()?;
        // Situation is a 4-octet field only for the IPSEC DOI (1).
        let situation = if doi == 1 { Some(r.u32()?) } else { None };
        let mut proposals = Vec::new();
        while r.rem() > 0 {
            let _next = r.u8()?;
            let _res = r.u8()?;
            let len = r.u16()? as usize;
            let pbody = r.take(len - PAYLOAD_HEADER_LEN)?;
            proposals.push(Proposal::parse(pbody)?);
        }
        Ok(SaPayload {
            doi,
            situation,
            proposals,
        })
    }
}

// ---------------------------------------------------------------------------
// Other payload bodies.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdPayload {
    pub id_type: u8,
    pub protocol_id: u8,
    pub port: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyPayload {
    pub doi: u32,
    pub protocol_id: u8,
    pub spi: Vec<u8>,
    pub message_type: u16,
    pub data: Vec<u8>,
}

/// ISAKMP-CFG (Transaction) attributes payload — Office Mode + hybrid-auth
/// SecurID exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributesPayload {
    pub kind: u8,
    pub identifier: u16,
    pub attributes: Vec<Attribute>,
}

// ---------------------------------------------------------------------------
// Payload enum.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Sa(SaPayload),
    KeyExchange(Vec<u8>),
    Nonce(Vec<u8>),
    Identification(IdPayload),
    Hash(Vec<u8>),
    Signature(Vec<u8>),
    Certificate(Vec<u8>),
    CertificateRequest(Vec<u8>),
    Notification(NotifyPayload),
    Delete(Vec<u8>),
    VendorId(Vec<u8>),
    Attributes(AttributesPayload),
    Natd(Vec<u8>),
    Other(u8, Vec<u8>),
}

impl Payload {
    pub fn payload_type(&self) -> u8 {
        let t = match self {
            Payload::Sa(_) => PayloadType::SecurityAssociation,
            Payload::KeyExchange(_) => PayloadType::KeyExchange,
            Payload::Nonce(_) => PayloadType::Nonce,
            Payload::Identification(_) => PayloadType::Identification,
            Payload::Hash(_) => PayloadType::Hash,
            Payload::Signature(_) => PayloadType::Signature,
            Payload::Certificate(_) => PayloadType::Certificate,
            Payload::CertificateRequest(_) => PayloadType::CertificateRequest,
            Payload::Notification(_) => PayloadType::Notification,
            Payload::Delete(_) => PayloadType::Delete,
            Payload::VendorId(_) => PayloadType::VendorId,
            Payload::Attributes(_) => PayloadType::Attributes,
            Payload::Natd(_) => PayloadType::Natd,
            Payload::Other(t, _) => return *t,
        };
        u8::from(t)
    }

    fn body(&self) -> Vec<u8> {
        match self {
            Payload::Sa(sa) => sa.body(),
            Payload::KeyExchange(d)
            | Payload::Nonce(d)
            | Payload::Hash(d)
            | Payload::Signature(d)
            | Payload::Certificate(d)
            | Payload::CertificateRequest(d)
            | Payload::Delete(d)
            | Payload::VendorId(d)
            | Payload::Natd(d)
            | Payload::Other(_, d) => d.clone(),
            Payload::Identification(id) => {
                let mut out = vec![id.id_type, id.protocol_id];
                out.extend_from_slice(&id.port.to_be_bytes());
                out.extend_from_slice(&id.data);
                out
            }
            Payload::Notification(n) => {
                let mut out = Vec::new();
                out.extend_from_slice(&n.doi.to_be_bytes());
                out.push(n.protocol_id);
                out.push(n.spi.len() as u8);
                out.extend_from_slice(&n.message_type.to_be_bytes());
                out.extend_from_slice(&n.spi);
                out.extend_from_slice(&n.data);
                out
            }
            Payload::Attributes(a) => {
                let mut out = vec![a.kind, 0];
                out.extend_from_slice(&a.identifier.to_be_bytes());
                for at in &a.attributes {
                    at.encode(&mut out);
                }
                out
            }
        }
    }

    fn parse(ptype: u8, body: &[u8]) -> Result<Payload, String> {
        Ok(match PayloadType::from(ptype) {
            PayloadType::SecurityAssociation => Payload::Sa(SaPayload::parse(body)?),
            PayloadType::KeyExchange => Payload::KeyExchange(body.to_vec()),
            PayloadType::Nonce => Payload::Nonce(body.to_vec()),
            PayloadType::Hash => Payload::Hash(body.to_vec()),
            PayloadType::Signature => Payload::Signature(body.to_vec()),
            PayloadType::Certificate => Payload::Certificate(body.to_vec()),
            PayloadType::CertificateRequest => Payload::CertificateRequest(body.to_vec()),
            PayloadType::Delete => Payload::Delete(body.to_vec()),
            PayloadType::VendorId => Payload::VendorId(body.to_vec()),
            PayloadType::Natd => Payload::Natd(body.to_vec()),
            PayloadType::Identification => {
                let mut r = Reader::new(body);
                let id_type = r.u8()?;
                let protocol_id = r.u8()?;
                let port = r.u16()?;
                Payload::Identification(IdPayload {
                    id_type,
                    protocol_id,
                    port,
                    data: body[4..].to_vec(),
                })
            }
            PayloadType::Notification => {
                let mut r = Reader::new(body);
                let doi = r.u32()?;
                let protocol_id = r.u8()?;
                let spi_size = r.u8()? as usize;
                let message_type = r.u16()?;
                let spi = r.take(spi_size)?.to_vec();
                let data = body[r.i..].to_vec();
                Payload::Notification(NotifyPayload {
                    doi,
                    protocol_id,
                    spi,
                    message_type,
                    data,
                })
            }
            PayloadType::Attributes => {
                let mut r = Reader::new(body);
                let kind = r.u8()?;
                r.u8()?; // reserved
                let identifier = r.u16()?;
                Payload::Attributes(AttributesPayload {
                    kind,
                    identifier,
                    attributes: parse_attributes(&body[4..])?,
                })
            }
            _ => Payload::Other(ptype, body.to_vec()),
        })
    }
}

// ---------------------------------------------------------------------------
// ISAKMP message.
// ---------------------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct IsakmpMessage {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub exchange_type: u8,
    pub flags: u8,
    pub message_id: u32,
    pub payloads: Vec<Payload>,
}

impl IsakmpMessage {
    /// Encode the chain of payloads (without the ISAKMP header). The returned
    /// first-payload type goes in the header's `next_payload` field.
    pub fn encode_payloads(payloads: &[Payload]) -> (u8, Vec<u8>) {
        let first = payloads.first().map_or(0, |p| p.payload_type());
        let mut out = Vec::new();
        for (i, p) in payloads.iter().enumerate() {
            let next = payloads.get(i + 1).map_or(0, |n| n.payload_type());
            let body = p.body();
            out.push(next);
            out.push(0);
            out.extend_from_slice(&((PAYLOAD_HEADER_LEN + body.len()) as u16).to_be_bytes());
            out.extend_from_slice(&body);
        }
        (first, out)
    }

    /// Parse a plaintext payload chain given the first payload's type.
    pub fn parse_payloads(first_type: u8, body: &[u8]) -> Result<Vec<Payload>, String> {
        let mut r = Reader::new(body);
        let mut payloads = Vec::new();
        let mut cur = first_type;
        while cur != u8::from(PayloadType::None) {
            let next = r.u8()?;
            let _res = r.u8()?;
            let len = r.u16()? as usize;
            if len < PAYLOAD_HEADER_LEN {
                return Err(format!("payload length {len} below header"));
            }
            let pbody = r.take(len - PAYLOAD_HEADER_LEN)?;
            payloads.push(Payload::parse(cur, pbody)?);
            cur = next;
        }
        Ok(payloads)
    }

    /// Full serialization, header + plaintext payloads.
    pub fn encode(&self) -> Vec<u8> {
        let (first, body) = Self::encode_payloads(&self.payloads);
        let mut out = Vec::with_capacity(ISAKMP_HEADER_LEN + body.len());
        out.extend_from_slice(&self.initiator_spi.to_be_bytes());
        out.extend_from_slice(&self.responder_spi.to_be_bytes());
        out.push(first);
        out.push(IKEV1_VERSION);
        out.push(self.exchange_type);
        out.push(self.flags);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&((ISAKMP_HEADER_LEN + body.len()) as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Decode a plaintext message (header + payload chain).
    pub fn decode(data: &[u8]) -> Result<IsakmpMessage, String> {
        if data.len() < ISAKMP_HEADER_LEN {
            return Err("short ISAKMP header".into());
        }
        let mut r = Reader::new(data);
        let initiator_spi = r.u64()?;
        let responder_spi = r.u64()?;
        let next_payload = r.u8()?;
        let _version = r.u8()?;
        let exchange_type = r.u8()?;
        let flags = r.u8()?;
        let message_id = r.u32()?;
        let length = r.u32()? as usize;
        if length != data.len() {
            return Err(format!("length {length} != data {}", data.len()));
        }
        let payloads = Self::parse_payloads(next_payload, &data[ISAKMP_HEADER_LEN..])?;
        Ok(IsakmpMessage {
            initiator_spi,
            responder_spi,
            exchange_type,
            flags,
            message_id,
            payloads,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MM: &[u8] = include_bytes!("../../testdata/mm.bin");

    #[test]
    fn roundtrip_main_mode() {
        let msg = IsakmpMessage::decode(MM).expect("decode mm.bin");
        assert_eq!(msg.exchange_type, u8::from(ExchangeType::IdentityProtection));
        assert_eq!(msg.message_id, 0);
        // First payload is the SA.
        let sa = match &msg.payloads[0] {
            Payload::Sa(sa) => sa,
            other => panic!("expected SA, got {other:?}"),
        };
        assert_eq!(sa.doi, 1);
        let t = &sa.proposals[0].transforms[0];
        let attr = |ty: IkeAttributeType| {
            t.attributes
                .iter()
                .find(|a| a.attr_type == u16::from(ty))
                .and_then(|a| a.as_u16())
        };
        assert_eq!(attr(IkeAttributeType::EncryptionAlgorithm), Some(IKE_ENC_AES_CBC));
        assert_eq!(attr(IkeAttributeType::HashAlgorithm), Some(IKE_HASH_SHA256));
        assert_eq!(attr(IkeAttributeType::GroupDescription), Some(IKE_GROUP_MODP1024));
        assert_eq!(
            attr(IkeAttributeType::AuthenticationMethod),
            Some(IKE_AUTH_HYBRID_INIT_RSA)
        );
        assert_eq!(attr(IkeAttributeType::KeyLength), Some(256));
        assert_eq!(attr(IkeAttributeType::LifeDuration), Some(28800));

        // Byte-exact round-trip.
        assert_eq!(msg.encode(), MM, "re-encode must match the captured bytes");
    }

    #[test]
    fn roundtrip_synthetic_quick_mode() {
        // SA with two transforms + a nonce, to exercise multi-transform nesting.
        let sa = Payload::Sa(SaPayload {
            doi: 1,
            situation: Some(1),
            proposals: vec![Proposal {
                number: 1,
                protocol_id: u8::from(ProtocolId::IpsecEsp),
                spi: vec![0xaa, 0xbb, 0xcc, 0xdd],
                transforms: vec![
                    Transform {
                        number: 1,
                        transform_id: u8::from(TransformId::EspAesCbc),
                        attributes: vec![Attribute::short(u16::from(EspAttributeType::KeyLength), 256)],
                    },
                    Transform {
                        number: 2,
                        transform_id: u8::from(TransformId::Esp3Des),
                        attributes: vec![Attribute::short(u16::from(EspAttributeType::LifeType), 1)],
                    },
                ],
            }],
        });
        let msg = IsakmpMessage {
            initiator_spi: 0x1122334455667788,
            responder_spi: 0,
            exchange_type: u8::from(ExchangeType::Quick),
            flags: 0,
            message_id: 0x0a0b0c0d,
            payloads: vec![sa, Payload::Nonce(vec![1, 2, 3, 4])],
        };
        let bytes = msg.encode();
        let back = IsakmpMessage::decode(&bytes).expect("decode synthetic");
        assert_eq!(back.encode(), bytes);
        assert_eq!(back.payloads.len(), 2);
    }
}
