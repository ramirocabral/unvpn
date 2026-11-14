//! IF-T/TLS framing and the EAP/AVP encoding spoken inside it.
//!
//! After an HTTP `Upgrade: IF-T/TLS 1.0` the connection carries length-prefixed
//! binary messages, each a 16-byte header followed by its payload:
//!
//! ```text
//!   0               1               2               3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |   reserved    |                vendor id                      |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                         message type                          |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                 message length (incl. header)                 |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                       sequence number                         |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The TCG messages (version, client auth) are standard IF-T; configuration,
//! data and control use the Juniper vendor id. Authentication is EAP inside the
//! TCG client-auth messages, with Diameter-style AVPs (RFC 5281 §10) as payload.

use crate::net::tls::TlsStream;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

pub const VENDOR_TCG: u32 = 0x5597;
pub const VENDOR_JUNIPER: u32 = 0x0a4c;
/// Vendor of the Juniper AVPs.
pub const VENDOR_JUNIPER2: u32 = 0x0583;

pub const VERSION_REQUEST: u32 = 1;
pub const VERSION_RESPONSE: u32 = 2;
pub const AUTH_CHALLENGE: u32 = 5;
pub const AUTH_RESPONSE: u32 = 6;
pub const AUTH_SUCCESS: u32 = 7;

/// Juniper message types.
pub const J_CONFIG: u32 = 0x01;
pub const J_DATA: u32 = 0x04;
pub const J_ESP_ON: u32 = 0x05;
pub const J_CLIENT_INFO: u32 = 0x88;
pub const J_LOGOUT: u32 = 0x89;
pub const J_CONFIG_END: u32 = 0x8f;
pub const J_FATAL: u32 = 0x93;
pub const J_LICENSE: u32 = 0x96;

/// IF-T auth type carried at the start of every client-auth payload.
pub const JUNIPER_1: u32 = (VENDOR_JUNIPER << 8) | 1;
/// EAP expanded type with the Juniper vendor id (`fe 00 0a 4c`).
pub const EXPANDED_JUNIPER: u32 = (0xfe << 24) | VENDOR_JUNIPER;

pub const EAP_REQUEST: u8 = 1;
pub const EAP_RESPONSE: u8 = 2;
pub const EAP_SUCCESS: u8 = 3;
pub const EAP_FAILURE: u8 = 4;
pub const EAP_TYPE_IDENTITY: u8 = 1;
pub const EAP_TYPE_GTC: u8 = 6;
pub const EAP_TYPE_TLS: u8 = 0x0d;
pub const EAP_TYPE_TTLS: u8 = 0x15;
pub const EAP_TYPE_EXPANDED: u8 = 0xfe;

/// EAP-Message AVP (RFC 3579), no vendor.
pub const AVP_EAP_MESSAGE: u32 = 79;
const AVP_FLAG_VENDOR: u8 = 0x80;
const AVP_FLAG_MANDATORY: u8 = 0x40;

pub const HEADER_LEN: usize = 16;
/// Larger than any configuration message a gateway sends.
const MAX_MESSAGE: usize = 1 << 20;

/// A parsed IF-T/TLS message: the header words plus the payload.
#[derive(Debug, Clone, PartialEq)]
pub struct IftMessage {
    pub vendor: u32,
    pub msg_type: u32,
    pub seq: u32,
    pub payload: Vec<u8>,
}

impl IftMessage {
    #[cfg(test)]
    pub fn new(vendor: u32, msg_type: u32, seq: u32, payload: Vec<u8>) -> Self {
        IftMessage {
            vendor,
            msg_type,
            seq,
            payload,
        }
    }

    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        encode(self.vendor, self.msg_type, self.seq, &self.payload)
    }

    /// One message from the front of `buf` and the bytes it used; `None` while
    /// `buf` doesn't hold a whole one yet.
    pub fn decode(buf: &[u8]) -> Result<Option<(IftMessage, usize)>, String> {
        if buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let len = be32(buf, 8) as usize;
        if !(HEADER_LEN..=MAX_MESSAGE).contains(&len) {
            return Err(format!("bad IF-T/TLS message length {len}"));
        }
        if buf.len() < len {
            return Ok(None);
        }
        Ok(Some((
            IftMessage {
                vendor: be32(buf, 0) & 0x00ff_ffff,
                msg_type: be32(buf, 4),
                seq: be32(buf, 12),
                payload: buf[HEADER_LEN..len].to_vec(),
            },
            len,
        )))
    }

    pub fn is(&self, vendor: u32, msg_type: u32) -> bool {
        self.vendor == vendor && self.msg_type == msg_type
    }
}

pub fn encode(vendor: u32, msg_type: u32, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = (HEADER_LEN + payload.len()) as u32;
    let mut out = Vec::with_capacity(len as usize);
    out.extend_from_slice(&vendor.to_be_bytes());
    out.extend_from_slice(&msg_type.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// The TLS connection after the upgrade: buffered reads, numbered sends.
pub struct IftConn {
    pub tls: TlsStream,
    rx: Vec<u8>,
    seq: u32,
}

impl IftConn {
    /// `leftover`: bytes that arrived with the HTTP upgrade response.
    pub fn new(tls: TlsStream, leftover: Vec<u8>) -> Self {
        IftConn {
            tls,
            rx: leftover,
            seq: 0,
        }
    }

    pub fn fd(&self) -> i32 {
        self.tls.get_ref().as_raw_fd()
    }

    pub fn send(&mut self, vendor: u32, msg_type: u32, payload: &[u8]) -> Result<(), String> {
        let wire = encode(vendor, msg_type, self.seq, payload);
        self.seq = self.seq.wrapping_add(1);
        let fd = self.fd();
        crate::sysnet::write_all_polling(&mut self.tls, Some(fd), &wire)?;
        self.tls.flush().map_err(|e| format!("IF-T/TLS write: {e}"))
    }

    /// Blocking: the next whole message (the socket's read timeout applies).
    pub fn recv(&mut self) -> Result<IftMessage, String> {
        loop {
            if let Some(m) = self.take()? {
                return Ok(m);
            }
            let mut tmp = [0u8; 16384];
            match self.tls.read(&mut tmp) {
                Ok(0) => return Err("the gateway closed the IF-T/TLS connection".into()),
                Ok(n) => self.rx.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(format!("IF-T/TLS read: {e}")),
            }
        }
    }

    /// Non-blocking socket: read whatever is available. `Ok(false)` once the
    /// gateway closed the connection and nothing new arrived.
    pub fn fill(&mut self) -> Result<bool, String> {
        let mut tmp = [0u8; 16384];
        let mut got_any = false;
        loop {
            match self.tls.read(&mut tmp) {
                Ok(0) => return Ok(got_any),
                Ok(n) => {
                    self.rx.extend_from_slice(&tmp[..n]);
                    got_any = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                // A peer that closes without a TLS close_notify.
                Err(e) if e.to_string().contains("unexpected eof") => return Ok(got_any),
                Err(e) => return Err(format!("IF-T/TLS read: {e}")),
            }
        }
    }

    /// The next buffered message, if a whole one has arrived.
    pub fn take(&mut self) -> Result<Option<IftMessage>, String> {
        Ok(IftMessage::decode(&self.rx)?.map(|(m, used)| {
            self.rx.drain(..used);
            m
        }))
    }
}

/// EAP packet: `code | ident | length | body`.
pub fn eap(code: u8, ident: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(code);
    out.push(ident);
    out.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// EAP of the expanded Juniper type with `subtype`.
pub fn eap_expanded(code: u8, ident: u8, subtype: u32, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + data.len());
    body.extend_from_slice(&EXPANDED_JUNIPER.to_be_bytes());
    body.extend_from_slice(&subtype.to_be_bytes());
    body.extend_from_slice(data);
    eap(code, ident, &body)
}

/// Client-auth message payload: the auth type, then the EAP packet.
pub fn auth_payload(eap: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + eap.len());
    out.extend_from_slice(&JUNIPER_1.to_be_bytes());
    out.extend_from_slice(eap);
    out
}

/// A Juniper (vendor) AVP, padded to 4 bytes.
pub fn avp(code: u32, data: &[u8]) -> Vec<u8> {
    let len = 12 + data.len();
    let mut out = Vec::with_capacity(len + 3);
    out.extend_from_slice(&code.to_be_bytes());
    out.push(AVP_FLAG_VENDOR);
    out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&VENDOR_JUNIPER2.to_be_bytes());
    out.extend_from_slice(data);
    pad4(&mut out);
    out
}

pub fn avp_u32(code: u32, v: u32) -> Vec<u8> {
    avp(code, &v.to_be_bytes())
}

/// EAP-Message AVP wrapping `eap`, padded to 4 bytes.
pub fn avp_eap_message(eap: &[u8]) -> Vec<u8> {
    let len = 8 + eap.len();
    let mut out = Vec::with_capacity(len + 3);
    out.extend_from_slice(&AVP_EAP_MESSAGE.to_be_bytes());
    out.push(AVP_FLAG_MANDATORY);
    out.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    out.extend_from_slice(eap);
    pad4(&mut out);
    out
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Avp<'a> {
    pub code: u32,
    /// 0 when the AVP carries no vendor id.
    pub vendor: u32,
    pub mandatory: bool,
    pub data: &'a [u8],
}

impl Avp<'_> {
    #[cfg(test)]
    pub fn is_juniper(&self, code: u32) -> bool {
        self.vendor == VENDOR_JUNIPER2 && self.code == code
    }

    pub fn u32(&self) -> Option<u32> {
        (self.data.len() == 4).then(|| be32(self.data, 0))
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(self.data)
            .trim_end_matches('\0')
            .to_string()
    }
}

/// All AVPs in `buf` (each padded to 4 bytes; the last may be unpadded).
pub fn parse_avps(mut buf: &[u8]) -> Result<Vec<Avp<'_>>, String> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        if buf.len() < 8 {
            return Err("truncated AVP header".into());
        }
        let code = be32(buf, 0);
        let flags = buf[4];
        let len = (be32(buf, 4) & 0x00ff_ffff) as usize;
        let hdr = if flags & AVP_FLAG_VENDOR != 0 { 12 } else { 8 };
        if len < hdr || len > buf.len() {
            return Err(format!("bad AVP length {len} (code {code:#x})"));
        }
        let vendor = if hdr == 12 { be32(buf, 8) } else { 0 };
        out.push(Avp {
            code,
            vendor,
            mandatory: flags & AVP_FLAG_MANDATORY != 0,
            data: &buf[hdr..len],
        });
        let next = (len + 3) & !3;
        buf = &buf[next.min(buf.len())..];
    }
    Ok(out)
}

/// The EAP request of a client-auth challenge, its length checked.
pub fn challenge_eap(m: &IftMessage) -> Result<&[u8], String> {
    if !m.is(VENDOR_TCG, AUTH_CHALLENGE) {
        return Err(format!(
            "expected an authentication challenge, got IF-T message {:#x}/{:#x}",
            m.vendor, m.msg_type
        ));
    }
    let p = &m.payload;
    if p.len() < 4 || be32(p, 0) != JUNIPER_1 {
        return Err("authentication challenge of an unknown auth type".into());
    }
    let eap = &p[4..];
    if eap.len() < 4 || usize::from(be16(eap, 2)) != eap.len() {
        return Err("malformed EAP in the authentication challenge".into());
    }
    match eap[0] {
        EAP_REQUEST if eap.len() >= 5 => Ok(eap),
        EAP_FAILURE => Err("the gateway ended the authentication (EAP failure)".into()),
        c => Err(format!(
            "unexpected EAP code {c} in the authentication challenge"
        )),
    }
}

/// The text of a fatal-error message (`errorType=N errorString=…`).
pub fn fatal_reason(p: &[u8]) -> String {
    let text = String::from_utf8_lossy(p);
    let text = text.trim_end_matches(['\0', '\n']);
    let (ty, msg) = match text
        .strip_prefix("errorType=")
        .and_then(|r| r.split_once(" errorString="))
    {
        Some((t, m)) => (t.trim(), crate::net::http::form_decode(m)),
        None => ("", text.to_string()),
    };
    let why = match ty {
        "6" => " (another session of this user replaced it)",
        "7" => " (terminated)",
        "8" => " (timed out)",
        _ => "",
    };
    format!(
        "the gateway ended the session: {}{why}",
        crate::sysnet::one_line(&msg)
    )
}

/// `true` for an EAP request of the expanded Juniper type with `subtype`.
pub fn is_expanded(eap: &[u8], subtype: u32) -> bool {
    eap.len() >= 12 && be32(eap, 4) == EXPANDED_JUNIPER && be32(eap, 8) == subtype
}

pub fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

pub fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrips() {
        let m = IftMessage::new(VENDOR_JUNIPER, J_CLIENT_INFO, 7, vec![1, 2, 3, 4, 5]);
        let bytes = m.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 5);
        assert_eq!(&bytes[8..12], &(bytes.len() as u32).to_be_bytes());
        let (back, used) = IftMessage::decode(&bytes).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(back, m);
    }

    #[test]
    fn decode_waits_for_a_whole_message() {
        let bytes = encode(VENDOR_TCG, 1, 0, &[9; 32]);
        assert!(IftMessage::decode(&bytes[..HEADER_LEN - 1])
            .unwrap()
            .is_none());
        assert!(IftMessage::decode(&bytes[..bytes.len() - 1])
            .unwrap()
            .is_none());
        assert!(IftMessage::decode(&bytes).unwrap().is_some());
    }

    #[test]
    fn decode_ignores_the_reserved_byte_and_rejects_bad_lengths() {
        let mut bytes = encode(VENDOR_TCG, VERSION_RESPONSE, 0, &[0, 0, 0, 2]);
        bytes[0] = 0xff;
        let (m, _) = IftMessage::decode(&bytes).unwrap().unwrap();
        assert!(m.is(VENDOR_TCG, VERSION_RESPONSE));
        bytes[8..12].copy_from_slice(&3u32.to_be_bytes());
        assert!(IftMessage::decode(&bytes).is_err());
    }

    #[test]
    fn avps_roundtrip_with_padding() {
        let mut buf = avp(0xd6d, b"alice");
        assert_eq!(buf.len(), 20);
        assert_eq!(&buf[4..8], &[0x80, 0, 0, 17]);
        let inner = eap(EAP_RESPONSE, 3, &[EAP_TYPE_GTC, b'1', b'2']);
        buf.extend(avp_eap_message(&inner));
        buf.extend(avp_u32(0xd7c, 1));
        let avps = parse_avps(&buf).unwrap();
        assert_eq!(avps.len(), 3);
        assert!(avps[0].is_juniper(0xd6d) && avps[0].text() == "alice");
        assert_eq!(
            (avps[1].code, avps[1].vendor, avps[1].mandatory),
            (AVP_EAP_MESSAGE, 0, true)
        );
        assert_eq!(avps[1].data, &inner[..]);
        assert_eq!(avps[2].u32(), Some(1));
    }

    #[test]
    fn truncated_avp_is_an_error() {
        let buf = avp(0xd53, b"cookie");
        assert!(parse_avps(&buf[..10]).is_err());
        assert!(parse_avps(&buf[..buf.len() - 4]).is_err());
    }

    #[test]
    fn fatal_reason_is_decoded() {
        assert_eq!(
            fatal_reason(b"errorType=8 errorString=Session%20timed+out\n\0"),
            "the gateway ended the session: Session timed out (timed out)"
        );
    }

    #[test]
    fn challenge_eap_validates_the_envelope() {
        let e = eap_expanded(EAP_REQUEST, 9, 1, &avp(0xd4e, b"Users"));
        let m = IftMessage::new(VENDOR_TCG, AUTH_CHALLENGE, 0, auth_payload(&e));
        let got = challenge_eap(&m).unwrap();
        assert!(is_expanded(got, 1) && got[1] == 9);
        let mut bad = m.clone();
        bad.payload[7] ^= 1; // EAP length
        assert!(challenge_eap(&bad).is_err());
        let fail = IftMessage::new(
            VENDOR_TCG,
            AUTH_CHALLENGE,
            0,
            auth_payload(&eap(EAP_FAILURE, 1, &[])),
        );
        assert!(challenge_eap(&fail).unwrap_err().contains("EAP failure"));
    }
}
