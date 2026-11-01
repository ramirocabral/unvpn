//! IF-T/TLS message framing for the Ivanti Connect Secure (Pulse) data plane.
//!
//! Once the web login hands over a `DSID` session cookie, the modern client
//! opens a second TLS connection and speaks a length-prefixed binary protocol
//! (TNC IF-T binding to TLS). Every message is a 16-byte header followed by its
//! payload:
//!
//! ```text
//!   0               1               2               3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                        vendor id                             |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                       message type                           |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                 message length (incl. header)                |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                     message identifier                       |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Standard (TNC) messages use vendor id 0; the vendor-specific control and
//! configuration messages use the Juniper enterprise number.

/// Juniper/Pulse enterprise number (IANA SMI PEN 2636).
pub const PEN_JUNIPER: u32 = 0x0000_0A4C;
/// Standard TNC IF-T messages carry vendor id 0.
pub const PEN_STANDARD: u32 = 0;

/// Bytes in the fixed IF-T/TLS header.
pub const HEADER_LEN: usize = 16;

/// A parsed IF-T/TLS message: the four header words plus the payload.
#[derive(Debug, Clone, PartialEq)]
pub struct IftMessage {
    pub vendor: u32,
    pub msg_type: u32,
    pub msg_id: u32,
    pub payload: Vec<u8>,
}

impl IftMessage {
    pub fn new(vendor: u32, msg_type: u32, msg_id: u32, payload: Vec<u8>) -> Self {
        IftMessage { vendor, msg_type, msg_id, payload }
    }

    /// Serialize header + payload. `message length` is the total wire size.
    pub fn encode(&self) -> Vec<u8> {
        let len = (HEADER_LEN + self.payload.len()) as u32;
        let mut out = Vec::with_capacity(len as usize);
        out.extend_from_slice(&self.vendor.to_be_bytes());
        out.extend_from_slice(&self.msg_type.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.msg_id.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse one message from the front of `buf`. Returns the message and the
    /// number of bytes consumed, or `None` if `buf` does not yet hold a whole
    /// message.
    pub fn decode(buf: &[u8]) -> Option<(IftMessage, usize)> {
        if buf.len() < HEADER_LEN {
            return None;
        }
        let w = |i: usize| u32::from_be_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        let vendor = w(0);
        let msg_type = w(4);
        let len = w(8) as usize;
        let msg_id = w(12);
        if len < HEADER_LEN || buf.len() < len {
            return None;
        }
        let payload = buf[HEADER_LEN..len].to_vec();
        Some((IftMessage { vendor, msg_type, msg_id, payload }, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrips() {
        let m = IftMessage::new(PEN_JUNIPER, 0x88, 7, vec![1, 2, 3, 4, 5]);
        let bytes = m.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 5);
        // message length word carries the full size.
        assert_eq!(&bytes[8..12], &(bytes.len() as u32).to_be_bytes());
        let (back, used) = IftMessage::decode(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(back, m);
    }

    #[test]
    fn decode_waits_for_a_whole_message() {
        let m = IftMessage::new(PEN_STANDARD, 1, 0, vec![9; 32]);
        let bytes = m.encode();
        assert!(IftMessage::decode(&bytes[..HEADER_LEN - 1]).is_none());
        assert!(IftMessage::decode(&bytes[..bytes.len() - 1]).is_none());
        assert!(IftMessage::decode(&bytes).is_some());
    }

    #[test]
    fn decode_reports_trailing_bytes() {
        let m = IftMessage::new(PEN_JUNIPER, 2, 1, vec![0xaa, 0xbb]);
        let mut bytes = m.encode();
        bytes.extend_from_slice(&[0xff, 0xee]); // start of a second message
        let (msg, used) = IftMessage::decode(&bytes).unwrap();
        assert_eq!(msg.payload, vec![0xaa, 0xbb]);
        assert_eq!(used, HEADER_LEN + 2);
        assert_eq!(&bytes[used..], &[0xff, 0xee]);
    }
}
