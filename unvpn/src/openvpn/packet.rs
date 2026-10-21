//! OpenVPN packet framing + the control channel's reliability layer.
//!
//! Every packet starts with one byte `opcode << 3 | key_id`. Control packets
//! then carry (after the `tls-auth`/`tls-crypt` wrapping, see [`super::crypto`]):
//!
//! ```text
//! op | session_id(8) | ack_count(1) | ack ids (4 each) | remote_sid(8, if acks)
//!    | message_id(4, absent for P_ACK_V1) | payload
//! ```
//!
//! The reliability layer (`reliable.c`) numbers each control message per key
//! state starting at 0, delivers them in order, acknowledges what it received and
//! retransmits what the peer hasn't acknowledged, with exponential back-off.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub const P_CONTROL_SOFT_RESET_V1: u8 = 3;
pub const P_CONTROL_V1: u8 = 4;
pub const P_ACK_V1: u8 = 5;
pub const P_DATA_V1: u8 = 6;
pub const P_CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
pub const P_CONTROL_HARD_RESET_SERVER_V2: u8 = 8;
pub const P_DATA_V2: u8 = 9;

pub fn opcode(b: u8) -> u8 {
    b >> 3
}

pub fn key_id(b: u8) -> u8 {
    b & 0x07
}

pub fn op_byte(op: u8, key_id: u8) -> u8 {
    (op << 3) | (key_id & 0x07)
}

pub fn is_data(op: u8) -> bool {
    op == P_DATA_V1 || op == P_DATA_V2
}

/// The decoded body of a control packet (everything after op|sid).
#[derive(Debug, PartialEq)]
pub struct Control {
    pub acks: Vec<u32>,
    pub remote_sid: Option<[u8; 8]>,
    pub msg_id: Option<u32>,
    pub payload: Vec<u8>,
}

/// Encode the post-sid part of a control packet.
pub fn encode_rest(acks: &[u32], remote_sid: &[u8; 8], msg_id: Option<u32>, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + acks.len() * 4 + 8 + 4 + payload.len());
    v.push(acks.len() as u8);
    for a in acks {
        v.extend_from_slice(&a.to_be_bytes());
    }
    if !acks.is_empty() {
        v.extend_from_slice(remote_sid);
    }
    if let Some(id) = msg_id {
        v.extend_from_slice(&id.to_be_bytes());
    }
    v.extend_from_slice(payload);
    v
}

pub fn decode_rest(op: u8, rest: &[u8]) -> Result<Control, String> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], String> {
        let s = rest.get(*p..*p + n).ok_or("truncated control packet")?;
        *p += n;
        Ok(s)
    };
    let n = take(&mut p, 1)?[0] as usize;
    let mut acks = Vec::with_capacity(n);
    for _ in 0..n {
        let b = take(&mut p, 4)?;
        acks.push(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    }
    let remote_sid = if n > 0 {
        let mut s = [0u8; 8];
        s.copy_from_slice(take(&mut p, 8)?);
        Some(s)
    } else {
        None
    };
    let msg_id = if op == P_ACK_V1 {
        None
    } else {
        let b = take(&mut p, 4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    };
    Ok(Control { acks, remote_sid, msg_id, payload: rest[p..].to_vec() })
}

/// Initial retransmit timeout (OpenVPN's `tls-timeout` default is 2 s).
const RTO_INITIAL: Duration = Duration::from_secs(2);
const RTO_MAX: Duration = Duration::from_secs(16);
/// Max unacknowledged messages in flight (OpenVPN keeps a few send buffers).
const SEND_WINDOW: usize = 4;
/// Max ACKs per packet (some servers — SoftEther — drop packets with more).
pub const MAX_ACKS: usize = 4;

struct Outgoing {
    id: u32,
    op: u8,
    payload: Vec<u8>,
    sent_at: Option<Instant>,
    rto: Duration,
}

/// Reliability state for one key_id.
#[derive(Default)]
pub struct Reliable {
    next_id: u32,
    out: Vec<Outgoing>,
    expect: u32,
    ooo: BTreeMap<u32, (u8, Vec<u8>)>,
    pub to_ack: Vec<u32>,
    /// On TCP the transport is reliable: never retransmit.
    pub no_retransmit: bool,
}

impl Reliable {
    pub fn queue(&mut self, op: u8, payload: Vec<u8>) {
        let id = self.next_id;
        self.next_id += 1;
        self.out.push(Outgoing { id, op, payload, sent_at: None, rto: RTO_INITIAL });
    }

    /// Returns true if any of ours got acknowledged.
    pub fn acked(&mut self, ids: &[u32]) -> bool {
        let before = self.out.len();
        self.out.retain(|o| !ids.contains(&o.id));
        self.out.len() != before
    }

    pub fn pending(&self, id: u32) -> bool {
        self.out.iter().any(|o| o.id == id)
    }

    /// Accept an incoming reliable message; returns the messages now deliverable
    /// in order. Duplicates/old ids are re-ACKed and dropped.
    pub fn receive(&mut self, id: u32, op: u8, payload: Vec<u8>) -> Vec<(u8, Vec<u8>)> {
        if !self.to_ack.contains(&id) {
            self.to_ack.push(id);
        }
        if id < self.expect || id > self.expect + 64 {
            return Vec::new();
        }
        self.ooo.entry(id).or_insert((op, payload));
        let mut ready = Vec::new();
        while let Some(m) = self.ooo.remove(&self.expect) {
            ready.push(m);
            self.expect += 1;
        }
        ready
    }

    /// Messages to (re)transmit now: never-sent ones within the window, plus
    /// any whose retransmit timer expired (backing off exponentially).
    pub fn due(&mut self, now: Instant) -> Vec<(u32, u8, Vec<u8>)> {
        let mut v = Vec::new();
        for o in self.out.iter_mut().take(SEND_WINDOW) {
            let fire = match o.sent_at {
                None => true,
                Some(t) => !self.no_retransmit && now.duration_since(t) >= o.rto,
            };
            if fire {
                if o.sent_at.is_some() {
                    o.rto = (o.rto * 2).min(RTO_MAX);
                }
                o.sent_at = Some(now);
                v.push((o.id, o.op, o.payload.clone()));
            }
        }
        v
    }

    /// Up to [`MAX_ACKS`] pending ACKs (removed from the owed list).
    pub fn take_acks(&mut self) -> Vec<u32> {
        let n = self.to_ack.len().min(MAX_ACKS);
        self.to_ack.drain(..n).collect()
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        if self.no_retransmit {
            return None;
        }
        self.out.iter().take(SEND_WINDOW).filter_map(|o| o.sent_at.map(|t| t + o.rto)).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rest_roundtrip() {
        let sid = [1, 2, 3, 4, 5, 6, 7, 8];
        let r = encode_rest(&[0, 3], &sid, Some(5), b"tls");
        let c = decode_rest(P_CONTROL_V1, &r).unwrap();
        assert_eq!(c, Control { acks: vec![0, 3], remote_sid: Some(sid), msg_id: Some(5), payload: b"tls".to_vec() });
        // Pure ACK: no message id.
        let r = encode_rest(&[9], &sid, None, b"");
        let c = decode_rest(P_ACK_V1, &r).unwrap();
        assert_eq!((c.acks, c.msg_id), (vec![9], None));
        // Hard reset with no acks: no remote sid.
        let r = encode_rest(&[], &sid, Some(0), b"");
        assert_eq!(r, vec![0, 0, 0, 0, 0]);
        assert!(decode_rest(P_CONTROL_V1, &[1, 0, 0]).is_err());
    }

    #[test]
    fn opcode_bytes() {
        assert_eq!(op_byte(P_CONTROL_HARD_RESET_CLIENT_V2, 0), 0x38);
        assert_eq!(op_byte(P_DATA_V2, 2), 0x4a);
        assert_eq!((opcode(0x4a), key_id(0x4a)), (P_DATA_V2, 2));
    }

    #[test]
    fn in_order_delivery_and_acks() {
        let mut r = Reliable::default();
        assert!(r.receive(1, 4, b"b".to_vec()).is_empty());
        let got = r.receive(0, 8, b"a".to_vec());
        assert_eq!(got, vec![(8, b"a".to_vec()), (4, b"b".to_vec())]);
        assert!(r.receive(0, 8, b"a".to_vec()).is_empty());
        let acks = r.take_acks();
        assert_eq!(acks, vec![1, 0]);
    }

    #[test]
    fn retransmit_backoff_and_ack() {
        let mut r = Reliable::default();
        r.queue(7, vec![]);
        let t0 = Instant::now();
        assert_eq!(r.due(t0).len(), 1);
        assert!(r.due(t0).is_empty());
        let t1 = t0 + RTO_INITIAL;
        assert_eq!(r.due(t1).len(), 1);
        assert!(r.due(t1 + RTO_INITIAL).is_empty()); // backed off to 4 s
        assert!(r.acked(&[0]));
        assert!(!r.pending(0));
    }

    #[test]
    fn send_window_limits_inflight() {
        let mut r = Reliable::default();
        for _ in 0..6 {
            r.queue(4, vec![1]);
        }
        let now = Instant::now();
        assert_eq!(r.due(now).len(), SEND_WINDOW);
        r.acked(&[0, 1]);
        assert_eq!(r.due(now).len(), 2);
    }
}
