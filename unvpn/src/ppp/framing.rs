//! How PPP frames ride on the SSL-VPN byte stream.
//!
//! Forti: `[be16 total = len + 6][0x5050][be16 len][frame]`, the frame always
//! `FF 03` + 2-byte protocol; Fortinet control records (`[be16 len]"GF"…`) are
//! interleaved with it.
//!
//! F5: `[0xf500][be16 len][frame]`; IP data goes out ACFC+PFC compressed (a bare
//! 1-byte protocol).
//!
//! HDLC: RFC 1662 async-HDLC, `7e` flags, `7d` stuffing and an FCS-16, with the
//! same compression as F5.

/// Pseudo-protocol for a Fortinet control record; not a PPP protocol number.
pub const FORTI_CTRL: u16 = 0xffff;

const FORTI_MAGIC: u16 = 0x5050;
const GF_MAGIC: u16 = 0x4746;
const F5_MAGIC: u16 = 0xf500;
const HDLC_FLAG: u8 = 0x7e;
const HDLC_ESC: u8 = 0x7d;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Forti,
    F5,
    Hdlc,
}

pub enum Frame {
    /// A PPP frame (address/control and protocol not yet parsed).
    Ppp(Vec<u8>),
    /// A vendor control record, passed up as-is.
    Control(Vec<u8>),
}

impl Framing {
    pub fn encode(self, proto: u16, payload: &[u8], out: &mut Vec<u8>) {
        let compress = self != Framing::Forti && proto < 0x0100;
        let mut frame = Vec::with_capacity(4 + payload.len());
        if compress {
            frame.push(proto as u8);
        } else {
            frame.extend_from_slice(&[0xff, 0x03]);
            frame.extend_from_slice(&proto.to_be_bytes());
        }
        frame.extend_from_slice(payload);
        match self {
            Framing::Forti => {
                out.extend_from_slice(&((frame.len() + 6) as u16).to_be_bytes());
                out.extend_from_slice(&FORTI_MAGIC.to_be_bytes());
                out.extend_from_slice(&(frame.len() as u16).to_be_bytes());
                out.extend_from_slice(&frame);
            }
            Framing::F5 => {
                out.extend_from_slice(&F5_MAGIC.to_be_bytes());
                out.extend_from_slice(&(frame.len() as u16).to_be_bytes());
                out.extend_from_slice(&frame);
            }
            Framing::Hdlc => hdlc_encode(&frame, out),
        }
    }

    /// Remove one complete frame from the front of `buf`; `None` until one is there.
    pub fn take(self, buf: &mut Vec<u8>) -> Result<Option<Frame>, String> {
        match self {
            Framing::Forti => take_forti(buf),
            Framing::F5 => take_f5(buf),
            Framing::Hdlc => Ok(take_hdlc(buf)),
        }
    }
}

fn be16(b: &[u8], at: usize) -> usize {
    u16::from_be_bytes([b[at], b[at + 1]]) as usize
}

fn take_forti(buf: &mut Vec<u8>) -> Result<Option<Frame>, String> {
    if buf.len() < 6 {
        return Ok(None);
    }
    let total = be16(buf, 0);
    let magic = be16(buf, 2) as u16;
    if magic == GF_MAGIC {
        if total < 4 {
            return Err(format!("bad Fortinet control record (len={total})"));
        }
        if buf.len() < total {
            return Ok(None);
        }
        let rec = buf.drain(..total).skip(2).collect();
        return Ok(Some(Frame::Control(rec)));
    }
    let frame_len = be16(buf, 4);
    if magic != FORTI_MAGIC || total != frame_len + 6 {
        return Err(format!(
            "bad Fortinet framing (magic={magic:#06x} total={total} frame_len={frame_len})"
        ));
    }
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(Frame::Ppp(buf.drain(..total).skip(6).collect())))
}

fn take_f5(buf: &mut Vec<u8>) -> Result<Option<Frame>, String> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let magic = be16(buf, 0) as u16;
    if magic != F5_MAGIC {
        return Err(format!("bad F5 framing (magic={magic:#06x})"));
    }
    let len = be16(buf, 2);
    if buf.len() < 4 + len {
        return Ok(None);
    }
    Ok(Some(Frame::Ppp(buf.drain(..4 + len).skip(4).collect())))
}

/// The FCS is stripped, not verified (the TLS/DTLS record already is).
fn take_hdlc(buf: &mut Vec<u8>) -> Option<Frame> {
    let start = buf
        .iter()
        .position(|&b| b != HDLC_FLAG && b != 0)
        .unwrap_or(buf.len());
    buf.drain(..start);
    let end = buf.iter().position(|&b| b == HDLC_FLAG)?;
    let raw: Vec<u8> = buf.drain(..=end).take(end).collect();
    let mut frame = hdlc_unstuff(&raw);
    // Shorter than address/control, protocol and FCS: dropped by the caller.
    let keep = if frame.len() < 4 { 0 } else { frame.len() - 2 };
    frame.truncate(keep);
    Some(Frame::Ppp(frame))
}

/// `(protocol, payload)` of a PPP frame, `FF 03` optional. An odd first protocol
/// octet is a PFC-compressed 1-byte protocol.
pub fn parse_frame(frame: &[u8]) -> Option<(u16, Vec<u8>)> {
    let off = if frame.starts_with(&[0xff, 0x03]) {
        2
    } else {
        0
    };
    let first = *frame.get(off)?;
    if first & 1 == 1 {
        return Some((first as u16, frame[off + 1..].to_vec()));
    }
    let second = *frame.get(off + 1)?;
    Some((
        u16::from_be_bytes([first, second]),
        frame[off + 2..].to_vec(),
    ))
}

/// RFC 1662 FCS-16 (initial 0xFFFF, polynomial 0x8408).
fn fcs16(data: &[u8]) -> u16 {
    let mut fcs: u16 = 0xffff;
    for &b in data {
        fcs ^= b as u16;
        for _ in 0..8 {
            fcs = if fcs & 1 != 0 {
                (fcs >> 1) ^ 0x8408
            } else {
                fcs >> 1
            };
        }
    }
    fcs
}

/// Escapes every byte below 0x20 as well as the flag and escape bytes, which a
/// peer accepts whatever ACCM was negotiated.
fn hdlc_encode(frame: &[u8], out: &mut Vec<u8>) {
    let fcs = fcs16(frame) ^ 0xffff;
    out.push(HDLC_FLAG);
    for &b in frame.iter().chain(&fcs.to_le_bytes()) {
        if b == HDLC_FLAG || b == HDLC_ESC || b < 0x20 {
            out.extend_from_slice(&[HDLC_ESC, b ^ 0x20]);
        } else {
            out.push(b);
        }
    }
    out.push(HDLC_FLAG);
}

fn hdlc_unstuff(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut esc = false;
    for &b in raw {
        if esc {
            out.push(b ^ 0x20);
            esc = false;
        } else if b == HDLC_ESC {
            esc = true;
        } else {
            out.push(b);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(f: Framing, proto: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        f.encode(proto, payload, &mut out);
        out
    }

    #[test]
    fn forti_layout() {
        let w = encoded(Framing::Forti, 0x0021, b"\x45\x00");
        assert_eq!(
            w,
            [0, 12, 0x50, 0x50, 0, 6, 0xff, 0x03, 0x00, 0x21, 0x45, 0x00]
        );
    }

    #[test]
    fn f5_compresses_data_not_control() {
        let w = encoded(Framing::F5, 0x0021, b"\x45\x00\x00\x14");
        assert_eq!(w, [0xf5, 0x00, 0, 5, 0x21, 0x45, 0x00, 0x00, 0x14]);
        let w = encoded(Framing::F5, 0xc021, b"\x01\x01\x00\x04");
        assert_eq!(&w[..8], &[0xf5, 0x00, 0, 8, 0xff, 0x03, 0xc0, 0x21]);
    }

    #[test]
    fn hdlc_fcs_residual_is_good() {
        let frame = b"\xff\x03\xc0\x21\x01\x01\x00\x04";
        let mut with_fcs = frame.to_vec();
        with_fcs.extend_from_slice(&(fcs16(frame) ^ 0xffff).to_le_bytes());
        assert_eq!(fcs16(&with_fcs), 0xf0b8);
    }

    #[test]
    fn hdlc_skips_flag_runs_and_unstuffs() {
        let mut buf = vec![HDLC_FLAG, HDLC_FLAG, 0];
        Framing::Hdlc.encode(0xc021, &[0x7e, 0x7d, 0x01], &mut buf);
        let Some(Frame::Ppp(f)) = Framing::Hdlc.take(&mut buf).unwrap() else {
            panic!("no frame");
        };
        assert_eq!(parse_frame(&f), Some((0xc021, vec![0x7e, 0x7d, 0x01])));
        assert!(buf.is_empty());
        assert!(Framing::Hdlc.take(&mut buf).unwrap().is_none());
    }

    #[test]
    fn pfc_and_short_frames() {
        assert_eq!(
            parse_frame(&[0x21, 0x45, 0x00]),
            Some((0x21, vec![0x45, 0x00]))
        );
        assert_eq!(
            parse_frame(&[0xff, 0x03, 0xc0, 0x21]),
            Some((0xc021, vec![]))
        );
        assert_eq!(parse_frame(&[0xff, 0x03]), None);
        assert_eq!(parse_frame(&[0xff, 0x03, 0xc0]), None);
        assert_eq!(parse_frame(&[]), None);
    }
}
