//! PPP over the Fortinet SSL-VPN tunnel (in-process, no pppd).
//!
//! Framing on the TLS stream (one header per packet; `encap_len = 6`):
//!
//! ```text
//!   [u16 be total_len = ppp_frame_len + 6]
//!   [u16    0x5050]                         magic 'PP'
//!   [u16 be ppp_frame_len]
//!   [ppp_frame]
//! ```
//!
//! The PPP frame itself is NOT HDLC (no 0x7e flags, no byte-stuffing, no FCS):
//!   `FF 03` (address+control, always — Fortinet clears ACCOMP)
//!   `[u16 be protocol]`   0xC021 LCP · 0x8021 IPCP · 0x0021 IPv4
//!   `[payload]`
//!
//! Because a TLS stream can't be split into independent read/write halves and a
//! partial record must not corrupt the framing, all reads go through a buffered
//! [`PppConn`] that extracts only complete frames.

use std::io::{Read, Write};
use std::net::Ipv4Addr;

pub const PPP_LCP: u16 = 0xc021;
pub const PPP_IPCP: u16 = 0x8021;
pub const PPP_IPV4: u16 = 0x0021;

const FRAME_MAGIC: u16 = 0x5050;
/// The gateway interleaves Fortinet control records — `[be16 len]"GF"type\0…` (the
/// `svrhello-tun`/heartbeat messages, "GF" = 0x4746) — with PPP frames, especially
/// over DTLS. They are not PPP, so `take_frame` surfaces them under this pseudo-proto
/// for the data loop to ignore (while still counting as inbound liveness). Not a real
/// PPP protocol number, so it can't collide with LCP/IPCP/IPv4.
pub const FORTI_CTRL: u16 = 0xffff;
const GF_MAGIC: u16 = 0x4746;

// PPP control codes (RFC 1661 §5).
const CONF_REQ: u8 = 1;
const CONF_ACK: u8 = 2;
const CONF_NAK: u8 = 3;
const CONF_REJ: u8 = 4;
const TERM_REQ: u8 = 5;
const TERM_ACK: u8 = 6;
const ECHO_REQ: u8 = 9;
const ECHO_REP: u8 = 10;

const LCP_OPT_MRU: u8 = 1;
const LCP_OPT_MAGIC: u8 = 5;

const IPCP_OPT_IP: u8 = 3;
const IPCP_OPT_DNS1: u8 = 129;
const IPCP_OPT_DNS2: u8 = 131;

/// Default MRU we advertise (≈10 bytes of PPP/encap overhead beyond TLS).
const DEFAULT_MRU: u16 = 1354;

#[derive(Debug, Clone)]
pub struct IpConfig {
    pub addr: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    /// The MRU the gateway asked for in its LCP Configure-Request: the largest PPP
    /// payload it accepts, so our tun MTU must not exceed it.
    pub peer_mru: Option<u16>,
}

/// Any byte transport a PPP link can run over (TLS stream, DTLS records).
pub trait Transport: Read + Write {}
impl<T: Read + Write> Transport for T {}

/// Buffers input so partial TLS records never corrupt frame boundaries.
pub struct PppConn<S> {
    stream: S,
    rbuf: Vec<u8>,
    /// Socket fd to wait on when a non-blocking write would block. Set once the link
    /// is in the (non-blocking) data phase; then `fill` also drains to `WouldBlock`.
    poll_fd: Option<i32>,
    txbuf: Vec<u8>,
    /// Whether several frames may share one write (true for a byte stream like TLS;
    /// false for DTLS, where each record must carry exactly one frame).
    coalesce: bool,
}

/// A read returned no data (timeout in blocking mode, or WouldBlock in
/// non-blocking mode) — the caller decides whether to retransmit or poll again.
pub const WOULDBLOCK: &str = "__wouldblock__";

impl<S: Read + Write> PppConn<S> {
    pub fn new(stream: S) -> Self {
        PppConn { stream, rbuf: Vec::with_capacity(4096), poll_fd: None, txbuf: Vec::new(), coalesce: true }
    }

    /// One frame per write (record-oriented transports such as DTLS).
    pub fn set_record_mode(&mut self) {
        self.coalesce = false;
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Erase the transport type, keeping any buffered input.
    pub fn boxed(self) -> PppConn<Box<dyn Transport>>
    where
        S: 'static,
    {
        PppConn {
            stream: Box::new(self.stream),
            rbuf: self.rbuf,
            poll_fd: self.poll_fd,
            txbuf: self.txbuf,
            coalesce: self.coalesce,
        }
    }

    /// The stream is now non-blocking: make `send` wait for `fd` to be writable
    /// instead of failing when the socket's send buffer is full.
    pub fn set_poll_fd(&mut self, fd: i32) {
        self.poll_fd = Some(fd);
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Flushes queued data frames first, so ordering is preserved.
    pub fn send(&mut self, proto: u16, payload: &[u8]) -> Result<(), String> {
        self.flush_tx()?;
        let mut out = Vec::with_capacity(10 + payload.len());
        encode_frame(proto, payload, &mut out);
        self.write_out(&out)
    }

    /// Queue a data frame; `flush_tx` writes the batch. On a byte stream a burst of
    /// packets then costs one TLS record + one syscall instead of one per packet.
    /// In record mode it is just `send`.
    pub fn queue(&mut self, proto: u16, payload: &[u8]) -> Result<(), String> {
        if !self.coalesce {
            return self.send(proto, payload);
        }
        encode_frame(proto, payload, &mut self.txbuf);
        if self.txbuf.len() >= 16 * 1024 {
            self.flush_tx()?;
        }
        Ok(())
    }

    pub fn flush_tx(&mut self) -> Result<(), String> {
        if self.txbuf.is_empty() {
            return Ok(());
        }
        let out = std::mem::take(&mut self.txbuf);
        let r = self.write_out(&out);
        self.txbuf = out;
        self.txbuf.clear();
        r
    }

    fn write_out(&mut self, out: &[u8]) -> Result<(), String> {
        crate::sysnet::write_all_polling(&mut self.stream, self.poll_fd, out).map_err(|e| format!("ppp {e}"))?;
        self.stream.flush().ok();
        Ok(())
    }

    /// Pull one complete frame from the buffer without doing I/O. Returns
    /// `(protocol, payload)` with the 6-byte header and optional `FF 03` stripped.
    pub fn take_frame(&mut self) -> Result<Option<(u16, Vec<u8>)>, String> {
        if self.rbuf.len() >= 4 && &self.rbuf[0..4] == b"HTTP" {
            // The gateway answered with HTTP. On success some gateways send
            // `200 OK` then switch straight to PPP; on failure, an error status.
            let Some(end) = self.rbuf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) else {
                return Ok(None);
            };
            let head = String::from_utf8_lossy(&self.rbuf[..end]);
            let status = head.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
            if status == 200 {
                self.rbuf.drain(..end);
            } else {
                let first = head.lines().next().unwrap_or("").trim().to_string();
                return Err(format!("tunnel refused (HTTP): {first}"));
            }
        }
        if self.rbuf.len() < 6 {
            return Ok(None);
        }
        let total = u16::from_be_bytes([self.rbuf[0], self.rbuf[1]]) as usize;
        let magic = u16::from_be_bytes([self.rbuf[2], self.rbuf[3]]);
        // A Fortinet control record (`[be16 len]"GF"…`): drain its `len` bytes and
        // report it as control, so a heartbeat can't desync the PPP byte stream.
        if magic == GF_MAGIC {
            if total < 4 {
                return Err(format!("bad Fortinet control record (len={total})"));
            }
            if self.rbuf.len() < total {
                return Ok(None);
            }
            let rec: Vec<u8> = self.rbuf.drain(..total).skip(2).collect();
            return Ok(Some((FORTI_CTRL, rec)));
        }
        let frame_len = u16::from_be_bytes([self.rbuf[4], self.rbuf[5]]) as usize;
        if magic != FRAME_MAGIC || total != frame_len + 6 {
            return Err(format!(
                "bad Fortinet framing (magic={magic:#06x} total={total} frame_len={frame_len})"
            ));
        }
        if self.rbuf.len() < 6 + frame_len {
            return Ok(None);
        }
        let frame: Vec<u8> = self.rbuf.drain(..6 + frame_len).skip(6).collect();
        let mut off = 0;
        if frame.len() >= 2 && frame[0] == 0xff && frame[1] == 0x03 {
            off = 2;
        }
        if frame.len() < off + 2 {
            return Err("PPP frame too short for protocol field".into());
        }
        let proto = u16::from_be_bytes([frame[off], frame[off + 1]]);
        Ok(Some((proto, frame[off + 2..].to_vec())))
    }

    /// Read into the buffer. Maps timeout/WouldBlock to `Ok(0)`. During negotiation
    /// (blocking reads with a timeout) this is one `read`; in the non-blocking data
    /// phase it drains until `WouldBlock`: TLS decrypts whole records into its own
    /// buffer, so data can sit there while `poll(fd)` reports nothing — a single
    /// read per wakeup would leave packets stranded until the next one.
    pub fn fill(&mut self) -> Result<usize, String> {
        let mut tmp = [0u8; 16384];
        let mut total = 0;
        loop {
            match self.stream.read(&mut tmp) {
                Ok(0) if total > 0 => return Ok(total),
                Ok(0) => return Err("tunnel closed by peer".into()),
                Ok(n) => {
                    self.rbuf.extend_from_slice(&tmp[..n]);
                    total += n;
                    if self.poll_fd.is_none() || total >= 256 * 1024 {
                        return Ok(total);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    return Ok(total)
                }
                Err(e) => return Err(format!("tunnel read: {e}")),
            }
        }
    }

    /// Blocking receive of one frame (the socket must have a read timeout set).
    /// Returns `Err(WOULDBLOCK)` on timeout with no complete frame.
    pub fn recv_blocking(&mut self) -> Result<(u16, Vec<u8>), String> {
        loop {
            if let Some(f) = self.take_frame()? {
                return Ok(f);
            }
            let n = self.fill()?;
            if n == 0 {
                return Err(WOULDBLOCK.into());
            }
        }
    }
}

fn encode_frame(proto: u16, payload: &[u8], out: &mut Vec<u8>) {
    let frame_len = 4 + payload.len();
    out.extend_from_slice(&((frame_len + 6) as u16).to_be_bytes());
    out.extend_from_slice(&FRAME_MAGIC.to_be_bytes());
    out.extend_from_slice(&(frame_len as u16).to_be_bytes());
    out.push(0xff);
    out.push(0x03);
    out.extend_from_slice(&proto.to_be_bytes());
    out.extend_from_slice(payload);
}

fn ctrl(code: u8, id: u8, options: &[u8]) -> Vec<u8> {
    let len = 4 + options.len();
    let mut v = Vec::with_capacity(len);
    v.push(code);
    v.push(id);
    v.extend_from_slice(&(len as u16).to_be_bytes());
    v.extend_from_slice(options);
    v
}

fn opt(t: u8, val: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + val.len());
    v.push(t);
    v.push((2 + val.len()) as u8);
    v.extend_from_slice(val);
    v
}

struct Ctrl {
    code: u8,
    id: u8,
    body: Vec<u8>,
}

fn parse_ctrl(payload: &[u8]) -> Option<Ctrl> {
    if payload.len() < 4 {
        return None;
    }
    let len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let end = len.min(payload.len());
    Some(Ctrl { code: payload[0], id: payload[1], body: payload[4..end].to_vec() })
}

fn iter_opts(body: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= body.len() {
        let t = body[i];
        let l = body[i + 1] as usize;
        if l < 2 || i + l > body.len() {
            break;
        }
        out.push((t, body[i + 2..i + l].to_vec()));
        i += l;
    }
    out
}

/// Run LCP then IPCP to completion. The socket must have a read timeout set.
pub fn negotiate<S: Read + Write>(conn: &mut PppConn<S>) -> Result<IpConfig, String> {
    let magic: [u8; 4] = crate::ike::crypto::random(4).try_into().unwrap_or([1, 2, 3, 4]);
    let peer_mru = lcp_phase(conn, &magic)?;
    let mut ipc = ipcp_phase(conn)?;
    ipc.peer_mru = peer_mru;
    Ok(ipc)
}

fn mru_option(body: &[u8]) -> Option<u16> {
    iter_opts(body).into_iter().find(|(t, v)| *t == LCP_OPT_MRU && v.len() == 2).map(|(_, v)| u16::from_be_bytes([v[0], v[1]]))
}

/// Returns the gateway's MRU (from its Configure-Request).
fn lcp_phase<S: Read + Write>(conn: &mut PppConn<S>, magic: &[u8; 4]) -> Result<Option<u16>, String> {
    let mut our_opts = Vec::new();
    our_opts.extend_from_slice(&opt(LCP_OPT_MRU, &DEFAULT_MRU.to_be_bytes()));
    our_opts.extend_from_slice(&opt(LCP_OPT_MAGIC, magic));

    let mut id = 1u8;
    let mut our_acked = false;
    let mut peer_acked = false;
    let mut peer_mru = None;
    conn.send(PPP_LCP, &ctrl(CONF_REQ, id, &our_opts))?;

    let mut tries = 0;
    while !(our_acked && peer_acked) {
        match conn.recv_blocking() {
            Ok((PPP_LCP, payload)) => {
                let Some(c) = parse_ctrl(&payload) else { continue };
                match c.code {
                    CONF_REQ => {
                        peer_mru = mru_option(&c.body).or(peer_mru);
                        conn.send(PPP_LCP, &ctrl(CONF_ACK, c.id, &c.body))?;
                        peer_acked = true;
                    }
                    CONF_ACK => our_acked = true,
                    CONF_NAK | CONF_REJ => {
                        id = id.wrapping_add(1);
                        our_opts = opt(LCP_OPT_MRU, &DEFAULT_MRU.to_be_bytes());
                        conn.send(PPP_LCP, &ctrl(CONF_REQ, id, &our_opts))?;
                    }
                    ECHO_REQ => conn.send(PPP_LCP, &ctrl(ECHO_REP, c.id, &c.body))?,
                    TERM_REQ => {
                        conn.send(PPP_LCP, &ctrl(TERM_ACK, c.id, &[]))?;
                        return Err("gateway terminated LCP".into());
                    }
                    _ => {}
                }
            }
            Ok((_other, _)) => {}
            Err(e) if e == WOULDBLOCK => {
                tries += 1;
                if tries > 10 {
                    return Err("LCP negotiation timed out".into());
                }
                if !our_acked {
                    conn.send(PPP_LCP, &ctrl(CONF_REQ, id, &our_opts))?;
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(peer_mru)
}

fn ipcp_phase<S: Read + Write>(conn: &mut PppConn<S>) -> Result<IpConfig, String> {
    let mut want_ip = Ipv4Addr::UNSPECIFIED;
    let mut dns1 = Ipv4Addr::UNSPECIFIED;
    let mut dns2 = Ipv4Addr::UNSPECIFIED;

    let build_req = |ip: Ipv4Addr, d1: Ipv4Addr, d2: Ipv4Addr| -> Vec<u8> {
        let mut o = Vec::new();
        o.extend_from_slice(&opt(IPCP_OPT_IP, &ip.octets()));
        o.extend_from_slice(&opt(IPCP_OPT_DNS1, &d1.octets()));
        o.extend_from_slice(&opt(IPCP_OPT_DNS2, &d2.octets()));
        o
    };

    let mut id = 1u8;
    let mut our_acked = false;
    let mut peer_acked = false;
    conn.send(PPP_IPCP, &ctrl(CONF_REQ, id, &build_req(want_ip, dns1, dns2)))?;

    let mut tries = 0;
    while !(our_acked && peer_acked) {
        match conn.recv_blocking() {
            Ok((PPP_IPCP, payload)) => {
                let Some(c) = parse_ctrl(&payload) else { continue };
                match c.code {
                    CONF_REQ => {
                        conn.send(PPP_IPCP, &ctrl(CONF_ACK, c.id, &c.body))?;
                        peer_acked = true;
                    }
                    CONF_ACK => our_acked = true,
                    CONF_NAK => {
                        for (t, v) in iter_opts(&c.body) {
                            if v.len() == 4 {
                                let a = Ipv4Addr::new(v[0], v[1], v[2], v[3]);
                                match t {
                                    IPCP_OPT_IP => want_ip = a,
                                    IPCP_OPT_DNS1 => dns1 = a,
                                    IPCP_OPT_DNS2 => dns2 = a,
                                    _ => {}
                                }
                            }
                        }
                        id = id.wrapping_add(1);
                        conn.send(PPP_IPCP, &ctrl(CONF_REQ, id, &build_req(want_ip, dns1, dns2)))?;
                    }
                    CONF_REJ => {
                        id = id.wrapping_add(1);
                        conn.send(PPP_IPCP, &ctrl(CONF_REQ, id, &opt(IPCP_OPT_IP, &want_ip.octets())))?;
                    }
                    TERM_REQ => {
                        conn.send(PPP_IPCP, &ctrl(TERM_ACK, c.id, &[]))?;
                        return Err("gateway terminated IPCP".into());
                    }
                    _ => {}
                }
            }
            Ok((PPP_LCP, payload)) => {
                if let Some(c) = parse_ctrl(&payload) {
                    match c.code {
                        ECHO_REQ => conn.send(PPP_LCP, &ctrl(ECHO_REP, c.id, &c.body))?,
                        TERM_REQ => {
                            conn.send(PPP_LCP, &ctrl(TERM_ACK, c.id, &[]))?;
                            return Err("gateway terminated link during IPCP".into());
                        }
                        _ => {}
                    }
                }
            }
            Ok((_other, _)) => {}
            Err(e) if e == WOULDBLOCK => {
                tries += 1;
                if tries > 10 {
                    return Err("IPCP negotiation timed out".into());
                }
                if !our_acked {
                    conn.send(PPP_IPCP, &ctrl(CONF_REQ, id, &build_req(want_ip, dns1, dns2)))?;
                }
            }
            Err(e) => return Err(e),
        }
    }

    if want_ip.is_unspecified() {
        return Err("IPCP completed without assigning an IP address".into());
    }
    let mut dns = Vec::new();
    if !dns1.is_unspecified() {
        dns.push(dns1);
    }
    if !dns2.is_unspecified() {
        dns.push(dns2);
    }
    Ok(IpConfig { addr: want_ip, dns, peer_mru: None })
}

/// Magic 0, no data.
pub fn echo_request(id: u8) -> Vec<u8> {
    ctrl(ECHO_REQ, id, &[0, 0, 0, 0])
}

pub fn terminate_request(id: u8) -> Vec<u8> {
    ctrl(TERM_REQ, id, &[])
}

/// Service an inbound LCP control frame during the data phase (reply to echo and
/// terminate). Returns `Ok(true)` if the peer asked to terminate.
pub fn handle_lcp_in<S: Read + Write>(conn: &mut PppConn<S>, payload: &[u8]) -> Result<bool, String> {
    if let Some(c) = parse_ctrl(payload) {
        match c.code {
            ECHO_REQ => conn.send(PPP_LCP, &ctrl(ECHO_REP, c.id, &c.body))?,
            TERM_REQ => {
                conn.send(PPP_LCP, &ctrl(TERM_ACK, c.id, &[]))?;
                return Ok(true);
            }
            _ => {}
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn nonblocking_send_waits_for_a_full_buffer_to_drain() {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;
        let (tx, mut rx) = UnixStream::pair().unwrap();
        tx.set_nonblocking(true).unwrap();
        let fd = tx.as_raw_fd();
        let mut conn = PppConn::new(tx);
        conn.set_poll_fd(fd);
        // A slow peer: starts reading only after the send buffer has long been full.
        let reader = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            let mut sink = Vec::new();
            rx.read_to_end(&mut sink).unwrap();
            sink.len()
        });
        let payload = [0x45u8; 1400];
        for _ in 0..2000 {
            // ~2.8 MB: far past the socket buffer — must block-and-retry, never fail.
            conn.send(PPP_IPV4, &payload).expect("send must not fail on WouldBlock");
        }
        drop(conn);
        assert_eq!(reader.join().unwrap(), 2000 * (6 + 4 + 1400));
    }

    #[test]
    fn framing_round_trip() {
        let mut c = PppConn::new(Cursor::new(Vec::<u8>::new()));
        c.send(PPP_IPV4, b"\x45\x00ping").unwrap();
        let framed = c.get_ref().get_ref().clone();
        assert_eq!(&framed[2..4], &[0x50, 0x50]);
        let mut r = PppConn::new(Cursor::new(Vec::<u8>::new()));
        r.rbuf.extend_from_slice(&framed);
        let (proto, payload) = r.take_frame().unwrap().unwrap();
        assert_eq!(proto, PPP_IPV4);
        assert_eq!(payload, b"\x45\x00ping");
        assert!(r.take_frame().unwrap().is_none());
    }

    #[test]
    fn queued_frames_coalesce_into_one_write_and_parse_back() {
        let mut c = PppConn::new(Cursor::new(Vec::<u8>::new()));
        c.queue(PPP_IPV4, b"\x45one").unwrap();
        c.queue(PPP_IPV4, b"\x45two").unwrap();
        assert!(c.get_ref().get_ref().is_empty(), "queued, not yet written");
        c.send(PPP_LCP, b"\x09\x01\x00\x08\x00\x00\x00\x00").unwrap(); // flushes the queue first
        let wire = c.get_ref().get_ref().clone();
        let mut r = PppConn::new(Cursor::new(Vec::<u8>::new()));
        r.rbuf.extend_from_slice(&wire);
        assert_eq!(r.take_frame().unwrap().unwrap(), (PPP_IPV4, b"\x45one".to_vec()));
        assert_eq!(r.take_frame().unwrap().unwrap(), (PPP_IPV4, b"\x45two".to_vec()));
        assert_eq!(r.take_frame().unwrap().unwrap().0, PPP_LCP);
        assert!(r.take_frame().unwrap().is_none());
    }

    #[test]
    fn peer_mru_option_is_read() {
        let body = [&opt(LCP_OPT_MAGIC, &[1, 2, 3, 4])[..], &opt(LCP_OPT_MRU, &1354u16.to_be_bytes())[..]].concat();
        assert_eq!(mru_option(&body), Some(1354));
        assert_eq!(mru_option(&opt(LCP_OPT_MAGIC, &[1, 2, 3, 4])), None);
    }

    #[test]
    fn fortinet_control_record_is_demuxed_not_a_framing_error() {
        let mut r = PppConn::new(Cursor::new(Vec::<u8>::new()));
        // A heartbeat control record: [00 13]"GFtype\0svrhello-tun" (len 19).
        let mut rec = vec![0x00u8, 0x00];
        rec.extend_from_slice(b"GFtype\0svrhello-tun");
        let n = rec.len() as u16;
        rec[..2].copy_from_slice(&n.to_be_bytes());
        let mut c = PppConn::new(Cursor::new(Vec::<u8>::new()));
        c.send(PPP_IPV4, b"\x45data").unwrap();
        let ppp_frame = c.get_ref().get_ref().clone();
        r.rbuf.extend_from_slice(&rec);
        r.rbuf.extend_from_slice(&ppp_frame);
        assert_eq!(r.take_frame().unwrap().unwrap().0, FORTI_CTRL);
        // The stream stays in sync: the PPP frame parses right after it.
        assert_eq!(r.take_frame().unwrap().unwrap(), (PPP_IPV4, b"\x45data".to_vec()));
        assert!(r.take_frame().unwrap().is_none());
    }

    #[test]
    fn detects_bad_magic() {
        let mut r = PppConn::new(Cursor::new(Vec::<u8>::new()));
        // total=8, magic=0x1234 (wrong), frame_len=2
        r.rbuf.extend_from_slice(&[0x00, 0x08, 0x12, 0x34, 0x00, 0x02, 0xff, 0x03]);
        assert!(r.take_frame().is_err());
    }

    #[test]
    fn detects_http_error_response() {
        let mut r = PppConn::new(Cursor::new(Vec::<u8>::new()));
        r.rbuf.extend_from_slice(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        let e = r.take_frame().unwrap_err();
        assert!(e.contains("HTTP"));
    }

    #[test]
    fn partial_frame_waits() {
        let mut r = PppConn::new(Cursor::new(Vec::<u8>::new()));
        // claims frame_len 100 but only a few bytes present
        r.rbuf.extend_from_slice(&[0x00, 106, 0x50, 0x50, 0x00, 100, 0xff, 0x03]);
        assert!(r.take_frame().unwrap().is_none());
    }
}
