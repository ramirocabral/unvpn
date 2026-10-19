//! PPP over the Fortinet SSL-VPN tunnel (in-process, no pppd).
//!
//! Framing on the TLS stream (one header per packet; `encap_len = 6`), verified
//! against openconnect's `PPP_ENCAP_FORTINET` and the FortiClient `vpn` binary:
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

// PPP control codes (RFC 1661 §5).
const CONF_REQ: u8 = 1;
const CONF_ACK: u8 = 2;
const CONF_NAK: u8 = 3;
const CONF_REJ: u8 = 4;
const TERM_REQ: u8 = 5;
const TERM_ACK: u8 = 6;
const ECHO_REQ: u8 = 9;
const ECHO_REP: u8 = 10;

// LCP option types.
const LCP_OPT_MRU: u8 = 1;
const LCP_OPT_MAGIC: u8 = 5;

// IPCP option types.
const IPCP_OPT_IP: u8 = 3;
const IPCP_OPT_DNS1: u8 = 129;
const IPCP_OPT_DNS2: u8 = 131;

/// Default MRU we advertise (≈10 bytes of PPP/encap overhead beyond TLS).
const DEFAULT_MRU: u16 = 1354;

/// What IPCP negotiation produced.
#[derive(Debug, Clone)]
pub struct IpConfig {
    pub addr: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
}

// ───────────────────────── buffered connection ──────────────────────────────

/// A PPP connection over a byte stream (the TLS tunnel). Buffers input so partial
/// TLS records never corrupt frame boundaries.
pub struct PppConn<S> {
    stream: S,
    rbuf: Vec<u8>,
    /// Socket fd to wait on when a non-blocking write would block.
    poll_fd: Option<i32>,
}

/// A read returned no data (timeout in blocking mode, or WouldBlock in
/// non-blocking mode) — the caller decides whether to retransmit or poll again.
pub const WOULDBLOCK: &str = "__wouldblock__";

impl<S: Read + Write> PppConn<S> {
    pub fn new(stream: S) -> Self {
        PppConn { stream, rbuf: Vec::with_capacity(4096), poll_fd: None }
    }

    /// The stream is now non-blocking: make `send` wait for `fd` to be writable
    /// instead of failing when the socket's send buffer is full.
    pub fn set_poll_fd(&mut self, fd: i32) {
        self.poll_fd = Some(fd);
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Send a PPP frame (protocol + payload) wrapped in the 6-byte header.
    pub fn send(&mut self, proto: u16, payload: &[u8]) -> Result<(), String> {
        let frame_len = 4 + payload.len();
        let total = frame_len + 6;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&(total as u16).to_be_bytes());
        out.extend_from_slice(&FRAME_MAGIC.to_be_bytes());
        out.extend_from_slice(&(frame_len as u16).to_be_bytes());
        out.push(0xff);
        out.push(0x03);
        out.extend_from_slice(&proto.to_be_bytes());
        out.extend_from_slice(payload);
        crate::sysnet::write_all_polling(&mut self.stream, self.poll_fd, &out).map_err(|e| format!("ppp {e}"))?;
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
                return Ok(None); // headers not fully arrived yet
            };
            let head = String::from_utf8_lossy(&self.rbuf[..end]);
            let status = head.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
            if status == 200 {
                self.rbuf.drain(..end); // consume headers; PPP frames follow
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
        let frame_len = u16::from_be_bytes([self.rbuf[4], self.rbuf[5]]) as usize;
        if magic != FRAME_MAGIC || total != frame_len + 6 {
            return Err(format!(
                "bad Fortinet framing (magic={magic:#06x} total={total} frame_len={frame_len})"
            ));
        }
        if self.rbuf.len() < 6 + frame_len {
            return Ok(None); // incomplete — wait for more bytes
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

    /// Do one `read` into the buffer. Maps timeout/WouldBlock to `Ok(0)`.
    pub fn fill(&mut self) -> Result<usize, String> {
        let mut tmp = [0u8; 16384];
        match self.stream.read(&mut tmp) {
            Ok(0) => Err("tunnel closed by peer".into()),
            Ok(n) => {
                self.rbuf.extend_from_slice(&tmp[..n]);
                Ok(n)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                Ok(0)
            }
            Err(e) => Err(format!("tunnel read: {e}")),
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

// ───────────────────────── control packet build ─────────────────────────────

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

// ─────────────────────────── negotiation ────────────────────────────────────

/// Run LCP then IPCP to completion. The socket must have a read timeout set.
pub fn negotiate<S: Read + Write>(conn: &mut PppConn<S>) -> Result<IpConfig, String> {
    let magic: [u8; 4] = crate::ike::crypto::random(4).try_into().unwrap_or([1, 2, 3, 4]);
    lcp_phase(conn, &magic)?;
    ipcp_phase(conn)
}

fn lcp_phase<S: Read + Write>(conn: &mut PppConn<S>, magic: &[u8; 4]) -> Result<(), String> {
    let mut our_opts = Vec::new();
    our_opts.extend_from_slice(&opt(LCP_OPT_MRU, &DEFAULT_MRU.to_be_bytes()));
    our_opts.extend_from_slice(&opt(LCP_OPT_MAGIC, magic));

    let mut id = 1u8;
    let mut our_acked = false;
    let mut peer_acked = false;
    conn.send(PPP_LCP, &ctrl(CONF_REQ, id, &our_opts))?;

    let mut tries = 0;
    while !(our_acked && peer_acked) {
        match conn.recv_blocking() {
            Ok((PPP_LCP, payload)) => {
                let Some(c) = parse_ctrl(&payload) else { continue };
                match c.code {
                    CONF_REQ => {
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
    Ok(())
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
    Ok(IpConfig { addr: want_ip, dns })
}

/// Build an LCP Echo-Request body (magic 0 + no data) for keepalive.
pub fn echo_request(id: u8) -> Vec<u8> {
    ctrl(ECHO_REQ, id, &[0, 0, 0, 0])
}

/// Build an LCP Terminate-Request for a clean shutdown.
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
        // send() writes the 6-byte header + FF03 + proto + payload; take_frame() parses it.
        let mut c = PppConn::new(Cursor::new(Vec::<u8>::new()));
        c.send(PPP_IPV4, b"\x45\x00ping").unwrap();
        let framed = c.get_ref().get_ref().clone();
        // header: total=4+6+... check magic bytes present
        assert_eq!(&framed[2..4], &[0x50, 0x50]);
        // feed into a fresh conn's buffer and parse
        let mut r = PppConn::new(Cursor::new(Vec::<u8>::new()));
        r.rbuf.extend_from_slice(&framed);
        let (proto, payload) = r.take_frame().unwrap().unwrap();
        assert_eq!(proto, PPP_IPV4);
        assert_eq!(payload, b"\x45\x00ping");
        // buffer fully consumed
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
        // claims frame_len 100 but only a few bytes present → None (wait for more)
        r.rbuf.extend_from_slice(&[0x00, 106, 0x50, 0x50, 0x00, 100, 0xff, 0x03]);
        assert!(r.take_frame().unwrap().is_none());
    }
}
