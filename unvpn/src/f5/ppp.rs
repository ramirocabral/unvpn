//! PPP over the F5 BIG-IP APM SSL-VPN tunnel (in-process, no pppd).
//!
//! F5 offers two framings on the byte stream, chosen by the `hdlc_framing` option:
//!
//!   * **F5** (non-HDLC, `encap_len = 6` here): one 4-byte header per packet,
//!     verified against openconnect's `PPP_ENCAP_F5` and `ppp.c`:
//!     ```text
//!       [u16 be 0xf500]            magic
//!       [u16 be payload_len]       = len(PPP frame)
//!       [PPP frame]
//!     ```
//!   * **F5 HDLC**: classic RFC1662 async-HDLC — `7e` flags, `7d`/`20` byte-stuffing
//!     and a trailing FCS-16. (openconnect disables DTLS in this mode because HDLC
//!     makes the MTU unpredictable; the TLS data plane still supports it.)
//!
//! The PPP frame itself is `FF 03` (address+control) + `[protocol]` (1 or 2 bytes)
//! + payload. We always *send* `FF 03` + a 2-byte protocol (always accepted); on
//! receive we tolerate a missing `FF 03` and a PFC-compressed 1-byte protocol.
//!
//! The LCP/IPCP state machine mirrors the Fortinet back-end (same RFC1661/1332
//! logic); only the on-the-wire framing differs.

use std::io::{Read, Write};
use std::net::Ipv4Addr;

pub const PPP_LCP: u16 = 0xc021;
pub const PPP_IPCP: u16 = 0x8021;
pub const PPP_IPV4: u16 = 0x0021;

const F5_MAGIC: u16 = 0xf500;
const HDLC_FLAG: u8 = 0x7e;
const HDLC_ESC: u8 = 0x7d;

// PPP control codes (RFC 1661 §5).
const CONF_REQ: u8 = 1;
const CONF_ACK: u8 = 2;
const CONF_NAK: u8 = 3;
const CONF_REJ: u8 = 4;
const TERM_REQ: u8 = 5;
const TERM_ACK: u8 = 6;
const ECHO_REQ: u8 = 9;
const ECHO_REP: u8 = 10;
const DISCARD_REQ: u8 = 11;

// LCP option types.
const LCP_OPT_MRU: u8 = 1;
const LCP_OPT_MAGIC: u8 = 5;

// IPCP option types.
const IPCP_OPT_IP: u8 = 3;
const IPCP_OPT_DNS1: u8 = 129;
const IPCP_OPT_DNS2: u8 = 131;

/// Default MRU we advertise.
const DEFAULT_MRU: u16 = 1354;

/// Which on-the-wire framing the tunnel uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// F5 4-byte header `[0xf500][len]`.
    F5,
    /// RFC1662 async-HDLC.
    Hdlc,
}

/// What IPCP negotiation produced.
#[derive(Debug, Clone)]
pub struct IpConfig {
    pub addr: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    /// The MRU the gateway asked for in its LCP Configure-Request (caps our MTU).
    pub peer_mru: Option<u16>,
}

pub use crate::forti::ppp::Transport;

// ───────────────────────── buffered connection ──────────────────────────────

/// A PPP connection over a byte stream (the TLS tunnel). Buffers input so partial
/// TLS records never corrupt frame boundaries.
pub struct PppConn<S> {
    stream: S,
    rbuf: Vec<u8>,
    framing: Framing,
    /// Socket fd to wait on when a non-blocking write would block. Set once the link
    /// is in the (non-blocking) data phase; then `fill` also drains to `WouldBlock`.
    poll_fd: Option<i32>,
    /// Data frames queued by [`PppConn::queue`], written in one go by `flush_tx`.
    txbuf: Vec<u8>,
    /// Several frames per write (TLS byte stream) vs exactly one per record (DTLS).
    coalesce: bool,
}

/// A read returned no data (timeout / WouldBlock).
pub const WOULDBLOCK: &str = "__wouldblock__";

impl<S: Read + Write> PppConn<S> {
    pub fn new(stream: S, framing: Framing) -> Self {
        PppConn { stream, rbuf: Vec::with_capacity(4096), framing, poll_fd: None, txbuf: Vec::new(), coalesce: true }
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
            framing: self.framing,
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

    /// Seed the read buffer with bytes already pulled off the stream — e.g. PPP
    /// bytes that arrived in the same TLS record as the `GET /myvpn` HTTP response.
    pub fn feed(&mut self, data: &[u8]) {
        self.rbuf.extend_from_slice(data);
    }

    /// Send a PPP frame (protocol + payload) under the active framing.
    ///
    /// Framing of the PPP header matches the real F5 data plane (cross-checked
    /// against openconnect and gof5): control protocols (LCP/IPCP/IP6CP, ≥0x0100)
    /// go out uncompressed as `FF 03` + 2-byte protocol, while IP data protocols
    /// (0x0021 / 0x0057) use ACFC+PFC — a bare 1-byte protocol, no `FF 03` — which
    /// is exactly what F5's own client emits (`[0xf500][len][0x21][ip]`).
    pub fn send(&mut self, proto: u16, payload: &[u8]) -> Result<(), String> {
        self.flush_tx()?;
        let out = self.encode(proto, payload);
        self.write_out(&out)
    }

    /// Queue a data frame; `flush_tx` writes the batch (one TLS record + one syscall
    /// per burst on a byte stream). In record mode it is just `send`.
    pub fn queue(&mut self, proto: u16, payload: &[u8]) -> Result<(), String> {
        if !self.coalesce {
            return self.send(proto, payload);
        }
        let out = self.encode(proto, payload);
        self.txbuf.extend_from_slice(&out);
        if self.txbuf.len() >= 16 * 1024 {
            self.flush_tx()?;
        }
        Ok(())
    }

    /// Write out the frames queued by `queue`.
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

    /// One frame under the active framing (see `send` for the header rules).
    fn encode(&self, proto: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(4 + payload.len());
        if proto < 0x0100 {
            frame.push(proto as u8);
        } else {
            frame.push(0xff);
            frame.push(0x03);
            frame.extend_from_slice(&proto.to_be_bytes());
        }
        frame.extend_from_slice(payload);

        match self.framing {
            Framing::F5 => {
                let mut o = Vec::with_capacity(4 + frame.len());
                o.extend_from_slice(&F5_MAGIC.to_be_bytes());
                o.extend_from_slice(&(frame.len() as u16).to_be_bytes());
                o.extend_from_slice(&frame);
                o
            }
            Framing::Hdlc => hdlc_encode(&frame),
        }
    }

    /// Pull one complete frame from the buffer without doing I/O. Returns
    /// `(protocol, payload)` with framing, `FF 03` and protocol field stripped.
    pub fn take_frame(&mut self) -> Result<Option<(u16, Vec<u8>)>, String> {
        // A mid-stream HTTP status means the gateway refused the tunnel.
        if self.rbuf.len() >= 4 && &self.rbuf[0..4] == b"HTTP" {
            let Some(end) = self.rbuf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) else {
                return Ok(None);
            };
            let head = String::from_utf8_lossy(&self.rbuf[..end]);
            let status = head.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
            if status == 200 || status == 201 {
                self.rbuf.drain(..end);
            } else {
                let first = head.lines().next().unwrap_or("").trim().to_string();
                return Err(format!("tunnel refused (HTTP): {first}"));
            }
        }
        let frame = match self.framing {
            Framing::F5 => match self.take_f5_frame()? {
                Some(f) => f,
                None => return Ok(None),
            },
            Framing::Hdlc => match self.take_hdlc_frame()? {
                Some(f) => f,
                None => return Ok(None),
            },
        };
        Ok(parse_ppp_frame(&frame))
    }

    /// Non-HDLC: `[0xf500][len][frame]`.
    fn take_f5_frame(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.rbuf.len() < 4 {
            return Ok(None);
        }
        let magic = u16::from_be_bytes([self.rbuf[0], self.rbuf[1]]);
        let payload_len = u16::from_be_bytes([self.rbuf[2], self.rbuf[3]]) as usize;
        if magic != F5_MAGIC {
            return Err(format!("bad F5 framing (magic={magic:#06x})"));
        }
        if self.rbuf.len() < 4 + payload_len {
            return Ok(None);
        }
        let frame: Vec<u8> = self.rbuf.drain(..4 + payload_len).skip(4).collect();
        Ok(Some(frame))
    }

    /// HDLC: a `7e`-delimited, byte-stuffed frame with a trailing FCS-16.
    fn take_hdlc_frame(&mut self) -> Result<Option<Vec<u8>>, String> {
        // Drop leading flags / nulls.
        let mut start = 0;
        while start < self.rbuf.len() && (self.rbuf[start] == HDLC_FLAG || self.rbuf[start] == 0) {
            start += 1;
        }
        if start > 0 {
            self.rbuf.drain(..start);
        }
        // Need a closing flag.
        let Some(end) = self.rbuf.iter().position(|&b| b == HDLC_FLAG) else {
            return Ok(None); // frame not complete yet
        };
        let raw: Vec<u8> = self.rbuf.drain(..=end).take(end).collect();
        let unstuffed = hdlc_unstuff(&raw);
        if unstuffed.len() < 4 {
            // Too short to hold FF03/proto + FCS — skip (keepalive flag run, etc.).
            return Ok(Some(Vec::new()));
        }
        // Strip the 2-byte FCS (not strictly verified here).
        let frame = unstuffed[..unstuffed.len() - 2].to_vec();
        Ok(Some(frame))
    }

    /// Do one `read` into the buffer. Maps timeout/WouldBlock to `Ok(0)`.
    pub fn fill(&mut self) -> Result<usize, String> {
        // One read while negotiating (blocking with a timeout); in the non-blocking
        // data phase, drain to WouldBlock — TLS keeps decrypted records in its own
        // buffer where poll(fd) can't see them.
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

/// Strip optional `FF 03` and a 1- or 2-byte protocol field from a PPP frame.
/// A protocol's low-order bit is 1, so an odd first octet is a PFC-compressed
/// single-byte protocol; an even one is the high byte of a 2-byte protocol.
fn parse_ppp_frame(frame: &[u8]) -> Option<(u16, Vec<u8>)> {
    let mut off = 0;
    if frame.len() >= 2 && frame[0] == 0xff && frame[1] == 0x03 {
        off = 2;
    }
    if off >= frame.len() {
        return None;
    }
    if frame[off] & 1 == 1 {
        // PFC-compressed single-byte protocol.
        let proto = frame[off] as u16;
        Some((proto, frame[off + 1..].to_vec()))
    } else {
        if off + 2 > frame.len() {
            return None;
        }
        let proto = u16::from_be_bytes([frame[off], frame[off + 1]]);
        Some((proto, frame[off + 2..].to_vec()))
    }
}

// ───────────────────────────── HDLC (RFC1662) ───────────────────────────────

/// Compute the RFC1662 PPP FCS-16 over `data` (initial value 0xFFFF, poly 0x8408).
fn fcs16(data: &[u8]) -> u16 {
    let mut fcs: u16 = 0xffff;
    for &b in data {
        fcs ^= b as u16;
        for _ in 0..8 {
            if fcs & 1 != 0 {
                fcs = (fcs >> 1) ^ 0x8408;
            } else {
                fcs >>= 1;
            }
        }
    }
    fcs
}

/// Wrap a raw PPP frame in HDLC: append the complemented FCS (little-endian), then
/// byte-stuff and bracket with `7e` flags. Worst-case escaping (all < 0x20 plus
/// `7e`/`7d`) — always accepted by the peer, independent of the negotiated ACCM.
fn hdlc_encode(frame: &[u8]) -> Vec<u8> {
    let fcs = fcs16(frame) ^ 0xffff;
    let mut body = frame.to_vec();
    body.push((fcs & 0xff) as u8);
    body.push((fcs >> 8) as u8);

    let mut out = Vec::with_capacity(body.len() + 8);
    out.push(HDLC_FLAG);
    for &b in &body {
        if b == HDLC_FLAG || b == HDLC_ESC || b < 0x20 {
            out.push(HDLC_ESC);
            out.push(b ^ 0x20);
        } else {
            out.push(b);
        }
    }
    out.push(HDLC_FLAG);
    out
}

/// Reverse HDLC byte-stuffing (`7d XX` → `XX ^ 0x20`).
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

/// Run LCP then IPCP to completion. `seed_ip` (from the `X-VPN-client-IP` response
/// header) is requested first; the gateway normally ACKs it. The socket must have
/// a read timeout set.
pub fn negotiate<S: Read + Write>(conn: &mut PppConn<S>, seed_ip: Option<Ipv4Addr>) -> Result<IpConfig, String> {
    let magic: [u8; 4] = crate::ike::crypto::random(4).try_into().unwrap_or([1, 2, 3, 4]);
    let peer_mru = lcp_phase(conn, &magic)?;
    let mut ipc = ipcp_phase(conn, seed_ip.unwrap_or(Ipv4Addr::UNSPECIFIED))?;
    ipc.peer_mru = peer_mru;
    Ok(ipc)
}

/// The MRU option in a peer's LCP Configure-Request body, if any.
fn mru_option(body: &[u8]) -> Option<u16> {
    iter_opts(body).into_iter().find(|(t, v)| *t == LCP_OPT_MRU && v.len() == 2).map(|(_, v)| u16::from_be_bytes([v[0], v[1]]))
}

/// LCP to completion. Returns the gateway's MRU (from its Configure-Request).
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
                        // Drop whatever the peer rejected; re-request just the MRU.
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

fn ipcp_phase<S: Read + Write>(conn: &mut PppConn<S>, seed_ip: Ipv4Addr) -> Result<IpConfig, String> {
    let mut want_ip = seed_ip;
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
                        // Peer rejected DNS options (or others): re-request IP only.
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

/// Build an LCP Echo-Request body — used for dead-peer detection (openconnect's
/// `KA_DPD`): the gateway replies with an Echo-Reply, proving the link is alive.
pub fn echo_request(id: u8) -> Vec<u8> {
    ctrl(ECHO_REQ, id, &[0, 0, 0, 0])
}

/// Build an LCP Discard-Request — openconnect's keepalive packet (`KA_KEEPALIVE`).
/// The peer silently discards it; its only purpose is to keep the link active so the
/// gateway's idle-session timer does not fire (which was tearing idle F5 tunnels down
/// after a couple of minutes). Carries the 4-byte Magic-Number field per RFC 1661.
pub fn discard_request(id: u8) -> Vec<u8> {
    ctrl(DISCARD_REQ, id, &[0, 0, 0, 0])
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
    fn f5_framing_round_trip() {
        let mut c = PppConn::new(Cursor::new(Vec::<u8>::new()), Framing::F5);
        c.send(PPP_IPV4, b"\x45\x00ping").unwrap();
        let framed = c.get_ref().get_ref().clone();
        assert_eq!(&framed[0..2], &[0xf5, 0x00]); // magic
        let mut r = PppConn::new(Cursor::new(Vec::<u8>::new()), Framing::F5);
        r.rbuf.extend_from_slice(&framed);
        let (proto, payload) = r.take_frame().unwrap().unwrap();
        assert_eq!(proto, PPP_IPV4);
        assert_eq!(payload, b"\x45\x00ping");
        assert!(r.take_frame().unwrap().is_none());
    }

    #[test]
    fn f5_bad_magic() {
        let mut r = PppConn::new(Cursor::new(Vec::<u8>::new()), Framing::F5);
        r.rbuf.extend_from_slice(&[0x12, 0x34, 0x00, 0x02, 0xff, 0x03]);
        assert!(r.take_frame().is_err());
    }

    #[test]
    fn f5_partial_waits() {
        let mut r = PppConn::new(Cursor::new(Vec::<u8>::new()), Framing::F5);
        r.rbuf.extend_from_slice(&[0xf5, 0x00, 0x00, 100, 0xff, 0x03]); // claims 100, has few
        assert!(r.take_frame().unwrap().is_none());
    }

    #[test]
    fn hdlc_round_trip() {
        let mut c = PppConn::new(Cursor::new(Vec::<u8>::new()), Framing::Hdlc);
        c.send(PPP_LCP, b"\x01\x01\x00\x04").unwrap();
        let framed = c.get_ref().get_ref().clone();
        assert_eq!(framed[0], HDLC_FLAG);
        assert_eq!(*framed.last().unwrap(), HDLC_FLAG);
        let mut r = PppConn::new(Cursor::new(Vec::<u8>::new()), Framing::Hdlc);
        r.rbuf.extend_from_slice(&framed);
        let (proto, payload) = r.take_frame().unwrap().unwrap();
        assert_eq!(proto, PPP_LCP);
        assert_eq!(payload, b"\x01\x01\x00\x04");
    }

    #[test]
    fn hdlc_fcs_residual_is_good() {
        // Receiver residual over frame+FCS must equal PPPGOODFCS16 (0xf0b8).
        let frame = b"\xff\x03\xc0\x21\x01\x01\x00\x04";
        let fcs = fcs16(frame) ^ 0xffff;
        let mut with_fcs = frame.to_vec();
        with_fcs.push((fcs & 0xff) as u8);
        with_fcs.push((fcs >> 8) as u8);
        assert_eq!(fcs16(&with_fcs), 0xf0b8);
    }

    #[test]
    fn pfc_compressed_proto() {
        // FF03 omitted, single-byte proto 0x21 (IPv4).
        let frame = [0x21u8, 0x45, 0x00];
        let (proto, payload) = parse_ppp_frame(&frame).unwrap();
        assert_eq!(proto, 0x21);
        assert_eq!(payload, &[0x45, 0x00]);
    }

    #[test]
    fn f5_data_frame_is_pfc_compressed() {
        // Cross-checked vs gof5 / F5's own client: IP data is [0xf500][len][0x21][ip],
        // ACFC+PFC compressed (no FF 03, 1-byte protocol).
        let mut c = PppConn::new(Cursor::new(Vec::<u8>::new()), Framing::F5);
        c.send(PPP_IPV4, b"\x45\x00\x00\x14").unwrap();
        let f = c.get_ref().get_ref().clone();
        assert_eq!(&f[0..2], &[0xf5, 0x00]);
        assert_eq!(u16::from_be_bytes([f[2], f[3]]) as usize, 1 + 4);
        assert_eq!(f[4], 0x21);
        assert_eq!(&f[5..], b"\x45\x00\x00\x14");
    }

    #[test]
    fn f5_control_frame_is_uncompressed() {
        // LCP/IPCP stay uncompressed: [0xf500][len][FF 03][C0 21][body].
        let mut c = PppConn::new(Cursor::new(Vec::<u8>::new()), Framing::F5);
        c.send(PPP_LCP, b"\x01\x01\x00\x04").unwrap();
        let f = c.get_ref().get_ref().clone();
        assert_eq!(&f[0..2], &[0xf5, 0x00]);
        assert_eq!(&f[4..6], &[0xff, 0x03]);
        assert_eq!(&f[6..8], &[0xc0, 0x21]);
    }

    #[test]
    fn http_error_detected() {
        let mut r = PppConn::new(Cursor::new(Vec::<u8>::new()), Framing::F5);
        r.rbuf.extend_from_slice(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        assert!(r.take_frame().unwrap_err().contains("HTTP"));
    }
}
