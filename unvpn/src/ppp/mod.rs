//! In-process PPP (no pppd) over an SSL-VPN tunnel stream: framing, the
//! buffered connection and LCP/IPCP.
//!
//! A TLS stream can't be split into read and write halves and a partial record
//! must not break frame boundaries, so every read goes through [`PppConn`], which
//! hands out complete frames only.

mod framing;
mod lcp;

pub use framing::{Framing, FORTI_CTRL};
pub use lcp::{
    discard_request, echo_request, handle_lcp_in, negotiate, terminate_request, IpConfig,
};

use std::io::{Read, Write};

pub const PPP_LCP: u16 = 0xc021;
pub const PPP_IPCP: u16 = 0x8021;
pub const PPP_IPV4: u16 = 0x0021;

/// A read returned no data (timeout in blocking mode, or WouldBlock in
/// non-blocking mode): the caller decides whether to retransmit or poll again.
pub const WOULDBLOCK: &str = "__wouldblock__";

/// Any byte transport a PPP link can run over (TLS stream, DTLS records).
pub trait Transport: Read + Write {}
impl<T: Read + Write> Transport for T {}

pub struct PppConn<S> {
    stream: S,
    framing: Framing,
    rbuf: Vec<u8>,
    /// Socket fd to wait on when a non-blocking write would block. Set once the
    /// link is in the (non-blocking) data phase; then `fill` also drains to
    /// `WouldBlock`.
    poll_fd: Option<i32>,
    txbuf: Vec<u8>,
    /// Several frames per write (a byte stream like TLS) or exactly one per
    /// record (DTLS).
    coalesce: bool,
}

impl<S: Read + Write> PppConn<S> {
    pub fn new(stream: S, framing: Framing) -> Self {
        PppConn {
            stream,
            framing,
            rbuf: Vec::with_capacity(4096),
            poll_fd: None,
            txbuf: Vec::new(),
            coalesce: true,
        }
    }

    /// One frame per write (record-oriented transports such as DTLS).
    pub fn set_record_mode(&mut self) {
        self.coalesce = false;
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
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
            framing: self.framing,
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

    /// Bytes already read off the stream, such as PPP that arrived in the same
    /// record as the tunnel request's HTTP answer.
    pub fn feed(&mut self, data: &[u8]) {
        self.rbuf.extend_from_slice(data);
    }

    /// Flushes queued data frames first, so ordering is preserved.
    pub fn send(&mut self, proto: u16, payload: &[u8]) -> Result<(), String> {
        self.flush_tx()?;
        let mut out = Vec::with_capacity(10 + payload.len());
        self.framing.encode(proto, payload, &mut out);
        self.write_out(&out)
    }

    /// Queue a data frame for `flush_tx`: on a byte stream a burst then costs one
    /// TLS record and one syscall. In record mode it is just `send`.
    pub fn queue(&mut self, proto: u16, payload: &[u8]) -> Result<(), String> {
        if !self.coalesce {
            return self.send(proto, payload);
        }
        self.framing.encode(proto, payload, &mut self.txbuf);
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
        crate::sysnet::write_all_polling(&mut self.stream, self.poll_fd, out)
            .map_err(|e| format!("ppp {e}"))?;
        self.stream.flush().ok();
        Ok(())
    }

    /// One complete frame from the buffer, without I/O, as `(protocol, payload)`.
    /// Frames too short to carry a protocol are dropped.
    pub fn take_frame(&mut self) -> Result<Option<(u16, Vec<u8>)>, String> {
        if !self.skip_http_head()? {
            return Ok(None);
        }
        loop {
            match self.framing.take(&mut self.rbuf)? {
                None => return Ok(None),
                Some(framing::Frame::Control(rec)) => return Ok(Some((FORTI_CTRL, rec))),
                Some(framing::Frame::Ppp(f)) => {
                    if let Some(p) = framing::parse_frame(&f) {
                        return Ok(Some(p));
                    }
                }
            }
        }
    }

    /// Some gateways answer the tunnel request with `200 OK` and switch straight
    /// to PPP; any other status is a refusal. `false` while the head is partial.
    fn skip_http_head(&mut self) -> Result<bool, String> {
        if !self.rbuf.starts_with(b"HTTP") {
            return Ok(true);
        }
        let Some(end) = crate::net::http::head_end(&self.rbuf) else {
            return Ok(false);
        };
        let head = String::from_utf8_lossy(&self.rbuf[..end]);
        let status = head.split_whitespace().nth(1).unwrap_or("");
        if status == "200" || status == "201" {
            self.rbuf.drain(..end);
            return Ok(true);
        }
        let first = head.lines().next().unwrap_or("").trim();
        Err(format!("tunnel refused (HTTP): {first}"))
    }

    /// Read into the buffer; timeout/WouldBlock is `Ok(0)`. While negotiating
    /// (blocking reads with a timeout) this is one read; in the non-blocking data
    /// phase it drains until `WouldBlock`, because TLS keeps decrypted records in
    /// its own buffer where `poll(fd)` can't see them.
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
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Ok(total)
                }
                Err(e) => return Err(format!("tunnel read: {e}")),
            }
        }
    }

    /// Blocking receive of one frame (the socket must have a read timeout set);
    /// `Err(WOULDBLOCK)` on timeout.
    pub fn recv_blocking(&mut self) -> Result<(u16, Vec<u8>), String> {
        loop {
            if let Some(f) = self.take_frame()? {
                return Ok(f);
            }
            if self.fill()? == 0 {
                return Err(WOULDBLOCK.into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn conn(f: Framing) -> PppConn<Cursor<Vec<u8>>> {
        PppConn::new(Cursor::new(Vec::new()), f)
    }

    fn wire(c: &PppConn<Cursor<Vec<u8>>>) -> Vec<u8> {
        c.get_ref().get_ref().clone()
    }

    #[test]
    fn round_trip_every_framing() {
        for f in [Framing::Forti, Framing::F5, Framing::Hdlc] {
            let mut c = conn(f);
            c.send(PPP_IPV4, b"\x45\x00ping").unwrap();
            c.send(PPP_LCP, b"\x01\x01\x00\x04").unwrap();
            let mut r = conn(f);
            r.feed(&wire(&c));
            assert_eq!(
                r.take_frame().unwrap(),
                Some((PPP_IPV4, b"\x45\x00ping".to_vec())),
                "{f:?}"
            );
            assert_eq!(
                r.take_frame().unwrap(),
                Some((PPP_LCP, b"\x01\x01\x00\x04".to_vec()))
            );
            assert!(r.take_frame().unwrap().is_none());
        }
    }

    #[test]
    fn queued_frames_coalesce_into_one_write() {
        let mut c = conn(Framing::Forti);
        c.queue(PPP_IPV4, b"\x45one").unwrap();
        c.queue(PPP_IPV4, b"\x45two").unwrap();
        assert!(wire(&c).is_empty(), "queued, not yet written");
        c.send(PPP_LCP, b"\x09\x01\x00\x08\x00\x00\x00\x00")
            .unwrap();
        let mut r = conn(Framing::Forti);
        r.feed(&wire(&c));
        assert_eq!(
            r.take_frame().unwrap(),
            Some((PPP_IPV4, b"\x45one".to_vec()))
        );
        assert_eq!(
            r.take_frame().unwrap(),
            Some((PPP_IPV4, b"\x45two".to_vec()))
        );
        assert_eq!(r.take_frame().unwrap().unwrap().0, PPP_LCP);
        assert!(r.take_frame().unwrap().is_none());
    }

    #[test]
    fn fortinet_control_record_is_demuxed() {
        let mut rec = vec![0u8, 0];
        rec.extend_from_slice(b"GFtype\0svrhello-tun");
        let n = rec.len() as u16;
        rec[..2].copy_from_slice(&n.to_be_bytes());
        let mut c = conn(Framing::Forti);
        c.send(PPP_IPV4, b"\x45data").unwrap();
        let mut r = conn(Framing::Forti);
        r.feed(&rec);
        r.feed(&wire(&c));
        assert_eq!(r.take_frame().unwrap().unwrap().0, FORTI_CTRL);
        assert_eq!(
            r.take_frame().unwrap(),
            Some((PPP_IPV4, b"\x45data".to_vec()))
        );
    }

    #[test]
    fn a_frame_without_protocol_does_not_stall_the_next() {
        let mut r = conn(Framing::F5);
        r.feed(&[0xf5, 0x00, 0x00, 0x02, 0xff, 0x03]);
        r.feed(&[0xf5, 0x00, 0x00, 0x02, 0x21, 0x45]);
        assert_eq!(r.take_frame().unwrap(), Some((PPP_IPV4, vec![0x45])));
    }

    #[test]
    fn framing_errors_and_partial_frames() {
        let mut r = conn(Framing::Forti);
        r.feed(&[0x00, 0x08, 0x12, 0x34, 0x00, 0x02, 0xff, 0x03]);
        assert!(r.take_frame().is_err());
        let mut r = conn(Framing::Forti);
        r.feed(&[0x00, 106, 0x50, 0x50, 0x00, 100, 0xff, 0x03]);
        assert!(r.take_frame().unwrap().is_none());
        let mut r = conn(Framing::F5);
        r.feed(&[0x12, 0x34, 0x00, 0x02, 0xff, 0x03]);
        assert!(r.take_frame().is_err());
        let mut r = conn(Framing::F5);
        r.feed(&[0xf5, 0x00, 0x00, 100, 0xff, 0x03]);
        assert!(r.take_frame().unwrap().is_none());
    }

    #[test]
    fn http_answer_before_ppp() {
        let mut r = conn(Framing::F5);
        r.feed(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        assert!(r.take_frame().unwrap_err().contains("HTTP"));
        let mut r = conn(Framing::F5);
        r.feed(b"HTTP/1.1 200 OK\r\n");
        assert!(r.take_frame().unwrap().is_none());
        r.feed(b"\r\n\xf5\x00\x00\x02\x21\x45");
        assert_eq!(r.take_frame().unwrap(), Some((PPP_IPV4, vec![0x45])));
    }

    #[test]
    fn nonblocking_send_waits_for_a_full_buffer_to_drain() {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;
        let (tx, mut rx) = UnixStream::pair().unwrap();
        tx.set_nonblocking(true).unwrap();
        let fd = tx.as_raw_fd();
        let mut conn = PppConn::new(tx, Framing::Forti);
        conn.set_poll_fd(fd);
        let reader = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            let mut sink = Vec::new();
            rx.read_to_end(&mut sink).unwrap();
            sink.len()
        });
        let payload = [0x45u8; 1400];
        for _ in 0..2000 {
            conn.send(PPP_IPV4, &payload)
                .expect("send must not fail on WouldBlock");
        }
        drop(conn);
        assert_eq!(reader.join().unwrap(), 2000 * (6 + 4 + 1400));
    }
}
