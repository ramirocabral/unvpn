//! IKE transports. UDP (plain on :500, NAT-T on :4500 with the Non-ESP marker,
//! RFC 3948). Visitor Mode (IKE/ESP over TLS:443) is a separate transport added
//! later if UDP is blocked.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Duration;

fn e<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

pub struct IkeUdp {
    sock: UdpSocket,
    natt: bool,
}

impl IkeUdp {
    /// Connect a UDP socket to the gateway. `natt` selects port 4500 (with the
    /// 4-byte Non-ESP marker) instead of 500.
    pub fn connect(gateway: &str, natt: bool, timeout: Duration) -> Result<Self, String> {
        let port = if natt { 4500 } else { 500 };
        let sock = UdpSocket::bind("0.0.0.0:0").map_err(e)?;
        sock.connect((gateway, port)).map_err(e)?;
        sock.set_read_timeout(Some(timeout)).ok();
        sock.set_write_timeout(Some(timeout)).ok();
        Ok(IkeUdp { sock, natt })
    }

    /// The source IPv4 the kernel picked for this gateway route (for NAT-D).
    pub fn local_ipv4(&self) -> Ipv4Addr {
        match self.sock.local_addr().map(|a| a.ip()) {
            Ok(IpAddr::V4(v)) => v,
            _ => Ipv4Addr::UNSPECIFIED,
        }
    }

    pub fn send(&self, msg: &[u8]) -> Result<(), String> {
        if self.natt {
            let mut buf = Vec::with_capacity(4 + msg.len());
            buf.extend_from_slice(&[0, 0, 0, 0]); // Non-ESP marker
            buf.extend_from_slice(msg);
            self.sock.send(&buf).map_err(e)?;
        } else {
            self.sock.send(msg).map_err(e)?;
        }
        Ok(())
    }

    /// Receive one IKE datagram, skipping NAT-keepalives and ESP packets on 4500.
    pub fn recv(&self) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; 65535];
        loop {
            let n = self.sock.recv(&mut buf).map_err(e)?;
            let data = &buf[..n];
            if self.natt {
                if n >= 4 && data[..4].iter().all(|b| *b == 0) {
                    return Ok(data[4..].to_vec());
                }
                // ESP (non-zero SPI) or 1-byte keepalive: not an IKE message.
                continue;
            }
            return Ok(data.to_vec());
        }
    }

    pub fn send_recv(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        self.send(msg)?;
        self.recv()
    }

    /// Clone the underlying socket (same local port) to carry ESP on the same
    /// NAT-T mapping the IKE handshake established.
    pub fn try_clone_socket(&self) -> std::io::Result<UdpSocket> {
        self.sock.try_clone()
    }
}
