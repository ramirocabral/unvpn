//! The OpenVPN transport: one UDP datagram per packet, or a TCP stream where
//! every packet is prefixed with its 16-bit big-endian length.

use super::config::{Proto, Remote};
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

pub enum Link {
    Udp(UdpSocket),
    Tcp { s: TcpStream, rx: Vec<u8> },
}

impl Link {
    /// Resolve `remote` (IPv4) and open the transport. Returns the link and the
    /// server address (used to pin its route outside the tunnel).
    pub fn open(remote: &Remote, timeout: Duration) -> Result<(Link, Ipv4Addr), String> {
        let ip = resolve_v4(&remote.host, remote.port)?;
        let addr = SocketAddr::V4(SocketAddrV4::new(ip, remote.port));
        let link = match remote.proto {
            Proto::Udp => {
                let s = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("udp bind: {e}"))?;
                s.connect(addr).map_err(|e| format!("udp connect {addr}: {e}"))?;
                s.set_nonblocking(true).ok();
                Link::Udp(s)
            }
            Proto::Tcp => {
                let s = TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("tcp connect {addr}: {e}"))?;
                s.set_nodelay(true).ok();
                s.set_nonblocking(true).ok();
                Link::Tcp { s, rx: Vec::new() }
            }
        };
        Ok((link, ip))
    }

    pub fn is_tcp(&self) -> bool {
        matches!(self, Link::Tcp { .. })
    }

    pub fn fd(&self) -> i32 {
        match self {
            Link::Udp(s) => s.as_raw_fd(),
            Link::Tcp { s, .. } => s.as_raw_fd(),
        }
    }

    pub fn send(&mut self, pkt: &[u8]) -> Result<(), String> {
        match self {
            Link::Udp(s) => match s.send(pkt) {
                Ok(_) => Ok(()),
                // A full socket buffer drops the datagram, like any lossy link would.
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
                // ICMP port-unreachable surfacing on a connected socket: transient.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Ok(()),
                Err(e) => Err(format!("udp send: {e}")),
            },
            Link::Tcp { s, .. } => {
                let mut frame = Vec::with_capacity(2 + pkt.len());
                frame.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
                frame.extend_from_slice(pkt);
                let fd = s.as_raw_fd();
                crate::sysnet::write_all_polling(s, Some(fd), &frame)
            }
        }
    }

    /// Drain everything readable into whole packets (non-blocking).
    pub fn recv_all(&mut self, out: &mut Vec<Vec<u8>>) -> Result<(), String> {
        match self {
            Link::Udp(s) => {
                let mut buf = [0u8; 2048];
                for _ in 0..256 {
                    match s.recv(&mut buf) {
                        Ok(n) => out.push(buf[..n].to_vec()),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => break,
                        Err(e) => return Err(format!("udp recv: {e}")),
                    }
                }
                Ok(())
            }
            Link::Tcp { s, rx } => {
                let mut buf = [0u8; 16384];
                loop {
                    match s.read(&mut buf) {
                        Ok(0) => {
                            split_frames(rx, out);
                            return Err("server closed the TCP connection".into());
                        }
                        Ok(n) => rx.extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(format!("tcp recv: {e}")),
                    }
                }
                split_frames(rx, out);
                Ok(())
            }
        }
    }
}

/// Split complete `len16 | packet` frames off the front of `rx`.
fn split_frames(rx: &mut Vec<u8>, out: &mut Vec<Vec<u8>>) {
    let mut p = 0;
    while rx.len() >= p + 2 {
        let n = u16::from_be_bytes([rx[p], rx[p + 1]]) as usize;
        if rx.len() < p + 2 + n {
            break;
        }
        out.push(rx[p + 2..p + 2 + n].to_vec());
        p += 2 + n;
    }
    rx.drain(..p);
}

pub fn resolve_v4(host: &str, port: u16) -> Result<Ipv4Addr, String> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}: {e}"))?
        .find_map(|sa| match sa.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .ok_or_else(|| format!("no IPv4 address for {host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_framing() {
        let mut rx = vec![0, 2, b'a', b'b', 0, 1, b'c', 0, 5, 1];
        let mut out = Vec::new();
        split_frames(&mut rx, &mut out);
        assert_eq!(out, vec![b"ab".to_vec(), b"c".to_vec()]);
        assert_eq!(rx, vec![0, 5, 1]); // partial frame kept
    }
}
