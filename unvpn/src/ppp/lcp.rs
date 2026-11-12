//! LCP and IPCP (RFC 1661, 1332, 1877): bring the link up, learn the address and
//! DNS servers, answer the peer during the data phase.

use super::{PppConn, PPP_IPCP, PPP_LCP, WOULDBLOCK};
use std::io::{Read, Write};
use std::net::Ipv4Addr;

const CONF_REQ: u8 = 1;
const CONF_ACK: u8 = 2;
const CONF_NAK: u8 = 3;
const CONF_REJ: u8 = 4;
const TERM_REQ: u8 = 5;
const TERM_ACK: u8 = 6;
const ECHO_REQ: u8 = 9;
const ECHO_REP: u8 = 10;
const DISCARD_REQ: u8 = 11;

const LCP_OPT_MRU: u8 = 1;
const LCP_OPT_MAGIC: u8 = 5;

const IPCP_OPT_IP: u8 = 3;
const IPCP_OPT_DNS1: u8 = 129;
const IPCP_OPT_DNS2: u8 = 131;

/// The MRU we advertise (room for the PPP and encapsulation headers under TLS).
const DEFAULT_MRU: u16 = 1354;

const MAX_RETRIES: u32 = 10;

#[derive(Debug, Clone)]
pub struct IpConfig {
    pub addr: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    /// The MRU from the gateway's LCP Configure-Request: the largest PPP payload
    /// it accepts, so our tun MTU must not exceed it.
    pub peer_mru: Option<u16>,
}

fn ctrl(code: u8, id: u8, options: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + options.len());
    v.push(code);
    v.push(id);
    v.extend_from_slice(&((4 + options.len()) as u16).to_be_bytes());
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
    if len < 4 {
        return None;
    }
    Some(Ctrl {
        code: payload[0],
        id: payload[1],
        body: payload[4..len.min(payload.len())].to_vec(),
    })
}

fn iter_opts(body: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= body.len() {
        let (t, l) = (body[i], body[i + 1] as usize);
        if l < 2 || i + l > body.len() {
            break;
        }
        out.push((t, body[i + 2..i + l].to_vec()));
        i += l;
    }
    out
}

fn mru_option(body: &[u8]) -> Option<u16> {
    iter_opts(body)
        .into_iter()
        .find(|(t, v)| *t == LCP_OPT_MRU && v.len() == 2)
        .map(|(_, v)| u16::from_be_bytes([v[0], v[1]]))
}

/// Run LCP then IPCP to completion; the socket must have a read timeout set.
/// `seed_ip` is asked for first (a gateway that already announced the address
/// normally acks it).
pub fn negotiate<S: Read + Write>(
    conn: &mut PppConn<S>,
    seed_ip: Option<Ipv4Addr>,
) -> Result<IpConfig, String> {
    let magic: [u8; 4] = crate::ike::crypto::random(4)
        .try_into()
        .unwrap_or([1, 2, 3, 4]);
    let peer_mru = lcp_phase(conn, &magic)?;
    let mut ipc = ipcp_phase(conn, seed_ip.unwrap_or(Ipv4Addr::UNSPECIFIED))?;
    ipc.peer_mru = peer_mru;
    Ok(ipc)
}

/// Returns the gateway's MRU.
fn lcp_phase<S: Read + Write>(
    conn: &mut PppConn<S>,
    magic: &[u8; 4],
) -> Result<Option<u16>, String> {
    let mut our_opts = opt(LCP_OPT_MRU, &DEFAULT_MRU.to_be_bytes());
    our_opts.extend_from_slice(&opt(LCP_OPT_MAGIC, magic));

    let mut id = 1u8;
    let (mut our_acked, mut peer_acked) = (false, false);
    let mut peer_mru = None;
    conn.send(PPP_LCP, &ctrl(CONF_REQ, id, &our_opts))?;

    let mut tries = 0;
    while !(our_acked && peer_acked) {
        match conn.recv_blocking() {
            Ok((PPP_LCP, payload)) => {
                let Some(c) = parse_ctrl(&payload) else {
                    continue;
                };
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
            Ok(_) => {}
            Err(e) if e == WOULDBLOCK => {
                tries += 1;
                if tries > MAX_RETRIES {
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

fn ipcp_request(ip: Ipv4Addr, dns1: Ipv4Addr, dns2: Ipv4Addr) -> Vec<u8> {
    let mut o = opt(IPCP_OPT_IP, &ip.octets());
    o.extend_from_slice(&opt(IPCP_OPT_DNS1, &dns1.octets()));
    o.extend_from_slice(&opt(IPCP_OPT_DNS2, &dns2.octets()));
    o
}

fn ipcp_phase<S: Read + Write>(
    conn: &mut PppConn<S>,
    seed_ip: Ipv4Addr,
) -> Result<IpConfig, String> {
    let mut want_ip = seed_ip;
    let mut dns1 = Ipv4Addr::UNSPECIFIED;
    let mut dns2 = Ipv4Addr::UNSPECIFIED;

    let mut id = 1u8;
    let (mut our_acked, mut peer_acked) = (false, false);
    conn.send(
        PPP_IPCP,
        &ctrl(CONF_REQ, id, &ipcp_request(want_ip, dns1, dns2)),
    )?;

    let mut tries = 0;
    while !(our_acked && peer_acked) {
        match conn.recv_blocking() {
            Ok((PPP_IPCP, payload)) => {
                let Some(c) = parse_ctrl(&payload) else {
                    continue;
                };
                match c.code {
                    CONF_REQ => {
                        conn.send(PPP_IPCP, &ctrl(CONF_ACK, c.id, &c.body))?;
                        peer_acked = true;
                    }
                    CONF_ACK => our_acked = true,
                    CONF_NAK => {
                        for (t, v) in iter_opts(&c.body) {
                            let Ok(a) = <[u8; 4]>::try_from(v.as_slice()) else {
                                continue;
                            };
                            match t {
                                IPCP_OPT_IP => want_ip = a.into(),
                                IPCP_OPT_DNS1 => dns1 = a.into(),
                                IPCP_OPT_DNS2 => dns2 = a.into(),
                                _ => {}
                            }
                        }
                        id = id.wrapping_add(1);
                        conn.send(
                            PPP_IPCP,
                            &ctrl(CONF_REQ, id, &ipcp_request(want_ip, dns1, dns2)),
                        )?;
                    }
                    CONF_REJ => {
                        id = id.wrapping_add(1);
                        conn.send(
                            PPP_IPCP,
                            &ctrl(CONF_REQ, id, &opt(IPCP_OPT_IP, &want_ip.octets())),
                        )?;
                    }
                    TERM_REQ => {
                        conn.send(PPP_IPCP, &ctrl(TERM_ACK, c.id, &[]))?;
                        return Err("gateway terminated IPCP".into());
                    }
                    _ => {}
                }
            }
            Ok((PPP_LCP, payload)) => {
                if handle_lcp_in(conn, &payload)? {
                    return Err("gateway terminated link during IPCP".into());
                }
            }
            Ok(_) => {}
            Err(e) if e == WOULDBLOCK => {
                tries += 1;
                if tries > MAX_RETRIES {
                    return Err("IPCP negotiation timed out".into());
                }
                if !our_acked {
                    conn.send(
                        PPP_IPCP,
                        &ctrl(CONF_REQ, id, &ipcp_request(want_ip, dns1, dns2)),
                    )?;
                }
            }
            Err(e) => return Err(e),
        }
    }

    if want_ip.is_unspecified() {
        return Err("IPCP completed without assigning an IP address".into());
    }
    let dns = [dns1, dns2]
        .into_iter()
        .filter(|d| !d.is_unspecified())
        .collect();
    Ok(IpConfig {
        addr: want_ip,
        dns,
        peer_mru: None,
    })
}

/// Dead-peer detection; magic 0, no data.
pub fn echo_request(id: u8) -> Vec<u8> {
    ctrl(ECHO_REQ, id, &[0, 0, 0, 0])
}

/// Keepalive that keeps a gateway's idle-session timer from firing.
pub fn discard_request(id: u8) -> Vec<u8> {
    ctrl(DISCARD_REQ, id, &[0, 0, 0, 0])
}

pub fn terminate_request(id: u8) -> Vec<u8> {
    ctrl(TERM_REQ, id, &[])
}

/// Answer an inbound LCP echo or terminate request; `Ok(true)` when the peer
/// asked to terminate.
pub fn handle_lcp_in<S: Read + Write>(
    conn: &mut PppConn<S>,
    payload: &[u8],
) -> Result<bool, String> {
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
    use super::super::Framing;
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn parse_ctrl_rejects_short_length_field() {
        assert!(parse_ctrl(&[1, 1, 0, 2, 0xaa, 0xbb]).is_none());
        assert!(parse_ctrl(&[1, 1, 0, 0]).is_none());
        let c = parse_ctrl(&[2, 7, 0, 6, 0xaa, 0xbb, 0xcc]).unwrap();
        assert_eq!((c.code, c.id, c.body), (2, 7, vec![0xaa, 0xbb]));
    }

    #[test]
    fn peer_mru_option_is_read() {
        let body = [
            &opt(LCP_OPT_MAGIC, &[1, 2, 3, 4])[..],
            &opt(LCP_OPT_MRU, &1354u16.to_be_bytes())[..],
        ]
        .concat();
        assert_eq!(mru_option(&body), Some(1354));
        assert_eq!(mru_option(&opt(LCP_OPT_MAGIC, &[1, 2, 3, 4])), None);
    }

    /// A gateway that answers each frame we send from a script.
    struct Peer {
        framing: Framing,
        rx: VecDeque<u8>,
        sent: Vec<(u16, Vec<u8>)>,
        script: fn(&(u16, Vec<u8>)) -> Vec<(u16, Vec<u8>)>,
    }

    impl Read for Peer {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.rx.is_empty() {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            let n = buf.len().min(self.rx.len());
            for (i, b) in self.rx.drain(..n).enumerate() {
                buf[i] = b;
            }
            Ok(n)
        }
    }

    impl Write for Peer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut r = PppConn::new(std::io::Cursor::new(Vec::new()), self.framing);
            r.feed(buf);
            while let Some(f) = r.take_frame().unwrap() {
                for (proto, payload) in (self.script)(&f) {
                    let mut out = Vec::new();
                    self.framing.encode(proto, &payload, &mut out);
                    self.rx.extend(out);
                }
                self.sent.push(f);
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn negotiation_takes_the_nakd_address_and_dns() {
        fn gateway(f: &(u16, Vec<u8>)) -> Vec<(u16, Vec<u8>)> {
            let c = parse_ctrl(&f.1).unwrap();
            match (f.0, c.code) {
                (PPP_LCP, CONF_REQ) => vec![
                    (PPP_LCP, ctrl(CONF_ACK, c.id, &c.body)),
                    (
                        PPP_LCP,
                        ctrl(CONF_REQ, 9, &opt(LCP_OPT_MRU, &1400u16.to_be_bytes())),
                    ),
                ],
                (PPP_IPCP, CONF_REQ) if c.body[2..6] == [0, 0, 0, 0] => {
                    let mut nak = opt(IPCP_OPT_IP, &[198, 51, 100, 7]);
                    nak.extend(opt(IPCP_OPT_DNS1, &[198, 51, 100, 53]));
                    vec![
                        (PPP_IPCP, ctrl(CONF_NAK, c.id, &nak)),
                        (
                            PPP_IPCP,
                            ctrl(CONF_REQ, 3, &opt(IPCP_OPT_IP, &[198, 51, 100, 1])),
                        ),
                    ]
                }
                (PPP_IPCP, CONF_REQ) => vec![(PPP_IPCP, ctrl(CONF_ACK, c.id, &c.body))],
                _ => vec![],
            }
        }
        for framing in [Framing::Forti, Framing::F5, Framing::Hdlc] {
            let peer = Peer {
                framing,
                rx: VecDeque::new(),
                sent: Vec::new(),
                script: gateway,
            };
            let mut conn = PppConn::new(peer, framing);
            let ipc = negotiate(&mut conn, None).unwrap();
            assert_eq!(ipc.addr, Ipv4Addr::new(198, 51, 100, 7));
            assert_eq!(ipc.dns, vec![Ipv4Addr::new(198, 51, 100, 53)]);
            assert_eq!(ipc.peer_mru, Some(1400));
            let acks = conn
                .get_ref()
                .sent
                .iter()
                .filter(|(_, p)| p[0] == CONF_ACK)
                .count();
            assert_eq!(
                acks, 2,
                "{framing:?}: we ack the peer's LCP and IPCP requests"
            );
        }
    }
}
