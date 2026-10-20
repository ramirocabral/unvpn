//! Kernel WireGuard over generic netlink — what `wg(8)` does, without the binary.
//!
//! The `wireguard` genl family (include/uapi/linux/wireguard.h):
//!   WG_CMD_GET_DEVICE (0, dump) / WG_CMD_SET_DEVICE (1), version 1.
//!   device attrs: IFINDEX 1, IFNAME 2, PRIVATE_KEY 3, PUBLIC_KEY 4, FLAGS 5
//!                 (REPLACE_PEERS = 1), LISTEN_PORT 6, FWMARK 7, PEERS 8 (nested)
//!   peer attrs:   PUBLIC_KEY 1, PRESHARED_KEY 2, FLAGS 3 (REMOVE_ME 1,
//!                 REPLACE_ALLOWEDIPS 2, UPDATE_ONLY 4), ENDPOINT 4 (sockaddr),
//!                 PERSISTENT_KEEPALIVE_INTERVAL 5, LAST_HANDSHAKE_TIME 6
//!                 (__kernel_timespec), RX_BYTES 7, TX_BYTES 8, ALLOWEDIPS 9 (nested),
//!                 PROTOCOL_VERSION 10
//!   allowed-ip:   FAMILY 1 (u16), IPADDR 2, CIDR_MASK 3 (u8)
//!
//! The family id is resolved at runtime through the genl controller.

use super::config::Net;
use std::net::{IpAddr, SocketAddr};

const NETLINK_GENERIC: libc::c_int = 16;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;
const NLA_F_NESTED: u16 = 0x8000;
const NLA_TYPE_MASK: u16 = 0x3fff;

const WG_CMD_GET_DEVICE: u8 = 0;
const WG_CMD_SET_DEVICE: u8 = 1;
const WG_GENL_VERSION: u8 = 1;

const WGDEVICE_A_IFNAME: u16 = 2;
const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
const WGDEVICE_A_FLAGS: u16 = 5;
const WGDEVICE_A_LISTEN_PORT: u16 = 6;
const WGDEVICE_A_FWMARK: u16 = 7;
const WGDEVICE_A_PEERS: u16 = 8;
const WGDEVICE_F_REPLACE_PEERS: u32 = 1;

const WGPEER_A_PUBLIC_KEY: u16 = 1;
const WGPEER_A_PRESHARED_KEY: u16 = 2;
const WGPEER_A_FLAGS: u16 = 3;
const WGPEER_A_ENDPOINT: u16 = 4;
const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
const WGPEER_A_RX_BYTES: u16 = 7;
const WGPEER_A_TX_BYTES: u16 = 8;
const WGPEER_A_ALLOWEDIPS: u16 = 9;
const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 2;
const WGPEER_F_UPDATE_ONLY: u32 = 4;

const WGALLOWEDIP_A_FAMILY: u16 = 1;
const WGALLOWEDIP_A_IPADDR: u16 = 2;
const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

/// Allowed IPs per message: keeps each SET well under the socket buffer (`wg`
/// chunks the same way); the rest follow as UPDATE_ONLY messages.
const ALLOWED_IPS_PER_MSG: usize = 1000;

/// One peer as we configure it.
pub struct PeerSet {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<Net>,
    /// Seconds; 0 = off.
    pub keepalive: u16,
}

/// The device as we configure it (replaces all of its peers).
pub struct DeviceSet {
    pub private_key: [u8; 32],
    pub listen_port: Option<u16>,
    pub fwmark: Option<u32>,
    pub peers: Vec<PeerSet>,
}

/// One peer as the kernel reports it.
#[derive(Clone, Debug, Default)]
pub struct PeerState {
    pub public_key: [u8; 32],
    pub endpoint: Option<SocketAddr>,
    /// Seconds since the Unix epoch; 0 = never.
    pub last_handshake: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct DeviceState {
    pub public_key: [u8; 32],
    pub listen_port: u16,
    pub peers: Vec<PeerState>,
}

// ───────────────────────────── message building ─────────────────────────────

/// A netlink message under construction; nested attributes are a start/finish pair.
struct Msg {
    buf: Vec<u8>,
}

impl Msg {
    fn new(ty: u16, flags: u16, seq: u32, cmd: u8, version: u8) -> Msg {
        let mut buf = vec![0u8; 20];
        buf[4..6].copy_from_slice(&ty.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        buf[16] = cmd;
        buf[17] = version;
        Msg { buf }
    }

    fn attr(&mut self, ty: u16, data: &[u8]) {
        let len = 4 + data.len();
        self.buf.extend_from_slice(&(len as u16).to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.pad();
    }

    fn u16(&mut self, ty: u16, v: u16) {
        self.attr(ty, &v.to_ne_bytes());
    }

    fn u32(&mut self, ty: u16, v: u32) {
        self.attr(ty, &v.to_ne_bytes());
    }

    fn str(&mut self, ty: u16, s: &str) {
        let mut b = s.as_bytes().to_vec();
        b.push(0);
        self.attr(ty, &b);
    }

    fn start(&mut self, ty: u16) -> usize {
        let at = self.buf.len();
        self.buf.extend_from_slice(&[0, 0]);
        self.buf.extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
        at
    }

    fn finish(&mut self, at: usize) {
        let len = (self.buf.len() - at) as u16;
        self.buf[at..at + 2].copy_from_slice(&len.to_ne_bytes());
    }

    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    fn done(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

/// Iterate the attributes in `b`: (type without flags, payload).
fn attrs(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if b.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let ty = u16::from_ne_bytes([b[2], b[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > b.len() {
            return None;
        }
        let payload = &b[4..len];
        let adv = (len + 3) & !3;
        b = &b[adv.min(b.len())..];
        Some((ty, payload))
    })
}

fn sockaddr_bytes(sa: &SocketAddr) -> Vec<u8> {
    match sa {
        SocketAddr::V4(a) => {
            let mut b = vec![0u8; 16];
            b[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            b[2..4].copy_from_slice(&a.port().to_be_bytes());
            b[4..8].copy_from_slice(&a.ip().octets());
            b
        }
        SocketAddr::V6(a) => {
            let mut b = vec![0u8; 28];
            b[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            b[2..4].copy_from_slice(&a.port().to_be_bytes());
            b[4..8].copy_from_slice(&a.flowinfo().to_be_bytes());
            b[8..24].copy_from_slice(&a.ip().octets());
            b[24..28].copy_from_slice(&a.scope_id().to_ne_bytes());
            b
        }
    }
}

fn parse_sockaddr(b: &[u8]) -> Option<SocketAddr> {
    if b.len() < 2 {
        return None;
    }
    let fam = u16::from_ne_bytes([b[0], b[1]]) as i32;
    if fam == libc::AF_INET && b.len() >= 8 {
        let port = u16::from_be_bytes([b[2], b[3]]);
        Some(SocketAddr::new(IpAddr::from([b[4], b[5], b[6], b[7]]), port))
    } else if fam == libc::AF_INET6 && b.len() >= 24 {
        let port = u16::from_be_bytes([b[2], b[3]]);
        let ip: [u8; 16] = b[8..24].try_into().ok()?;
        Some(SocketAddr::new(IpAddr::from(ip), port))
    } else {
        None
    }
}

fn allowed_ip(m: &mut Msg, n: &Net) {
    let a = m.start(0);
    match n.addr {
        IpAddr::V4(v) => {
            m.u16(WGALLOWEDIP_A_FAMILY, libc::AF_INET as u16);
            m.attr(WGALLOWEDIP_A_IPADDR, &v.octets());
        }
        IpAddr::V6(v) => {
            m.u16(WGALLOWEDIP_A_FAMILY, libc::AF_INET6 as u16);
            m.attr(WGALLOWEDIP_A_IPADDR, &v.octets());
        }
    }
    m.attr(WGALLOWEDIP_A_CIDR_MASK, &[n.prefix]);
    m.finish(a);
}

/// The SET_DEVICE messages for `dev`: the first replaces every peer; peers with
/// more allowed IPs than fit spill into follow-up UPDATE_ONLY messages.
fn set_messages(family: u16, ifname: &str, dev: &DeviceSet, seq: &mut u32) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut m = Msg::new(family, NLM_F_REQUEST | NLM_F_ACK, next(seq), WG_CMD_SET_DEVICE, WG_GENL_VERSION);
    m.str(WGDEVICE_A_IFNAME, ifname);
    m.attr(WGDEVICE_A_PRIVATE_KEY, &dev.private_key);
    m.u32(WGDEVICE_A_FLAGS, WGDEVICE_F_REPLACE_PEERS);
    if let Some(p) = dev.listen_port {
        m.u16(WGDEVICE_A_LISTEN_PORT, p);
    }
    m.u32(WGDEVICE_A_FWMARK, dev.fwmark.unwrap_or(0));
    let peers = m.start(WGDEVICE_A_PEERS);
    let mut spill: Vec<(&[u8; 32], &[Net])> = Vec::new();
    for p in &dev.peers {
        let a = m.start(0);
        m.attr(WGPEER_A_PUBLIC_KEY, &p.public_key);
        m.u32(WGPEER_A_FLAGS, WGPEER_F_REPLACE_ALLOWEDIPS);
        // An all-zero key clears it — what we want when none is configured.
        m.attr(WGPEER_A_PRESHARED_KEY, &p.preshared_key.unwrap_or([0; 32]));
        if let Some(ep) = &p.endpoint {
            m.attr(WGPEER_A_ENDPOINT, &sockaddr_bytes(ep));
        }
        m.u16(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, p.keepalive);
        let (first, rest) = p.allowed_ips.split_at(p.allowed_ips.len().min(ALLOWED_IPS_PER_MSG));
        let ips = m.start(WGPEER_A_ALLOWEDIPS);
        for n in first {
            allowed_ip(&mut m, n);
        }
        m.finish(ips);
        m.finish(a);
        if !rest.is_empty() {
            spill.push((&p.public_key, rest));
        }
    }
    m.finish(peers);
    out.push(m.done());

    for (key, rest) in spill {
        for chunk in rest.chunks(ALLOWED_IPS_PER_MSG) {
            let mut m = Msg::new(family, NLM_F_REQUEST | NLM_F_ACK, next(seq), WG_CMD_SET_DEVICE, WG_GENL_VERSION);
            m.str(WGDEVICE_A_IFNAME, ifname);
            let peers = m.start(WGDEVICE_A_PEERS);
            let a = m.start(0);
            m.attr(WGPEER_A_PUBLIC_KEY, key);
            m.u32(WGPEER_A_FLAGS, WGPEER_F_UPDATE_ONLY);
            let ips = m.start(WGPEER_A_ALLOWEDIPS);
            for n in chunk {
                allowed_ip(&mut m, n);
            }
            m.finish(ips);
            m.finish(a);
            m.finish(peers);
            out.push(m.done());
        }
    }
    out
}

fn next(seq: &mut u32) -> u32 {
    *seq = seq.wrapping_add(1);
    *seq
}

/// Parse one GET_DEVICE reply part into `st` (a big device spans several parts;
/// a peer may be split across two, continued under the same public key).
fn parse_device_part(payload: &[u8], st: &mut DeviceState) {
    for (ty, v) in attrs(payload) {
        match ty {
            WGDEVICE_A_PUBLIC_KEY if v.len() == 32 => st.public_key.copy_from_slice(v),
            WGDEVICE_A_LISTEN_PORT if v.len() >= 2 => st.listen_port = u16::from_ne_bytes([v[0], v[1]]),
            WGDEVICE_A_PEERS => {
                for (_, pv) in attrs(v) {
                    let mut p = PeerState::default();
                    for (pt, x) in attrs(pv) {
                        match pt {
                            WGPEER_A_PUBLIC_KEY if x.len() == 32 => p.public_key.copy_from_slice(x),
                            WGPEER_A_ENDPOINT => p.endpoint = parse_sockaddr(x),
                            WGPEER_A_LAST_HANDSHAKE_TIME if x.len() >= 8 => {
                                p.last_handshake = i64::from_ne_bytes(x[..8].try_into().unwrap()).max(0) as u64
                            }
                            WGPEER_A_RX_BYTES if x.len() >= 8 => p.rx_bytes = u64::from_ne_bytes(x[..8].try_into().unwrap()),
                            WGPEER_A_TX_BYTES if x.len() >= 8 => p.tx_bytes = u64::from_ne_bytes(x[..8].try_into().unwrap()),
                            _ => {}
                        }
                    }
                    match st.peers.last_mut() {
                        Some(last) if last.public_key == p.public_key => {
                            // Continuation of the previous part's peer (more allowed IPs).
                            if p.last_handshake != 0 || p.rx_bytes != 0 || p.tx_bytes != 0 {
                                *last = p;
                            }
                        }
                        _ => st.peers.push(p),
                    }
                }
            }
            _ => {}
        }
    }
}

// ───────────────────────────────── socket ───────────────────────────────────

/// A generic-netlink socket bound to the `wireguard` family.
pub struct WgNetlink {
    fd: libc::c_int,
    family: u16,
    seq: u32,
}

impl Drop for WgNetlink {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

impl WgNetlink {
    /// Open the socket and resolve the family id. Fails when the kernel has no
    /// WireGuard (module not loaded/available).
    pub fn open() -> Result<WgNetlink, String> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_GENERIC) };
        if fd < 0 {
            return Err(format!("netlink socket: {}", std::io::Error::last_os_error()));
        }
        let mut s = WgNetlink { fd, family: 0, seq: 0 };
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        let r = unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32) };
        if r < 0 {
            return Err(format!("netlink bind: {}", std::io::Error::last_os_error()));
        }
        // 5 s receive timeout: a kernel reply is immediate; never hang the engine.
        let tv = libc::timeval { tv_sec: 5, tv_usec: 0 };
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32)
        };

        let mut m = Msg::new(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK, next(&mut s.seq), CTRL_CMD_GETFAMILY, 1);
        m.str(CTRL_ATTR_FAMILY_NAME, "wireguard");
        let mut family = None;
        s.transact(&m.done(), |payload| {
            for (ty, v) in attrs(payload) {
                if ty == CTRL_ATTR_FAMILY_ID && v.len() >= 2 {
                    family = Some(u16::from_ne_bytes([v[0], v[1]]));
                }
            }
        })
        .map_err(|e| if e.contains("No such file") { "the kernel has no WireGuard (genl family not found)".to_string() } else { e })?;
        s.family = family.ok_or("genl controller returned no family id")?;
        Ok(s)
    }

    /// Configure `ifname` (replacing all its peers).
    pub fn set_device(&mut self, ifname: &str, dev: &DeviceSet) -> Result<(), String> {
        for m in set_messages(self.family, ifname, dev, &mut self.seq) {
            self.transact(&m, |_| {})?;
        }
        Ok(())
    }

    /// Change one peer's persistent-keepalive interval (UPDATE_ONLY).
    pub fn set_keepalive(&mut self, ifname: &str, public_key: &[u8; 32], secs: u16) -> Result<(), String> {
        let mut m = Msg::new(self.family, NLM_F_REQUEST | NLM_F_ACK, next(&mut self.seq), WG_CMD_SET_DEVICE, WG_GENL_VERSION);
        m.str(WGDEVICE_A_IFNAME, ifname);
        let peers = m.start(WGDEVICE_A_PEERS);
        let a = m.start(0);
        m.attr(WGPEER_A_PUBLIC_KEY, public_key);
        m.u32(WGPEER_A_FLAGS, WGPEER_F_UPDATE_ONLY);
        m.u16(WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, secs);
        m.finish(a);
        m.finish(peers);
        self.transact(&m.done(), |_| {})
    }

    pub fn get_device(&mut self, ifname: &str) -> Result<DeviceState, String> {
        let mut m = Msg::new(self.family, NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP, next(&mut self.seq), WG_CMD_GET_DEVICE, WG_GENL_VERSION);
        m.str(WGDEVICE_A_IFNAME, ifname);
        let mut st = DeviceState::default();
        self.transact(&m.done(), |payload| parse_device_part(payload, &mut st))?;
        Ok(st)
    }

    /// Send one request and read replies until its ACK / DONE. `on_payload` gets
    /// each data message's attributes (after the genl header).
    fn transact(&mut self, req: &[u8], mut on_payload: impl FnMut(&[u8])) -> Result<(), String> {
        let seq = u32::from_ne_bytes(req[8..12].try_into().unwrap());
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        let n = unsafe {
            libc::sendto(self.fd, req.as_ptr() as *const libc::c_void, req.len(), 0, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32)
        };
        if n < 0 {
            return Err(format!("netlink send: {}", std::io::Error::last_os_error()));
        }
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                return Err(format!("netlink recv: {}", std::io::Error::last_os_error()));
            }
            let mut b = &buf[..n as usize];
            while b.len() >= 16 {
                let len = u32::from_ne_bytes(b[0..4].try_into().unwrap()) as usize;
                if len < 16 || len > b.len() {
                    return Err("netlink: truncated message".into());
                }
                let ty = u16::from_ne_bytes([b[4], b[5]]);
                let mseq = u32::from_ne_bytes(b[8..12].try_into().unwrap());
                let body = &b[16..len];
                b = &b[((len + 3) & !3).min(b.len())..];
                if mseq != seq {
                    continue; // stale reply to an earlier request
                }
                match ty {
                    NLMSG_ERROR => {
                        let err = i32::from_ne_bytes(body.get(..4).ok_or("netlink: short error")?.try_into().unwrap());
                        if err == 0 {
                            return Ok(()); // ACK
                        }
                        return Err(format!("netlink: {}", std::io::Error::from_raw_os_error(-err)));
                    }
                    NLMSG_DONE => {
                        // A dump ends with DONE, then the ACK we asked for; DONE is enough.
                        return Ok(());
                    }
                    _ => {
                        if body.len() >= 4 {
                            on_payload(&body[4..]); // skip the genl header
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_message_layout() {
        let dev = DeviceSet {
            private_key: [1; 32],
            listen_port: Some(51820),
            fwmark: None,
            peers: vec![PeerSet {
                public_key: [2; 32],
                preshared_key: None,
                endpoint: Some("192.0.2.1:51820".parse().unwrap()),
                allowed_ips: vec![Net::parse("0.0.0.0/0").unwrap(), Net::parse("::/0").unwrap()],
                keepalive: 25,
            }],
        };
        let mut seq = 0;
        let msgs = set_messages(0x22, "wg-test", &dev, &mut seq);
        assert_eq!(msgs.len(), 1);
        let m = &msgs[0];
        assert_eq!(u32::from_ne_bytes(m[0..4].try_into().unwrap()) as usize, m.len());
        assert_eq!(u16::from_ne_bytes([m[4], m[5]]), 0x22);
        assert_eq!(m[16], WG_CMD_SET_DEVICE);

        // Walk it back: ifname, key, flags, port, fwmark, one peer with 2 allowed IPs.
        let top: Vec<(u16, &[u8])> = attrs(&m[20..]).collect();
        assert_eq!(top[0], (WGDEVICE_A_IFNAME, &b"wg-test\0"[..]));
        assert_eq!(top[1].1, &[1u8; 32][..]);
        let peers = top.iter().find(|(t, _)| *t == WGDEVICE_A_PEERS).unwrap().1;
        let peer: Vec<(u16, &[u8])> = attrs(attrs(peers).next().unwrap().1).collect();
        let ep = peer.iter().find(|(t, _)| *t == WGPEER_A_ENDPOINT).unwrap().1;
        assert_eq!(parse_sockaddr(ep), Some("192.0.2.1:51820".parse().unwrap()));
        let ips = peer.iter().find(|(t, _)| *t == WGPEER_A_ALLOWEDIPS).unwrap().1;
        let fams: Vec<u16> = attrs(ips)
            .map(|(_, ip)| attrs(ip).find(|(t, _)| *t == WGALLOWEDIP_A_FAMILY).map(|(_, v)| u16::from_ne_bytes([v[0], v[1]])).unwrap())
            .collect();
        assert_eq!(fams, vec![libc::AF_INET as u16, libc::AF_INET6 as u16]);
    }

    #[test]
    fn big_allowed_ip_sets_are_chunked() {
        let ips: Vec<Net> = (0..2500u32).map(|i| Net { addr: IpAddr::from((0x0a00_0000 + (i << 8)).to_be_bytes()), prefix: 24 }).collect();
        let dev = DeviceSet {
            private_key: [1; 32],
            listen_port: None,
            fwmark: None,
            peers: vec![PeerSet { public_key: [2; 32], preshared_key: None, endpoint: None, allowed_ips: ips, keepalive: 0 }],
        };
        let mut seq = 0;
        let msgs = set_messages(0x22, "wg", &dev, &mut seq);
        assert_eq!(msgs.len(), 3, "1000 + 1000 + 500");
        assert!(msgs.iter().all(|m| m.len() < 64 * 1024));
    }

    #[test]
    fn sockaddr_v6_roundtrip() {
        let sa: SocketAddr = "[2001:db8::1]:51820".parse().unwrap();
        assert_eq!(parse_sockaddr(&sockaddr_bytes(&sa)), Some(sa));
    }
}
