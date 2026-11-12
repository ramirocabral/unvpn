//! Proactive reconnect trigger ("link kick").
//!
//! The data loops already rebuild a dropped link, but they only notice a drop
//! when a keepalive/DPD times out — up to a minute after the machine resumes from
//! sleep or the network changes (Wi-Fi ↔ cable). This module watches for those two
//! events and pokes an `eventfd` the loops add to their `poll` set, so they wake at
//! once, return "link down", and the session loop reconnects in about a second —
//! reusing the existing session, with no re-auth.
//!
//!  - Resume: a thread that measures how much `CLOCK_BOOTTIME` advanced across a
//!    short sleep. Boottime counts time spent suspended, so a 2 s sleep that took
//!    far longer means the machine was asleep in between.
//!  - Network change: a `NETLINK_ROUTE` socket subscribed to link / address /
//!    route events.
//!
//! Kicks are rate-limited so a burst of netlink events (including the churn our own
//! reconnect causes) collapses into one.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

const REASON_RESUME: u8 = 1;
const REASON_NETCHANGE: u8 = 2;

/// Netlink message types we parse for an interface index (stable kernel ABI).
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
/// Route attributes: destination address and output interface index.
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
/// Link (`IFLA_IFNAME`) and address (`IFA_LABEL`) attribute carrying the device name.
const ATTR_NAME: u16 = 3;

/// Interface index whose own netlink churn must not trigger a reconnect: the tunnel
/// device. Our own connect/reconnect adds and removes the session's routes, address
/// and link on this interface, a burst of link/address/route events that would
/// otherwise look like a network change and kick us into an endless reconnect loop.
/// 0 ⇒ not set (filter nothing), so back-ends that don't call [`ignore_iface`] keep
/// the old behaviour.
static IGNORED_IFINDEX: AtomicU32 = AtomicU32::new(0);

/// The gateway (IPv4, as u32; 0 = unknown): a route change that can't move the path
/// to it — another session's gateway pin or excludes, a container bridge — is no
/// reason to reconnect.
static GATEWAY: AtomicU32 = AtomicU32::new(0);

pub fn watch_gateway(gw: std::net::Ipv4Addr) {
    GATEWAY.store(u32::from(gw), Ordering::SeqCst);
}

/// Stop treating `name`'s own netlink events (its routes/address/link) as a network
/// change. Call once the tunnel device is up; safe to call again (last wins).
pub fn ignore_iface(name: &str) {
    let Ok(c) = std::ffi::CString::new(name) else {
        return;
    };
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    IGNORED_IFINDEX.store(idx, Ordering::SeqCst);
}

/// A 2 s sleep whose boottime delta exceeds this was interrupted by a suspend.
const SUSPEND_GAP_SECS: u64 = 8;
/// At most one kick per this window, so a burst of events is one reconnect.
const COOLDOWN_SECS: u64 = 3;

/// Netlink multicast groups (values are part of the stable kernel ABI): links up/
/// down, IPv4 address changes, IPv4 route changes — the signals of a path change.
const RTMGRP_LINK: u32 = 0x1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV4_ROUTE: u32 = 0x40;

static EVENTFD: OnceLock<i32> = OnceLock::new();
static REASON: AtomicU8 = AtomicU8::new(0);
/// Boottime seconds of the last kick we fired, for the cooldown.
static LAST_KICK: AtomicU64 = AtomicU64::new(0);

/// The readable fd a data loop adds to its `poll` set, starting the watchers on the
/// first call. A negative return (eventfd unavailable) is safe: `poll` ignores it
/// and [`took_kick`] always reports nothing.
pub fn kick_fd() -> i32 {
    *EVENTFD.get_or_init(|| {
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            return -1;
        }
        // Arm the cooldown now, so the route/address churn of the connect that just
        // finished (before this first call) doesn't immediately fire a kick.
        LAST_KICK.store(boottime_secs(), Ordering::SeqCst);
        spawn_resume_watcher();
        spawn_netlink_watcher();
        fd
    })
}

/// If a kick is pending, clear it and name the reason; otherwise `None`. Cheap to
/// call every loop iteration — one non-blocking `read`.
pub fn took_kick() -> Option<&'static str> {
    let fd = *EVENTFD.get()?;
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 8];
    let r = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 8) };
    if r != 8 {
        return None;
    }
    Some(match REASON.swap(0, Ordering::SeqCst) {
        REASON_RESUME => "resumed from sleep",
        REASON_NETCHANGE => "network changed",
        _ => "link change",
    })
}

fn boottime_secs() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as u64
}

/// Fire a kick unless one fired within the cooldown. The write wakes any data loop
/// blocked in `poll`.
fn kick(reason: u8) {
    let now = boottime_secs();
    if !cooldown_elapsed(LAST_KICK.load(Ordering::SeqCst), now, COOLDOWN_SECS) {
        return;
    }
    LAST_KICK.store(now, Ordering::SeqCst);
    REASON.store(reason, Ordering::SeqCst);
    if let Some(&fd) = EVENTFD.get() {
        if fd >= 0 {
            let one: u64 = 1;
            unsafe { libc::write(fd, &one as *const u64 as *const libc::c_void, 8) };
        }
    }
}

fn cooldown_elapsed(last: u64, now: u64, cooldown: u64) -> bool {
    now.saturating_sub(last) >= cooldown
}

fn suspend_detected(boottime_delta: u64, gap: u64) -> bool {
    boottime_delta > gap
}

fn spawn_resume_watcher() {
    std::thread::spawn(|| {
        let mut last = boottime_secs();
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let now = boottime_secs();
            if suspend_detected(now.saturating_sub(last), SUSPEND_GAP_SECS) {
                kick(REASON_RESUME);
            }
            last = now;
        }
    });
}

fn spawn_netlink_watcher() {
    std::thread::spawn(|| {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return;
        }
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
        let r = unsafe {
            libc::bind(
                fd,
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if r < 0 {
            unsafe { libc::close(fd) };
            return;
        }
        let mut buf = [0u8; 8192];
        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n <= 0 {
                if n < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                break; // socket error/closed — stop watching
            }
            // Only kick for a change outside unvpn's tunnels. Our own device's churn
            // (its routes, address and link on every reconnect) would loop us, and
            // another session's tunnel coming or going is no change of our path.
            if batch_has_foreign_event(&buf[..n as usize]) {
                kick(REASON_NETCHANGE);
            }
        }
        unsafe { libc::close(fd) };
    });
}

/// True if the netlink batch contains at least one link/address/route event that is
/// not on an unvpn tunnel device (or whose interface we can't determine — treated
/// as foreign so a real change is never missed). Before [`ignore_iface`], any event
/// counts.
fn batch_has_foreign_event(data: &[u8]) -> bool {
    let own = IGNORED_IFINDEX.load(Ordering::SeqCst);
    if own == 0 {
        return !data.is_empty();
    }
    let gw = match GATEWAY.load(Ordering::SeqCst) {
        0 => None,
        g => Some(std::net::Ipv4Addr::from(g)),
    };
    batch_has_foreign(data, gw, &|idx, name| {
        idx == own
            || match name {
                Some(n) => crate::tun::is_unvpn_device(n),
                None => index_name(idx).is_some_and(|n| crate::tun::is_unvpn_device(&n)),
            }
    })
}

fn index_name(idx: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    let p = unsafe { libc::if_indextoname(idx, buf.as_mut_ptr()) };
    if p.is_null() {
        return None;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    s.to_str().ok().map(String::from)
}

/// `tunnel(index, name)` says whether an event on that interface is a tunnel's
/// own (the name when the message carries it). With `gw` known, a route whose
/// destination doesn't cover it doesn't count.
fn batch_has_foreign(
    mut data: &[u8],
    gw: Option<std::net::Ipv4Addr>,
    tunnel: &dyn Fn(u32, Option<&str>) -> bool,
) -> bool {
    // Walk the concatenated netlink messages: each is a 16-byte nlmsghdr
    // (len u32, type u16, flags u16, seq u32, pid u32) then a type-aligned payload.
    while data.len() >= 16 {
        let len = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let ty = u16::from_ne_bytes([data[4], data[5]]);
        if len < 16 || len > data.len() {
            break; // truncated / malformed — stop
        }
        let payload = &data[16..len];
        match event(ty, payload) {
            Some(Event {
                index: Some(i),
                name,
                ..
            }) if tunnel(i, name) => {}
            Some(Event { dst: Some(d), .. }) if gw.is_some_and(|g| !covers(d, g)) => {}
            _ => return true,
        }
        let aligned = (len + 3) & !3; // NLMSG_ALIGN
        if aligned == 0 || aligned > data.len() {
            break;
        }
        data = &data[aligned..];
    }
    false
}

/// What a link/address/route netlink message concerns.
#[derive(Debug, PartialEq)]
struct Event<'a> {
    /// The interface; a route with no `RTA_OIF` (blackhole, multipath) has none.
    index: Option<u32>,
    /// The device name, when the message carries it.
    name: Option<&'a str>,
    /// A route's destination prefix.
    dst: Option<(std::net::Ipv4Addr, u8)>,
}

/// `None` for message types we don't parse or payloads too short to trust.
fn event(ty: u16, payload: &[u8]) -> Option<Event<'_>> {
    let index_at_4 = || {
        let b = payload.get(4..8)?;
        Some(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
    };
    let named = |hdr: usize| {
        Some(Event {
            index: Some(index_at_4()?),
            name: attr(payload.get(hdr..)?, ATTR_NAME).and_then(c_str),
            dst: None,
        })
    };
    match ty {
        // ifinfomsg (16 bytes) / ifaddrmsg (8 bytes): index @ 4, then attributes.
        RTM_NEWLINK | RTM_DELLINK => named(16),
        RTM_NEWADDR | RTM_DELADDR => named(8),
        // rtmsg (12 bytes): dst_len @ 1, then attributes.
        RTM_NEWROUTE | RTM_DELROUTE => {
            let rtas = payload.get(12..)?;
            let len = *payload.get(1)?;
            let addr = match attr(rtas, RTA_DST).and_then(|b| b.get(..4)) {
                Some(b) => std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]),
                None => std::net::Ipv4Addr::UNSPECIFIED,
            };
            let index = attr(rtas, RTA_OIF)
                .and_then(|b| b.get(..4))
                .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
            Some(Event {
                index,
                name: None,
                dst: (len <= 32).then_some((addr, len)),
            })
        }
        _ => None,
    }
}

fn covers((net, len): (std::net::Ipv4Addr, u8), ip: std::net::Ipv4Addr) -> bool {
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    u32::from(net) & mask == u32::from(ip) & mask
}

/// The payload of the first `want` attribute in a run of netlink attributes.
fn attr(mut rta: &[u8], want: u16) -> Option<&[u8]> {
    while rta.len() >= 4 {
        let rlen = u16::from_ne_bytes([rta[0], rta[1]]) as usize;
        let rtype = u16::from_ne_bytes([rta[2], rta[3]]);
        if rlen < 4 || rlen > rta.len() {
            break;
        }
        if rtype == want {
            return Some(&rta[4..rlen]);
        }
        let aligned = (rlen + 3) & !3; // RTA_ALIGN
        if aligned == 0 || aligned > rta.len() {
            break;
        }
        rta = &rta[aligned..];
    }
    None
}

fn c_str(b: &[u8]) -> Option<&str> {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    std::str::from_utf8(&b[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cooldown_window() {
        assert!(cooldown_elapsed(100, 103, 3)); // exactly the window
        assert!(cooldown_elapsed(100, 110, 3));
        assert!(!cooldown_elapsed(100, 102, 3)); // inside the window
                                                 // A clock that went backwards must not fire a storm (saturating sub = 0).
        assert!(!cooldown_elapsed(200, 100, 3));
    }

    #[test]
    fn suspend_threshold() {
        assert!(suspend_detected(30, 8)); // a 2 s sleep that took 30 s → suspended
        assert!(!suspend_detected(2, 8)); // normal sleep
        assert!(!suspend_detected(8, 8)); // right at the gap, not over
    }

    /// Build one netlink message: 16-byte header + payload, padded to NLMSG_ALIGN.
    fn nlmsg(ty: u16, payload: &[u8]) -> Vec<u8> {
        let len = 16 + payload.len();
        let mut m = Vec::new();
        m.extend_from_slice(&(len as u32).to_ne_bytes());
        m.extend_from_slice(&ty.to_ne_bytes());
        m.extend_from_slice(&0u16.to_ne_bytes()); // flags
        m.extend_from_slice(&0u32.to_ne_bytes()); // seq
        m.extend_from_slice(&0u32.to_ne_bytes()); // pid
        m.extend_from_slice(payload);
        while m.len() % 4 != 0 {
            m.push(0);
        }
        m
    }

    fn route_msg_oif(ifindex: u32) -> Vec<u8> {
        route_msg(ifindex, None)
    }

    /// A route via `ifindex` to `dst` (`None`: the default route).
    fn route_msg(ifindex: u32, dst: Option<([u8; 4], u8)>) -> Vec<u8> {
        let mut p = vec![0u8; 12]; // rtmsg
        if let Some((a, len)) = dst {
            p[1] = len;
            p.extend_from_slice(&8u16.to_ne_bytes());
            p.extend_from_slice(&RTA_DST.to_ne_bytes());
            p.extend_from_slice(&a);
        }
        p.extend_from_slice(&8u16.to_ne_bytes());
        p.extend_from_slice(&RTA_OIF.to_ne_bytes());
        p.extend_from_slice(&ifindex.to_ne_bytes());
        nlmsg(RTM_NEWROUTE, &p)
    }

    fn link_msg(ifindex: u32, name: Option<&str>) -> Vec<u8> {
        let mut p = vec![0u8; 4]; // family, pad, type
        p.extend_from_slice(&ifindex.to_ne_bytes());
        p.extend_from_slice(&[0u8; 8]); // flags, change
        if let Some(n) = name {
            let mut v = n.as_bytes().to_vec();
            v.push(0);
            p.extend_from_slice(&((4 + v.len()) as u16).to_ne_bytes());
            p.extend_from_slice(&ATTR_NAME.to_ne_bytes());
            p.extend_from_slice(&v);
            while !p.len().is_multiple_of(4) {
                p.push(0);
            }
        }
        nlmsg(RTM_NEWLINK, &p)
    }

    /// Index 8 is this session's tunnel; names decide the rest.
    fn tunnel(idx: u32, name: Option<&str>) -> bool {
        idx == 8 || name.is_some_and(crate::tun::is_unvpn_device)
    }

    #[test]
    fn ignores_our_own_tunnel_churn() {
        let mut batch = route_msg_oif(8);
        batch.extend(link_msg(8, None));
        assert!(!batch_has_foreign(&batch, None, &tunnel));
        let mut mixed = route_msg_oif(8);
        mixed.extend(route_msg_oif(3));
        assert!(batch_has_foreign(&mixed, None, &tunnel));
    }

    #[test]
    fn another_sessions_tunnel_is_no_network_change() {
        assert!(!batch_has_foreign(
            &link_msg(12, Some("cpfg1")),
            None,
            &tunnel
        ));
        assert!(batch_has_foreign(
            &link_msg(2, Some("wlan0")),
            None,
            &tunnel
        ));
        assert_eq!(
            event(RTM_NEWLINK, &link_msg(12, Some("cpfg1"))[16..]),
            Some(Event {
                index: Some(12),
                name: Some("cpfg1"),
                dst: None
            })
        );
    }

    #[test]
    fn only_routes_that_can_move_the_gateway_path_count() {
        let gw = Some(std::net::Ipv4Addr::new(198, 51, 100, 7));
        // Another session pins its own gateway on the LAN interface: no kick.
        let pin = route_msg(2, Some(([203, 0, 113, 9], 32)));
        assert!(!batch_has_foreign(&pin, gw, &tunnel));
        assert!(!batch_has_foreign(
            &route_msg(2, Some(([172, 17, 0, 0], 16))),
            gw,
            &tunnel
        ));
        // A new default route, or one covering our gateway: kick.
        assert!(batch_has_foreign(&route_msg(2, None), gw, &tunnel));
        assert!(batch_has_foreign(
            &route_msg(2, Some(([198, 51, 100, 0], 24))),
            gw,
            &tunnel
        ));
        // Gateway unknown: every route outside the tunnels counts.
        assert!(batch_has_foreign(&pin, None, &tunnel));
        assert!(covers(
            (std::net::Ipv4Addr::UNSPECIFIED, 0),
            std::net::Ipv4Addr::new(1, 2, 3, 4)
        ));
        assert!(!covers(
            (std::net::Ipv4Addr::new(10, 0, 0, 0), 8),
            std::net::Ipv4Addr::new(11, 0, 0, 1)
        ));
    }

    #[test]
    fn route_without_oif_is_treated_as_foreign() {
        let batch = nlmsg(RTM_NEWROUTE, &[0u8; 12]);
        assert!(batch_has_foreign(&batch, None, &tunnel));
    }

    #[test]
    fn truncated_batch_does_not_panic() {
        let mut b = route_msg_oif(8);
        b.truncate(10);
        let _ = batch_has_foreign(&b, None, &tunnel);
        let mut b = link_msg(8, Some("cpfg0"));
        let n = b.len();
        b.truncate(n - 3);
        let _ = batch_has_foreign(&b, None, &tunnel);
    }

    #[test]
    fn unvpn_devices_are_known_by_name() {
        for n in ["unvpn0", "cpfg12", "cpwg0", "gpvpn3", "cpovpn0"] {
            assert!(crate::tun::is_unvpn_device(n), "{n}");
        }
        for n in ["cpfg", "eth0", "tun0", "cpfgx", "wlan0", "unvpn0a"] {
            assert!(!crate::tun::is_unvpn_device(n), "{n}");
        }
    }
}
