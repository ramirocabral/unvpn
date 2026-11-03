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
/// Route attribute carrying the output interface index.
const RTA_OIF: u16 = 4;

/// Interface index whose own netlink churn must not trigger a reconnect: the tunnel
/// device. Our own connect/reconnect adds and removes the session's routes, address
/// and link on this interface, a burst of link/address/route events that would
/// otherwise look like a network change and kick us into an endless reconnect loop.
/// 0 ⇒ not set (filter nothing), so back-ends that don't call [`ignore_iface`] keep
/// the old behaviour.
static IGNORED_IFINDEX: AtomicU32 = AtomicU32::new(0);

/// Stop treating `name`'s own netlink events (its routes/address/link) as a network
/// change. Call once the tunnel device is up; safe to call again (last wins).
pub fn ignore_iface(name: &str) {
    let Ok(c) = std::ffi::CString::new(name) else { return };
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
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
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
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
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
                if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break; // socket error/closed — stop watching
            }
            // Only kick for a change on some *other* interface. Events that belong to
            // our own tunnel device (the churn of installing/removing its routes,
            // address and link on every reconnect) must not re-trigger us — that is
            // the reconnect loop this filter exists to break.
            if batch_has_foreign_event(&buf[..n as usize]) {
                kick(REASON_NETCHANGE);
            }
        }
        unsafe { libc::close(fd) };
    });
}

/// True if the netlink batch contains at least one link/address/route event that is
/// *not* for the ignored tunnel interface (or one whose interface we can't determine
/// — treated as foreign so a real change is never missed). With no ignored interface
/// set, any event counts, preserving the pre-filter behaviour.
fn batch_has_foreign_event(data: &[u8]) -> bool {
    batch_has_foreign(data, IGNORED_IFINDEX.load(Ordering::SeqCst))
}

fn batch_has_foreign(mut data: &[u8], ignored: u32) -> bool {
    if ignored == 0 {
        return !data.is_empty();
    }
    // Walk the concatenated netlink messages: each is a 16-byte nlmsghdr
    // (len u32, type u16, flags u16, seq u32, pid u32) then a type-aligned payload.
    while data.len() >= 16 {
        let len = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let ty = u16::from_ne_bytes([data[4], data[5]]);
        if len < 16 || len > data.len() {
            break; // truncated / malformed — stop
        }
        let payload = &data[16..len];
        match msg_ifindex(ty, payload) {
            Some(idx) if idx == ignored => {} // our own tunnel — ignore
            Some(_) | None => return true,    // another interface, or unknown → foreign
        }
        let aligned = (len + 3) & !3; // NLMSG_ALIGN
        if aligned == 0 || aligned > data.len() {
            break;
        }
        data = &data[aligned..];
    }
    false
}

/// The interface index a link/address/route netlink message concerns, if we can read
/// it. `None` for message types we don't parse or payloads too short to trust.
fn msg_ifindex(ty: u16, payload: &[u8]) -> Option<u32> {
    match ty {
        // ifinfomsg: family u8, pad u8, type u16, index i32 @ offset 4.
        RTM_NEWLINK | RTM_DELLINK => {
            let b = payload.get(4..8)?;
            Some(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
        }
        // ifaddrmsg: family u8, prefixlen u8, flags u8, scope u8, index u32 @ offset 4.
        RTM_NEWADDR | RTM_DELADDR => {
            let b = payload.get(4..8)?;
            Some(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
        }
        // rtmsg (12 bytes) then RTAs; the output interface is the RTA_OIF attribute.
        RTM_NEWROUTE | RTM_DELROUTE => {
            let mut rta = payload.get(12..)?;
            while rta.len() >= 4 {
                let rlen = u16::from_ne_bytes([rta[0], rta[1]]) as usize;
                let rtype = u16::from_ne_bytes([rta[2], rta[3]]);
                if rlen < 4 || rlen > rta.len() {
                    break;
                }
                if rtype == RTA_OIF && rlen >= 8 {
                    let b = &rta[4..8];
                    return Some(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]));
                }
                let aligned = (rlen + 3) & !3; // RTA_ALIGN
                if aligned == 0 || aligned > rta.len() {
                    break;
                }
                rta = &rta[aligned..];
            }
            None // a route with no RTA_OIF (e.g. blackhole) → unknown
        }
        _ => None,
    }
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
        let mut p = vec![0u8; 12]; // rtmsg
        // one RTA: len u16, type u16, u32 payload
        p.extend_from_slice(&8u16.to_ne_bytes());
        p.extend_from_slice(&RTA_OIF.to_ne_bytes());
        p.extend_from_slice(&ifindex.to_ne_bytes());
        nlmsg(RTM_NEWROUTE, &p)
    }

    fn link_msg(ifindex: u32) -> Vec<u8> {
        let mut p = vec![0u8; 4]; // family, pad, type
        p.extend_from_slice(&ifindex.to_ne_bytes());
        p.extend_from_slice(&[0u8; 8]); // flags, change
        nlmsg(RTM_NEWLINK, &p)
    }

    #[test]
    fn ignores_our_own_tunnel_churn() {
        let tun = 8u32;
        // A route and a link event, both on the tunnel: no kick.
        let mut batch = route_msg_oif(tun);
        batch.extend(link_msg(tun));
        assert!(!batch_has_foreign(&batch, tun));
        // The same batch with a route on another interface mixed in: kick.
        let mut mixed = route_msg_oif(tun);
        mixed.extend(route_msg_oif(3));
        assert!(batch_has_foreign(&mixed, tun));
    }

    #[test]
    fn route_without_oif_is_treated_as_foreign() {
        // A route message carrying no RTA_OIF → interface unknown → don't miss it.
        let batch = nlmsg(RTM_NEWROUTE, &[0u8; 12]);
        assert!(batch_has_foreign(&batch, 8));
    }

    #[test]
    fn no_ignored_iface_keeps_old_behaviour() {
        // ignored == 0 ⇒ any non-empty batch kicks (pre-filter behaviour).
        assert!(batch_has_foreign(&link_msg(8), 0));
        assert!(!batch_has_foreign(&[], 0));
    }

    #[test]
    fn truncated_batch_does_not_panic() {
        let mut b = route_msg_oif(8);
        b.truncate(10); // chop mid-message
        let _ = batch_has_foreign(&b, 8); // must not panic
    }
}
