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

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

const REASON_RESUME: u8 = 1;
const REASON_NETCHANGE: u8 = 2;

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
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n <= 0 {
                if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break; // socket error/closed — stop watching
            }
            kick(REASON_NETCHANGE);
        }
        unsafe { libc::close(fd) };
    });
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
}
