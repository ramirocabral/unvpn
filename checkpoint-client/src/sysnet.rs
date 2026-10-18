//! Shared system-networking helpers used by every VPN back-end.
//!
//! - DNS: point `/etc/resolv.conf` at the corporate resolver while connected and
//!   restore it on disconnect (symlink-aware: systemd-resolved / resolvconf).
//! - A stop flag driven by SIGTERM/SIGINT and by the GUI's stdin pipe
//!   (`disconnect` line or EOF), so a back-end's data loop can shut down cleanly.
//!
//! These are vendor-neutral; the Check Point (IKE/ESP) and Fortinet (SSL/PPP)
//! data planes both build on them.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// What `/etc/resolv.conf` looked like before we touched it, so disconnect can
/// put it back exactly — a plain file's contents, or a symlink we replaced with
/// a static file and must re-link.
pub struct DnsBackup {
    symlink_target: Option<PathBuf>,
    content: Option<String>,
}

/// Point `/etc/resolv.conf` at `dns` + `domains` while connected. Works across
/// distros: if resolv.conf is a symlink (systemd-resolved/resolvconf), replace it
/// with a static file and restore the symlink on disconnect; glibc reads this file
/// regardless of the resolver in use. Returns `None` (no-op) when `dns` is empty.
pub fn set_dns(dns: &[Ipv4Addr], domains: &str) -> Option<DnsBackup> {
    if dns.is_empty() {
        return None;
    }
    let is_symlink = std::fs::symlink_metadata(RESOLV_CONF)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    let backup = DnsBackup {
        symlink_target: if is_symlink { std::fs::read_link(RESOLV_CONF).ok() } else { None },
        content: std::fs::read_to_string(RESOLV_CONF).ok(), // follows the symlink
    };

    let mut content = String::from("# written by cpvpn — restored on disconnect\n");
    let search: Vec<&str> = domains.split([',', ';', ' ']).filter(|s| !s.is_empty()).collect();
    if !search.is_empty() {
        content.push_str(&format!("search {}\n", search.join(" ")));
    }
    for d in dns {
        content.push_str(&format!("nameserver {d}\n"));
    }
    if is_symlink {
        let _ = std::fs::remove_file(RESOLV_CONF); // replace the symlink with our file
    }
    match std::fs::write(RESOLV_CONF, content) {
        Ok(_) => println!("# DNS → {dns:?} (search {})", search.join(" ")),
        Err(e) => println!("# (could not set DNS: {e})"),
    }
    Some(backup)
}

/// Undo [`set_dns`], restoring the original file or symlink.
pub fn restore_dns(backup: Option<DnsBackup>) {
    let Some(b) = backup else { return };
    if let Some(target) = b.symlink_target {
        let _ = std::fs::remove_file(RESOLV_CONF);
        let _ = std::os::unix::fs::symlink(target, RESOLV_CONF);
    } else if let Some(c) = b.content {
        let _ = std::fs::write(RESOLV_CONF, c);
    }
    println!("# DNS restored");
}

// ─────────────────────────── stop flag (signals + stdin) ────────────────────

/// The single live stop flag. A tunnel runs one at a time, so one slot is enough;
/// the C signal handler reads it without allocating.
static STOP_FLAG: AtomicPtr<AtomicBool> = AtomicPtr::new(ptr::null_mut());

extern "C" fn on_stop_signal(_sig: libc::c_int) {
    let p = STOP_FLAG.load(Ordering::SeqCst);
    if !p.is_null() {
        // Safe: the pointer is a `&'static AtomicBool` handed to install_stop_signals.
        unsafe { (*p).store(true, Ordering::SeqCst) };
    }
}

/// Install SIGTERM/SIGINT handlers that set `flag`. `flag` must be `'static`
/// (a module-level static in the caller); the handler reads it after we return.
pub fn install_stop_signals(flag: &'static AtomicBool) {
    STOP_FLAG.store(flag as *const AtomicBool as *mut AtomicBool, Ordering::SeqCst);
    unsafe {
        let h = on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGTERM, h);
        libc::signal(libc::SIGINT, h);
    }
}

/// Spawn a thread that sets `flag` when stdin yields a `disconnect` line or EOF.
/// The GUI owns this pipe; a TTY user can type `disconnect` + Enter or ^D.
pub fn spawn_stdin_disconnect(flag: &'static AtomicBool) {
    std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            match std::io::stdin().read_line(&mut line) {
                Ok(0) => break, // EOF → disconnect
                Ok(_) if line.trim().eq_ignore_ascii_case("disconnect") => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        flag.store(true, Ordering::SeqCst);
    });
}
