//! Shared system-networking helpers used by every VPN back-end.
//!
//! - DNS: point `/etc/resolv.conf` at the corporate resolver while connected and
//!   restore it on disconnect (symlink-aware: systemd-resolved / resolvconf).
//! - A stop flag driven by SIGTERM/SIGINT and by the GUI's stdin pipe
//!   (`disconnect` line or EOF), so a back-end's data loop can shut down cleanly.
//! - A stdin pump: ONE thread reads stdin for the whole process and hands lines
//!   out through a channel, so the auth prompts (2FA code, SAML paste, push), and
//!   later the tunnel's `disconnect` watcher, never race each other for a line.
//!
//! These are vendor-neutral; the Check Point (IKE/ESP) and Fortinet (SSL/PPP)
//! data planes both build on them.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

pub const RESOLV_CONF: &str = "/etc/resolv.conf";
/// First line of the resolv.conf we write, used to recognise our own leftover.
const DNS_MARKER: &str = "# written by cpvpn";
/// Persistent copy of the pre-VPN resolv.conf, so a later connect can recover the
/// true original even if a previous session crashed without restoring (in-memory
/// backup lost). `/run` is tmpfs — fine, resolv.conf is regenerated on boot anyway.
const DNS_SIDECAR: &str = "/run/cpvpn/resolv.orig";

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
///
/// Crash-safe: the true original is also written to a persistent sidecar. If the
/// current resolv.conf is already *ours* (a prior session crashed/overlapped and
/// never restored), we must NOT back that up — we'd "restore" the corp DNS and
/// leave the host unable to resolve. In that case we recover the real original
/// from the sidecar and leave the sidecar untouched.
pub fn set_dns(dns: &[Ipv4Addr], domains: &str) -> Option<DnsBackup> {
    if dns.is_empty() {
        return None;
    }
    let is_symlink = std::fs::symlink_metadata(RESOLV_CONF)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    let current = std::fs::read_to_string(RESOLV_CONF).ok(); // follows the symlink
    let already_ours = current.as_deref().is_some_and(|c| c.starts_with(DNS_MARKER));

    let backup = if already_ours {
        // Leftover from a crashed/overlapping session — the file no longer holds the
        // real original. Recover it from the sidecar (the first session saved it).
        out!("# (resolv.conf was already cpvpn's — recovering the original from {DNS_SIDECAR})");
        read_dns_sidecar().unwrap_or(DnsBackup { symlink_target: None, content: None })
    } else {
        let b = DnsBackup {
            symlink_target: if is_symlink { std::fs::read_link(RESOLV_CONF).ok() } else { None },
            content: current,
        };
        write_dns_sidecar(&b); // persist the true original for crash recovery
        b
    };

    let mut content = format!("{DNS_MARKER} — restored on disconnect\n");
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
        Ok(_) => out!("# DNS → {dns:?} (search {})", search.join(" ")),
        Err(e) => out!("# (could not set DNS: {e})"),
    }
    Some(backup)
}

/// Undo [`set_dns`], restoring the original file or symlink and clearing the sidecar.
pub fn restore_dns(backup: Option<DnsBackup>) {
    let Some(b) = backup else { return };
    if let Some(target) = b.symlink_target {
        let _ = std::fs::remove_file(RESOLV_CONF);
        let _ = std::os::unix::fs::symlink(target, RESOLV_CONF);
    } else if let Some(c) = b.content {
        let _ = std::fs::write(RESOLV_CONF, c);
    }
    let _ = std::fs::remove_file(DNS_SIDECAR);
    out!("# DNS restored");
}

/// Persist the true original resolv.conf for crash recovery.
fn write_dns_sidecar(b: &DnsBackup) {
    let Some(body) = encode_sidecar(b) else { return }; // nothing worth persisting
    if let Some(dir) = std::path::Path::new(DNS_SIDECAR).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(DNS_SIDECAR, body);
}

/// Read the crash-recovery sidecar back into a [`DnsBackup`].
fn read_dns_sidecar() -> Option<DnsBackup> {
    decode_sidecar(&std::fs::read_to_string(DNS_SIDECAR).ok()?)
}

/// Serialise a backup: `SYMLINK <target>` or `FILE\n<original bytes>`. `None` when
/// there's no original to keep (resolv.conf didn't exist).
fn encode_sidecar(b: &DnsBackup) -> Option<String> {
    if let Some(t) = &b.symlink_target {
        Some(format!("SYMLINK {}\n", t.display()))
    } else {
        b.content.as_ref().map(|c| format!("FILE\n{c}"))
    }
}

/// Parse what [`encode_sidecar`] wrote.
fn decode_sidecar(raw: &str) -> Option<DnsBackup> {
    if let Some(rest) = raw.strip_prefix("SYMLINK ") {
        let target = rest.lines().next().unwrap_or("").trim();
        Some(DnsBackup { symlink_target: Some(PathBuf::from(target)), content: None })
    } else if let Some(rest) = raw.strip_prefix("FILE\n") {
        Some(DnsBackup { symlink_target: None, content: Some(rest.to_string()) })
    } else {
        None
    }
}

/// Undoes our DNS change and the routes we added when dropped: on the normal
/// teardown, on an early error return, and on a panic unwinding through a
/// back-end's `run` (e.g. a print to a stdout whose reader — the GUI — is gone).
/// Prints nothing that could panic.
#[derive(Default)]
pub struct NetRestore {
    pub dns: Option<DnsBackup>,
    /// `route del …` lines for `ip -batch`.
    pub routes: Vec<String>,
}

impl Drop for NetRestore {
    fn drop(&mut self) {
        restore_dns(self.dns.take());
        let _ = crate::tun::ip_batch(&self.routes); // remove our routes in one shot
    }
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

/// Install SIGTERM/SIGINT/SIGHUP/SIGQUIT handlers that set `flag`, so every way
/// of ending us (GUI, ^C, closing the terminal — sudo relays SIGHUP) still runs the
/// teardown. `flag` must be `'static` (a module-level static in the caller); the
/// handler reads it after we return.
pub fn install_stop_signals(flag: &'static AtomicBool) {
    STOP_FLAG.store(flag as *const AtomicBool as *mut AtomicBool, Ordering::SeqCst);
    unsafe {
        let h = on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
            libc::signal(sig, h);
        }
    }
}

/// Spawn a thread that sets `flag` when stdin yields a `disconnect` line or EOF.
/// The GUI owns this pipe; a TTY user can type `disconnect` + Enter or ^D.
/// Reads through the [`stdin_next`] pump, so lines typed during auth aren't lost.
pub fn spawn_stdin_disconnect(flag: &'static AtomicBool) {
    std::thread::spawn(move || {
        loop {
            match stdin_next(None) {
                StdinEvent::Line(l) if is_disconnect(&l) => break,
                StdinEvent::Line(_) | StdinEvent::Timeout => continue,
                StdinEvent::Eof => break, // EOF → disconnect
            }
        }
        flag.store(true, Ordering::SeqCst);
    });
}

// ─────────────────────────────── stdin pump ─────────────────────────────────

/// One stdin event from the pump.
#[derive(Debug, PartialEq)]
pub enum StdinEvent {
    /// A line, without its trailing newline.
    Line(String),
    /// stdin closed (the GUI went away, or ^D on a TTY).
    Eof,
    /// Nothing arrived within the timeout.
    Timeout,
}

/// Receiving end of the pump; the reader thread starts on first use. Dropping its
/// sender (on EOF) makes every later receive report `Eof`.
static STDIN_RX: OnceLock<Mutex<mpsc::Receiver<String>>> = OnceLock::new();

/// Raised by the pump's reader as soon as it sees `disconnect` or EOF — before any
/// consumer gets to the line — so code blocked in a long request (a login the
/// gateway holds open) can abort without waiting for its next stdin read.
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// The GUI (or the TTY user) asked us to stop.
pub fn stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

fn stdin_rx() -> &'static Mutex<mpsc::Receiver<String>> {
    STDIN_RX.get_or_init(|| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            loop {
                line.clear();
                match std::io::stdin().read_line(&mut line) {
                    Ok(0) | Err(_) => {
                        STOP_REQUESTED.store(true, Ordering::SeqCst);
                        return; // drops tx → Eof for the receiver
                    }
                    Ok(_) => {
                        let l = line.trim_end_matches(['\r', '\n']).to_string();
                        if is_disconnect(&l) {
                            STOP_REQUESTED.store(true, Ordering::SeqCst);
                        }
                        if tx.send(l).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        Mutex::new(rx)
    })
}

/// Next stdin line, waiting at most `timeout` (`None` = until a line or EOF). Code
/// that mixes this with direct `stdin().read_line` must do its direct reads first.
pub fn stdin_next(timeout: Option<Duration>) -> StdinEvent {
    let rx = stdin_rx().lock().unwrap_or_else(|e| e.into_inner());
    match timeout {
        None => rx.recv().map(StdinEvent::Line).unwrap_or(StdinEvent::Eof),
        Some(t) => match rx.recv_timeout(t) {
            Ok(l) => StdinEvent::Line(l),
            Err(RecvTimeoutError::Timeout) => StdinEvent::Timeout,
            Err(RecvTimeoutError::Disconnected) => StdinEvent::Eof,
        },
    }
}

/// `write_all` for a non-blocking socket: on `WouldBlock`, wait (up to 20 s) for
/// `fd` to become writable and retry the SAME remaining bytes — OpenSSL requires
/// an interrupted `SSL_write` to be retried with the same data, and a full send
/// buffer under a big upload is normal, not a reason to drop the tunnel.
pub fn write_all_polling<W: std::io::Write>(w: &mut W, fd: Option<i32>, mut buf: &[u8]) -> Result<(), String> {
    while !buf.is_empty() {
        match w.write(buf) {
            Ok(0) => return Err("write: connection closed".into()),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && fd.is_some() => {
                let mut p = libc::pollfd { fd: fd.unwrap_or(-1), events: libc::POLLOUT, revents: 0 };
                let r = unsafe { libc::poll(&mut p, 1, 20_000) };
                if r == 0 {
                    return Err("write: socket not writable for 20 s".into());
                }
                if r < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                    return Err(format!("poll: {}", std::io::Error::last_os_error()));
                }
            }
            Err(e) => return Err(format!("write: {e}")),
        }
    }
    Ok(())
}

/// The GUI's (or a TTY user's) cancel/teardown line.
pub fn is_disconnect(line: &str) -> bool {
    line.trim().eq_ignore_ascii_case("disconnect")
}

/// Turns terminal echo off on stdin while alive (no-op when stdin isn't a TTY), so
/// a secret typed at a prompt isn't shown. Echo comes back on drop.
pub struct EchoOff(Option<libc::termios>);

impl EchoOff {
    pub fn new() -> Self {
        let fd = libc::STDIN_FILENO;
        unsafe {
            if libc::isatty(fd) != 1 {
                return EchoOff(None);
            }
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut t) != 0 {
                return EchoOff(None);
            }
            let mut quiet = t;
            quiet.c_lflag &= !libc::ECHO;
            libc::tcsetattr(fd, libc::TCSANOW, &quiet);
            EchoOff(Some(t))
        }
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        if let Some(t) = self.0 {
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) };
            eprintln!(); // the user's Enter wasn't echoed; move to the next line
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_roundtrip_file() {
        let b = DnsBackup {
            symlink_target: None,
            content: Some("# Generated by NetworkManager\nnameserver 192.168.9.53\n".to_string()),
        };
        let enc = encode_sidecar(&b).unwrap();
        let dec = decode_sidecar(&enc).unwrap();
        assert!(dec.symlink_target.is_none());
        assert_eq!(dec.content.as_deref(), Some("# Generated by NetworkManager\nnameserver 192.168.9.53\n"));
    }

    #[test]
    fn sidecar_roundtrip_symlink() {
        let b = DnsBackup {
            symlink_target: Some(PathBuf::from("/run/systemd/resolve/stub-resolv.conf")),
            content: Some("ignored when it was a symlink".to_string()),
        };
        let enc = encode_sidecar(&b).unwrap();
        assert!(enc.starts_with("SYMLINK /run/systemd/resolve/stub-resolv.conf"));
        let dec = decode_sidecar(&enc).unwrap();
        assert_eq!(dec.symlink_target.as_deref(), Some(std::path::Path::new("/run/systemd/resolve/stub-resolv.conf")));
        assert!(dec.content.is_none());
    }

    #[test]
    fn sidecar_empty_backup_not_persisted() {
        assert!(encode_sidecar(&DnsBackup { symlink_target: None, content: None }).is_none());
    }

    #[test]
    fn our_own_resolv_is_recognised() {
        // A resolv.conf we wrote must be detected by the marker so set_dns won't
        // back it up as if it were the user's original.
        let ours = format!("{DNS_MARKER} — restored on disconnect\nnameserver 10.0.0.1\n");
        assert!(ours.starts_with(DNS_MARKER));
        assert!(!"# Generated by NetworkManager\n".starts_with(DNS_MARKER));
    }
}
