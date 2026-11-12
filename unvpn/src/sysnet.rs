//! Shared system-networking helpers used by every VPN back-end.
//!
//! - A stop flag driven by SIGTERM/SIGINT, by the GUI's stdin pipe (`disconnect`
//!   line or EOF) and by the control socket, so a back-end's data loop can shut
//!   down cleanly.
//! - A stdin pump: ONE thread reads stdin for the whole process and hands lines
//!   out through a channel, so the auth prompts (2FA code, SAML paste, push), and
//!   later the tunnel's `disconnect` watcher, never race each other for a line.

use std::collections::VecDeque;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub use unvpn_profiles::marker::{one_line, one_word};

/// Undoes our DNS change and the routes we added when dropped: on the normal
/// teardown, on an early error return, and on a panic unwinding through a
/// back-end's `run` (e.g. a print to a stdout whose reader — the GUI — is gone).
/// Prints nothing that could panic.
#[derive(Default)]
pub struct NetRestore {
    pub dns: Option<crate::dns::DnsBackup>,
    /// `route del …` lines for `ip -batch`.
    pub routes: Vec<String>,
    /// The kill-switch / IPv6 nftables table, removed last so the link stays
    /// fail-closed until DNS and routes are back to their pre-VPN state.
    pub leak: Option<crate::leakguard::LeakGuard>,
}

impl NetRestore {
    /// Record what this holds for `unvpn recover`, in case we are killed before it drops.
    pub fn commit(&self, iface: &str) {
        crate::control::save_undo(
            iface,
            &self.routes,
            self.leak.as_ref().map(|l| l.table()),
            self.dns.is_some(),
        );
    }
}

impl Drop for NetRestore {
    fn drop(&mut self) {
        crate::dns::restore_dns(self.dns.take());
        let _ = crate::tun::ip_batch(&self.routes);
        drop(self.leak.take());
        crate::control::clear_undo();
    }
}

/// The single live stop flag. A tunnel runs one at a time, so one slot is enough;
/// the C signal handler reads it without allocating.
static STOP_FLAG: AtomicPtr<AtomicBool> = AtomicPtr::new(ptr::null_mut());

extern "C" fn on_stop_signal(_sig: libc::c_int) {
    let p = STOP_FLAG.load(Ordering::SeqCst);
    if !p.is_null() {
        // SAFETY: the pointer is a `&'static AtomicBool` handed to install_stop_signals.
        unsafe { (*p).store(true, Ordering::SeqCst) };
    }
}

/// Install SIGTERM/SIGINT/SIGHUP/SIGQUIT handlers that set `flag`, so every way
/// of ending us (GUI, ^C, closing the terminal — sudo relays SIGHUP) still runs the
/// teardown. `flag` must be `'static` (a module-level static in the caller); the
/// handler reads it after we return.
pub fn install_stop_signals(flag: &'static AtomicBool) {
    STOP_FLAG.store(
        flag as *const AtomicBool as *mut AtomicBool,
        Ordering::SeqCst,
    );
    unsafe {
        let h = on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
            libc::signal(sig, h);
        }
    }
}

/// Stop as a `disconnect` line on stdin would (asked over the control socket).
pub fn request_stop() {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
    on_stop_signal(0);
}

/// With `--detachable`, stdin closing once the tunnel is up leaves it running (the
/// front-end went away; the control socket can still stop it).
static DETACHABLE: AtomicBool = AtomicBool::new(false);

pub fn set_detachable(on: bool) {
    DETACHABLE.store(on, Ordering::SeqCst);
}

/// Spawn a thread that sets `flag` when stdin yields a `disconnect` line or EOF
/// (unless the tunnel is detachable and up), or a stop is requested otherwise.
/// The GUI owns this pipe; a TTY user can type `disconnect` + Enter or ^D.
/// Reads through the [`stdin_next`] pump, so lines typed during auth aren't lost.
pub fn spawn_stdin_disconnect(flag: &'static AtomicBool) {
    std::thread::spawn(move || {
        loop {
            // Short waits so the pump's lock is free while a [`StdinWatchPause`] lets
            // a mid-session re-login read its prompts' answers.
            if WATCH_PAUSED.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            match stdin_next(Some(Duration::from_millis(250))) {
                StdinEvent::Line(l) if is_disconnect(&l) => break,
                StdinEvent::Line(_) | StdinEvent::Timeout => continue,
                StdinEvent::Eof if stop_requested() => break,
                StdinEvent::Eof => return,
            }
        }
        flag.store(true, Ordering::SeqCst);
    });
}

static WATCH_PAUSED: AtomicBool = AtomicBool::new(false);

/// While alive, the [`spawn_stdin_disconnect`] watcher leaves stdin alone, so the
/// session can ask (2FA, password) on it again; a `disconnect` typed meanwhile
/// reaches whoever is reading.
pub struct StdinWatchPause;

impl StdinWatchPause {
    pub fn new() -> Self {
        WATCH_PAUSED.store(true, Ordering::SeqCst);
        StdinWatchPause
    }
}

impl Drop for StdinWatchPause {
    fn drop(&mut self) {
        WATCH_PAUSED.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug, PartialEq)]
pub enum StdinEvent {
    /// A line, without its trailing newline.
    Line(String),
    /// stdin closed (the GUI went away, or ^D on a TTY), or a stop was requested.
    Eof,
    Timeout,
}

/// How often a wait on stdin looks at [`stop_requested`].
const STOP_POLL: Duration = Duration::from_millis(200);

/// Receiving end of the pump; the reader thread starts on first use. Dropping its
/// sender (on EOF) makes every later receive report `Eof`.
static STDIN_RX: OnceLock<Mutex<mpsc::Receiver<String>>> = OnceLock::new();

/// Raised by the pump's reader as soon as it sees `disconnect` or EOF — before any
/// consumer gets to the line — so code blocked in a long request (a login the
/// gateway holds open) can abort without waiting for its next stdin read.
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

pub fn stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

/// Sleep up to `secs`, returning early with `true` once `flag` is set or a
/// disconnect was requested on stdin.
pub fn sleep_interruptible(secs: u64, flag: &AtomicBool) -> bool {
    let stopped = || flag.load(Ordering::SeqCst) || stop_requested();
    for _ in 0..secs * 10 {
        if stopped() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    stopped()
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
                        if DETACHABLE.load(Ordering::SeqCst) && crate::report::was_up() && !stop_requested() {
                            out!("# the front-end is gone — the tunnel stays up (`unvpn disconnect` stops it)");
                        } else {
                            STOP_REQUESTED.store(true, Ordering::SeqCst);
                        }
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

/// Lines [`stdin_ask`] read past while waiting for its answer, handed out before
/// anything newer.
static STDIN_HELD: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Next stdin line, waiting at most `timeout` (`None` = until a line or EOF). Code
/// that mixes this with direct `stdin.read_line` must do its direct reads first.
pub fn stdin_next(timeout: Option<Duration>) -> StdinEvent {
    if let Some(l) = STDIN_HELD
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .pop_front()
    {
        return StdinEvent::Line(l);
    }
    let rx = stdin_rx().lock().unwrap_or_else(|e| e.into_inner());
    match recv_until(&rx, timeout.map(|t| Instant::now() + t), &stop_requested) {
        Ok(l) => StdinEvent::Line(l),
        Err(RecvTimeoutError::Timeout) => StdinEvent::Timeout,
        Err(RecvTimeoutError::Disconnected) => StdinEvent::Eof,
    }
}

/// The next line before `deadline` (`None` = no limit). Ends as `Disconnected`
/// when the pump closed or `stopped()` turns true.
fn recv_until(
    rx: &mpsc::Receiver<String>,
    deadline: Option<Instant>,
    stopped: &dyn Fn() -> bool,
) -> Result<String, RecvTimeoutError> {
    loop {
        let step = match deadline {
            None => STOP_POLL,
            Some(d) => d
                .checked_duration_since(Instant::now())
                .ok_or(RecvTimeoutError::Timeout)?
                .min(STOP_POLL),
        };
        match rx.recv_timeout(step) {
            Ok(l) => return Ok(l),
            Err(RecvTimeoutError::Timeout) if stopped() => {
                return Err(RecvTimeoutError::Disconnected)
            }
            Err(RecvTimeoutError::Timeout) if deadline.is_some_and(|d| Instant::now() >= d) => {
                return Err(RecvTimeoutError::Timeout)
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(RecvTimeoutError::Disconnected),
        }
    }
}

/// Ask a question whose answer the front-end tags, so it can't be confused with
/// the lines it wrote ahead of time (the password, …). `announce` prints the
/// question once this holds the reader, so no other reader can take the answer.
/// Lines `pick` rejects stay queued, in order, for the next [`stdin_next`].
/// `None` on `disconnect`, EOF or timeout.
pub fn stdin_ask<T>(
    announce: impl FnOnce(),
    timeout: Option<Duration>,
    pick: impl FnMut(&str) -> Option<T>,
) -> Option<T> {
    let rx = stdin_rx().lock().unwrap_or_else(|e| e.into_inner());
    announce();
    ask_from(&rx, &STDIN_HELD, timeout, &stop_requested, pick)
}

fn ask_from<T>(
    rx: &mpsc::Receiver<String>,
    held: &Mutex<VecDeque<String>>,
    timeout: Option<Duration>,
    stopped: &dyn Fn() -> bool,
    mut pick: impl FnMut(&str) -> Option<T>,
) -> Option<T> {
    let deadline = timeout.map(|t| Instant::now() + t);
    loop {
        let line = recv_until(rx, deadline, stopped).ok()?;
        if is_disconnect(&line) {
            return None;
        }
        match pick(&line) {
            Some(v) => return Some(v),
            None => held
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push_back(line),
        }
    }
}

/// `write_all` for a non-blocking socket: on `WouldBlock`, wait (up to 20 s) for
/// `fd` to become writable and retry the SAME remaining bytes — OpenSSL requires
/// an interrupted `SSL_write` to be retried with the same data, and a full send
/// buffer under a big upload is normal, not a reason to drop the tunnel.
pub fn write_all_polling<W: std::io::Write>(
    w: &mut W,
    fd: Option<i32>,
    mut buf: &[u8],
) -> Result<(), String> {
    while !buf.is_empty() {
        match w.write(buf) {
            Ok(0) => return Err("write: connection closed".into()),
            Ok(n) => buf = &buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && fd.is_some() => {
                let mut p = libc::pollfd {
                    fd: fd.unwrap_or(-1),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let r = unsafe { libc::poll(&mut p, 1, 20_000) };
                if r == 0 {
                    return Err("write: socket not writable for 20 s".into());
                }
                if r < 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                {
                    return Err(format!("poll: {}", std::io::Error::last_os_error()));
                }
            }
            Err(e) => return Err(format!("write: {e}")),
        }
    }
    Ok(())
}

pub fn is_disconnect(line: &str) -> bool {
    line.trim().eq_ignore_ascii_case("disconnect")
}

/// `(uid, gid)` of the user who started us through sudo or pkexec, when we run as
/// root on their behalf.
pub fn invoker_ids() -> Option<(u32, u32)> {
    invoker().map(|(u, g, _)| (u, g))
}

/// The user who started us through sudo or pkexec, when we run as root on their
/// behalf: `(uid, primary gid, supplementary groups)`.
fn invoker() -> Option<(u32, u32, Vec<libc::gid_t>)> {
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let uid: u32 = std::env::var("SUDO_UID")
        .or_else(|_| std::env::var("PKEXEC_UID"))
        .ok()?
        .parse()
        .ok()?;
    if uid == 0 {
        return None;
    }
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut res: *mut libc::passwd = ptr::null_mut();
    unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut res) };
    if res.is_null() {
        let gid = std::env::var("SUDO_GID")
            .ok()
            .and_then(|g| g.parse().ok())
            .unwrap_or(65534);
        return Some((uid, gid, vec![gid]));
    }
    let gid = pw.pw_gid;
    let mut groups = vec![0 as libc::gid_t; 256];
    let mut n = groups.len() as libc::c_int;
    if unsafe { libc::getgrouplist(pw.pw_name, gid, groups.as_mut_ptr(), &mut n) } < 0 {
        n = 1;
        groups[0] = gid;
    }
    groups.truncate(n.max(0) as usize);
    Some((uid, gid, groups))
}

/// The calling thread's file-system identity, put back on drop.
struct FsIdentity {
    uid: u32,
    gid: u32,
    groups: Vec<libc::gid_t>,
}

impl Drop for FsIdentity {
    fn drop(&mut self) {
        unsafe {
            libc::setfsuid(self.uid);
            libc::setfsgid(self.gid);
            // The raw syscall changes only this thread; glibc's wrapper would change them all.
            libc::syscall(libc::SYS_setgroups, self.groups.len(), self.groups.as_ptr());
        }
    }
}

/// Run `f` with the file-system identity (fsuid, fsgid, groups) of the user who
/// started us through sudo or pkexec, so a path they named is opened with their
/// permissions, not root's. Applies to the calling thread only; runs `f` as is
/// when we were not started that way.
pub fn as_invoker<T>(f: impl FnOnce() -> T) -> T {
    let Some((uid, gid, groups)) = invoker() else {
        return f();
    };
    let saved = unsafe {
        let n = libc::getgroups(0, ptr::null_mut());
        let mut cur = vec![0 as libc::gid_t; n.max(0) as usize];
        let n = libc::getgroups(cur.len() as libc::c_int, cur.as_mut_ptr());
        cur.truncate(n.max(0) as usize);
        let gid0 = libc::setfsgid(u32::MAX);
        libc::syscall(libc::SYS_setgroups, groups.len(), groups.as_ptr());
        libc::setfsgid(gid);
        FsIdentity {
            uid: libc::setfsuid(uid) as u32,
            gid: gid0 as u32,
            groups: cur,
        }
    };
    let r = f();
    drop(saved);
    r
}

fn open_user_regular(path: &Path, opts: &std::fs::OpenOptions) -> std::io::Result<std::fs::File> {
    let f = opts.open(path)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(f)
}

/// Read a file the user named, with their permissions (see [`as_invoker`]).
pub fn read_user_file(path: impl AsRef<Path>) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    as_invoker(|| {
        let mut f = open_user_regular(path.as_ref(), std::fs::OpenOptions::new().read(true))?;
        let mut v = Vec::new();
        f.read_to_end(&mut v)?;
        Ok(v)
    })
}

pub fn read_user_string(path: impl AsRef<Path>) -> std::io::Result<String> {
    String::from_utf8(read_user_file(path)?)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "not UTF-8"))
}

/// Write a private (0600) file where the user asked, with their permissions and
/// without following a symlink in the last component.
pub fn write_user_file(path: impl AsRef<Path>, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    as_invoker(|| {
        let mut f = open_user_regular(
            path.as_ref(),
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW),
        )?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        f.write_all(data)
    })
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
    fn an_asked_question_leaves_earlier_lines_queued_in_order() {
        let (tx, rx) = mpsc::channel();
        let held = Mutex::new(VecDeque::new());
        for l in ["the password", "a second secret", "tag yes", "later"] {
            tx.send(l.to_string()).unwrap();
        }
        let pick = |l: &str| l.strip_prefix("tag ").map(str::to_string);
        let go_on = || false;
        assert_eq!(
            ask_from(&rx, &held, None, &go_on, pick).as_deref(),
            Some("yes")
        );
        assert_eq!(
            held.lock().unwrap().iter().collect::<Vec<_>>(),
            ["the password", "a second secret"]
        );
        assert_eq!(rx.recv().unwrap(), "later");

        tx.send("disconnect".into()).unwrap();
        assert_eq!(ask_from(&rx, &held, None, &go_on, pick), None);
        assert_eq!(
            ask_from(&rx, &held, Some(Duration::from_millis(20)), &go_on, pick),
            None
        );
        let t = Instant::now();
        assert_eq!(
            ask_from(
                &rx,
                &held,
                None,
                &|| t.elapsed() > Duration::from_millis(50),
                pick
            ),
            None
        );
        drop(tx);
        assert_eq!(ask_from(&rx, &held, None, &go_on, pick), None);
    }

    #[test]
    fn a_wait_ends_at_its_deadline_or_on_a_stop() {
        let (tx, rx) = mpsc::channel::<String>();
        let t = Instant::now();
        assert_eq!(
            recv_until(&rx, Some(t + Duration::from_millis(30)), &|| false),
            Err(RecvTimeoutError::Timeout)
        );
        assert!(t.elapsed() < Duration::from_millis(150));
        let t = Instant::now();
        let stop_at = Duration::from_millis(250);
        assert_eq!(
            recv_until(&rx, None, &|| t.elapsed() > stop_at),
            Err(RecvTimeoutError::Disconnected)
        );
        tx.send("x".into()).unwrap();
        assert_eq!(recv_until(&rx, None, &|| true).as_deref(), Ok("x"));
    }

    /// Meaningful only under sudo/pkexec (run the test binary with `sudo`); a no-op otherwise.
    #[test]
    fn user_files_open_with_the_invokers_permissions() {
        use std::os::unix::fs::MetadataExt;
        let Some((uid, _, _)) = invoker() else { return };
        let dir = std::env::temp_dir().join(format!("unvpn-invoker-{}", std::process::id()));
        as_invoker(|| std::fs::create_dir(&dir)).unwrap();
        let file = dir.join("cookie");
        write_user_file(&file, b"abc").unwrap();
        let md = std::fs::metadata(&file).unwrap();
        assert_eq!((md.uid(), md.mode() & 0o777), (uid, 0o600));
        assert_eq!(read_user_file(&file).unwrap(), b"abc");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(write_user_file(&link, b"x").is_err());
        assert!(read_user_file("/etc/shadow").is_err());
        assert!(write_user_file("/etc/unvpn-invoker-test", b"x").is_err());
        assert!(write_user_file("/dev/null", b"x").is_err());
        assert!(std::fs::read("/etc/shadow").is_ok(), "fs identity restored");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
