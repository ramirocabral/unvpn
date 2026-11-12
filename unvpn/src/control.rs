//! The engine's control socket (protocol in `unvpn_profiles::control`) and the
//! `status` / `disconnect` commands.
//!
//! While a session runs, its stdout and stderr pass through a relay thread: what
//! the engine prints still reaches whoever reads it, a reader that went away can't
//! make a print fail, and the recent lines stay available to `log` requests.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, TryLockError};
use std::time::{Duration, Instant};

use unvpn_profiles::control::{self as ctl, Status, RUN_DIR};
use unvpn_profiles::marker::State;

static STATUS: Mutex<Option<Status>> = Mutex::new(None);
static SOCKET: OnceLock<PathBuf> = OnceLock::new();

/// Lines of the session's output kept for `log` requests.
const LOG_LINES: usize = 1000;
const LOG_LINE_MAX: usize = 4096;

struct Log {
    next: u64,
    lines: VecDeque<(u64, String)>,
    partial: [Vec<u8>; 2],
}

static LOG: Mutex<Log> = Mutex::new(Log { next: 1, lines: VecDeque::new(), partial: [Vec::new(), Vec::new()] });

/// The original stdout/stderr and the read ends of the pipes now standing in for them.
struct Relay {
    orig: [i32; 2],
    read: [i32; 2],
}

static RELAY: OnceLock<Relay> = OnceLock::new();
/// Held while a chunk moves through the relay, so the exit flush can't reorder it.
static RELAY_IO: Mutex<()> = Mutex::new(());

/// Start serving this session (as root only): the output relay, the status, and
/// the socket, owned by the user who started us through sudo/pkexec.
pub fn start(backend: &str, label: &str, args: &[String]) {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let pid = std::process::id();
    *STATUS.lock().unwrap_or_else(|e| e.into_inner()) = Some(Status {
        pid,
        backend: backend.to_string(),
        label: label.to_string(),
        gateway: gateway_in(args).unwrap_or_default(),
        ..Default::default()
    });
    start_relay();
    unsafe { libc::atexit(at_exit) };

    if let Err(e) = std::fs::create_dir_all(RUN_DIR) {
        out!("# (no control socket: {RUN_DIR}: {e})");
        return;
    }
    let path = ctl::socket_path(pid);
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            out!("# (no control socket: {}: {e})", path.display());
            return;
        }
    };
    let owner = crate::sysnet::invoker_ids();
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        if let Some((uid, gid)) = owner {
            let _ = std::os::unix::fs::chown(&path, Some(uid), Some(gid));
        }
    }
    let _ = SOCKET.set(path);
    let allowed = owner.map(|(uid, _)| uid);
    std::thread::spawn(move || serve(listener, allowed));
}

pub fn update(f: impl FnOnce(&mut Status)) {
    if let Some(s) = STATUS.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
        f(s);
    }
}

/// The gateway named on the command line (`-g`, `--gateway`, an F5 `--launch` link).
fn gateway_in(args: &[String]) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-g" | "--gateway" => return it.next().cloned(),
            "--launch" => {
                let ep = unvpn_profiles::f5_launch_endpoint(it.next()?)?;
                return Some(ep.strip_suffix(":443").map(String::from).unwrap_or(ep));
            }
            _ => {}
        }
    }
    None
}

fn serve(listener: UnixListener, allowed: Option<u32>) {
    for conn in listener.incoming() {
        let Ok(mut c) = conn else { continue };
        match peer_uid(&c) {
            Some(0) => {}
            Some(uid) if Some(uid) == allowed => {}
            _ => continue,
        }
        let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = c.set_write_timeout(Some(Duration::from_secs(2)));
        let Some(req) = read_request(&mut c) else { continue };
        let reply = answer(&req);
        let _ = c.write_all(reply.as_bytes());
    }
}

fn answer(req: &str) -> String {
    let mut w = req.split_whitespace();
    match (w.next(), w.next()) {
        (Some("status"), None) => {
            STATUS.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(Status::encode).unwrap_or_default()
        }
        (Some("disconnect"), None) => {
            out!("# disconnect requested over the control socket");
            crate::sysnet::request_stop();
            "ok\n".to_string()
        }
        (Some("log"), after) => {
            let after: u64 = after.and_then(|a| a.parse().ok()).unwrap_or(0);
            let log = LOG.lock().unwrap_or_else(|e| e.into_inner());
            let mut out = format!("next={}\n", log.next - 1);
            for (_, l) in log.lines.iter().filter(|(n, _)| *n > after) {
                out.push_str(l);
                out.push('\n');
            }
            out
        }
        _ => "error: unknown request\n".to_string(),
    }
}

fn read_request(c: &mut UnixStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while buf.len() < 64 {
        match c.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => break,
            Ok(1) => buf.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8(buf).ok()
}

fn peer_uid(c: &UnixStream) -> Option<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            c.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (r == 0).then_some(cred.uid)
}

extern "C" fn at_exit() {
    flush_relay();
    if let Some(p) = SOCKET.get() {
        let _ = std::fs::remove_file(p);
    }
}

fn start_relay() {
    let mut orig = [-1; 2];
    let mut pipes = [[-1; 2]; 2];
    for (i, fd) in [libc::STDOUT_FILENO, libc::STDERR_FILENO].into_iter().enumerate() {
        orig[i] = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if orig[i] < 0 || unsafe { libc::pipe2(pipes[i].as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            for f in orig.iter().chain(pipes.iter().flatten()).filter(|f| **f >= 0) {
                unsafe { libc::close(*f) };
            }
            return;
        }
    }
    for (i, fd) in [libc::STDOUT_FILENO, libc::STDERR_FILENO].into_iter().enumerate() {
        unsafe {
            let fl = libc::fcntl(pipes[i][0], libc::F_GETFL);
            libc::fcntl(pipes[i][0], libc::F_SETFL, fl | libc::O_NONBLOCK);
            libc::dup2(pipes[i][1], fd);
            libc::close(pipes[i][1]);
        }
    }
    if RELAY.set(Relay { orig, read: [pipes[0][0], pipes[1][0]] }).is_err() {
        return;
    }
    std::thread::spawn(relay_loop);
}

fn relay_loop() {
    let Some(r) = RELAY.get() else { return };
    let mut fds = [
        libc::pollfd { fd: r.read[0], events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: r.read[1], events: libc::POLLIN, revents: 0 },
    ];
    loop {
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        let _io = RELAY_IO.lock().unwrap_or_else(|e| e.into_inner());
        for (i, p) in fds.iter_mut().enumerate() {
            if p.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 && pump(r, i) {
                p.fd = -1;
            }
        }
        if fds.iter().all(|p| p.fd < 0) {
            return;
        }
    }
}

/// Move what is waiting on relay pipe `i` to the original descriptor and the log.
/// True once the pipe is closed for good.
fn pump(r: &Relay, i: usize) -> bool {
    let mut buf = [0u8; 8192];
    loop {
        let n = unsafe { libc::read(r.read[i], buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            let chunk = &buf[..n as usize];
            write_fd(r.orig[i], chunk);
            keep(i, chunk);
            continue;
        }
        if n == 0 {
            return true;
        }
        return match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::Interrupted => continue,
            std::io::ErrorKind::WouldBlock => false,
            _ => true,
        };
    }
}

/// Write it all, or give up on the first error (a reader that went away).
fn write_fd(fd: i32, mut data: &[u8]) {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n > 0 {
            data = &data[n as usize..];
        } else if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        } else {
            return;
        }
    }
}

fn keep(i: usize, chunk: &[u8]) {
    let mut log = LOG.lock().unwrap_or_else(|e| e.into_inner());
    let mut part = std::mem::take(&mut log.partial[i]);
    for &b in chunk {
        if b == b'\n' || part.len() >= LOG_LINE_MAX {
            let line = String::from_utf8_lossy(&part).into_owned();
            push_line(&mut log, line);
            part.clear();
            if b == b'\n' {
                continue;
            }
        }
        part.push(b);
    }
    log.partial[i] = part;
}

fn push_line(log: &mut Log, line: String) {
    let n = log.next;
    log.next += 1;
    log.lines.push_back((n, line));
    while log.lines.len() > LOG_LINES {
        log.lines.pop_front();
    }
}

/// At exit: pass on what is still in the relay, unless the relay is stuck on a
/// reader that stopped reading.
fn flush_relay() {
    let Some(r) = RELAY.get() else { return };
    let deadline = Instant::now() + Duration::from_secs(1);
    let _io = loop {
        match RELAY_IO.try_lock() {
            Ok(g) => break g,
            Err(TryLockError::Poisoned(p)) => break p.into_inner(),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(TryLockError::WouldBlock) => return,
        }
    };
    for i in 0..2 {
        pump(r, i);
    }
}

fn usage_status() {
    eprintln!("usage: unvpn status [--json]");
}

/// `unvpn status [--json]`: the running tunnels this user may see.
pub fn cmd_status(args: &[String]) {
    let mut json = false;
    for a in args {
        match a.as_str() {
            "--json" => json = true,
            "--help" | "-h" => return usage_status(),
            other => {
                eprintln!("unknown argument: {other}");
                usage_status();
                std::process::exit(2);
            }
        }
    }
    let mut live = Vec::new();
    let mut notes = Vec::new();
    for (pid, path) in ctl::sockets() {
        match ctl::status(&path) {
            Ok(s) => live.push(s),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(_) => notes.push(format!("# pid {pid}: not running (its socket was left behind)")),
        }
    }
    let mut out = std::io::stdout().lock();
    if json {
        let items: Vec<String> = live.iter().map(Status::to_json).collect();
        let _ = writeln!(out, "[{}]", items.join(","));
    } else if live.is_empty() {
        let _ = writeln!(out, "no tunnel running");
    } else {
        for s in &live {
            let _ = writeln!(out, "{}", describe(s));
        }
    }
    for n in notes {
        eprintln!("{n}");
    }
}

fn describe(s: &Status) -> String {
    let mut parts = vec![format!("“{}”", s.name()), s.state.as_str().to_string(), s.backend.clone()];
    if !s.gateway.is_empty() && s.gateway != s.name() {
        parts.push(s.gateway.clone());
    }
    if !s.iface.is_empty() {
        parts.push(s.iface.clone());
    }
    if !s.ip.is_empty() {
        parts.push(format!("IP {}", s.ip));
    }
    if !s.dns.is_empty() {
        parts.push(format!("DNS {}", s.dns.join(", ")));
    }
    if s.since > 0 && matches!(s.state, State::Up | State::Reconnecting) {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        parts.push(format!("up {}", duration(now.saturating_sub(s.since))));
    }
    parts.push(format!("pid {}", s.pid));
    parts.join("  ")
}

fn duration(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    match (h, m) {
        (0, 0) => format!("{s}s"),
        (0, _) => format!("{m}m {s:02}s"),
        _ => format!("{h}h {m:02}m"),
    }
}

fn usage_disconnect() {
    eprintln!("usage: unvpn disconnect [<name> | --all]");
    eprintln!("  <name>: the profile name (or a unique start of it), the gateway, the interface or the pid");
}

/// `unvpn disconnect [<name> | --all]`.
pub fn cmd_disconnect(args: &[String]) {
    let mut all = false;
    let mut name: Option<&str> = None;
    for a in args {
        match a.as_str() {
            "--all" | "-a" => all = true,
            "--help" | "-h" => return usage_disconnect(),
            s if s.starts_with('-') => {
                eprintln!("unknown argument: {s}");
                usage_disconnect();
                std::process::exit(2);
            }
            s => name = Some(s),
        }
    }
    let running = ctl::running();
    if running.is_empty() {
        eprintln!("no tunnel running");
        std::process::exit(1);
    }
    let targets: Vec<&(PathBuf, Status)> = match (all, name) {
        (true, _) => running.iter().collect(),
        (false, Some(q)) => match pick(&running, q) {
            Ok(t) => vec![t],
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        },
        (false, None) if running.len() == 1 => running.iter().collect(),
        (false, None) => {
            eprintln!("several tunnels are up — name one, or --all:");
            for (_, s) in &running {
                eprintln!("  {}", describe(s));
            }
            std::process::exit(2);
        }
    };
    let mut code = 0;
    for (path, s) in targets {
        if let Err(e) = ctl::disconnect(path) {
            eprintln!("“{}”: {e}", s.name());
            code = 1;
            continue;
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while ctl::status(path).is_ok() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
        if ctl::status(path).is_ok() {
            eprintln!("“{}” is still tearing down", s.name());
            code = 1;
        } else {
            eprintln!("“{}” disconnected", s.name());
        }
    }
    std::process::exit(code);
}

/// The session `q` names: its pid or interface, else its label or gateway (exact,
/// case-insensitive, then a unique start).
fn pick<'a>(running: &'a [(PathBuf, Status)], q: &str) -> Result<&'a (PathBuf, Status), String> {
    if let Some(t) = running.iter().find(|(_, s)| s.pid.to_string() == q || s.iface == q) {
        return Ok(t);
    }
    let ql = q.to_lowercase();
    let tests: [&dyn Fn(&str) -> bool; 3] =
        [&|n| n == q, &|n| n.to_lowercase() == ql, &|n| !n.is_empty() && n.to_lowercase().starts_with(&ql)];
    for test in tests {
        let hits: Vec<_> = running.iter().filter(|(_, s)| test(&s.label) || test(&s.gateway)).collect();
        match hits[..] {
            [t] => return Ok(t),
            [] => continue,
            _ => {
                let names: Vec<String> = hits.iter().map(|(_, s)| format!("“{}”", s.name())).collect();
                return Err(format!("“{q}” matches {} — which one?", names.join(", ")));
            }
        }
    }
    Err(format!("no running tunnel “{q}” — `unvpn status` lists them"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_keeps_whole_lines_from_both_streams() {
        keep(0, b"# one\n# tw");
        keep(1, b"err\n");
        keep(0, b"o\n");
        let text = answer("log 0");
        let mut lines = text.lines();
        let next: u64 = lines.next().unwrap().strip_prefix("next=").unwrap().parse().unwrap();
        let rest: Vec<&str> = lines.collect();
        assert_eq!(rest, ["# one", "err", "# two"]);
        assert_eq!(answer(&format!("log {next}")), format!("next={next}\n"));
        assert_eq!(answer("bogus"), "error: unknown request\n");
    }

    #[test]
    fn sessions_are_named_by_label_gateway_iface_or_pid() {
        let s = |pid: u32, label: &str, gw: &str, iface: &str| {
            (PathBuf::new(), Status { pid, label: label.into(), gateway: gw.into(), iface: iface.into(), ..Default::default() })
        };
        let run = [s(10, "Office", "vpn.example.com", "unvpn0"), s(11, "office eu", "eu.example.com", "unvpn1")];
        assert_eq!(pick(&run, "Office").unwrap().1.pid, 10);
        assert_eq!(pick(&run, "office").unwrap().1.pid, 10);
        assert_eq!(pick(&run, "office e").unwrap().1.pid, 11);
        assert_eq!(pick(&run, "unvpn1").unwrap().1.pid, 11);
        assert_eq!(pick(&run, "11").unwrap().1.pid, 11);
        assert_eq!(pick(&run, "eu.example.com").unwrap().1.pid, 11);
        assert!(pick(&run, "off").unwrap_err().contains("matches"));
        assert!(pick(&run, "lab").unwrap_err().contains("no running tunnel"));
    }

    #[test]
    fn the_gateway_comes_from_the_command_line() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(gateway_in(&a(&["-g", "vpn.example.com", "-u", "x"])).as_deref(), Some("vpn.example.com"));
        assert_eq!(
            gateway_in(&a(&["--launch", "f5-vpn://x/?server=gw.example.com&port=443&otc=C"])).as_deref(),
            Some("gw.example.com")
        );
        assert_eq!(gateway_in(&a(&["-c", "/x/wg0.conf"])), None);
    }
}
