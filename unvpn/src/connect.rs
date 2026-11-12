//! `unvpn connect <profile>`: connects a profile saved in the app.
//!
//! Runs as the user, who owns the profiles and the keyring: reads the profile and
//! its saved secrets, starts the engine as root with them on its stdin, and asks
//! the engine's `# AUTH-PROMPT:` questions (2FA code, SSO token, …) on the
//! terminal — the same protocol the GUI drives. Ctrl-C asks the engine to
//! disconnect and waits for its teardown.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use unvpn_profiles::{self as profiles, Backend, Profile};

/// The engine's stdin, where the signal handler writes `disconnect`; -1 before it starts.
static ENGINE_STDIN: AtomicI32 = AtomicI32::new(-1);
/// The terminal mode at start, put back on exit (a secret prompt turns echo off).
static TTY_MODE: OnceLock<libc::termios> = OnceLock::new();

/// A push notification that is still pending after this long, when the engine
/// prints again, was settled without us (approved on the phone, or refused).
const PUSH_SETTLED: Duration = Duration::from_millis(300);

macro_rules! say {
    ($($t:tt)*) => {{
        let _ = writeln!(std::io::stderr(), $($t)*);
    }};
}

#[derive(Default)]
struct Opts {
    name: Option<String>,
    list: bool,
    dry_run: bool,
    no_dtls: bool,
    killswitch: bool,
    allow_ipv6: bool,
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  unvpn connect <profile> [--no-dtls] [--killswitch] [--allow-ipv6]");
    eprintln!("  unvpn connect <profile> --dry-run      # show the engine command, connect nothing");
    eprintln!("  unvpn connect --list                   # the saved profiles");
    eprintln!("Run it as your user: it reads your profiles and keyring, and asks for sudo itself.");
}

pub fn cmd_connect(args: &[String], killswitch: bool, allow_ipv6: bool) {
    let mut o = Opts { killswitch, allow_ipv6, ..Default::default() };
    for a in args {
        match a.as_str() {
            "--list" | "-l" => o.list = true,
            "--dry-run" | "-n" => o.dry_run = true,
            "--no-dtls" => o.no_dtls = true,
            "--help" | "-h" => {
                usage();
                return;
            }
            s if s.starts_with('-') => {
                eprintln!("unknown argument: {s}");
                usage();
                std::process::exit(2);
            }
            s if o.name.is_some() => {
                eprintln!("one profile at a time (got “{}” and “{s}”) — quote a name with spaces", o.name.as_deref().unwrap_or(""));
                std::process::exit(2);
            }
            s => o.name = Some(s.to_string()),
        }
    }

    drop_sudo();
    let profs = profiles::load().unwrap_or_else(|e| {
        eprintln!("unvpn: can't read the saved profiles: {e}");
        std::process::exit(1);
    });
    let Some(name) = o.name.as_deref().filter(|_| !o.list) else {
        list(&profs);
        if o.name.is_none() && !o.list {
            eprintln!();
            usage();
            std::process::exit(2);
        }
        return;
    };
    let p = match find(&profs, name) {
        Ok(p) => p.clone(),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    match run(&p, &o) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            restore_tty();
            eprintln!("connect failed: {e}");
            std::process::exit(1);
        }
    }
}

fn list(profs: &[Profile]) {
    if profs.is_empty() {
        eprintln!("no saved profiles ({}) — create them in unvpn-gui", profiles::profiles_path().display());
        return;
    }
    let w = profs.iter().map(|p| p.name.chars().count()).max().unwrap_or(0);
    let mut out = std::io::stdout().lock();
    for p in profs {
        if writeln!(out, "{:<w$}  {}", p.name, p.subtitle()).is_err() {
            return;
        }
    }
}

/// The profile called `q`: exact name, else case-insensitive, else the one whose
/// name starts with it.
fn find<'a>(profs: &'a [Profile], q: &str) -> Result<&'a Profile, String> {
    if let Some(p) = profs.iter().find(|p| p.name == q) {
        return Ok(p);
    }
    let ql = q.to_lowercase();
    let same: Vec<&Profile> = profs.iter().filter(|p| p.name.to_lowercase() == ql).collect();
    if let [p] = same[..] {
        return Ok(p);
    }
    let pre: Vec<&Profile> = profs.iter().filter(|p| p.name.to_lowercase().starts_with(&ql)).collect();
    match pre[..] {
        [p] => Ok(p),
        [] => Err(format!("no profile “{q}” — `unvpn connect --list` shows the saved ones")),
        _ => {
            let names: Vec<String> = pre.iter().map(|p| format!("“{}”", p.name)).collect();
            Err(format!("“{q}” matches {} — which one?", names.join(", ")))
        }
    }
}

/// Under `sudo unvpn connect …`: become the invoking user again, whose profiles
/// and keyring these are (root can't reach that user's Secret Service). The
/// engine is escalated on its own afterwards, like from a user shell.
fn drop_sudo() {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let uid = ["SUDO_UID", "PKEXEC_UID"]
        .iter()
        .find_map(|v| std::env::var(v).ok()?.parse::<libc::uid_t>().ok())
        .filter(|&u| u != 0);
    let Some(uid) = uid else { return };
    let (name, home, gid) = unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            eprintln!("connect: unknown user id {uid}");
            std::process::exit(1);
        }
        let name = std::ffi::CStr::from_ptr((*pw).pw_name).to_owned();
        let home = std::ffi::CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
        (name, home, (*pw).pw_gid)
    };
    let ok = unsafe { libc::initgroups(name.as_ptr(), gid) == 0 && libc::setgid(gid) == 0 && libc::setuid(uid) == 0 };
    if !ok {
        eprintln!("connect: could not switch back to {}: {}", name.to_string_lossy(), std::io::Error::last_os_error());
        std::process::exit(1);
    }
    std::env::set_var("HOME", home);
    std::env::set_var("USER", name.to_string_lossy().as_ref());
    let run = format!("/run/user/{uid}");
    if std::path::Path::new(&run).is_dir() {
        std::env::set_var("XDG_RUNTIME_DIR", &run);
        let bus = format!("{run}/bus");
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() && std::path::Path::new(&bus).exists() {
            std::env::set_var("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={bus}"));
        }
    }
}

fn run(p: &Profile, o: &Opts) -> Result<i32, String> {
    let psk = (p.backend == Backend::FortiIpsec)
        .then(|| profiles::secret_get(&profiles::psk_account(&p.name)))
        .flatten()
        .filter(|k| !k.is_empty());
    let mut args = profiles::engine_args(p, psk.is_some());
    let mut add = |flag: &str| {
        if !args.iter().any(|a| a == flag) {
            args.push(flag.to_string());
        }
    };
    if o.killswitch {
        if p.backend == Backend::WireGuard {
            say!("# note: --killswitch is not used by WireGuard; ignored");
        } else {
            add("--killswitch");
        }
    }
    if o.no_dtls {
        if p.backend.uses_dtls() {
            add("--no-dtls");
        } else {
            say!("# note: {} has no DTLS channel; --no-dtls ignored", p.backend.label());
        }
    }
    if o.allow_ipv6 {
        add("--allow-ipv6");
    }

    let bin = engine_bin()?;
    let mut argv: Vec<String> = escalation();
    argv.push(bin.to_string_lossy().into_owned());
    argv.extend(args);

    let saved_password = (profiles::takes_password(p) && p.remember_password)
        .then(|| profiles::secret_get(&p.name))
        .flatten()
        .filter(|s| !s.is_empty());

    if o.dry_run {
        say!("# {}: {}", p.name, p.subtitle());
        let _ = writeln!(std::io::stdout(), "{}", shell_line(&argv));
        if profiles::takes_password(p) {
            let what = if saved_password.is_some() { "from the keyring" } else { "asked on the terminal" };
            let token = if p.backend == Backend::CheckPoint && !p.cp_cert { " + token code (asked)" } else { "" };
            say!("# stdin: {} ({what}){token}", password_label(p));
        }
        if psk.is_some() {
            say!("# stdin: group key (PSK) from the keyring, before the password");
        }
        if p.backend == Backend::FortiIpsec && psk.is_none() {
            say!("# no group key (PSK) saved for this profile: the gateway's AUTH is not verified");
        }
        return Ok(0);
    }

    if let Ok(t) = tty_mode() {
        let _ = TTY_MODE.set(t);
    }
    install_signal_handlers();
    let mut term = Term::default();

    say!("# connecting “{}” — {}", p.name, p.subtitle());
    if p.uses_sso() && !p.sso_user_agent.trim().is_empty() {
        say!("# note: the profile's sign-in User-Agent applies only to the app's SSO window; here your browser signs in");
    }

    let mut first_line: Option<String> = None;
    if profiles::takes_password(p) {
        let label = password_label(p);
        let pw = match saved_password {
            Some(s) => {
                say!("# {label}: from the keyring");
                s
            }
            None => {
                if p.remember_password {
                    say!("# {label}: not in the keyring");
                }
                match term.ask(&label, true, || false) {
                    Answer::Line(s) if !s.is_empty() => s,
                    _ => return Err(format!("{label}: nothing entered")),
                }
            }
        };
        first_line = Some(if p.backend == Backend::CheckPoint && !p.cp_cert {
            match term.ask("Token code", false, || false) {
                Answer::Line(t) => format!("{pw}{}", t.trim()),
                _ => return Err("no token code given".into()),
            }
        } else {
            pw
        });
    }
    let key_pass = (p.backend == Backend::OpenVpn && p.remember_key_pass)
        .then(|| profiles::secret_get(&profiles::keypass_account(&p.name)))
        .flatten();

    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("start {}: {e}", argv[0]))?;
    let mut stdin = child.stdin.take().ok_or("no engine stdin")?;
    ENGINE_STDIN.store(stdin.as_raw_fd(), Ordering::SeqCst);
    for l in psk.iter().chain(first_line.iter()) {
        let _ = writeln!(stdin, "{l}");
    }
    let _ = stdin.flush();
    let stdin = Arc::new(Mutex::new(stdin));

    let gen = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let (ptx, prx) = mpsc::channel::<Prompt>();
    {
        let (stdin, gen, done) = (stdin.clone(), gen.clone(), done.clone());
        std::thread::spawn(move || answer_prompts(prx, term, stdin, gen, done, key_pass));
    }

    let mut sso = Sso::new(p);
    let mut push_since: Option<Instant> = None;
    let mut out = BufReader::new(child.stdout.take().ok_or("no engine stdout")?);
    let mut raw = Vec::new();
    loop {
        raw.clear();
        match out.read_until(b'\n', &mut raw) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let line = String::from_utf8_lossy(&raw);
        let line = line.trim_end_matches(['\n', '\r']);
        if push_since.is_some_and(|t| t.elapsed() >= PUSH_SETTLED) {
            push_since = None;
            gen.fetch_add(1, Ordering::SeqCst);
        }
        let clean = line.trim_start_matches(['#', ' ']);
        if let Some((kind, message)) = parse_prompt(clean) {
            if kind == "push" {
                push_since = Some(Instant::now());
            }
            let _ = ptx.send(Prompt { kind, message, id: gen.load(Ordering::SeqCst) });
            continue;
        }
        let (print, open) = sso.on_line(clean);
        if print {
            let mut so = std::io::stdout().lock();
            let _ = writeln!(so, "{line}");
            let _ = so.flush();
        }
        if let Some(target) = open {
            open_browser(&target);
        }
    }

    done.store(true, Ordering::SeqCst);
    let status = child.wait().map_err(|e| e.to_string())?;
    ENGINE_STDIN.store(-1, Ordering::SeqCst);
    restore_tty();
    sso.cleanup();
    use std::os::unix::process::ExitStatusExt;
    Ok(status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
}

fn password_label(p: &Profile) -> String {
    match p.backend {
        Backend::CheckPoint if p.cp_cert => "Certificate password",
        Backend::CheckPoint => "Password (PIN)",
        _ => "Password",
    }
    .to_string()
}

/// The engine to run: `$UNVPN_BIN`, else this very binary.
fn engine_bin() -> Result<PathBuf, String> {
    if let Some(b) = std::env::var_os("UNVPN_BIN").filter(|b| !b.is_empty()) {
        return Ok(PathBuf::from(b));
    }
    std::env::current_exe().map_err(|e| format!("can't locate the unvpn binary: {e}"))
}

/// How to run the engine as root: nothing when already root, else `sudo` (asks on
/// the terminal if it needs a password), or `pkexec` with `UNVPN_PRIV=pkexec`.
fn escalation() -> Vec<String> {
    if unsafe { libc::geteuid() } == 0 {
        return Vec::new();
    }
    match std::env::var("UNVPN_PRIV").as_deref() {
        Ok("pkexec") => vec!["pkexec".into()],
        _ => vec!["sudo".into()],
    }
}

/// `argv` as a shell line.
fn shell_line(argv: &[String]) -> String {
    argv.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
}

fn quote(a: &str) -> String {
    let plain = !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:=@,+%".contains(c));
    if plain {
        a.to_string()
    } else {
        format!("'{}'", a.replace('\'', r"'\''"))
    }
}

/// `AUTH-PROMPT: <kind>: <message>` at the start of a line (already stripped of `# `).
fn parse_prompt(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix("AUTH-PROMPT: ")?;
    let (kind, message) = rest.split_once(": ").unwrap_or((rest, ""));
    Some((kind.trim().to_string(), message.trim().to_string()))
}

struct Prompt {
    kind: String,
    message: String,
    /// The prompt generation it belongs to; a bump cancels it.
    id: u64,
}

/// Label, masked, confirm, empty answer allowed.
fn prompt_spec(kind: &str) -> (&'static str, bool, bool, bool) {
    match kind {
        "push" => ("Code (or approve the sign-in on your phone)", false, false, false),
        "code2" => ("Next code", false, false, false),
        "answer" => ("Answer", true, false, false),
        "newpass" => ("New password", true, true, false),
        "renew" => ("New password (Enter keeps the current one)", true, true, true),
        "sso" => ("SSO token", true, false, false),
        "keypass" => ("Private key passphrase", true, false, false),
        "username" => ("Username", false, false, false),
        _ => ("Code", false, false, false),
    }
}

fn answer_prompts(
    prompts: mpsc::Receiver<Prompt>,
    mut term: Term,
    stdin: Arc<Mutex<ChildStdin>>,
    gen: Arc<AtomicU64>,
    done: Arc<AtomicBool>,
    mut key_pass: Option<String>,
) {
    let send = |s: &str| {
        let mut si = stdin.lock().unwrap_or_else(|e| e.into_inner());
        let _ = writeln!(si, "{s}");
        let _ = si.flush();
    };
    for pr in prompts {
        if pr.kind == "keypass" {
            if let Some(k) = key_pass.take() {
                say!("# saved key passphrase sent");
                send(&k);
                continue;
            }
        }
        let (label, masked, confirm, empty_ok) = prompt_spec(&pr.kind);
        let cancelled = || done.load(Ordering::SeqCst) || gen.load(Ordering::SeqCst) != pr.id;
        if !pr.message.is_empty() {
            say!("{}", pr.message);
        }
        loop {
            let answer = match term.ask(label, masked, cancelled) {
                Answer::Line(l) => {
                    if masked {
                        l
                    } else {
                        l.trim().to_string()
                    }
                }
                Answer::Cancelled => break,
                Answer::Eof => {
                    send("disconnect");
                    return;
                }
            };
            if answer.is_empty() && !empty_ok {
                continue;
            }
            if confirm && !answer.is_empty() {
                match term.ask("Confirm", true, cancelled) {
                    Answer::Line(c) if c == answer => {}
                    Answer::Line(_) => {
                        say!("they don't match — try again");
                        continue;
                    }
                    Answer::Cancelled => break,
                    Answer::Eof => {
                        send("disconnect");
                        return;
                    }
                }
            }
            send(&answer);
            break;
        }
    }
}

enum Answer {
    Line(String),
    Cancelled,
    Eof,
}

/// Line input from our stdin (normally the terminal) that a pending question can
/// be withdrawn from: reads poll, so `cancelled` is checked every 200 ms.
#[derive(Default)]
struct Term {
    buf: Vec<u8>,
    eof: bool,
}

impl Term {
    fn ask(&mut self, label: &str, masked: bool, cancelled: impl Fn() -> bool) -> Answer {
        let _ = write!(std::io::stderr(), "{label}: ");
        let _ = std::io::stderr().flush();
        let _quiet = masked.then(EchoOff::new);
        self.line(cancelled)
    }

    fn line(&mut self, cancelled: impl Fn() -> bool) -> Answer {
        loop {
            if let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
                let rest = self.buf.split_off(i + 1);
                let l = std::mem::replace(&mut self.buf, rest);
                let l = String::from_utf8_lossy(&l);
                return Answer::Line(l.trim_end_matches(['\n', '\r']).to_string());
            }
            if self.eof {
                if self.buf.is_empty() {
                    return Answer::Eof;
                }
                let l = String::from_utf8_lossy(&std::mem::take(&mut self.buf)).into_owned();
                return Answer::Line(l);
            }
            if cancelled() {
                let _ = writeln!(std::io::stderr());
                return Answer::Cancelled;
            }
            let mut pfd = libc::pollfd { fd: libc::STDIN_FILENO, events: libc::POLLIN, revents: 0 };
            if unsafe { libc::poll(&mut pfd, 1, 200) } <= 0 {
                continue; // timeout, or a signal
            }
            let mut chunk = [0u8; 4096];
            let n = unsafe { libc::read(libc::STDIN_FILENO, chunk.as_mut_ptr().cast(), chunk.len()) };
            match n {
                0 => self.eof = true,
                n if n > 0 => self.buf.extend_from_slice(&chunk[..n as usize]),
                _ if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted => {}
                _ => self.eof = true,
            }
        }
    }
}

/// Echo off on the terminal while alive (no-op when stdin isn't one).
struct EchoOff(Option<libc::termios>);

impl EchoOff {
    fn new() -> Self {
        let Ok(t) = tty_mode() else { return EchoOff(None) };
        let mut quiet = t;
        quiet.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &quiet) };
        EchoOff(Some(t))
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        if let Some(t) = self.0 {
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) };
            let _ = writeln!(std::io::stderr());
        }
    }
}

fn tty_mode() -> Result<libc::termios, ()> {
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::isatty(libc::STDIN_FILENO) == 1 && libc::tcgetattr(libc::STDIN_FILENO, &mut t) == 0 {
            Ok(t)
        } else {
            Err(())
        }
    }
}

fn restore_tty() {
    if let Some(t) = TTY_MODE.get() {
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, t) };
    }
}

/// Ctrl-C / SIGTERM / SIGHUP: ask the engine to disconnect (it tears down DNS and
/// routes, then exits, which ends us). Before the engine runs, just quit.
extern "C" fn on_signal(_sig: libc::c_int) {
    let fd = ENGINE_STDIN.load(Ordering::SeqCst);
    if fd < 0 {
        if let Some(t) = TTY_MODE.get() {
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, t) };
        }
        unsafe { libc::_exit(130) };
    }
    let msg = b"disconnect\n";
    unsafe { libc::write(fd, msg.as_ptr().cast(), msg.len()) };
}

fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            libc::sigaction(s, &sa, std::ptr::null_mut());
        }
    }
}

/// Opens the SSO sign-in in the user's browser — only the entry point of the
/// profile's own gateway (GlobalProtect: whatever IdP its gateway names).
struct Sso {
    backend: Backend,
    entry: Option<String>,
    gp_headers: bool,
    opened: bool,
    page: Option<PathBuf>,
}

impl Sso {
    fn new(p: &Profile) -> Self {
        let entry = match p.backend {
            _ if !p.uses_sso() => None,
            Backend::Forti => Some(profiles::saml_entry(&p.gateway)),
            Backend::AnyConnect => Some(profiles::anyconnect_saml_entry(&p.gateway)),
            _ => None,
        };
        Sso { backend: p.backend, entry, gp_headers: false, opened: false, page: None }
    }

    /// Looks at one engine line: whether to print it as is, and what to open in
    /// the browser once it is.
    fn on_line(&mut self, clean: &str) -> (bool, Option<String>) {
        if clean.starts_with("SAML-HEADERS:") {
            self.gp_headers = true;
        }
        let Some(url) = clean.strip_prefix("SAML-URL: ").map(str::trim) else { return (true, None) };
        if self.opened {
            return (true, None);
        }
        if self.backend == Backend::GlobalProtect && self.gp_headers {
            if url.starts_with("https://") {
                self.opened = true;
                return (true, Some(url.to_string()));
            }
            if let Some(b64) = url.strip_prefix("data:text/html;base64,") {
                // An auto-submitting form: a browser won't open a data: URL handed
                // over from outside, so it goes through a private file.
                self.opened = true;
                return match self.save_page(b64) {
                    Ok(path) => {
                        say!("# SAML-URL: sign-in form saved to {}", path.display());
                        (false, Some(path.to_string_lossy().into_owned()))
                    }
                    Err(e) => {
                        say!("# could not save the sign-in form: {e}");
                        (false, None)
                    }
                };
            }
        } else if self.entry.as_deref().is_some_and(|e| url.starts_with(e)) {
            self.opened = true;
            return (true, Some(url.to_string()));
        }
        (true, None)
    }

    fn save_page(&mut self, b64: &str) -> Result<PathBuf, String> {
        use std::os::unix::fs::OpenOptionsExt;
        let html = openssl::base64::decode_block(b64).map_err(|e| e.to_string())?;
        let dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let path = dir.join(format!("unvpn-sso-{}.html", std::process::id()));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        f.write_all(&html).map_err(|e| e.to_string())?;
        self.page = Some(path.clone());
        Ok(path)
    }

    fn cleanup(&mut self) {
        if let Some(p) = self.page.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

fn open_browser(target: &str) {
    say!("# opening the sign-in page in your browser");
    match Command::new("xdg-open").arg(target).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn() {
        Ok(mut c) => {
            std::thread::spawn(move || c.wait());
        }
        Err(e) => say!("# could not run xdg-open ({e}) — open the URL above yourself"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(names: &[&str]) -> Vec<Profile> {
        let body: String = names.iter().map(|n| format!("[[profile]]\nname = \"{n}\"\nbackend = \"f5\"\n\n")).collect();
        let dir = std::env::temp_dir().join(format!("unvpn-connect-test-{}-{}", std::process::id(), names.len()));
        std::fs::create_dir_all(dir.join("unvpn")).unwrap();
        std::fs::write(dir.join("unvpn/profiles.toml"), body).unwrap();
        let profs = profiles::load_from(&dir.join("unvpn/profiles.toml")).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        profs
    }

    #[test]
    fn finds_profiles_by_exact_then_loose_name() {
        let profs = named(&["Office", "office eu", "lab", "Lab West"]);
        assert_eq!(find(&profs, "Office").unwrap().name, "Office");
        assert_eq!(find(&profs, "office").unwrap().name, "Office");
        assert_eq!(find(&profs, "lab").unwrap().name, "lab");
        assert_eq!(find(&profs, "lab w").unwrap().name, "Lab West");
        assert_eq!(find(&profs, "office e").unwrap().name, "office eu");
        assert!(find(&profs, "off").unwrap_err().contains("matches"));
        assert!(find(&profs, "nope").unwrap_err().contains("no profile"));
    }

    #[test]
    fn prompt_markers() {
        assert_eq!(parse_prompt("AUTH-PROMPT: code: Enter the code"), Some(("code".into(), "Enter the code".into())));
        assert_eq!(parse_prompt("AUTH-PROMPT: push"), Some(("push".into(), String::new())));
        assert_eq!(parse_prompt("gateway says AUTH-PROMPT: code: x"), None);
    }

    #[test]
    fn dry_run_line_quotes_arguments() {
        let argv: Vec<String> =
            ["sudo", "/usr/local/bin/unvpn", "forti-ipsec", "-g", "vpn.example.com", "--psk-stdin", "-u", "o'neil"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(
            shell_line(&argv),
            r"sudo /usr/local/bin/unvpn forti-ipsec -g vpn.example.com --psk-stdin -u 'o'\''neil'"
        );
    }
}
