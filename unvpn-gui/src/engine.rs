//! Engine driver: runs the privileged `unvpn` engine as a subprocess and turns
//! its stdout/stderr into [`UiMsg`] events for the GTK main loop.
//!
//! The GUI runs as the user and escalates the engine via `pkexec`/`sudo -n`. The
//! password (or SecurID PIN) is piped on the engine's stdin — never argv; writing
//! `disconnect` triggers a clean teardown. The engine's markers on stdout (see
//! `unvpn_profiles::marker`) carry its state, address, DNS and mid-login
//! questions (2FA code, challenge, new password, push), each answered with one
//! stdin line.
//!
//! The engine runs `--detachable`: once up, it outlives the app, and a later app
//! (or this one, for a tunnel started from the command line) attaches to it over
//! its control socket.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use unvpn_profiles::control::{self as ctl, Status};
use unvpn_profiles::marker::{self, Marker};

/// Connection state. Shared with the tray (which colours its icon from it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Disconnected,
    Connecting,
    Connected,
    /// The tunnel dropped and the back-end is rebuilding it (reconnect / rekey /
    /// address change). The engine is still running; the data plane is briefly down.
    Reconnecting,
    /// `disconnect` sent; the engine is tearing down (DNS/routes) and will exit.
    Disconnecting,
    Error(String),
}

/// What the engine is asking mid-login. `kind` is `code` (OTP / email / SMS
/// token), `code2` (next token code, drift resync), `answer` (challenge),
/// `newpass` (password expired), `renew` (password change the user may skip —
/// an empty answer), `push` (approve in the app — or type a code) or `trust` (a
/// gateway certificate no trusted CA vouches for, see `TrustQuestion`).
#[derive(Clone)]
pub struct AuthPrompt {
    pub kind: String,
    pub message: String,
}

pub enum EngineEvent {
    Log(String),
    Ip(String),
    Dns(String),
    Prompt(AuthPrompt),
    /// SAML: show `login` in the embedded SSO window and answer the pending
    /// `sso` prompt with what `watch` captures. `user_agent`, when set, overrides
    /// the sign-in window's User-Agent (e.g. to present as Windows).
    SsoBrowser {
        login: String,
        watch: SsoWatch,
        user_agent: Option<String>,
    },
    /// The tunnel device, so the UI can read its byte counters from /sys and time
    /// the session.
    Iface(String),
    /// Attached to a tunnel this app didn't start: its name and when it came up.
    Attached {
        name: String,
        since: u64,
    },
    StateChanged,
}

/// How the embedded SSO window recognises a finished login.
#[derive(Clone)]
#[cfg_attr(not(feature = "webview"), allow(dead_code))]
pub enum SsoWatch {
    /// AnyConnect: once `final_url` has loaded, the token is the `cookie` cookie.
    Cookie { final_url: String, cookie: String },
    /// GlobalProtect: the result comes as response headers of the page that ends
    /// the flow (`saml-username` + `prelogin-cookie`/`portal-userauthcookie`), or
    /// as a navigation to `globalprotectcallback:`.
    GpHeaders,
    /// Fortinet: nothing to scrape — the IdP redirects to `http://127.0.0.1:<port>`
    /// and the engine's own loopback listener takes the token. The window just
    /// hosts the login and closes when it reaches loopback (or the tunnel is up).
    Loopback,
}

pub enum TrayCmd {
    Show,
    /// A saved profile was picked in the tray menu.
    ConnectProfile(String),
    Disconnect,
    Quit,
}

pub enum UiMsg {
    Engine(EngineEvent),
    Tray(TrayCmd),
}

pub type Tx = async_channel::Sender<UiMsg>;

/// `https://host[:port]` of a URL (`None` if it isn't https).
fn sso_origin(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(&url[..8 + end])
}

/// Resolve the engine binary to an absolute path (pkexec requires absolute).
/// Order: $UNVPN_BIN, the engine built in the same source tree as this GUI
/// (running from `<repo>/target/<profile>/`), $PATH, then a sensible default.
pub fn unvpn_bin() -> String {
    if let Ok(p) = std::env::var("UNVPN_BIN") {
        return p;
    }
    if let Some(dev) = dev_engine() {
        return dev.to_string_lossy().into_owned();
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':').filter(|d| !d.is_empty()) {
            let cand = std::path::Path::new(dir).join("unvpn");
            if cand.is_file() {
                return cand.to_string_lossy().into_owned();
            }
        }
    }
    "/usr/local/bin/unvpn".to_string()
}

/// `<repo>/target/release/unvpn`, when this GUI runs from
/// `<repo>/target/<profile>/unvpn-gui` (a development checkout).
fn dev_engine() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let target = exe.parent()?.parent()?;
    let repo = target.parent()?;
    if !repo.join("unvpn/Cargo.toml").is_file() {
        return None;
    }
    let cand = target.join("release/unvpn");
    cand.is_file().then_some(cand)
}

/// How to run the engine as root. `pkexec` needs a PolicyKit agent (GNOME/KDE
/// have one); minimal WMs (Sway/i3/…) often don't, but frequently have
/// passwordless sudo, which needs no agent. Auto-picks; override with
/// `UNVPN_PRIV=pkexec|sudo`.
fn priv_escalation() -> (&'static str, Vec<&'static str>) {
    match std::env::var("UNVPN_PRIV").as_deref() {
        Ok("sudo") => return ("sudo", vec!["-n"]),
        Ok("pkexec") => return ("pkexec", vec![]),
        _ => {}
    }
    let passwordless_sudo = Command::new("sudo")
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if passwordless_sudo {
        ("sudo", vec!["-n"])
    } else {
        ("pkexec", vec![])
    }
}

/// A tunnel this app follows over its control socket instead of a pipe.
struct Attached {
    socket: PathBuf,
    status: Status,
    /// The engine's log lines shown so far.
    log_seen: u64,
}

/// Manages the privileged engine subprocess. Lives on the GTK main thread; the
/// stdout/stderr reader threads only *send* [`UiMsg`]s, never touch this struct.
pub struct Vpn {
    pub state: Arc<Mutex<State>>,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    attached: Option<Attached>,
    /// Bumped per connection: a previous engine's late output can't touch this one.
    gen: Arc<AtomicU64>,
    tx: Tx,
}

impl Vpn {
    pub fn new(tx: Tx) -> Self {
        Vpn {
            state: Arc::new(Mutex::new(State::Disconnected)),
            child: None,
            stdin: None,
            attached: None,
            gen: Arc::new(AtomicU64::new(0)),
            tx,
        }
    }

    pub fn state(&self) -> State {
        self.state.lock().unwrap().clone()
    }

    fn log(&self, line: impl Into<String>) {
        let _ = self
            .tx
            .try_send(UiMsg::Engine(EngineEvent::Log(line.into())));
    }

    pub fn is_busy(&self) -> bool {
        self.child.is_some()
            || self.attached.is_some()
            || matches!(
                *self.state.lock().unwrap(),
                State::Connecting | State::Connected | State::Reconnecting | State::Disconnecting
            )
    }

    /// Launch the privileged engine. `engine_args` are the `unvpn` subcommand args
    /// (e.g. `ike …` or `forti …`); `stdin_lines` are secrets/inputs piped on
    /// stdin in order (password, token, …) — never in argv. `label` is a log line.
    /// `saml_entry`: for an SSO login, the only URL the engine may have us open.
    pub fn connect(
        &mut self,
        engine_args: Vec<String>,
        stdin_lines: Vec<String>,
        label: String,
        saml_entry: Option<String>,
        sso_user_agent: Option<String>,
    ) {
        if self.is_busy() {
            return;
        }
        let my_gen = self.gen.fetch_add(1, Ordering::SeqCst) + 1;
        *self.state.lock().unwrap() = State::Connecting;
        let _ = self.tx.try_send(UiMsg::Engine(EngineEvent::StateChanged));

        let (prog, pre) = priv_escalation();
        self.log(format!("{label} (via {prog})…"));

        let mut child = match Command::new(prog)
            .args(&pre)
            .arg(unvpn_bin())
            .args(&engine_args)
            .arg("--detachable")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                *self.state.lock().unwrap() = State::Error(format!("spawn {prog}: {e}"));
                let _ = self.tx.try_send(UiMsg::Engine(EngineEvent::StateChanged));
                return;
            }
        };

        if let Some(mut si) = child.stdin.take() {
            for line in &stdin_lines {
                let _ = writeln!(si, "{line}");
            }
            let _ = si.flush();
            self.stdin = Some(si);
        }

        for (reader, is_err) in [
            (
                child
                    .stdout
                    .take()
                    .map(|o| Box::new(o) as Box<dyn std::io::Read + Send>),
                false,
            ),
            (
                child
                    .stderr
                    .take()
                    .map(|o| Box::new(o) as Box<dyn std::io::Read + Send>),
                true,
            ),
        ] {
            let Some(r) = reader else { continue };
            let state = self.state.clone();
            let gen = self.gen.clone();
            let saml_entry = saml_entry.clone();
            let sso_user_agent = sso_user_agent.clone();
            let tx = self.tx.clone();
            std::thread::spawn(move || {
                let mut saml_opened = false;
                // AnyConnect sso-v2 (embedded-browser flow): announced before SAML-URL.
                let mut saml_final: Option<String> = None;
                let mut saml_cookie: Option<String> = None;
                // GlobalProtect: the SAML result arrives as response headers.
                let mut saml_headers = false;
                for line in BufReader::new(r).lines().map_while(Result::ok) {
                    let clean = line.trim_start_matches(['#', ' ']).to_string();
                    eprintln!("[engine] {clean}");
                    if gen.load(Ordering::SeqCst) != my_gen {
                        continue; // a previous connection's engine, still draining
                    }
                    let send = |ev: EngineEvent| {
                        let _ = tx.try_send(UiMsg::Engine(ev));
                    };
                    let set_state = |to: State, only_from: &[State]| {
                        let mut st = state.lock().unwrap();
                        if *st != State::Disconnecting
                            && (only_from.is_empty() || only_from.contains(&st))
                            && *st != to
                        {
                            *st = to;
                            drop(st);
                            let _ = tx.try_send(UiMsg::Engine(EngineEvent::StateChanged));
                        }
                    };

                    // Markers come only from the engine's stdout.
                    let m = if is_err { None } else { marker::parse(&line) };
                    let Some(m) = m else {
                        send(EngineEvent::Log(clean));
                        continue;
                    };
                    match m {
                        Marker::SamlFinal(u) => saml_final = Some(u),
                        Marker::SamlCookie(c) => saml_cookie = Some(c),
                        Marker::SamlHeaders(_) => saml_headers = true,
                        // SAML: open the IdP sign-in (the engine runs as root and can't
                        // reach the user's session) — once, and only the exact entry
                        // point of the gateway the user typed.
                        Marker::SamlUrl(url) => {
                            // GlobalProtect hands over the IdP's own URL (any host —
                            // the gateway picks the IdP) or an auto-posting form as a
                            // `data:` page; the latter only ever goes to the embedded view.
                            let gp_https = url.starts_with("https://");
                            let gp_form = url.starts_with("data:text/html");
                            if !saml_opened
                                && saml_headers
                                && saml_entry.is_some()
                                && (gp_https || gp_form)
                            {
                                saml_opened = true;
                                if cfg!(feature = "webview") {
                                    send(EngineEvent::SsoBrowser {
                                        login: url.clone(),
                                        watch: SsoWatch::GpHeaders,
                                        user_agent: sso_user_agent.clone(),
                                    });
                                } else if gp_https {
                                    let _ = Command::new("xdg-open").arg(&url).spawn();
                                }
                            } else if !saml_opened
                                && saml_entry.as_deref().is_some_and(|e| url.starts_with(e))
                            {
                                saml_opened = true;
                                // Embedded window when the engine told us where the flow
                                // ends (and that page is on the same gateway host).
                                let same_host = |u: &str| {
                                    saml_entry.as_deref().and_then(sso_origin) == sso_origin(u)
                                };
                                match (&saml_final, &saml_cookie) {
                                    (Some(f), Some(c))
                                        if cfg!(feature = "webview") && same_host(f) =>
                                    {
                                        send(EngineEvent::SsoBrowser {
                                            login: url.clone(),
                                            watch: SsoWatch::Cookie {
                                                final_url: f.clone(),
                                                cookie: c.clone(),
                                            },
                                            user_agent: sso_user_agent.clone(),
                                        });
                                    }
                                    // Fortinet (no cookie/headers to scrape): host the login in
                                    // the embedded window only when a UA override is set — that's
                                    // the whole point of routing it here instead of the browser.
                                    // Otherwise keep the default: open the user's own browser.
                                    _ if cfg!(feature = "webview") && sso_user_agent.is_some() => {
                                        send(EngineEvent::SsoBrowser {
                                            login: url.clone(),
                                            watch: SsoWatch::Loopback,
                                            user_agent: sso_user_agent.clone(),
                                        });
                                    }
                                    _ => {
                                        let _ = Command::new("xdg-open").arg(&url).spawn();
                                    }
                                }
                            }
                            send(EngineEvent::Log(clean));
                        }
                        // The engine blocks on stdin per question, so there's never more
                        // than one outstanding.
                        Marker::Prompt { kind, message } => {
                            if *state.lock().unwrap() != State::Disconnecting {
                                send(EngineEvent::Prompt(AuthPrompt { kind, message }));
                            }
                        }
                        Marker::State(marker::State::Up) => {
                            set_state(State::Connected, &[State::Connecting, State::Reconnecting])
                        }
                        Marker::State(marker::State::Reconnecting) => {
                            set_state(State::Reconnecting, &[State::Connected])
                        }
                        Marker::State(_) => {}
                        Marker::Ip(ip) => send(EngineEvent::Ip(ip.to_string())),
                        Marker::Dns(d) => send(EngineEvent::Dns(dns_text(&d))),
                        Marker::Iface(i) => send(EngineEvent::Iface(i)),
                        Marker::Error { message, .. } => set_state(State::Error(message), &[]),
                    }
                }
            });
        }

        self.child = Some(child);
    }

    /// Answer the engine's pending `AUTH-PROMPT` with one stdin line.
    pub fn answer_prompt(&mut self, line: &str) {
        if let Some(si) = self.stdin.as_mut() {
            let _ = writeln!(si, "{line}");
            let _ = si.flush();
        }
    }

    /// Ask the engine to stop — never blocks the UI. The engine aborts a login in
    /// progress, or restores DNS/routes, and exits; [`Vpn::poll`] notices.
    pub fn disconnect(&mut self) {
        if let Some(a) = &self.attached {
            match ctl::disconnect(&a.socket) {
                Ok(()) => {
                    let mut st = self.state.lock().unwrap();
                    if *st != State::Disconnecting {
                        *st = State::Disconnecting;
                        drop(st);
                        self.log("disconnecting…");
                    }
                }
                Err(e) => {
                    self.log(format!("could not reach the tunnel to disconnect it: {e}"));
                    self.attached = None;
                    *self.state.lock().unwrap() = State::Disconnected;
                }
            }
            let _ = self.tx.try_send(UiMsg::Engine(EngineEvent::StateChanged));
            return;
        }
        if let Some(mut si) = self.stdin.take() {
            let _ = writeln!(si, "disconnect");
            let _ = si.flush();
        }
        let mut st = self.state.lock().unwrap();
        if self.child.is_some() {
            if *st != State::Disconnecting {
                *st = State::Disconnecting;
                drop(st);
                self.log("disconnecting…");
            }
        } else {
            *st = State::Disconnected;
        }
        let _ = self.tx.try_send(UiMsg::Engine(EngineEvent::StateChanged));
    }

    /// For quitting: ask the engine to stop and give it a few seconds to finish its
    /// teardown before the window goes away (it completes on its own regardless).
    pub fn shutdown(&mut self) {
        self.disconnect();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let gone = |v: &mut Self| match (v.child.as_mut(), &v.attached) {
            (Some(c), _) => !matches!(c.try_wait(), Ok(None)),
            (None, Some(a)) => ctl::status(&a.socket).is_err(),
            (None, None) => true,
        };
        while !gone(self) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// Follow the engine: reap ours when it exits, keep an attached one's status
    /// current, and attach to a running tunnel while idle. Returns true when the
    /// state changed here (an attached tunnel's changes come as events).
    pub fn poll(&mut self) -> bool {
        if self.child.is_some() {
            return self.poll_exit();
        }
        if self.attached.is_some() {
            self.poll_attached();
        } else if matches!(self.state(), State::Disconnected | State::Error(_)) {
            self.try_attach();
        }
        false
    }

    fn poll_exit(&mut self) -> bool {
        if let Some(c) = self.child.as_mut() {
            if let Ok(Some(status)) = c.try_wait() {
                self.child = None;
                self.stdin = None;
                let mut st = self.state.lock().unwrap();
                match *st {
                    State::Disconnecting => {
                        *st = State::Disconnected;
                        drop(st);
                        self.log("disconnected");
                        return true;
                    }
                    // Exited before the tunnel came up, and no ERROR marker already
                    // recorded why → pkexec cancelled or auth failed.
                    State::Connecting => {
                        *st = State::Error(format!(
                            "engine exited before connecting ({status}) — auth cancelled or failed; see log"
                        ));
                    }
                    // Exited on its own while up (or mid-reconnect): a clean peer close
                    // is a plain disconnect; a non-zero exit means the tunnel dropped and
                    // the engine gave up — surface it so the user knows to reconnect.
                    State::Connected | State::Reconnecting => {
                        *st = if status.success() {
                            State::Disconnected
                        } else {
                            State::Error("tunnel lost — reconnect (see log)".into())
                        };
                    }
                    _ => {} // keep a specific Error already set by the parser
                }
                return true;
            }
        }
        false
    }

    fn send(&self, ev: EngineEvent) {
        let _ = self.tx.try_send(UiMsg::Engine(ev));
    }

    /// Take over the display of a tunnel this app isn't running (started from the
    /// command line, by the browser, or by this app before it restarted).
    fn try_attach(&mut self) {
        let Some((socket, status)) = ctl::running()
            .into_iter()
            .find(|(_, s)| s.state != marker::State::Down)
        else {
            return;
        };
        self.gen.fetch_add(1, Ordering::SeqCst);
        self.send(EngineEvent::Attached {
            name: status.name().to_string(),
            since: status.since,
        });
        let mut log_seen = 0;
        if let Ok((next, lines)) = ctl::log(&socket, 0) {
            log_seen = next;
            for l in lines.iter().filter_map(|l| shown(l)) {
                self.log(l);
            }
        }
        self.log(format!(
            "— following “{}” ({}, pid {}), which is running outside this window —",
            status.name(),
            status.backend,
            status.pid
        ));
        self.announce(&status, &Status::default());
        *self.state.lock().unwrap() = state_of(status.state, &State::Disconnected);
        self.attached = Some(Attached {
            socket,
            status,
            log_seen,
        });
        self.send(EngineEvent::StateChanged);
    }

    fn poll_attached(&mut self) {
        let Some(a) = self.attached.as_mut() else {
            return;
        };
        let mut lines = Vec::new();
        if let Ok((next, l)) = ctl::log(&a.socket, a.log_seen) {
            a.log_seen = next;
            lines = l;
        }
        let now = ctl::status(&a.socket);
        let prev = a.status.clone();
        if let Ok(s) = &now {
            a.status = s.clone();
        }
        for l in lines.iter().filter_map(|l| shown(l)) {
            self.log(l);
        }
        let mut st = self.state.lock().unwrap();
        let next = match &now {
            Ok(s) if !s.error.is_empty() && *st != State::Disconnecting => {
                State::Error(s.error.clone())
            }
            Ok(s) => state_of(s.state, &st),
            Err(_) => match &*st {
                State::Error(e) => State::Error(e.clone()),
                _ => State::Disconnected,
            },
        };
        let changed = *st != next;
        *st = next;
        drop(st);
        match now {
            Ok(s) => self.announce(&s, &prev),
            Err(_) => {
                self.attached = None;
                self.log("disconnected");
            }
        }
        if changed {
            self.send(EngineEvent::StateChanged);
        }
    }

    /// The address, DNS and interface of `s` that differ from `prev`.
    fn announce(&self, s: &Status, prev: &Status) {
        if !s.iface.is_empty() && s.iface != prev.iface && marker::is_iface_name(&s.iface) {
            self.send(EngineEvent::Iface(s.iface.clone()));
        }
        if !s.ip.is_empty() && s.ip != prev.ip {
            self.send(EngineEvent::Ip(s.ip.clone()));
        }
        let first = prev.pid == 0;
        if s.dns != prev.dns || (first && s.state == marker::State::Up) {
            self.send(EngineEvent::Dns(s.dns.join(", ")));
        }
    }
}

/// The app's state for an engine reporting `s`, while the app shows `current`.
fn state_of(s: marker::State, current: &State) -> State {
    match s {
        _ if *current == State::Disconnecting => State::Disconnecting,
        marker::State::Connecting => State::Connecting,
        marker::State::Up => State::Connected,
        marker::State::Reconnecting => State::Reconnecting,
        marker::State::Down => State::Disconnecting,
    }
}

/// A line of an engine's log as the log view shows it; markers are not shown.
fn shown(line: &str) -> Option<String> {
    marker::parse(line)
        .is_none()
        .then(|| line.trim_start_matches(['#', ' ']).to_string())
}

fn dns_text(d: &[std::net::IpAddr]) -> String {
    d.iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_attached_engines_state_maps_to_the_apps() {
        assert_eq!(
            state_of(marker::State::Up, &State::Disconnected),
            State::Connected
        );
        assert_eq!(
            state_of(marker::State::Reconnecting, &State::Connected),
            State::Reconnecting
        );
        assert_eq!(
            state_of(marker::State::Connecting, &State::Disconnected),
            State::Connecting
        );
        assert_eq!(
            state_of(marker::State::Down, &State::Connected),
            State::Disconnecting
        );
        assert_eq!(
            state_of(marker::State::Up, &State::Disconnecting),
            State::Disconnecting
        );
    }

    #[test]
    fn the_log_view_leaves_markers_out() {
        assert_eq!(
            shown("# TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)").as_deref(),
            Some("TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)")
        );
        assert_eq!(
            shown("f5 failed: tunnel dropped"),
            Some("f5 failed: tunnel dropped".into())
        );
        assert_eq!(shown("# STATE: up"), None);
        assert_eq!(shown("# AUTH-PROMPT: code: Enter the code"), None);
        assert_eq!(shown("# IP: 198.51.100.7"), None);
    }

    #[test]
    fn dns_reads_as_a_list() {
        let d: Vec<std::net::IpAddr> = vec![
            "203.0.113.53".parse().unwrap(),
            "203.0.113.54".parse().unwrap(),
        ];
        assert_eq!(dns_text(&d), "203.0.113.53, 203.0.113.54");
        assert_eq!(dns_text(&[]), "");
    }
}
