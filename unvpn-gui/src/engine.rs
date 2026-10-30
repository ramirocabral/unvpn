//! Engine driver: runs the privileged `unvpn` engine as a subprocess and turns
//! its stdout/stderr into [`UiMsg`] events for the GTK main loop.
//!
//! The GUI runs as the user and escalates the engine via `pkexec`/`sudo -n`. The
//! password (or SecurID PIN) is piped on the engine's stdin — never argv; writing
//! `disconnect` (or closing stdin) triggers a clean teardown. Engine stdout is
//! parsed for live status and for `# AUTH-PROMPT: <kind>: <message>` lines — a
//! mid-login question (2FA code, challenge, new password, push) answered with one
//! stdin line.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Connection state. Shared with the tray (which colours its icon from it).
#[derive(Clone, PartialEq, Eq)]
pub enum State {
    Disconnected,
    Connecting,
    Connected,
    /// `disconnect` sent; the engine is tearing down (DNS/routes) and will exit.
    Disconnecting,
    Error(String),
}

/// What the engine is asking mid-login. `kind` is `code` (OTP / email / SMS
/// token), `code2` (next token code, drift resync), `answer` (challenge),
/// `newpass` (password expired), `renew` (password change the user may skip —
/// an empty answer) or `push` (approve in the app — or type a code).
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
    SsoBrowser { login: String, watch: SsoWatch, user_agent: Option<String> },
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

/// Parse `AUTH-PROMPT: <kind>: <message>` (already stripped of the `# ` prefix).
/// Only at the start of a line: gateway-supplied text (a challenge message) can
/// appear later in a line and must not be able to fake a marker.
fn parse_auth_prompt(line: &str) -> Option<AuthPrompt> {
    let rest = line.strip_prefix("AUTH-PROMPT: ")?;
    let (kind, message) = rest.split_once(": ").unwrap_or((rest, ""));
    Some(AuthPrompt { kind: kind.trim().to_string(), message: message.trim().to_string() })
}

/// The SSO entry point the engine prints for `gateway` (`host[:port]`, default 443):
/// the only URL the GUI will hand to the browser.
pub fn saml_entry(gateway: &str) -> String {
    let g = gateway.trim();
    let hostport = match g.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => format!("{h}:{p}"),
        _ => format!("{g}:443"),
    };
    format!("https://{hostport}/remote/saml/start?")
}

/// AnyConnect's SSO entry point for `gateway` (a URL, maybe with a group path):
/// the ASA/FTD `sso-v2-login` on the same host — `https://host[:port]/+CSCOE+/saml/`.
/// The gateway omits the default port, so `:443` is dropped here too.
pub fn anyconnect_saml_entry(gateway: &str) -> String {
    let g = gateway.trim();
    let g = g.strip_prefix("https://").or_else(|| g.strip_prefix("http://")).unwrap_or(g);
    let hostport = g.split(['/', '?', '#']).next().unwrap_or_default();
    let hostport = hostport.strip_suffix(":443").unwrap_or(hostport);
    format!("https://{hostport}/+CSCOE+/saml/")
}

/// `https://host[:port]` of a URL (`None` if it isn't https).
fn sso_origin(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(&url[..8 + end])
}

/// Resolve the engine binary to an absolute path (pkexec requires absolute).
/// Order: $UNVPN_BIN, the engine built in the same source tree as this GUI
/// (running from `unvpn-gui/target/<profile>/`), $PATH, then a sensible default.
fn unvpn_bin() -> String {
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

/// `<repo>/unvpn/target/release/unvpn`, when this GUI runs from
/// `<repo>/unvpn-gui/target/<profile>/unvpn-gui` (a development checkout).
fn dev_engine() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let repo = exe.parent()?.parent()?.parent()?.parent()?; // <profile> → target → unvpn-gui → repo
    let cand = repo.join("unvpn/target/release/unvpn");
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

/// Manages the privileged engine subprocess. Lives on the GTK main thread; the
/// stdout/stderr reader threads only *send* [`UiMsg`]s, never touch this struct.
pub struct Vpn {
    pub state: Arc<Mutex<State>>,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
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
            gen: Arc::new(AtomicU64::new(0)),
            tx,
        }
    }

    pub fn state(&self) -> State {
        self.state.lock().unwrap().clone()
    }

    fn log(&self, line: impl Into<String>) {
        let _ = self.tx.try_send(UiMsg::Engine(EngineEvent::Log(line.into())));
    }

    pub fn is_busy(&self) -> bool {
        self.child.is_some()
            || matches!(
                *self.state.lock().unwrap(),
                State::Connecting | State::Connected | State::Disconnecting
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
            (child.stdout.take().map(|o| Box::new(o) as Box<dyn std::io::Read + Send>), false),
            (child.stderr.take().map(|o| Box::new(o) as Box<dyn std::io::Read + Send>), true),
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

                    // Markers come only from the engine's stdout, only at the start of a
                    // line (gateway text is flattened into the middle of other lines).
                    if !is_err {
                        // SAML: open the IdP sign-in in the user's browser (the engine
                        // runs as root and can't reach the user's session) — once, and
                        // only the exact entry point of the gateway the user typed.
                        if let Some(rest) = clean.strip_prefix("SAML-FINAL: ") {
                            saml_final = Some(rest.trim().to_string());
                        }
                        if let Some(rest) = clean.strip_prefix("SAML-COOKIE: ") {
                            saml_cookie = Some(rest.trim().to_string());
                        }
                        if clean.starts_with("SAML-HEADERS:") {
                            saml_headers = true;
                        }
                        if let Some(rest) = clean.strip_prefix("SAML-URL: ") {
                            let url = rest.trim();
                            // GlobalProtect hands over the IdP's own URL (any host —
                            // the gateway picks the IdP) or an auto-posting form as a
                            // `data:` page; the latter only ever goes to the embedded view.
                            let gp_https = url.starts_with("https://");
                            let gp_form = url.starts_with("data:text/html");
                            if !saml_opened && saml_headers && saml_entry.is_some() && (gp_https || gp_form) {
                                saml_opened = true;
                                if cfg!(feature = "webview") {
                                    let _ = tx.try_send(UiMsg::Engine(EngineEvent::SsoBrowser {
                                        login: url.to_string(),
                                        watch: SsoWatch::GpHeaders,
                                        user_agent: sso_user_agent.clone(),
                                    }));
                                } else if gp_https {
                                    let _ = Command::new("xdg-open").arg(url).spawn();
                                }
                            } else if !saml_opened && saml_entry.as_deref().is_some_and(|e| url.starts_with(e)) {
                                saml_opened = true;
                                // Embedded window when the engine told us where the flow
                                // ends (and that page is on the same gateway host).
                                let same_host = |u: &str| saml_entry.as_deref().and_then(sso_origin) == sso_origin(u);
                                match (&saml_final, &saml_cookie) {
                                    (Some(f), Some(c)) if cfg!(feature = "webview") && same_host(f) => {
                                        let _ = tx.try_send(UiMsg::Engine(EngineEvent::SsoBrowser {
                                            login: url.to_string(),
                                            watch: SsoWatch::Cookie { final_url: f.clone(), cookie: c.clone() },
                                            user_agent: sso_user_agent.clone(),
                                        }));
                                    }
                                    // Fortinet (no cookie/headers to scrape): host the login in
                                    // the embedded window only when a UA override is set — that's
                                    // the whole point of routing it here instead of the browser.
                                    // Otherwise keep the default: open the user's own browser.
                                    _ if cfg!(feature = "webview") && sso_user_agent.is_some() => {
                                        let _ = tx.try_send(UiMsg::Engine(EngineEvent::SsoBrowser {
                                            login: url.to_string(),
                                            watch: SsoWatch::Loopback,
                                            user_agent: sso_user_agent.clone(),
                                        }));
                                    }
                                    _ => {
                                        let _ = Command::new("xdg-open").arg(url).spawn();
                                    }
                                }
                            }
                        }
                        // A mid-login question carries gateway text — don't mine it for
                        // IP/DNS/state. The engine blocks on stdin per question, so there's
                        // never more than one outstanding.
                        if let Some(p) = parse_auth_prompt(&clean) {
                            if *state.lock().unwrap() != State::Disconnecting {
                                let _ = tx.try_send(UiMsg::Engine(EngineEvent::Prompt(p)));
                            }
                            continue;
                        }
                    }

                    let _ = tx.try_send(UiMsg::Engine(EngineEvent::Log(clean.clone())));
                    let disconnecting = *state.lock().unwrap() == State::Disconnecting;
                    if !is_err {
                        // Internal IP: Check Point "Office Mode: IP x" / Fortinet "PPP up — IP x".
                        if let Some(rest) = clean
                            .split("Office Mode: IP ")
                            .nth(1)
                            .or_else(|| clean.split("— IP ").nth(1))
                        {
                            let ip = rest.split_whitespace().next().unwrap_or("").to_string();
                            if !ip.is_empty() {
                                let _ = tx.try_send(UiMsg::Engine(EngineEvent::Ip(ip)));
                            }
                        }
                        if let Some(rest) = clean.split("DNS [").nth(1) {
                            let dns = rest.split(']').next().unwrap_or("").to_string();
                            let _ = tx.try_send(UiMsg::Engine(EngineEvent::Dns(dns)));
                        }
                    }

                    if disconnecting {
                    // teardown chatter ("cancelled", …) must not override Disconnecting
                    } else if !is_err && clean.contains("TUNNEL UP") {
                        *state.lock().unwrap() = State::Connected;
                        let _ = tx.try_send(UiMsg::Engine(EngineEvent::StateChanged));
                    } else if clean.contains("AUTH FAILED")
                        || clean.starts_with("IKE failed")
                        || clean.starts_with("forti failed")
                        || clean.starts_with("forti-ipsec failed")
                        || clean.starts_with("f5 failed")
                        || clean.starts_with("anyconnect failed")
                        || clean.starts_with("globalprotect failed")
                        || clean.starts_with("openvpn failed")
                        || clean.starts_with("wireguard failed")
                        || clean.contains("login rejected")
                        || clean.contains("Two-factor Authentication failed")
                        || clean.contains("auth not completed")
                    {
                        *state.lock().unwrap() = State::Error(clean.clone());
                        let _ = tx.try_send(UiMsg::Engine(EngineEvent::StateChanged));
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
    /// progress, or restores DNS/routes, and exits; [`Vpn::poll_exit`] reaps it.
    pub fn disconnect(&mut self) {
        if let Some(mut si) = self.stdin.take() {
            let _ = writeln!(si, "disconnect");
            let _ = si.flush();
        } // stdin dropped: EOF too
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
        while let Some(c) = self.child.as_mut() {
            if !matches!(c.try_wait(), Ok(None)) || std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// Reap the engine if it exited. Returns true if the state changed.
    pub fn poll_exit(&mut self) -> bool {
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
                    // Exited before the tunnel came up, and the stdout parser didn't
                    // already record a specific error → pkexec cancelled or auth failed.
                    State::Connecting => {
                            *st = State::Error(format!(
                            "engine exited before connecting ({status}) — auth cancelled or failed; see log"
                        ));
                    }
                    // Exited on its own while up: a clean peer close is a plain
                    // disconnect; a non-zero exit means the tunnel dropped and the
                    // engine gave up (e.g. an IKE session that can't rekey) — surface
                    // it so the user knows to reconnect.
                    State::Connected => {
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
}
