//! cpvpn-gui — a small native VPN client GUI with a system-tray icon.
//!
//! The GUI runs as the user and drives the privileged `cpvpn` engine as a
//! subprocess via `pkexec` (graphical PolicyKit auth). The passcode is piped on
//! the engine's stdin (never argv); writing `disconnect` (or closing stdin)
//! triggers a clean teardown. Engine stdout is parsed for live status, and for
//! `# AUTH-PROMPT: <kind>: <message>` lines — a mid-login question (2FA code,
//! challenge answer, new password, push approval) answered with one stdin line.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod icon;

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use eframe::egui;

const SELFSERVICE_URL: &str = "https://securid.example.net/console-selfservice/";

#[derive(Clone, PartialEq)]
enum State {
    Disconnected,
    Connecting,
    Connected,
    /// `disconnect` sent; the engine is tearing down (DNS/routes) and will exit.
    Disconnecting,
    Error(String),
}

#[derive(Default)]
struct Status {
    ip: String,
    dns: String,
    log: VecDeque<String>,
    /// A pending engine question (`# AUTH-PROMPT:`), answered with one stdin line.
    prompt: Option<AuthPrompt>,
    /// Numbers the prompts, so a new question never inherits the old one's input.
    prompt_seq: u64,
}

/// What the engine is asking mid-login. `kind` is `code` (OTP / email / SMS
/// token), `code2` (next token code, drift resync), `answer` (challenge),
/// `newpass` (password expired), `renew` (password change the user may skip —
/// an empty answer) or `push` (approve in the app — or type a code).
#[derive(Clone)]
struct AuthPrompt {
    kind: String,
    message: String,
    seq: u64,
}

/// Parse `AUTH-PROMPT: <kind>: <message>` (already stripped of the `# ` prefix).
/// Only at the start of a line: gateway-supplied text (a challenge message) can
/// appear later in a line and must not be able to fake a marker.
fn parse_auth_prompt(line: &str) -> Option<AuthPrompt> {
    let rest = line.strip_prefix("AUTH-PROMPT: ")?;
    let (kind, message) = rest.split_once(": ").unwrap_or((rest, ""));
    Some(AuthPrompt { kind: kind.trim().to_string(), message: message.trim().to_string(), seq: 0 })
}

/// The SSO entry point the engine prints for `gateway` (`host[:port]`, default 443):
/// the only URL the GUI will hand to the browser.
fn saml_entry(gateway: &str) -> String {
    let g = gateway.trim();
    let hostport = match g.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => format!("{h}:{p}"),
        _ => format!("{g}:443"),
    };
    format!("https://{hostport}/remote/saml/start?")
}

/// Resolve the engine binary to an absolute path (pkexec requires absolute).
/// Order: $CPVPN_BIN, the dev build, $PATH, then a sensible default.
fn cpvpn_bin() -> String {
    if let Ok(p) = std::env::var("CPVPN_BIN") {
        return p;
    }
    let dev = "/home/user/projects/re/checkpoint-client/target/release/cpvpn";
    if std::path::Path::new(dev).exists() {
        return dev.to_string();
    }
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':').filter(|d| !d.is_empty()) {
            let cand = std::path::Path::new(dir).join("cpvpn");
            if cand.is_file() {
                return cand.to_string_lossy().into_owned();
            }
        }
    }
    "/usr/local/bin/cpvpn".to_string()
}

/// How to run the engine as root. `pkexec` needs a PolicyKit agent (GNOME/KDE
/// have one); minimal WMs (Sway/i3/…) often don't, but frequently have
/// passwordless sudo, which needs no agent. Auto-picks; override with
/// `CPVPN_PRIV=pkexec|sudo`.
fn priv_escalation() -> (&'static str, Vec<&'static str>) {
    match std::env::var("CPVPN_PRIV").as_deref() {
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

// ───────────────────────── system tray (StatusNotifierItem) ─────────────────

enum TrayCmd {
    Show,
    Connect,
    Disconnect,
    Quit,
}

struct VpnTray {
    state: Arc<Mutex<State>>,
    tx: mpsc::Sender<TrayCmd>,
    ctx: egui::Context,
}

impl VpnTray {
    fn send(&self, cmd: TrayCmd) {
        let _ = self.tx.send(cmd);
        self.ctx.request_repaint(); // wake the (possibly hidden) event loop
    }
}

impl ksni::Tray for VpnTray {
    fn id(&self) -> String {
        "cpvpn".into()
    }
    fn title(&self) -> String {
        "cpvpn".into()
    }
    fn icon_name(&self) -> String {
        String::new() // we supply a pixmap instead, so the icon is theme-independent
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let color = match &*self.state.lock().unwrap() {
            State::Connected => [60, 200, 110],
            State::Connecting | State::Disconnecting => [230, 170, 50],
            State::Error(_) => [230, 80, 80],
            State::Disconnected => [150, 156, 168],
        };
        vec![icon::tray_pixmap(color)]
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        let desc = match &*self.state.lock().unwrap() {
            State::Connected => "Connected",
            State::Connecting => "Connecting…",
            State::Disconnecting => "Disconnecting…",
            State::Error(_) => "Error",
            State::Disconnected => "Disconnected",
        };
        ksni::ToolTip {
            icon_name: String::new(),
            icon_pixmap: vec![],
            title: "cpvpn".into(),
            description: desc.into(),
        }
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(TrayCmd::Show); // left-click opens the window
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        let state = self.state.lock().unwrap().clone();
        let connected = matches!(state, State::Connected | State::Connecting);
        let label = match state {
            State::Connected | State::Connecting => "Disconnect",
            State::Disconnecting => "Disconnecting…",
            _ => "Connect…",
        };
        vec![
            StandardItem {
                label: "Show cpvpn".into(),
                activate: Box::new(|t: &mut Self| t.send(TrayCmd::Show)),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: label.into(),
                enabled: state != State::Disconnecting,
                activate: Box::new(move |t: &mut Self| {
                    t.send(if connected { TrayCmd::Disconnect } else { TrayCmd::Connect })
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|t: &mut Self| t.send(TrayCmd::Quit)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

/// True if a StatusNotifierWatcher (a tray host) is on the session bus, so it is
/// safe to hide the window to the tray instead of quitting.
fn tray_available() -> bool {
    use dbus::blocking::Connection;
    let Ok(c) = Connection::new_session() else {
        return false;
    };
    let proxy = c.with_proxy(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        std::time::Duration::from_millis(400),
    );
    let r: Result<(bool,), _> = proxy.method_call(
        "org.freedesktop.DBus",
        "NameHasOwner",
        ("org.kde.StatusNotifierWatcher",),
    );
    r.map(|(b,)| b).unwrap_or(false)
}

/// Manages the privileged engine subprocess.
struct Vpn {
    state: Arc<Mutex<State>>,
    status: Arc<Mutex<Status>>,
    child: Option<Child>,
    stdin: Option<std::process::ChildStdin>,
    /// Bumped per connection: a previous engine's late output can't touch this one.
    gen: Arc<AtomicU64>,
}

impl Vpn {
    fn new() -> Self {
        Vpn {
            state: Arc::new(Mutex::new(State::Disconnected)),
            status: Arc::new(Mutex::new(Status::default())),
            child: None,
            stdin: None,
            gen: Arc::new(AtomicU64::new(0)),
        }
    }

    fn log(&self, line: impl Into<String>) {
        let mut s = self.status.lock().unwrap();
        s.log.push_back(line.into());
        while s.log.len() > 300 {
            s.log.pop_front();
        }
    }

    /// Launch the privileged engine. `engine_args` are the `cpvpn` subcommand args
    /// (e.g. `ike …` or `forti …`); `stdin_lines` are secrets/inputs piped on
    /// stdin in order (password, token, …) — never in argv. `label` is a log line.
    /// `saml_entry`: for an SSO login, the only URL the engine may have us open.
    fn connect(
        &mut self,
        engine_args: Vec<String>,
        stdin_lines: Vec<String>,
        label: String,
        saml_entry: Option<String>,
        ctx: egui::Context,
    ) {
        if self.child.is_some()
            || matches!(*self.state.lock().unwrap(), State::Connecting | State::Connected | State::Disconnecting)
        {
            return;
        }
        let my_gen = self.gen.fetch_add(1, Ordering::SeqCst) + 1;
        *self.state.lock().unwrap() = State::Connecting;
        {
            let mut s = self.status.lock().unwrap();
            s.ip.clear();
            s.dns.clear();
            s.log.clear();
            s.prompt = None;
        }
        let (prog, pre) = priv_escalation();
        self.log(format!("{label} (via {prog})…"));

        let mut child = match Command::new(prog)
            .args(&pre)
            .arg(cpvpn_bin())
            .args(&engine_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                *self.state.lock().unwrap() = State::Error(format!("spawn {prog}: {e}"));
                return;
            }
        };

        // Pipe inputs (password, token, …) as stdin lines; keep stdin for disconnect.
        if let Some(mut si) = child.stdin.take() {
            for line in &stdin_lines {
                let _ = writeln!(si, "{line}");
            }
            let _ = si.flush();
            self.stdin = Some(si);
        }

        // Pump stdout + stderr → status/log.
        for (reader, is_err) in [
            (child.stdout.take().map(|o| Box::new(o) as Box<dyn std::io::Read + Send>), false),
            (child.stderr.take().map(|o| Box::new(o) as Box<dyn std::io::Read + Send>), true),
        ] {
            let Some(r) = reader else { continue };
            let state = self.state.clone();
            let status = self.status.clone();
            let gen = self.gen.clone();
            let saml_entry = saml_entry.clone();
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                let mut saml_opened = false;
                for line in BufReader::new(r).lines().map_while(Result::ok) {
                    let clean = line.trim_start_matches(['#', ' ']).to_string();
                    eprintln!("[engine] {clean}"); // mirror to our stderr for logs/debugging
                    if gen.load(Ordering::SeqCst) != my_gen {
                        continue; // a previous connection's engine, still draining
                    }

                    // Markers come only from the engine's stdout, only at the start of a
                    // line (gateway text is flattened into the middle of other lines).
                    let mut prompt = None;
                    if !is_err {
                        // SAML: open the IdP sign-in in the user's browser (the engine
                        // runs as root and can't reach the user's session) — once, and
                        // only the exact entry point of the gateway the user typed.
                        if let Some(rest) = clean.strip_prefix("SAML-URL: ") {
                            let url = rest.trim();
                            if !saml_opened && saml_entry.as_deref().is_some_and(|e| url.starts_with(e)) {
                                saml_opened = true;
                                let _ = Command::new("xdg-open").arg(url).spawn();
                            }
                        }
                        prompt = parse_auth_prompt(&clean);
                    }
                    let disconnecting = *state.lock().unwrap() == State::Disconnecting;
                    {
                        let mut s = status.lock().unwrap();
                        s.log.push_back(clean.clone());
                        while s.log.len() > 300 {
                            s.log.pop_front();
                        }
                        if let Some(mut p) = prompt {
                            if !disconnecting {
                                s.prompt_seq += 1;
                                p.seq = s.prompt_seq;
                                s.prompt = Some(p);
                            }
                            // carries gateway text — don't mine it for IP/DNS/state
                            drop(s);
                            ctx.request_repaint();
                            continue;
                        }
                        if !is_err {
                            // Internal IP: Check Point "Office Mode: IP x" / Fortinet "PPP up — IP x".
                            if let Some(rest) = clean
                                .split("Office Mode: IP ")
                                .nth(1)
                                .or_else(|| clean.split("— IP ").nth(1))
                            {
                                s.ip = rest.split_whitespace().next().unwrap_or("").to_string();
                            }
                            if let Some(rest) = clean.split("DNS [").nth(1) {
                                s.dns = rest.split(']').next().unwrap_or("").to_string();
                            }
                        }
                    }
                    if disconnecting {
                        // teardown chatter ("cancelled", …) must not override Disconnecting
                    } else if !is_err && clean.contains("TUNNEL UP") {
                        *state.lock().unwrap() = State::Connected;
                        status.lock().unwrap().prompt = None;
                    } else if clean.contains("AUTH FAILED")
                        || clean.starts_with("IKE failed")
                        || clean.starts_with("forti failed")
                        || clean.starts_with("f5 failed")
                        || clean.contains("login rejected")
                        || clean.contains("Two-factor Authentication failed")
                        || clean.contains("auth not completed")
                    {
                        *state.lock().unwrap() = State::Error(clean.clone());
                    }
                    ctx.request_repaint();
                }
            });
        }

        self.child = Some(child);
    }

    /// Answer the engine's pending `AUTH-PROMPT` number `seq` with one stdin line.
    fn answer_prompt(&mut self, seq: u64, line: &str) {
        if let Some(si) = self.stdin.as_mut() {
            let _ = writeln!(si, "{line}");
            let _ = si.flush();
        }
        let mut s = self.status.lock().unwrap();
        if s.prompt.as_ref().is_some_and(|p| p.seq == seq) {
            s.prompt = None; // a newer question that already arrived stays up
        }
    }

    /// Ask the engine to stop — never waits on the UI thread. The engine aborts a
    /// login in progress, or restores DNS/routes, and exits; [`poll_exit`] reaps it.
    fn disconnect(&mut self) {
        self.status.lock().unwrap().prompt = None;
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
    }

    /// For quitting: ask the engine to stop and give it a few seconds to finish its
    /// teardown before the window goes away (it completes on its own regardless).
    fn shutdown(&mut self) {
        self.disconnect();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while let Some(c) = self.child.as_mut() {
            if !matches!(c.try_wait(), Ok(None)) || std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    fn poll_exit(&mut self) {
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
                        return;
                    }
                    // Exited before the tunnel came up, and the stdout parser didn't
                    // already record a specific error → pkexec cancelled or auth failed.
                    State::Connecting => {
                        *st = State::Error(format!(
                            "engine exited before connecting ({status}) — auth cancelled or failed; see log"
                        ));
                    }
                    State::Connected => *st = State::Disconnected,
                    _ => {} // keep a specific Error already set by the parser
                }
            }
        }
    }
}

struct App {
    client: String,
    gateway: String,
    user: String,
    pin: String,
    tokencode: String,
    // Fortinet-specific inputs.
    password: String,
    realm: String,
    forti_saml: bool,
    /// Answer being typed for a pending engine `AUTH-PROMPT` (+ confirmation for `newpass`).
    prompt_input: String,
    prompt_confirm: String,
    /// The prompt (seq) those fields belong to.
    prompt_seq_seen: u64,
    vpn: Vpn,
    tray: Option<ksni::Handle<VpnTray>>,
    tray_rx: Option<mpsc::Receiver<TrayCmd>>,
    tray_active: bool,
    last_tray_state: Option<State>,
    want_quit: bool,
    /// An F5 tunnel launched from the browser (webtop "Start"), detected via its
    /// status file. The GUI shows it and can stop it even though it didn't start it.
    external_f5: Option<ExternalF5>,
}

/// An F5 tunnel started outside the GUI (by the `f5-vpn://` scheme handler), read from
/// `~/.cache/cpvpn-f5/tunnel.status`. The engine writes it; deleting it stops the tunnel.
struct ExternalF5 {
    gateway: String,
    ip: String,
    dns: String,
}

/// Path of the browser-launch status file (same as the scheme-handler wrapper writes).
fn f5_status_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(std::path::PathBuf::from(home).join(".cache/cpvpn-f5/tunnel.status"))
}

/// Detect a live browser-launched F5 tunnel: parse the status file and confirm its
/// process is still running. Returns None if there's no such tunnel.
fn detect_external_f5() -> Option<ExternalF5> {
    let content = std::fs::read_to_string(f5_status_path()?).ok()?;
    let (mut pid, mut gateway, mut ip, mut dns) = (0u32, String::new(), String::new(), String::new());
    for line in content.lines() {
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().to_string();
            match k.trim() {
                "pid" => pid = v.parse().unwrap_or(0),
                "gateway" => gateway = v,
                "ip" => ip = v,
                "dns" => dns = v,
                _ => {}
            }
        }
    }
    // A stale file whose process is gone is not a live tunnel.
    if pid == 0 || !std::path::Path::new(&format!("/proc/{pid}")).exists() {
        return None;
    }
    Some(ExternalF5 { gateway, ip, dns })
}

/// Stop a browser-launched F5 tunnel: delete its status file. The engine (running as
/// root) watches the file and tears the tunnel down cleanly when it disappears — which
/// the GUI, running as the user, could not do by signalling the process directly.
fn disconnect_external_f5() {
    if let Some(p) = f5_status_path() {
        let _ = std::fs::remove_file(p);
    }
}

impl Default for App {
    fn default() -> Self {
        App {
            client: "Check Point".to_string(),
            gateway: "203.0.113.10".to_string(),
            user: "u-123456".to_string(),
            pin: String::new(),
            tokencode: String::new(),
            password: String::new(),
            realm: String::new(),
            forti_saml: false,
            prompt_input: String::new(),
            prompt_confirm: String::new(),
            prompt_seq_seen: 0,
            vpn: Vpn::new(),
            tray: None,
            tray_rx: None,
            tray_active: false,
            last_tray_state: None,
            want_quit: false,
            external_f5: None,
        }
    }
}

impl App {
    /// Spawn the tray service (if a tray host exists) and keep a handle to refresh
    /// its icon when the connection state changes.
    fn init_tray(&mut self, ctx: egui::Context) {
        if !tray_available() {
            eprintln!("cpvpn: no system tray detected — running as a normal window.");
            return;
        }
        let (tx, rx) = mpsc::channel();
        let tray = VpnTray {
            state: self.vpn.state.clone(),
            tx,
            ctx,
        };
        let service = ksni::TrayService::new(tray);
        self.tray = Some(service.handle());
        service.spawn();
        self.tray_rx = Some(rx);
        self.tray_active = true;
    }

    fn handle_tray(&mut self, ctx: &egui::Context, state: &State) {
        if let Some(rx) = &self.tray_rx {
            while let Ok(cmd) = rx.try_recv() {
                match cmd {
                    TrayCmd::Show | TrayCmd::Connect => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    }
                    TrayCmd::Disconnect => self.vpn.disconnect(),
                    TrayCmd::Quit => self.want_quit = true,
                }
            }
        }
        if self.want_quit {
            self.vpn.shutdown();
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        // Refresh the tray icon/menu when the state changes.
        if let Some(h) = &self.tray {
            if self.last_tray_state.as_ref() != Some(state) {
                h.update(|_| {});
                self.last_tray_state = Some(state.clone());
            }
        }
        // Closing the window disconnects cleanly and quits — predictable (no
        // vanishing-to-an-invisible-tray). Minimize-to-tray can come back later.
        if ctx.input(|i| i.viewport().close_requested()) {
            self.vpn.shutdown();
            // not cancelled → the window closes and the app exits
        }
    }

    /// Build the Fortinet engine invocation (password or SAML) and launch it.
    fn start_forti(&mut self, ctx: egui::Context) {
        let mut args: Vec<String> = vec!["forti".into(), "-g".into(), self.gateway.clone()];
        if !self.realm.trim().is_empty() {
            args.push("--realm".into());
            args.push(self.realm.trim().to_string());
        }
        let saml = self.forti_saml.then(|| saml_entry(&self.gateway));
        let (stdin_lines, label) = if self.forti_saml {
            args.push("--saml".into());
            args.push("--no-browser".into()); // we open it ourselves, as the user (SAML-URL marker)
            args.push("--connect".into());
            (vec![], format!("SAML sign-in to {}", self.gateway))
        } else {
            args.push("-u".into());
            args.push(self.user.clone());
            args.push("--connect".into());
            // Only the password up front: any second factor (token, email/SMS code,
            // push, challenge) is asked interactively via `AUTH-PROMPT` — an emailed
            // code doesn't even exist until the password has been accepted.
            (vec![self.password.clone()], format!("connecting to {} as {}", self.gateway, self.user))
        };
        self.prompt_input.clear();
        self.prompt_confirm.clear();
        self.vpn.connect(args, stdin_lines, label, saml, ctx);
    }

    /// Build the F5 BIG-IP APM engine invocation and launch it. Only the password is
    /// sent up front; a one-time passcode (if the gateway asks) is answered
    /// interactively via `AUTH-PROMPT` — an emailed/SMS code doesn't exist until the
    /// password has been accepted. The webtop "Start" launch flow is separate (handled
    /// by the `f5-vpn://` scheme handler, not this GUI).
    fn start_f5(&mut self, ctx: egui::Context) {
        let args: Vec<String> = vec![
            "f5".into(),
            "-g".into(),
            self.gateway.clone(),
            "-u".into(),
            self.user.clone(),
            "--connect".into(),
        ];
        let label = format!("connecting to {} as {}", self.gateway, self.user);
        self.prompt_input.clear();
        self.prompt_confirm.clear();
        self.vpn.connect(args, vec![self.password.clone()], label, None, ctx);
    }

    /// The card for a pending engine question (2FA code, challenge, new password, push).
    fn prompt_ui(&mut self, ui: &mut egui::Ui, p: &AuthPrompt) {
        // A new question starts with empty fields and the keyboard focus.
        let fresh = p.seq != self.prompt_seq_seen;
        if fresh {
            self.prompt_seq_seen = p.seq;
            self.prompt_input.clear();
            self.prompt_confirm.clear();
        }
        ui.add_space(6.0);
        ui.group(|ui| {
            ui.set_width(ui.available_width());
            let title = match p.kind.as_str() {
                "push" => "Approve the sign-in",
                "newpass" => "Password expired",
                "renew" => "Change your password?",
                "answer" => "Additional verification",
                _ => "Two-factor authentication",
            };
            ui.label(egui::RichText::new(title).strong());
            if !p.message.is_empty() {
                ui.label(egui::RichText::new(&p.message).small());
            }
            let new_password = p.kind == "newpass" || p.kind == "renew";
            // Challenge answers can be a PIN+tokencode; never shown, never trimmed.
            let masked = new_password || p.kind == "answer";
            let hint = match p.kind.as_str() {
                "push" => "…or type the code instead",
                "code2" => "Next code",
                "newpass" | "renew" => "New password",
                "answer" => "Answer",
                _ => "Code",
            };
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.prompt_input)
                    .password(masked)
                    .hint_text(hint)
                    .desired_width(f32::INFINITY),
            );
            if fresh {
                resp.request_focus();
            }
            let confirm_resp = new_password.then(|| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.prompt_confirm)
                        .password(true)
                        .hint_text("Confirm new password")
                        .desired_width(f32::INFINITY),
                )
            });
            let answer = if masked { self.prompt_input.clone() } else { self.prompt_input.trim().to_string() };
            let mismatch = new_password && !answer.is_empty() && answer != self.prompt_confirm;
            if mismatch {
                ui.label(egui::RichText::new("Passwords don't match").small().color(egui::Color32::from_rgb(230, 120, 120)));
            }
            let ready = !answer.is_empty() && !mismatch;
            let enter = (resp.lost_focus() || confirm_resp.as_ref().is_some_and(|r| r.lost_focus()))
                && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let (send, skip) = ui
                .horizontal(|ui| {
                    let send = ui.add_enabled(ready, egui::Button::new("Send")).clicked();
                    // `renew`: an empty answer keeps the current password (portal "Skip").
                    let skip = p.kind == "renew" && ui.button("Skip").clicked();
                    (send, skip)
                })
                .inner;
            if skip {
                self.vpn.answer_prompt(p.seq, "");
                self.vpn.log("→ keeping the current password");
                self.prompt_input.clear();
                self.prompt_confirm.clear();
            } else if ready && (send || enter) {
                self.vpn.answer_prompt(p.seq, &answer);
                self.vpn.log(if masked { "→ new password sent" } else { "→ answer sent" });
                self.prompt_input.clear();
                self.prompt_confirm.clear();
            } else if p.kind == "push" {
                ui.label(egui::RichText::new("Waiting for approval in FortiToken Mobile…").weak().small());
            }
        });
    }
}

fn setup_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = egui::Color32::from_rgb(18, 20, 27);
    v.window_fill = egui::Color32::from_rgb(18, 20, 27);
    v.override_text_color = Some(egui::Color32::from_rgb(222, 226, 235));
    v.widgets.noninteractive.rounding = egui::Rounding::same(8.0);
    v.widgets.inactive.rounding = egui::Rounding::same(8.0);
    v.widgets.hovered.rounding = egui::Rounding::same(8.0);
    v.widgets.active.rounding = egui::Rounding::same(8.0);
    ctx.set_visuals(v);
    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    ctx.set_style(style);
}

fn dot(state: &State) -> (egui::Color32, &'static str) {
    match state {
        State::Disconnected => (egui::Color32::from_rgb(120, 125, 135), "Disconnected"),
        State::Connecting => (egui::Color32::from_rgb(230, 170, 50), "Connecting…"),
        State::Connected => (egui::Color32::from_rgb(60, 200, 110), "Connected"),
        State::Disconnecting => (egui::Color32::from_rgb(230, 170, 50), "Disconnecting…"),
        State::Error(_) => (egui::Color32::from_rgb(230, 80, 80), "Error"),
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.vpn.poll_exit();
        let state = self.vpn.state.lock().unwrap().clone();
        self.external_f5 = detect_external_f5(); // a browser-launched tunnel, if any
        self.handle_tray(ctx, &state);

        egui::CentralPanel::default().show(ctx, |ui| {
            // The whole page scrolls, so nothing (a 2FA card's Send button) ever ends
            // up below a short window's edge. It must wrap the centering row: inside
            // a horizontal row it would only get the row's few pixels of height.
            egui::ScrollArea::vertical().id_salt("main").auto_shrink([false, false]).show(ui, |ui| {
            // Center a fixed-width column so the form looks intentional even when a
            // tiling WM stretches the window to fill its region.
            let col_w = 440.0_f32.min((ui.available_width() - 16.0).max(120.0));
            let side = ((ui.available_width() - col_w) / 2.0).max(0.0);
            ui.horizontal(|ui| {
            ui.add_space(side);
            ui.vertical(|ui| {
            ui.set_width(col_w);
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading(egui::RichText::new("🛡  cpvpn").strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (c, label) = dot(&state);
                    ui.label(egui::RichText::new(label).color(c).small());
                    ui.label(egui::RichText::new("●").color(c));
                });
            });
            ui.label(egui::RichText::new("Native Linux VPN").weak().small());
            ui.separator();

            // A tunnel started from the browser (webtop "Start") — the GUI didn't launch
            // it, but detects it via the status file and can stop it (by deleting that
            // file; the root engine watches it and tears down cleanly).
            if let Some(ext) = &self.external_f5 {
                let (gw, ip, dns) = (ext.gateway.clone(), ext.ip.clone(), ext.dns.clone());
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("●").color(egui::Color32::from_rgb(70, 190, 120)));
                        ui.label(egui::RichText::new("F5 conectada (desde el navegador)").strong());
                    });
                    if !gw.is_empty() {
                        ui.label(egui::RichText::new(format!("Gateway:  {gw}")).small());
                    }
                    if !ip.is_empty() {
                        ui.label(egui::RichText::new(format!("Internal IP:  {ip}")).monospace().small());
                    }
                    if !dns.is_empty() {
                        ui.label(egui::RichText::new(format!("DNS:  {dns}")).monospace().small());
                    }
                    ui.add_space(4.0);
                    let btn = egui::Button::new(egui::RichText::new("Disconnect").strong())
                        .fill(egui::Color32::from_rgb(170, 60, 60))
                        .min_size(egui::vec2(ui.available_width(), 32.0));
                    if ui.add(btn).clicked() {
                        disconnect_external_f5();
                        self.external_f5 = None; // optimistic; detection reconfirms next frames
                    }
                });
                ui.add_space(6.0);
            }

            // Mid-login question from the engine (2FA code, challenge, push, …): first
            // thing in the window, where it can't be missed.
            let prompt = self.vpn.status.lock().unwrap().prompt.clone();
            if let (State::Connecting, Some(p)) = (&state, prompt) {
                self.prompt_ui(ui, &p);
                ui.add_space(4.0);
            }

            ui.label(egui::RichText::new("VPN client").weak().small());
            egui::ComboBox::from_id_salt("vpn")
                .selected_text(&self.client)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.client, "Check Point".to_string(), "Check Point");
                    ui.selectable_value(&mut self.client, "FortiClient".to_string(), "FortiClient");
                    ui.selectable_value(&mut self.client, "F5".to_string(), "F5");
                    ui.add_enabled(false, egui::SelectableLabel::new(false, "OpenVPN (soon)"));
                });

            let is_forti = self.client == "FortiClient";
            let is_f5 = self.client == "F5";
            let editable = matches!(state, State::Disconnected | State::Error(_));
            ui.add_space(4.0);
            ui.label("Gateway");
            ui.add_enabled(
                editable,
                egui::TextEdit::singleline(&mut self.gateway)
                    .hint_text(if is_forti || is_f5 { "vpn.example.com:443" } else { "" })
                    .desired_width(f32::INFINITY),
            );

            if is_forti {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("Auth:");
                    ui.add_enabled_ui(editable, |ui| {
                        ui.selectable_value(&mut self.forti_saml, false, "Password");
                        ui.selectable_value(&mut self.forti_saml, true, "SSO / SAML");
                    });
                });
                ui.label("Realm (optional)");
                ui.add_enabled(editable, egui::TextEdit::singleline(&mut self.realm).desired_width(f32::INFINITY));
                if !self.forti_saml {
                    ui.label("User");
                    ui.add_enabled(editable, egui::TextEdit::singleline(&mut self.user).desired_width(f32::INFINITY));
                    ui.label("Password");
                    ui.add_enabled(
                        editable,
                        egui::TextEdit::singleline(&mut self.password).password(true).desired_width(f32::INFINITY),
                    );
                    ui.label(egui::RichText::new("A token / 2FA code is asked for if the gateway needs one.").weak().small());
                } else {
                    ui.add_space(2.0);
                    ui.label(egui::RichText::new("You'll sign in through your browser.").weak().small());
                }
            } else if is_f5 {
                ui.label("User");
                ui.add_enabled(editable, egui::TextEdit::singleline(&mut self.user).desired_width(f32::INFINITY));
                ui.label("Password");
                ui.add_enabled(
                    editable,
                    egui::TextEdit::singleline(&mut self.password).password(true).desired_width(f32::INFINITY),
                );
                ui.label(egui::RichText::new("A one-time passcode is asked for if the gateway needs one.").weak().small());
            } else {
                ui.label("User");
                ui.add_enabled(editable, egui::TextEdit::singleline(&mut self.user).desired_width(f32::INFINITY));
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label("PIN");
                        ui.add_enabled(
                            editable,
                            egui::TextEdit::singleline(&mut self.pin).password(true).desired_width(90.0),
                        );
                    });
                    ui.vertical(|ui| {
                        ui.label("Token (email)");
                        ui.add_enabled(editable, egui::TextEdit::singleline(&mut self.tokencode).desired_width(130.0));
                    });
                    ui.vertical(|ui| {
                        ui.label(" ");
                        if ui.button("Get code ↗").clicked() {
                            let _ = Command::new("xdg-open").arg(SELFSERVICE_URL).spawn();
                        }
                    });
                });
            }

            ui.add_space(8.0);
            match state {
                State::Disconnected | State::Error(_) => {
                    let ready = if is_forti {
                        !self.gateway.is_empty()
                            && (self.forti_saml || (!self.user.is_empty() && !self.password.is_empty()))
                    } else if is_f5 {
                        !self.gateway.is_empty() && !self.user.is_empty() && !self.password.is_empty()
                    } else {
                        !self.gateway.is_empty() && !self.user.is_empty() && !self.tokencode.is_empty()
                    };
                    let btn_label = if is_forti && self.forti_saml { "Sign in with browser" } else { "Connect" };
                    let btn = egui::Button::new(egui::RichText::new(btn_label).strong())
                        .fill(egui::Color32::from_rgb(40, 110, 220))
                        .min_size(egui::vec2(ui.available_width(), 38.0));
                    if ui.add_enabled(ready, btn).clicked() {
                        if is_forti {
                            self.start_forti(ctx.clone());
                        } else if is_f5 {
                            self.start_f5(ctx.clone());
                        } else {
                            let passcode = format!("{}{}", self.pin.trim(), self.tokencode.trim());
                            let args = vec![
                                "ike".into(), "-g".into(), self.gateway.clone(),
                                "-u".into(), self.user.clone(), "--connect".into(),
                            ];
                            let label = format!("connecting to {} as {}", self.gateway, self.user);
                            self.vpn.connect(args, vec![passcode], label, None, ctx.clone());
                            self.tokencode.clear(); // one-time code
                        }
                    }
                }
                State::Connecting | State::Connected => {
                    let btn = egui::Button::new(egui::RichText::new("Disconnect").strong())
                        .fill(egui::Color32::from_rgb(170, 60, 60))
                        .min_size(egui::vec2(ui.available_width(), 38.0));
                    if ui.add(btn).clicked() {
                        self.vpn.disconnect();
                    }
                }
                State::Disconnecting => {
                    let btn = egui::Button::new(egui::RichText::new("Disconnecting…").strong())
                        .min_size(egui::vec2(ui.available_width(), 38.0));
                    ui.add_enabled(false, btn);
                }
            }

            if let State::Error(ref e) = state {
                ui.add_space(4.0);
                ui.label(egui::RichText::new(e).color(egui::Color32::from_rgb(230, 120, 120)).small());
            }

            // Status card
            {
                let st = self.vpn.status.lock().unwrap();
                if !st.ip.is_empty() {
                    ui.add_space(6.0);
                    ui.group(|ui| {
                        ui.label(egui::RichText::new(format!("Internal IP:  {}", st.ip)).monospace());
                        if !st.dns.is_empty() {
                            ui.label(egui::RichText::new(format!("DNS:  {}", st.dns)).monospace().small());
                        }
                    });
                }
            }

            ui.add_space(6.0);
            ui.label(egui::RichText::new("Log").weak().small());
            egui::ScrollArea::vertical().id_salt("log").stick_to_bottom(true).max_height(160.0).show(ui, |ui| {
                let st = self.vpn.status.lock().unwrap();
                for l in &st.log {
                    ui.label(egui::RichText::new(l).monospace().small().color(egui::Color32::from_rgb(150, 156, 168)));
                }
            });
            }); // fixed-width column
            }); // centering row
            }); // scroll area
        });

        if matches!(state, State::Connecting | State::Connected | State::Disconnecting) {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        } else {
            // Keep polling (while the window is open) for a browser-launched F5 tunnel,
            // and to reflect its teardown after a Disconnect.
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
    }
}

fn dump_icon(path: &str) {
    let (w, h, rgba) = icon::preview_rgba();
    let mut ppm = format!("P6\n{w} {h}\n255\n").into_bytes();
    for p in 0..w * h {
        ppm.extend_from_slice(&rgba[p * 4..p * 4 + 3]);
    }
    std::fs::write(path, ppm).expect("write ppm");
    eprintln!("wrote {path}");
}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--dump-icon") {
        dump_icon(args.get(2).map(String::as_str).unwrap_or("/tmp/cpvpn-icon.ppm"));
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("--dump-rgba") {
        let path = args.get(2).map(String::as_str).unwrap_or("/tmp/cpvpn.raw");
        let size: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(256);
        std::fs::write(path, icon::app_icon_rgba(size)).expect("write raw");
        eprintln!("wrote {path} ({size}x{size} rgba)");
        return Ok(());
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([440.0, 620.0])
            .with_min_inner_size([380.0, 520.0])
            .with_icon(std::sync::Arc::new(icon::window_icon()))
            .with_title("cpvpn"),
        ..Default::default()
    };
    eframe::run_native(
        "cpvpn",
        options,
        Box::new(|cc| {
            setup_theme(&cc.egui_ctx);
            let mut app = App::default();
            app.init_tray(cc.egui_ctx.clone());
            Ok(Box::new(app))
        }),
    )
}
