//! cpvpn-gui — a small native VPN client GUI with a system-tray icon.
//!
//! The GUI runs as the user and drives the privileged `cpvpn` engine as a
//! subprocess via `pkexec` (graphical PolicyKit auth). The passcode is piped on
//! the engine's stdin (never argv); writing `disconnect` (or closing stdin)
//! triggers a clean teardown. Engine stdout is parsed for live status.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod icon;

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};

use eframe::egui;

const SELFSERVICE_URL: &str = "https://securid.example.net/console-selfservice/";

#[derive(Clone, PartialEq)]
enum State {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

#[derive(Default)]
struct Status {
    ip: String,
    dns: String,
    log: VecDeque<String>,
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
            State::Connecting => [230, 170, 50],
            State::Error(_) => [230, 80, 80],
            State::Disconnected => [150, 156, 168],
        };
        vec![icon::tray_pixmap(color)]
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        let desc = match &*self.state.lock().unwrap() {
            State::Connected => "Connected",
            State::Connecting => "Connecting…",
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
        let connected = matches!(
            &*self.state.lock().unwrap(),
            State::Connected | State::Connecting
        );
        vec![
            StandardItem {
                label: "Show cpvpn".into(),
                activate: Box::new(|t: &mut Self| t.send(TrayCmd::Show)),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: if connected { "Disconnect" } else { "Connect…" }.into(),
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
}

impl Vpn {
    fn new() -> Self {
        Vpn {
            state: Arc::new(Mutex::new(State::Disconnected)),
            status: Arc::new(Mutex::new(Status::default())),
            child: None,
            stdin: None,
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
    fn connect(&mut self, engine_args: Vec<String>, stdin_lines: Vec<String>, label: String, ctx: egui::Context) {
        if matches!(*self.state.lock().unwrap(), State::Connecting | State::Connected) {
            return;
        }
        *self.state.lock().unwrap() = State::Connecting;
        {
            let mut s = self.status.lock().unwrap();
            s.ip.clear();
            s.dns.clear();
            s.log.clear();
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
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(r).lines().map_while(Result::ok) {
                    let clean = line.trim_start_matches(['#', ' ']).to_string();
                    eprintln!("[engine] {clean}"); // mirror to our stderr for logs/debugging

                    // SAML: the engine prints the IdP URL; open it in the user's browser
                    // (the engine runs as root and can't reach the user's session).
                    if let Some(rest) = clean.split("SAML-URL: ").nth(1) {
                        let url = rest.trim().to_string();
                        let _ = Command::new("xdg-open").arg(&url).spawn();
                    }
                    {
                        let mut s = status.lock().unwrap();
                        s.log.push_back(clean.clone());
                        while s.log.len() > 300 {
                            s.log.pop_front();
                        }
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
                    if clean.contains("TUNNEL UP") {
                        *state.lock().unwrap() = State::Connected;
                    } else if clean.contains("AUTH FAILED")
                        || clean.starts_with("IKE failed")
                        || clean.starts_with("forti failed")
                        || clean.contains("login rejected")
                        || clean.contains("Two-factor Authentication failed")
                        || clean.contains("auth not completed")
                    {
                        *state.lock().unwrap() = State::Error(clean.clone());
                    }
                    let _ = is_err;
                    ctx.request_repaint();
                }
            });
        }

        // Watch for process exit → Disconnected.
        {
            let state = self.state.clone();
            let ctx2 = ctx.clone();
            // We can't move `child` into the waiter (we keep it), so poll via a clone of the pid.
            // Instead, mark disconnected when stdout closes is handled above; also set here on drop.
            let _ = (&state, &ctx2);
        }

        self.child = Some(child);
    }

    fn disconnect(&mut self) {
        if let Some(mut si) = self.stdin.take() {
            let _ = writeln!(si, "disconnect");
            let _ = si.flush();
        }
        // Give the engine a moment; it restores DNS + tears down, then exits.
        if let Some(mut c) = self.child.take() {
            let _ = c.wait();
        }
        *self.state.lock().unwrap() = State::Disconnected;
        self.log("disconnected");
    }

    fn poll_exit(&mut self) {
        if let Some(c) = self.child.as_mut() {
            if let Ok(Some(status)) = c.try_wait() {
                self.child = None;
                self.stdin = None;
                let mut st = self.state.lock().unwrap();
                match *st {
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
    code: String,
    forti_saml: bool,
    vpn: Vpn,
    tray: Option<ksni::Handle<VpnTray>>,
    tray_rx: Option<mpsc::Receiver<TrayCmd>>,
    tray_active: bool,
    last_tray_state: Option<State>,
    want_quit: bool,
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
            code: String::new(),
            forti_saml: false,
            vpn: Vpn::new(),
            tray: None,
            tray_rx: None,
            tray_active: false,
            last_tray_state: None,
            want_quit: false,
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
            self.vpn.disconnect();
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
            self.vpn.disconnect();
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
        let (stdin_lines, label) = if self.forti_saml {
            args.push("--saml".into());
            args.push("--connect".into());
            (vec![], format!("SAML sign-in to {}", self.gateway))
        } else {
            args.push("-u".into());
            args.push(self.user.clone());
            args.push("--connect".into());
            // Password first, then the OTP (consumed only if the gateway challenges).
            let mut lines = vec![self.password.clone()];
            if !self.code.trim().is_empty() {
                lines.push(self.code.trim().to_string());
            }
            (lines, format!("connecting to {} as {}", self.gateway, self.user))
        };
        self.vpn.connect(args, stdin_lines, label, ctx);
        self.code.clear(); // OTP is one-time
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
        State::Error(_) => (egui::Color32::from_rgb(230, 80, 80), "Error"),
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.vpn.poll_exit();
        let state = self.vpn.state.lock().unwrap().clone();
        self.handle_tray(ctx, &state);

        egui::CentralPanel::default().show(ctx, |ui| {
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

            ui.label(egui::RichText::new("VPN client").weak().small());
            egui::ComboBox::from_id_salt("vpn")
                .selected_text(&self.client)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.client, "Check Point".to_string(), "Check Point");
                    ui.selectable_value(&mut self.client, "FortiClient".to_string(), "FortiClient");
                    ui.add_enabled(false, egui::SelectableLabel::new(false, "OpenVPN (soon)"));
                    ui.add_enabled(false, egui::SelectableLabel::new(false, "F5 (soon)"));
                });

            let is_forti = self.client == "FortiClient";
            let editable = matches!(state, State::Disconnected | State::Error(_));
            ui.add_space(4.0);
            ui.label("Gateway");
            ui.add_enabled(
                editable,
                egui::TextEdit::singleline(&mut self.gateway)
                    .hint_text(if is_forti { "vpn.example.com:443" } else { "" })
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
                    ui.label(egui::RichText::new("Token / OTP (only if 2FA)").weak().small());
                    ui.add_enabled(editable, egui::TextEdit::singleline(&mut self.code).desired_width(f32::INFINITY));
                } else {
                    ui.add_space(2.0);
                    ui.label(egui::RichText::new("You'll sign in through your browser.").weak().small());
                }
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
                        } else {
                            let passcode = format!("{}{}", self.pin.trim(), self.tokencode.trim());
                            let args = vec![
                                "ike".into(), "-g".into(), self.gateway.clone(),
                                "-u".into(), self.user.clone(), "--connect".into(),
                            ];
                            let label = format!("connecting to {} as {}", self.gateway, self.user);
                            self.vpn.connect(args, vec![passcode], label, ctx.clone());
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
            egui::ScrollArea::vertical().stick_to_bottom(true).max_height(160.0).show(ui, |ui| {
                let st = self.vpn.status.lock().unwrap();
                for l in &st.log {
                    ui.label(egui::RichText::new(l).monospace().small().color(egui::Color32::from_rgb(150, 156, 168)));
                }
            });
            }); // fixed-width column
            }); // centering row
        });

        if matches!(state, State::Connecting | State::Connected) {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
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
