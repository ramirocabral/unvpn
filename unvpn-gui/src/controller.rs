//! Starting and stopping connections and reacting to the engine and the tray.
//! Several connections run side by side, one [`Session`] each.

use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;
use gtk::glib;

use crate::engine::{EngineEvent, SessionId, State, TrayCmd, UiMsg, Vpn};
use crate::profiles::{anyconnect_saml_entry, ivanti_saml_entry, saml_entry, Backend};
use crate::session::{Session, SessionRow};
use crate::{profiles, tray, App};

/// A drop shorter than this (a transparent reconnect) raises no notification.
const DROP_NOTICE_AFTER: Duration = Duration::from_secs(5);

impl App {
    /// The running connection that goes by `name`.
    pub(crate) fn session_named(&self, name: &str) -> Option<SessionId> {
        self.sessions
            .borrow()
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.id)
    }

    pub(crate) fn session_state(&self, id: SessionId) -> Option<State> {
        self.sessions
            .borrow()
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.vpn.state())
    }

    /// Connection `id`'s name, also for a while after it ended (its engine's
    /// last lines arrive late).
    pub(crate) fn session_name(&self, id: SessionId) -> String {
        if let Some(s) = self.sessions.borrow().iter().find(|s| s.id == id) {
            return s.name.clone();
        }
        self.ended
            .borrow()
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, n)| n.clone())
            .unwrap_or_default()
    }

    /// Run `f` on connection `id`, if it still exists.
    pub(crate) fn with_session<T>(
        &self,
        id: SessionId,
        f: impl FnOnce(&mut Session) -> T,
    ) -> Option<T> {
        self.sessions
            .borrow_mut()
            .iter_mut()
            .find(|s| s.id == id)
            .map(f)
    }

    /// Add a connection with its row; `start` launches (or attaches) its engine.
    fn add_session(
        &self,
        name: String,
        backend: Option<Backend>,
        from_tray: bool,
        start: impl FnOnce(SessionId) -> Vpn,
    ) -> SessionId {
        let id = self.next_session.get();
        self.next_session.set(id + 1);
        self.failed.set(false);
        let row = SessionRow::new(&name, self.sessions.borrow().is_empty());
        let app = self.rc();
        row.stop
            .connect_clicked(move |_| app.disconnect_session(id));
        self.sessions_group.add(&row.expander);
        let vpn = start(id);
        // A tunnel found running has no news to tell: its state is where it starts.
        let shown = if vpn.attached_pid().is_some() {
            vpn.state()
        } else {
            State::Disconnected
        };
        self.sessions.borrow_mut().push(Session {
            id,
            name,
            backend,
            vpn,
            row,
            iface: None,
            since: None,
            from_tray,
            pending_key_pass: None,
            key_pass_to_store: None,
            waiting_prompt: None,
            shown,
            drop_notified: false,
        });
        self.on_session_state(id);
        id
    }

    /// The webtop's "Start" (an `f5-vpn://` link the browser handed over): run the
    /// handoff like any connection, so its questions and status show here. The
    /// saved F5 profile for that gateway, if any, lends its certificates and options.
    pub(crate) fn launch_f5(&self, url: &str) {
        let Some(endpoint) = profiles::f5_launch_endpoint(url) else {
            self.show_window();
            self.toast("That F5 link names no gateway");
            return;
        };
        let profs = self.profiles.borrow();
        let saved = profs.iter().find(|p| {
            p.backend == Backend::F5 && profiles::gateway_endpoint(&p.gateway) == endpoint
        });
        let name = saved
            .map(|p| p.name.clone())
            .unwrap_or_else(|| endpoint.clone());
        if self.session_named(&name).is_some() {
            drop(profs);
            self.show_window();
            self.toast(&format!(
                "Disconnect “{name}” first to start it from the browser"
            ));
            return;
        }
        let mut args: Vec<String> = ["f5", "--launch", url, "--watch-stdin", "--label", &name]
            .map(String::from)
            .to_vec();
        if saved.is_some_and(|p| p.killswitch) {
            args.push("--killswitch".into());
        }
        if saved.is_some_and(|p| p.no_dtls) {
            args.push("--no-dtls".into());
        }
        let mut pins = profiles::pins_for(&profs, &endpoint);
        drop(profs);
        if let Some(fp) = self.session_pins.borrow().get(&endpoint) {
            pins.push(format!("{endpoint}={fp}"));
        }
        for pin in pins {
            args.extend(["--pin".to_string(), pin]);
        }
        let tx = self.tx.clone();
        // Like a tray connect: the window opens for a question or a failure.
        self.add_session(name, Some(Backend::F5), true, move |id| {
            let mut vpn = Vpn::new(id, tx);
            vpn.connect(
                args,
                Vec::new(),
                format!("F5 from the browser: {endpoint}"),
                None,
                None,
            );
            vpn
        });
    }

    /// The name the form's connection goes by: the profile name, else the gateway.
    pub(crate) fn form_name(&self) -> String {
        let n = self.name_row.text().trim().to_string();
        if n.is_empty() {
            self.gateway_row.text().trim().to_string()
        } else {
            n
        }
    }

    /// The form's Connect button: connect what the form describes, or stop it.
    pub(crate) fn on_connect_clicked(&self) {
        match self.session_named(&self.form_name()) {
            Some(id) => self.disconnect_session(id),
            None => {
                self.start_connect(false);
                if self.session_named(&self.form_name()).is_some() {
                    self.show_main();
                }
            }
        }
    }

    pub(crate) fn start_connect(&self, from_tray: bool) {
        if !self.form_ready() {
            self.toast("Missing details to connect");
            return;
        }
        let name = self.form_name();
        if self.session_named(&name).is_some() {
            return;
        }
        let pending_key_pass = (self.backend() == Backend::OpenVpn
            && self.key_pass_row.is_visible())
        .then(|| self.key_pass_row.text().to_string())
        .filter(|k| !k.is_empty());

        let gw = self.gateway_row.text().trim().to_string();
        // SSO User-Agent override for the embedded sign-in window (empty ⇒ none).
        let sso_ua = {
            let u = self.ua_row.text().trim().to_string();
            (self.sso() && !u.is_empty()).then_some(u)
        };
        let label = format!("connecting to {gw}");

        let mut p = self.form_profile();
        for (endpoint, fp) in self.session_pins.borrow().iter() {
            p.pins.entry(endpoint.clone()).or_insert_with(|| fp.clone());
        }
        let psk = (p.backend == Backend::FortiIpsec)
            .then(|| self.psk_row.text().to_string())
            .filter(|k| !k.is_empty());
        let mut args = profiles::engine_args(&p, psk.is_some());
        args.extend(["--label".to_string(), name.clone()]);
        // Secrets go on stdin. The Check Point token code follows the PIN; a
        // second factor asked later comes as `# AUTH-PROMPT: code:`.
        let mut stdin_lines = if p.backend == Backend::CheckPoint && !p.cp_cert {
            let passcode = format!(
                "{}{}",
                self.password_row.text(),
                self.token_row.text().trim()
            );
            self.token_row.set_text(""); // one-time code
            vec![passcode]
        } else if profiles::takes_password(&p) {
            vec![self.password_row.text().to_string()]
        } else {
            Vec::new()
        };
        if let Some(k) = psk {
            stdin_lines.insert(0, k);
        }
        // GlobalProtect's IdP can be any host: the gateway announces it.
        let saml = match p.backend {
            _ if !p.uses_sso() => None,
            Backend::Forti => Some(saml_entry(&gw)),
            Backend::AnyConnect => Some(anyconnect_saml_entry(&gw)),
            Backend::Ivanti => Some(ivanti_saml_entry(&gw)),
            _ => Some(gw.clone()),
        };

        let tx = self.tx.clone();
        let id = self.add_session(name, Some(p.backend), from_tray, move |id| {
            let mut vpn = Vpn::new(id, tx);
            vpn.connect(args, stdin_lines, label, saml, sso_ua);
            vpn
        });
        self.with_session(id, |s| s.pending_key_pass = pending_key_pass);
    }

    pub(crate) fn disconnect_session(&self, id: SessionId) {
        self.with_session(id, |s| s.vpn.disconnect());
        self.clear_prompt_of(id);
        self.on_session_state(id);
    }

    pub(crate) fn disconnect_all(&self) {
        let ids: Vec<SessionId> = self.sessions.borrow().iter().map(|s| s.id).collect();
        for id in ids {
            self.disconnect_session(id);
        }
    }

    pub(crate) fn handle_msg(&self, msg: UiMsg) {
        match msg {
            UiMsg::Engine(id, ev) => self.handle_engine(id, ev),
            UiMsg::Tray(cmd) => self.handle_tray(cmd),
        }
    }

    fn handle_engine(&self, id: SessionId, ev: EngineEvent) {
        match ev {
            EngineEvent::Log(s) => self.session_log(id, &s),
            EngineEvent::Ip(ip) => {
                self.with_session(id, |s| {
                    s.row.ip.set_subtitle(&ip);
                    s.row.show_state(&s.vpn.state());
                });
                // The tunnel is up; a lingering SSO window (e.g. Fortinet's
                // loopback login) has done its job — close it.
                self.close_sso_window(id);
            }
            EngineEvent::Dns(dns) => {
                let text = if dns.is_empty() {
                    "System resolver (unchanged)"
                } else {
                    dns.as_str()
                };
                self.with_session(id, |s| s.row.dns.set_subtitle(text));
            }
            EngineEvent::Prompt(p) => self.show_prompt(id, p),
            EngineEvent::SsoBrowser {
                login,
                watch,
                user_agent,
            } => self.open_sso_window(id, &login, &watch, user_agent.as_deref()),
            EngineEvent::Iface(name) => {
                self.with_session(id, |s| {
                    s.iface = Some(name);
                    if s.since.is_none() {
                        s.since = Some(std::time::Instant::now());
                    }
                });
            }
            EngineEvent::StateChanged => self.on_session_state(id),
        }
    }

    /// React to connection `id` reaching a new state: its row, the prompt card,
    /// the SSO window, toasts and notifications, then the window and the tray.
    pub(crate) fn on_session_state(&self, id: SessionId) {
        let Some((prev, now, name, from_tray)) = self.with_session(id, |s| {
            let now = s.vpn.state();
            s.row.show_state(&now);
            let prev = std::mem::replace(&mut s.shown, now.clone());
            (prev, now, s.name.clone(), s.from_tray)
        }) else {
            return;
        };
        if prev == now {
            self.sync_ui();
            return;
        }
        if now != State::Connecting {
            self.close_sso_window(id);
        }
        match (&prev, &now) {
            (_, State::Connected) => {
                // A push approved on the phone leaves its card up; the tunnel answers it.
                self.clear_prompt_of(id);
                self.store_key_pass(id);
                if prev == State::Reconnecting {
                    if self.with_session(id, |s| std::mem::take(&mut s.drop_notified)) == Some(true)
                    {
                        self.notify(&name, &format!("Reconnected to “{name}”"), "", false);
                    }
                } else {
                    let ip = self
                        .with_session(id, |s| s.row.ip.subtitle().unwrap_or_default().to_string())
                        .unwrap_or_default();
                    let body = if ip.is_empty() {
                        String::new()
                    } else {
                        format!("Internal IP {ip}")
                    };
                    self.notify(&name, &format!("Connected to “{name}”"), &body, false);
                }
            }
            (State::Connected, State::Reconnecting) => {
                let app = self.rc();
                glib::timeout_add_local_once(DROP_NOTICE_AFTER, move || app.notify_drop(id));
            }
            (_, State::Error(e)) => {
                self.clear_prompt_of(id);
                self.toast(&format!("{name}: {e}"));
                let title = if prev == State::Connecting {
                    format!("Couldn't connect to “{name}”")
                } else {
                    format!("“{name}” disconnected")
                };
                self.notify(&name, &title, e, true);
                if from_tray {
                    self.reveal_log();
                }
            }
            (State::Connected | State::Reconnecting, State::Disconnected) => {
                self.notify(
                    &name,
                    &format!("“{name}” disconnected"),
                    "The gateway ended the session",
                    true,
                );
            }
            _ => {}
        }
        self.sync_ui();
    }

    /// Still reconnecting a while after the drop: say so.
    fn notify_drop(&self, id: SessionId) {
        let still = self.with_session(id, |s| {
            let lost = s.vpn.state() == State::Reconnecting && !s.drop_notified;
            s.drop_notified |= lost;
            lost.then(|| s.name.clone())
        });
        if let Some(Some(name)) = still {
            self.notify(
                &name,
                &format!("Connection to “{name}” lost"),
                "Reconnecting…",
                false,
            );
        }
    }

    pub(crate) fn handle_tray(&self, cmd: TrayCmd) {
        match cmd {
            TrayCmd::Show => self.show_window(),
            TrayCmd::ConnectProfile(name) => self.connect_profile(&name, true),
            TrayCmd::Disconnect(name) => {
                if let Some(id) = self.session_named(&name) {
                    self.disconnect_session(id);
                }
            }
            TrayCmd::DisconnectAll => self.disconnect_all(),
            TrayCmd::Quit => self.request_quit(),
        }
    }

    pub(crate) fn show_window(&self) {
        self.window.set_visible(true);
        self.window.present();
    }

    /// Connect a saved profile without the window (tray menu, a notification's
    /// button). If something is missing (a one-time token, a password that isn't
    /// remembered) the window opens on the profile; a runtime prompt or a failure
    /// opens it too. Other connections stay up.
    pub(crate) fn connect_profile(&self, name: &str, from_tray: bool) {
        if self.session_named(name).is_some() {
            return;
        }
        let Some(p) = self
            .profiles
            .borrow()
            .iter()
            .find(|p| p.name == name)
            .cloned()
        else {
            return;
        };
        self.load_profile(&p);
        if !self.form_ready() {
            self.show_window();
            self.open_editor(name);
            self.toast(&format!("“{name}” needs more details to connect"));
            self.focus_missing_field();
            return;
        }
        self.start_connect(from_tray);
    }

    /// Show the connections and profiles in the tray, when they changed.
    pub(crate) fn update_tray(&self) {
        let view = tray::TrayView {
            sessions: self
                .sessions
                .borrow()
                .iter()
                .map(|s| (s.name.clone(), s.vpn.state()))
                .collect(),
            profiles: self
                .profiles
                .borrow()
                .iter()
                .map(|p| p.name.clone())
                .collect(),
            failed: self.failed.get(),
        };
        {
            let mut v = self.tray_view.lock().unwrap();
            if *v == view {
                return;
            }
            *v = view;
        }
        if let Some(h) = self.tray.borrow().as_ref() {
            h.update(|_| {});
        }
    }

    /// Really quit (tray/menu "Quit"): mark it, then close — the close handler tears the
    /// tunnels down and lets the window be destroyed instead of hiding it.
    pub(crate) fn request_quit(&self) {
        self.quitting.set(true);
        self.window.close();
    }

    /// For quitting: stop every connection and give the engines a few seconds to
    /// finish their teardown (they complete on their own regardless).
    pub(crate) fn shutdown(&self) {
        let mut sessions = self.sessions.borrow_mut();
        for s in sessions.iter_mut() {
            s.vpn.disconnect();
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline && !sessions.iter_mut().all(|s| s.vpn.gone()) {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Follow every running connection: reap the engines that exited, keep the
    /// followed ones current, and pick up tunnels started elsewhere.
    pub(crate) fn poll_sessions(&self) {
        let ids: Vec<SessionId> = self.sessions.borrow().iter().map(|s| s.id).collect();
        for id in ids {
            if self.with_session(id, |s| s.vpn.poll()) == Some(true) {
                self.on_session_state(id);
            }
        }
        let done: Vec<SessionId> = self
            .sessions
            .borrow()
            .iter()
            .filter(|s| s.vpn.finished())
            .map(|s| s.id)
            .collect();
        for id in done {
            self.on_session_state(id);
            self.remove_session(id);
        }
        self.attach_running();
    }

    fn remove_session(&self, id: SessionId) {
        self.clear_prompt_of(id);
        self.close_sso_window(id);
        let s = {
            let mut sessions = self.sessions.borrow_mut();
            let Some(i) = sessions.iter().position(|s| s.id == id) else {
                return;
            };
            sessions.remove(i)
        };
        if matches!(s.vpn.state(), State::Error(_)) {
            self.failed.set(true);
        }
        {
            let mut ended = self.ended.borrow_mut();
            ended.push((id, s.name.clone()));
            if ended.len() > 16 {
                ended.remove(0);
            }
        }
        self.sessions_group.remove(&s.row.expander);
        self.sync_ui();
    }

    /// Follow the tunnels running that this app doesn't (started from the command
    /// line, by the browser, or by this app before it restarted).
    fn attach_running(&self) {
        for (socket, status) in Vpn::running() {
            let known = self
                .sessions
                .borrow()
                .iter()
                .any(|s| match s.vpn.attached_pid() {
                    Some(pid) => pid == status.pid,
                    None => s.name == status.name(),
                });
            if known {
                continue;
            }
            let tx = self.tx.clone();
            let name = status.name().to_string();
            let since = status.since;
            let id = self.add_session(name, None, false, move |id| {
                Vpn::attach(id, tx, socket, status)
            });
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let up_for = Duration::from_secs(now.saturating_sub(since));
            self.with_session(id, |s| {
                s.since = (since > 0).then(|| std::time::Instant::now() - up_for);
            });
        }
    }

    pub(crate) fn init_tray(self: &Rc<Self>) {
        if !tray::tray_available() {
            eprintln!("unvpn: no system tray detected — running as a normal window.");
            return;
        }
        use ksni::blocking::TrayMethods;
        self.update_tray();
        let tray = tray::VpnTray {
            view: self.tray_view.clone(),
            tx: self.tx.clone(),
        };
        match tray.spawn() {
            Ok(h) => *self.tray.borrow_mut() = Some(h),
            Err(e) => eprintln!("unvpn: tray unavailable ({e}) — running as a normal window."),
        }
    }
}
