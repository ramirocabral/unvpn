//! Starting and stopping connections and reacting to the engine and the tray.

use std::rc::Rc;
use std::time::Duration;

use adw::prelude::*;

use crate::engine::{EngineEvent, State, TrayCmd, UiMsg};
use crate::profiles::{anyconnect_saml_entry, saml_entry, Backend};
use crate::{profiles, tray, App};

impl App {
    /// The webtop's "Start" (an `f5-vpn://` link the browser handed over): run the
    /// handoff like any connection, so its questions and status show here. The
    /// saved F5 profile for that gateway, if any, lends its certificates and options.
    pub(crate) fn launch_f5(&self, url: &str) {
        let Some(endpoint) = profiles::f5_launch_endpoint(url) else {
            self.show_window();
            self.toast("That F5 link names no gateway");
            return;
        };
        if self.vpn.borrow().is_busy() {
            self.show_window();
            self.toast("Disconnect first to start the F5 connection from the browser");
            return;
        }
        self.log_buffer.set_text("");
        self.ip_row.set_subtitle("");
        self.dns_row.set_subtitle("");
        self.status_group.set_visible(false);
        self.clear_prompt();
        self.pending_key_pass.replace(None);
        self.key_pass_to_store.replace(None);

        let profs = self.profiles.borrow();
        let saved = profs.iter().find(|p| {
            p.backend == Backend::F5 && profiles::gateway_endpoint(&p.gateway) == endpoint
        });
        let name = saved
            .map(|p| p.name.clone())
            .unwrap_or_else(|| endpoint.clone());
        *self.active_profile.lock().unwrap() = name.clone();
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
        // Like a tray connect: the window opens for a question or a failure.
        self.from_tray.set(true);
        self.vpn.borrow_mut().connect(
            args,
            Vec::new(),
            format!("F5 from the browser: {endpoint}"),
            None,
            None,
        );
        self.sync_ui();
    }

    pub(crate) fn on_connect_clicked(&self) {
        let st = self.vpn.borrow().state();
        match st {
            State::Disconnected | State::Error(_) => {
                self.from_tray.set(false);
                self.start_connect()
            }
            State::Connecting | State::Connected | State::Reconnecting => {
                self.vpn.borrow_mut().disconnect();
                self.sync_ui();
            }
            State::Disconnecting => {}
        }
    }

    pub(crate) fn start_connect(&self) {
        if !self.form_ready() {
            self.toast("Missing details to connect");
            return;
        }
        self.log_buffer.set_text("");
        self.ip_row.set_subtitle("");
        self.dns_row.set_subtitle("");
        self.status_group.set_visible(false);
        self.clear_prompt();
        self.key_pass_to_store.replace(None);
        self.pending_key_pass.replace(
            (self.backend() == Backend::OpenVpn && self.key_pass_row.is_visible())
                .then(|| self.key_pass_row.text().to_string())
                .filter(|k| !k.is_empty()),
        );

        let gw = self.gateway_row.text().trim().to_string();
        // SSO User-Agent override for the embedded sign-in window (empty ⇒ none).
        let sso_ua = {
            let u = self.ua_row.text().trim().to_string();
            (self.sso() && !u.is_empty()).then_some(u)
        };
        let label = format!("connecting to {gw}");

        let name = {
            let n = self.name_row.text().trim().to_string();
            if n.is_empty() {
                gw.clone()
            } else {
                n
            }
        };
        *self.active_profile.lock().unwrap() = name.clone();

        let mut p = self.form_profile();
        for (endpoint, fp) in self.session_pins.borrow().iter() {
            p.pins.entry(endpoint.clone()).or_insert_with(|| fp.clone());
        }
        let psk = (p.backend == Backend::FortiIpsec)
            .then(|| self.psk_row.text().to_string())
            .filter(|k| !k.is_empty());
        let mut args = profiles::engine_args(&p, psk.is_some());
        args.extend(["--label".to_string(), name]);
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
            _ => Some(gw.clone()),
        };

        self.vpn
            .borrow_mut()
            .connect(args, stdin_lines, label, saml, sso_ua);
        self.sync_ui();
    }

    pub(crate) fn handle_msg(&self, msg: UiMsg) {
        match msg {
            UiMsg::Engine(ev) => match ev {
                EngineEvent::Log(s) => self.append_log(&s),
                EngineEvent::Ip(ip) => {
                    self.ip_row.set_subtitle(&ip);
                    self.status_group.set_visible(true);
                    // The tunnel is up; a lingering SSO window (e.g. Fortinet's
                    // loopback login) has done its job — close it.
                    self.close_sso_window();
                }
                EngineEvent::Dns(dns) => {
                    let text = if dns.is_empty() {
                        "System resolver (unchanged)"
                    } else {
                        dns.as_str()
                    };
                    self.dns_row.set_subtitle(text);
                }
                EngineEvent::Prompt(p) => self.show_prompt(p),
                EngineEvent::SsoBrowser {
                    login,
                    watch,
                    user_agent,
                } => self.open_sso_window(&login, &watch, user_agent.as_deref()),
                EngineEvent::Iface(name) => {
                    self.iface.replace(Some(name));
                    if self.conn_since.borrow().is_none() {
                        self.conn_since.replace(Some(std::time::Instant::now()));
                    }
                    self.status_group.set_visible(true);
                }
                EngineEvent::Attached { name, since } => {
                    self.log_buffer.set_text("");
                    self.clear_prompt();
                    *self.active_profile.lock().unwrap() = name;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let up_for = Duration::from_secs(now.saturating_sub(since));
                    self.conn_since
                        .replace((since > 0).then(|| std::time::Instant::now() - up_for));
                }
                EngineEvent::StateChanged => self.sync_ui(),
            },
            UiMsg::Tray(cmd) => self.handle_tray(cmd),
        }
    }

    pub(crate) fn handle_tray(&self, cmd: TrayCmd) {
        match cmd {
            TrayCmd::Show => self.show_window(),
            TrayCmd::ConnectProfile(name) => self.connect_from_tray(&name),
            TrayCmd::Disconnect => {
                self.pending_switch.replace(None);
                self.vpn.borrow_mut().disconnect();
                self.sync_ui();
            }
            TrayCmd::Quit => self.request_quit(),
        }
    }

    pub(crate) fn show_window(&self) {
        self.window.set_visible(true);
        self.window.present();
    }

    /// Tray menu pick: connect that saved profile without the window. If something
    /// is missing (a one-time token, a password that isn't remembered) the window
    /// opens on the profile; a runtime prompt or a failure opens it too.
    pub(crate) fn connect_from_tray(&self, name: &str) {
        match self.vpn.borrow().state() {
            State::Disconnected | State::Error(_) => {}
            State::Disconnecting => {
                self.pending_switch.replace(Some(name.to_string()));
                return;
            }
            State::Connecting | State::Connected | State::Reconnecting => {
                if *self.active_profile.lock().unwrap() != name {
                    self.pending_switch.replace(Some(name.to_string()));
                }
                self.vpn.borrow_mut().disconnect();
                self.sync_ui();
                return;
            }
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
            self.toast(&format!("“{name}” needs more details to connect"));
            self.focus_missing_field();
            return;
        }
        self.from_tray.set(true);
        self.start_connect();
    }

    pub(crate) fn update_tray(&self) {
        if let Some(h) = self.tray.borrow().as_ref() {
            h.update(|_| {});
        }
    }

    /// Really quit (tray/menu "Quit"): mark it, then close — the close handler tears the
    /// tunnel down and lets the window be destroyed instead of hiding it.
    pub(crate) fn request_quit(&self) {
        self.quitting.set(true);
        self.window.close();
    }

    pub(crate) fn init_tray(self: &Rc<Self>) {
        if !tray::tray_available() {
            eprintln!("unvpn: no system tray detected — running as a normal window.");
            return;
        }
        use ksni::blocking::TrayMethods;
        let tray = tray::VpnTray {
            state: self.vpn.borrow().state.clone(),
            tx: self.tx.clone(),
            profile: self.active_profile.clone(),
            profiles: self.tray_profiles.clone(),
        };
        match tray.spawn() {
            Ok(h) => *self.tray.borrow_mut() = Some(h),
            Err(e) => eprintln!("unvpn: tray unavailable ({e}) — running as a normal window."),
        }
    }
}
