//! cpvpn-gui — a native Linux VPN client with a clean GTK4 / libadwaita UI and a
//! system-tray icon. Supports Check Point, Fortinet (FortiClient) and F5 BIG-IP
//! APM back-ends, and saved connection **profiles** (switch between gateways
//! without retyping). Passwords are kept in the system keyring (Secret Service);
//! 2FA tokens are single-use and always asked for.
//!
//! The GUI runs as the user and drives the privileged `cpvpn` engine as a
//! subprocess (see `engine.rs`); the tray is in `tray.rs`, profiles in
//! `profiles.rs`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;
mod icon;
mod profiles;
mod tray;

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use adw::prelude::*;
use gtk::{gdk, gio, glib};

use engine::{anyconnect_saml_entry, saml_entry, AuthPrompt, EngineEvent, State, TrayCmd, Tx, UiMsg, Vpn};
use profiles::{Backend, Profile};

const APP_ID: &str = "io.github.cpvpn.Client";

const CSS: &str = "
.statuspill { font-weight: bold; }
.st-on  { color: #2ec27e; }
.st-off { color: #9a9fab; }
.st-busy{ color: #e5a50a; }
.st-err { color: #e01b24; }
";

// ───────────────────────── browser-launched F5 tunnel ──────────────────────

/// An F5 tunnel started outside the GUI (by the `f5-vpn://` scheme handler), read
/// from `~/.cache/cpvpn-f5/tunnel.status`. The engine writes it; deleting it stops
/// the tunnel (the root engine watches the file and tears down cleanly).
struct ExternalF5 {
    gateway: String,
    ip: String,
    dns: String,
}

fn f5_status_path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(std::path::PathBuf::from(home).join(".cache/cpvpn-f5/tunnel.status"))
}

/// Detect a live browser-launched F5 tunnel: parse the status file and confirm its
/// process is still running. None if there's no such tunnel.
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
    if pid == 0 || !std::path::Path::new(&format!("/proc/{pid}")).exists() {
        return None; // a stale file whose process is gone is not a live tunnel
    }
    Some(ExternalF5 { gateway, ip, dns })
}

fn disconnect_external_f5() {
    if let Some(p) = f5_status_path() {
        let _ = std::fs::remove_file(p);
    }
}

// ─────────────────────────────────── App ───────────────────────────────────

/// All the GUI state. Held in an `Rc` and cloned into signal handlers; mutable
/// bits use interior mutability so handlers can take `&self`.
struct App {
    window: adw::ApplicationWindow,
    toast: adw::ToastOverlay,

    // header
    status_pill: gtk::Label,

    // profiles
    profiles_group: adw::PreferencesGroup,
    profile_rows: RefCell<Vec<adw::ActionRow>>,
    profiles: RefCell<Vec<Profile>>,

    // connection form
    form_group: adw::PreferencesGroup,
    name_row: adw::EntryRow,
    backend_row: adw::ComboRow,
    gateway_row: adw::EntryRow,
    user_row: adw::EntryRow,
    password_row: adw::PasswordEntryRow,
    token_row: adw::EntryRow,
    realm_row: adw::EntryRow,
    sso_row: adw::ComboRow,
    remember_row: adw::SwitchRow,
    save_btn: gtk::Button,

    // action
    connect_btn: gtk::Button,

    // active-connection status
    status_group: adw::PreferencesGroup,
    ip_row: adw::ActionRow,
    dns_row: adw::ActionRow,

    // browser-launched F5
    ext_group: adw::PreferencesGroup,
    ext_gw_row: adw::ActionRow,
    ext_ip_row: adw::ActionRow,
    ext_dns_row: adw::ActionRow,

    // mid-login question
    prompt_group: adw::PreferencesGroup,
    prompt_rows: RefCell<Vec<gtk::Widget>>,

    // log
    log_buffer: gtk::TextBuffer,
    log_view: gtk::TextView,

    // engine + tray
    vpn: RefCell<Vpn>,
    tray: RefCell<Option<ksni::Handle<tray::VpnTray>>>,
    tx: Tx,
    last_state: RefCell<Option<State>>,
    /// Name of the profile used for the current connection — shown on hover (header
    /// status pill + tray tooltip). Shared with the tray thread.
    active_profile: Arc<Mutex<String>>,
    /// Set only when the user really quits (tray/menu "Quit"); otherwise closing the
    /// window just hides it to the tray (the tunnel keeps running).
    quitting: Cell<bool>,
    /// Self-reference, so `&self` handlers can clone the owning `Rc` for callbacks.
    me: RefCell<Weak<App>>,
}

impl App {
    fn new(app: &adw::Application, tx: Tx) -> Rc<Self> {
        // ---- header -----------------------------------------------------------
        let status_pill = gtk::Label::builder().css_classes(["statuspill", "st-off"]).build();
        let header = adw::HeaderBar::new();
        header.set_title_widget(Some(&adw::WindowTitle::new("cpvpn", "")));
        header.pack_start(&status_pill);

        let menu = gio::Menu::new();
        menu.append(Some("About cpvpn"), Some("app.about"));
        menu.append(Some("Quit"), Some("app.quit"));
        let menu_btn = gtk::MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .menu_model(&menu)
            .tooltip_text("Menu")
            .build();
        header.pack_end(&menu_btn);

        // ---- profiles ---------------------------------------------------------
        let add_btn = gtk::Button::builder()
            .icon_name("list-add-symbolic")
            .css_classes(["flat"])
            .tooltip_text("New profile (clears the form)")
            .build();
        let profiles_group = adw::PreferencesGroup::builder().title("Profiles").build();
        profiles_group.set_header_suffix(Some(&add_btn));

        // ---- connection form --------------------------------------------------
        let name_row = adw::EntryRow::builder().title("Profile name").build();

        let backend_model = gtk::StringList::new(&["Check Point", "FortiClient", "F5", "AnyConnect (Cisco)"]);
        let backend_row = adw::ComboRow::builder().title("VPN client").model(&backend_model).build();

        let gateway_row = adw::EntryRow::builder().title("Gateway").build();
        let user_row = adw::EntryRow::builder().title("User").build();
        let password_row = adw::PasswordEntryRow::builder().title("Password").build();

        let token_row = adw::EntryRow::builder().title("Token (email)").build();

        let auth_model = gtk::StringList::new(&["Password", "SSO / SAML"]);
        let sso_row = adw::ComboRow::builder().title("Authentication").model(&auth_model).build();
        let realm_row = adw::EntryRow::builder().title("Realm (optional)").build();

        let remember_row = adw::SwitchRow::builder()
            .title("Remember password")
            .subtitle("Store in the system keyring")
            .subtitle_lines(0)
            .build();

        let save_btn = gtk::Button::builder().label("Save").css_classes(["flat"]).build();
        let form_group = adw::PreferencesGroup::builder().title("Connection").build();
        form_group.set_header_suffix(Some(&save_btn));
        form_group.add(&name_row);
        form_group.add(&backend_row);
        form_group.add(&sso_row);
        form_group.add(&gateway_row);
        form_group.add(&realm_row);
        form_group.add(&user_row);
        form_group.add(&password_row);
        form_group.add(&token_row);
        form_group.add(&remember_row);

        // ---- connect button ---------------------------------------------------
        let connect_btn = gtk::Button::builder()
            .label("Connect")
            .css_classes(["suggested-action", "pill"])
            .hexpand(true)
            .margin_top(4)
            .build();
        connect_btn.set_height_request(40);

        // ---- active-connection status ----------------------------------------
        let ip_row = adw::ActionRow::builder().title("Internal IP").css_classes(["property"]).build();
        let dns_row = adw::ActionRow::builder().title("DNS").css_classes(["property"]).build();
        let status_group = adw::PreferencesGroup::builder().title("Active connection").visible(false).build();
        status_group.add(&ip_row);
        status_group.add(&dns_row);

        // ---- browser-launched F5 ---------------------------------------------
        let ext_gw_row = adw::ActionRow::builder().title("Gateway").css_classes(["property"]).build();
        let ext_ip_row = adw::ActionRow::builder().title("Internal IP").css_classes(["property"]).build();
        let ext_dns_row = adw::ActionRow::builder().title("DNS").css_classes(["property"]).build();
        let ext_disconnect = gtk::Button::builder()
            .icon_name("media-playback-stop-symbolic")
            .css_classes(["flat"])
            .valign(gtk::Align::Center)
            .tooltip_text("Disconnect")
            .build();
        ext_gw_row.add_suffix(&ext_disconnect);
        let ext_group = adw::PreferencesGroup::builder()
            .title("F5 — opened from the browser")
            .visible(false)
            .build();
        ext_group.add(&ext_gw_row);
        ext_group.add(&ext_ip_row);
        ext_group.add(&ext_dns_row);

        // ---- mid-login question ----------------------------------------------
        let prompt_group = adw::PreferencesGroup::builder().visible(false).build();

        // ---- log --------------------------------------------------------------
        let log_buffer = gtk::TextBuffer::builder().build();
        let log_view = gtk::TextView::builder()
            .buffer(&log_buffer)
            .editable(false)
            .cursor_visible(false)
            .monospace(true)
            .wrap_mode(gtk::WrapMode::WordChar)
            .left_margin(8)
            .right_margin(8)
            .top_margin(6)
            .bottom_margin(6)
            .build();
        let log_scroll = gtk::ScrolledWindow::builder()
            .min_content_height(170)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .child(&log_view)
            .build();
        let log_expander = adw::ExpanderRow::builder().title("Connection log").build();
        log_expander.add_row(&log_scroll);
        let diag_group = adw::PreferencesGroup::builder().build();
        diag_group.add(&log_expander);

        // ---- assemble ---------------------------------------------------------
        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(18)
            .margin_top(18)
            .margin_bottom(18)
            .margin_start(12)
            .margin_end(12)
            .build();
        content.append(&prompt_group);
        content.append(&ext_group);
        content.append(&status_group);
        content.append(&profiles_group);
        content.append(&form_group);
        content.append(&connect_btn);
        content.append(&diag_group);

        let clamp = adw::Clamp::builder().maximum_size(560).child(&content).build();
        let scroll = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&clamp)
            .build();
        let toast = adw::ToastOverlay::new();
        toast.set_child(Some(&scroll));

        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&header);
        toolbar.set_content(Some(&toast));

        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("cpvpn")
            .default_width(600)
            .default_height(840)
            .content(&toolbar)
            .build();
        window.set_size_request(360, 480);

        let this = Rc::new(App {
            window,
            toast,
            status_pill,
            profiles_group,
            profile_rows: RefCell::new(Vec::new()),
            profiles: RefCell::new(profiles::load()),
            form_group,
            name_row,
            backend_row,
            gateway_row,
            user_row,
            password_row,
            token_row,
            realm_row,
            sso_row,
            remember_row,
            save_btn,
            connect_btn,
            status_group,
            ip_row,
            dns_row,
            ext_group,
            ext_gw_row,
            ext_ip_row,
            ext_dns_row,
            prompt_group,
            prompt_rows: RefCell::new(Vec::new()),
            log_buffer,
            log_view,
            vpn: RefCell::new(Vpn::new(tx.clone())),
            tray: RefCell::new(None),
            tx,
            last_state: RefCell::new(None),
            active_profile: Arc::new(Mutex::new(String::new())),
            quitting: Cell::new(false),
            me: RefCell::new(Weak::new()),
        });
        *this.me.borrow_mut() = Rc::downgrade(&this);

        Self::wire(&this, &add_btn, &ext_disconnect);
        this.refresh_profiles_list();
        this.update_form_visibility();
        this.sync_ui();
        this
    }

    /// Connect all signal handlers (needs the `Rc` to clone into closures).
    fn wire(app: &Rc<Self>, add_btn: &gtk::Button, ext_disconnect: &gtk::Button) {
        app.backend_row.connect_selected_notify(glib::clone!(#[strong] app, move |_| {
            app.update_form_visibility();
            app.sync_ui();
        }));
        app.sso_row.connect_selected_notify(glib::clone!(#[strong] app, move |_| {
            app.update_form_visibility();
            app.sync_ui();
        }));

        // Re-evaluate the Connect button's "ready" state as the user types.
        app.gateway_row.connect_changed(glib::clone!(#[strong] app, move |_| app.sync_ui()));
        app.user_row.connect_changed(glib::clone!(#[strong] app, move |_| app.sync_ui()));
        app.token_row.connect_changed(glib::clone!(#[strong] app, move |_| app.sync_ui()));
        app.password_row.connect_changed(glib::clone!(#[strong] app, move |_| app.sync_ui()));

        app.connect_btn.connect_clicked(glib::clone!(#[strong] app, move |_| app.on_connect_clicked()));
        app.save_btn.connect_clicked(glib::clone!(#[strong] app, move |_| app.save_profile()));
        add_btn.connect_clicked(glib::clone!(#[strong] app, move |_| app.on_new_profile()));

        ext_disconnect.connect_clicked(glib::clone!(#[strong] app, move |_| {
            disconnect_external_f5();
            app.ext_group.set_visible(false);
        }));

        // Closing the window keeps the app (and the tunnel) running in the tray, like a
        // normal VPN client. The user quits only via the tray/menu "Quit". If there's no
        // tray to return from, closing quits (otherwise the window would be unreachable).
        app.window.connect_close_request(glib::clone!(#[strong] app, move |_| {
            if app.quitting.get() {
                app.vpn.borrow_mut().shutdown();
                return glib::Propagation::Proceed; // destroy the window → app exits
            }
            if app.tray.borrow().is_some() {
                app.window.set_visible(false); // minimize to tray, tunnel stays up
                return glib::Propagation::Stop;
            }
            app.vpn.borrow_mut().shutdown();
            glib::Propagation::Proceed
        }));
    }

    // ── form helpers ───────────────────────────────────────────────────────

    fn backend(&self) -> Backend {
        Backend::from_index(self.backend_row.selected())
    }
    /// SSO/SAML (browser) login selected, on a back-end that has one.
    fn sso(&self) -> bool {
        self.backend().has_sso() && self.sso_row.selected() == 1
    }

    /// Show only the rows relevant to the selected back-end / auth method.
    fn update_form_visibility(&self) {
        let b = self.backend();
        let forti = b == Backend::Forti;
        let cp = b == Backend::CheckPoint;
        let anyconnect = b == Backend::AnyConnect;
        let saml = self.sso();
        let need_creds = !saml;

        self.sso_row.set_visible(b.has_sso());
        // The realm row doubles as AnyConnect's optional tunnel-group field.
        self.realm_row.set_visible(forti || anyconnect);
        self.realm_row.set_title(if anyconnect { "Group (optional)" } else { "Realm (optional)" });
        self.user_row.set_visible(need_creds);
        self.password_row.set_visible(need_creds);
        self.remember_row.set_visible(need_creds);
        self.token_row.set_visible(cp);
        self.password_row.set_title(if cp { "PIN" } else { "Password" });

        let hint = if saml && anyconnect {
            "You'll sign in through your browser, then paste the SSO token cookie here."
        } else if saml {
            "You'll sign in through your browser."
        } else if cp {
            "SecurID PIN + the one-time token emailed to you."
        } else if anyconnect {
            "Full gateway URL incl. any group path. A 2FA code is requested if needed."
        } else {
            "A token / 2FA code is requested if the gateway needs one."
        };
        self.form_group.set_description(Some(hint));
    }

    fn form_ready(&self) -> bool {
        let gw = !self.gateway_row.text().trim().is_empty();
        match self.backend() {
            Backend::Forti | Backend::AnyConnect if self.sso() => gw,
            Backend::Forti | Backend::F5 | Backend::AnyConnect => {
                gw && !self.user_row.text().trim().is_empty()
                    && !self.password_row.text().is_empty()
            }
            Backend::CheckPoint => {
                gw && !self.user_row.text().trim().is_empty()
                    && !self.token_row.text().trim().is_empty()
            }
        }
    }

    // ── profiles ───────────────────────────────────────────────────────────

    fn refresh_profiles_list(&self) {
        for row in self.profile_rows.borrow_mut().drain(..) {
            self.profiles_group.remove(&row);
        }
        let profs = self.profiles.borrow();
        if profs.is_empty() {
            let row = adw::ActionRow::builder()
                .title("No saved profiles")
                .subtitle("Fill in the details and click Save")
                .sensitive(false)
                .build();
            self.profiles_group.add(&row);
            self.profile_rows.borrow_mut().push(row);
            return;
        }
        for p in profs.iter() {
            let row = adw::ActionRow::builder()
                .title(&p.name)
                .subtitle(&p.subtitle())
                .subtitle_lines(0)
                .activatable(true)
                .build();
            let conn = gtk::Button::builder()
                .icon_name("media-playback-start-symbolic")
                .css_classes(["flat"])
                .valign(gtk::Align::Center)
                .tooltip_text("Connect")
                .build();
            let del = gtk::Button::builder()
                .icon_name("user-trash-symbolic")
                .css_classes(["flat"])
                .valign(gtk::Align::Center)
                .tooltip_text("Delete profile")
                .build();
            row.add_suffix(&conn);
            row.add_suffix(&del);

            let app_rc = self.rc();
            let p1 = p.clone();
            row.connect_activated(glib::clone!(#[strong] app_rc, move |_| app_rc.load_profile(&p1)));
            let app2 = app_rc.clone();
            let p2 = p.clone();
            conn.connect_clicked(move |_| {
                app2.load_profile(&p2);
                app2.on_connect_clicked();
            });
            let app3 = app_rc.clone();
            let name = p.name.clone();
            del.connect_clicked(move |_| app3.delete_profile(&name));

            self.profiles_group.add(&row);
            self.profile_rows.borrow_mut().push(row);
        }
    }

    fn load_profile(&self, p: &Profile) {
        self.backend_row.set_selected(p.backend.index());
        self.sso_row.set_selected(if p.sso { 1 } else { 0 });
        self.name_row.set_text(&p.name);
        self.gateway_row.set_text(&p.gateway);
        self.user_row.set_text(&p.user);
        // realm_row doubles as AnyConnect's group field.
        self.realm_row.set_text(if p.backend == Backend::AnyConnect { &p.group } else { &p.realm });
        self.remember_row.set_active(p.remember_password);
        self.token_row.set_text("");
        let secret = if p.remember_password { profiles::secret_get(&p.name).unwrap_or_default() } else { String::new() };
        self.password_row.set_text(&secret);
        self.update_form_visibility();
        self.sync_ui();
    }

    fn save_profile(&self) {
        let name = self.name_row.text().trim().to_string();
        if name.is_empty() {
            self.toast("Enter a name to save the profile");
            self.name_row.grab_focus();
            return;
        }
        // "Remember" only applies when the password field is in play (not SSO).
        let creds_in_play = !self.sso();
        let remember = self.remember_row.is_active() && creds_in_play;
        let backend = self.backend();
        let realm_field = self.realm_row.text().trim().to_string();
        let p = Profile {
            name: name.clone(),
            backend,
            gateway: self.gateway_row.text().trim().to_string(),
            user: self.user_row.text().trim().to_string(),
            // realm_row doubles as AnyConnect's group field.
            realm: if backend == Backend::AnyConnect { String::new() } else { realm_field.clone() },
            group: if backend == Backend::AnyConnect { realm_field } else { String::new() },
            sso: self.sso(),
            remember_password: remember,
        };

        // Keyring: store the password/PIN only if "remember" is on and non-empty.
        let pw = self.password_row.text().to_string();
        if remember && !pw.is_empty() {
            if !profiles::secret_set(&name, &pw) {
                self.toast("Couldn't save to the keyring (is a Secret Service running?)");
            }
        } else {
            profiles::secret_delete(&name);
        }

        {
            let mut profs = self.profiles.borrow_mut();
            if let Some(slot) = profs.iter_mut().find(|e| e.name == name) {
                *slot = p;
            } else {
                profs.push(p);
            }
            if let Err(e) = profiles::save(&profs) {
                drop(profs);
                self.toast(&format!("Couldn't save: {e}"));
                return;
            }
        }
        self.refresh_profiles_list();
        self.toast(&format!("Saved profile “{name}”"));
    }

    fn delete_profile(&self, name: &str) {
        profiles::secret_delete(name);
        {
            let mut profs = self.profiles.borrow_mut();
            profs.retain(|e| e.name != name);
            let _ = profiles::save(&profs);
        }
        self.refresh_profiles_list();
        self.toast(&format!("Deleted profile “{name}”"));
    }

    fn on_new_profile(&self) {
        self.name_row.set_text("");
        self.gateway_row.set_text("");
        self.user_row.set_text("");
        self.password_row.set_text("");
        self.realm_row.set_text("");
        self.token_row.set_text("");
        self.remember_row.set_active(false);
        self.update_form_visibility();
        self.sync_ui();
        self.name_row.grab_focus();
    }

    // ── connect / disconnect ────────────────────────────────────────────────

    fn on_connect_clicked(&self) {
        let st = self.vpn.borrow().state();
        match st {
            State::Disconnected | State::Error(_) => self.start_connect(),
            State::Connecting | State::Connected => {
                self.vpn.borrow_mut().disconnect();
                self.sync_ui();
            }
            State::Disconnecting => {}
        }
    }

    fn start_connect(&self) {
        if !self.form_ready() {
            self.toast("Missing details to connect");
            return;
        }
        // Fresh slate for this attempt.
        self.log_buffer.set_text("");
        self.ip_row.set_subtitle("");
        self.dns_row.set_subtitle("");
        self.status_group.set_visible(false);
        self.clear_prompt();

        let gw = self.gateway_row.text().trim().to_string();
        let user = self.user_row.text().trim().to_string();
        let realm = self.realm_row.text().trim().to_string();
        let label = format!("connecting to {gw}");

        // Remember which profile this connection is for (hover tooltip). Fall back to the
        // gateway when connecting without a saved/named profile.
        *self.active_profile.lock().unwrap() = {
            let n = self.name_row.text().trim().to_string();
            if n.is_empty() { gw.clone() } else { n }
        };

        let (args, stdin_lines, saml): (Vec<String>, Vec<String>, Option<String>) = match self.backend() {
            Backend::CheckPoint => {
                let passcode = format!("{}{}", self.password_row.text(), self.token_row.text().trim());
                self.token_row.set_text(""); // one-time code
                (
                    vec!["ike".into(), "-g".into(), gw.clone(), "-u".into(), user, "--connect".into()],
                    vec![passcode],
                    None,
                )
            }
            Backend::Forti => {
                let mut args: Vec<String> = vec!["forti".into(), "-g".into(), gw.clone()];
                if !realm.is_empty() {
                    args.push("--realm".into());
                    args.push(realm);
                }
                if self.sso() {
                    args.push("--saml".into());
                    args.push("--no-browser".into()); // we open it ourselves, as the user
                    args.push("--connect".into());
                    (args, vec![], Some(saml_entry(&gw)))
                } else {
                    args.push("-u".into());
                    args.push(user);
                    args.push("--connect".into());
                    (args, vec![self.password_row.text().to_string()], None)
                }
            }
            Backend::F5 => (
                vec!["f5".into(), "-g".into(), gw.clone(), "-u".into(), user, "--connect".into()],
                vec![self.password_row.text().to_string()],
                None,
            ),
            Backend::AnyConnect => {
                // realm_row doubles as the optional tunnel group for AnyConnect.
                let mut args: Vec<String> = vec!["anyconnect".into(), "-g".into(), gw.clone()];
                if !realm.is_empty() {
                    args.push("--group".into());
                    args.push(realm);
                }
                if self.sso() {
                    // SAML: we open the gateway's login URL in the user's browser; the
                    // token cookie is pasted into the `# AUTH-PROMPT: sso:` card.
                    args.push("--sso".into());
                    args.push("--connect".into());
                    (args, vec![], Some(anyconnect_saml_entry(&gw)))
                } else {
                    args.push("-u".into());
                    args.push(user);
                    args.push("--connect".into());
                    // Password piped up front (like F5); a 2FA code, if any, is collected
                    // interactively via `# AUTH-PROMPT: code:`.
                    (args, vec![self.password_row.text().to_string()], None)
                }
            }
        };

        self.vpn.borrow_mut().connect(args, stdin_lines, label, saml);
        self.sync_ui();
    }

    // ── engine events ────────────────────────────────────────────────────────

    fn handle_msg(&self, msg: UiMsg) {
        match msg {
            UiMsg::Engine(ev) => match ev {
                EngineEvent::Log(s) => self.append_log(&s),
                EngineEvent::Ip(ip) => {
                    self.ip_row.set_subtitle(&ip);
                    self.status_group.set_visible(true);
                }
                EngineEvent::Dns(dns) => {
                    self.dns_row.set_subtitle(&dns);
                    self.dns_row.set_visible(!dns.is_empty());
                }
                EngineEvent::Prompt(p) => self.show_prompt(p),
                EngineEvent::StateChanged => self.sync_ui(),
            },
            UiMsg::Tray(cmd) => self.handle_tray(cmd),
        }
    }

    fn handle_tray(&self, cmd: TrayCmd) {
        match cmd {
            TrayCmd::Show | TrayCmd::Connect => {
                self.window.set_visible(true);
                self.window.present();
            }
            TrayCmd::Disconnect => {
                self.vpn.borrow_mut().disconnect();
                self.sync_ui();
            }
            TrayCmd::Quit => self.request_quit(),
        }
    }

    /// Really quit (tray/menu "Quit"): mark it, then close — the close handler tears the
    /// tunnel down and lets the window be destroyed instead of hiding it.
    fn request_quit(&self) {
        self.quitting.set(true);
        self.window.close();
    }

    fn append_log(&self, line: &str) {
        let b = &self.log_buffer;
        let mut end = b.end_iter();
        b.insert(&mut end, line);
        b.insert(&mut b.end_iter(), "\n");
        let lines = b.line_count();
        if lines > 500 {
            if let Some(mut cut) = b.iter_at_line(lines - 500) {
                let mut start = b.start_iter();
                b.delete(&mut start, &mut cut);
            }
        }
        self.log_view.scroll_to_iter(&mut b.end_iter(), 0.0, false, 0.0, 0.0);
    }

    /// Reap the engine and poll for a browser-launched F5 tunnel (timer-driven).
    fn tick(&self) {
        if self.vpn.borrow_mut().poll_exit() {
            self.sync_ui();
        }
        match detect_external_f5() {
            Some(e) => {
                self.ext_gw_row.set_subtitle(&e.gateway);
                self.ext_ip_row.set_subtitle(&e.ip);
                self.ext_dns_row.set_subtitle(&e.dns);
                self.ext_dns_row.set_visible(!e.dns.is_empty());
                self.ext_group.set_visible(true);
            }
            None => self.ext_group.set_visible(false),
        }
    }

    // ── mid-login question UI ────────────────────────────────────────────────

    fn show_prompt(&self, p: AuthPrompt) {
        self.clear_prompt();

        let (title, hint) = match p.kind.as_str() {
            "push" => ("Approve the sign-in", "…or type the code"),
            "newpass" => ("Password expired", "New password"),
            "renew" => ("Change your password?", "New password"),
            "answer" => ("Additional verification", "Answer"),
            "sso" => ("Finish the browser sign-in", "SSO token"),
            "code2" => ("Second code", "Next code"),
            _ => ("Two-factor authentication", "Code"),
        };
        self.prompt_group.set_title(title);
        self.prompt_group.set_description((!p.message.is_empty()).then_some(p.message.as_str()));

        let new_password = p.kind == "newpass" || p.kind == "renew";
        let masked = new_password || p.kind == "answer" || p.kind == "sso";

        // The input row: masked (password/challenge) vs visible (OTP code).
        let entry: gtk::Widget = if masked {
            adw::PasswordEntryRow::builder().title(hint).build().upcast()
        } else {
            adw::EntryRow::builder().title(hint).build().upcast()
        };
        let confirm = new_password.then(|| adw::PasswordEntryRow::builder().title("Confirm password").build());

        self.prompt_group.add(&entry);
        self.prompt_rows.borrow_mut().push(entry.clone());
        if let Some(c) = &confirm {
            self.prompt_group.add(c);
            self.prompt_rows.borrow_mut().push(c.clone().upcast());
        }

        // Buttons row (Send + optional Skip for a renewable password).
        let btns = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .halign(gtk::Align::End)
            .margin_top(8)
            .build();
        let send = gtk::Button::builder().label("Send").css_classes(["suggested-action"]).build();
        let skip = (p.kind == "renew").then(|| gtk::Button::with_label("Skip"));
        if let Some(s) = &skip {
            btns.append(s);
        }
        btns.append(&send);
        self.prompt_group.add(&btns);
        self.prompt_rows.borrow_mut().push(btns.upcast());

        self.prompt_group.set_visible(true);
        entry.grab_focus();

        // Wire actions. The entry widgets are captured directly (no field needed).
        let app = self.rc();
        let entry_for_send = entry.clone();
        let confirm_for_send = confirm.clone();
        let kind = p.kind.clone();
        let do_send: Rc<dyn Fn()> = Rc::new(move || {
            let text = app.editable_text(&entry_for_send);
            let answer = if masked { text } else { text.trim().to_string() };
            if new_password {
                let c = confirm_for_send.as_ref().map(|c| c.text().to_string()).unwrap_or_default();
                if answer != c {
                    app.toast("Passwords don't match");
                    return;
                }
            }
            if answer.is_empty() && kind != "renew" {
                return;
            }
            app.vpn.borrow_mut().answer_prompt(&answer);
            app.append_log(match kind.as_str() {
                "sso" => "→ SSO token sent",
                _ if masked => "→ password sent",
                _ => "→ answer sent",
            });
            app.clear_prompt();
        });

        send.connect_clicked({
            let d = do_send.clone();
            move |_| d()
        });
        if let Some(s) = &skip {
            let app2 = self.rc();
            s.connect_clicked(move |_| {
                app2.vpn.borrow_mut().answer_prompt("");
                app2.append_log("→ keeping the current password");
                app2.clear_prompt();
            });
        }
        // Enter in the (visible) code field sends too.
        if let Ok(er) = entry.clone().downcast::<adw::EntryRow>() {
            let d = do_send.clone();
            er.connect_entry_activated(move |_| d());
        }
    }

    fn clear_prompt(&self) {
        for w in self.prompt_rows.borrow_mut().drain(..) {
            self.prompt_group.remove(&w);
        }
        self.prompt_group.set_visible(false);
    }

    /// Read text from either an AdwEntryRow or an AdwPasswordEntryRow.
    fn editable_text(&self, w: &gtk::Widget) -> String {
        w.downcast_ref::<gtk::Editable>()
            .map(|e| e.text().to_string())
            .unwrap_or_default()
    }

    // ── state → UI ────────────────────────────────────────────────────────────

    fn sync_ui(&self) {
        let state = self.vpn.borrow().state();

        let (txt, cls) = match &state {
            State::Disconnected => ("Disconnected", "st-off"),
            State::Connecting => ("Connecting…", "st-busy"),
            State::Connected => ("Connected", "st-on"),
            State::Disconnecting => ("Disconnecting…", "st-busy"),
            State::Error(_) => ("Error", "st-err"),
        };
        self.status_pill.set_text(&format!("● {txt}"));
        self.status_pill.set_css_classes(&["statuspill", cls]);

        // Hovering the status pill shows the active profile name while connected.
        if matches!(state, State::Connected) {
            let name = self.active_profile.lock().unwrap().clone();
            self.status_pill.set_tooltip_text((!name.is_empty()).then_some(name.as_str()));
        } else {
            self.status_pill.set_tooltip_text(None);
        }

        let editable = matches!(state, State::Disconnected | State::Error(_));
        self.form_group.set_sensitive(editable);
        self.profiles_group.set_sensitive(editable);

        match &state {
            State::Disconnected | State::Error(_) => {
                let label = if self.sso() {
                    "Sign in with browser"
                } else {
                    "Connect"
                };
                self.connect_btn.set_label(label);
                self.connect_btn.set_css_classes(&["suggested-action", "pill"]);
                self.connect_btn.set_sensitive(self.form_ready());
                self.clear_prompt();
                self.status_group.set_visible(false);
                self.ip_row.set_subtitle("");
                self.dns_row.set_subtitle("");
            }
            State::Connecting | State::Connected => {
                self.connect_btn.set_label("Disconnect");
                self.connect_btn.set_css_classes(&["destructive-action", "pill"]);
                self.connect_btn.set_sensitive(true);
            }
            State::Disconnecting => {
                self.connect_btn.set_label("Disconnecting…");
                self.connect_btn.set_css_classes(&["pill"]);
                self.connect_btn.set_sensitive(false);
            }
        }

        // Toast + tray refresh only on an actual state change.
        let changed = self.last_state.borrow().as_ref() != Some(&state);
        if changed {
            if let State::Error(e) = &state {
                self.toast(e);
            }
            if let Some(h) = self.tray.borrow().as_ref() {
                h.update(|_| {});
            }
            *self.last_state.borrow_mut() = Some(state);
        }
    }

    fn toast(&self, msg: &str) {
        self.toast.add_toast(adw::Toast::new(msg));
    }

    /// The owning `Rc<App>` (set once in [`App::new`]) — for cloning into callbacks.
    fn rc(&self) -> Rc<App> {
        self.me.borrow().upgrade().expect("App dropped while a handler ran")
    }

    fn init_tray(self: &Rc<Self>) {
        if !tray::tray_available() {
            eprintln!("cpvpn: no system tray detected — running as a normal window.");
            return;
        }
        let tray = tray::VpnTray {
            state: self.vpn.borrow().state.clone(),
            tx: self.tx.clone(),
            profile: self.active_profile.clone(),
        };
        let service = ksni::TrayService::new(tray);
        *self.tray.borrow_mut() = Some(service.handle());
        service.spawn();
    }
}

fn build_ui(app: &adw::Application) {
    let (tx, rx) = async_channel::unbounded::<UiMsg>();
    let state_app = App::new(app, tx);

    // App actions for the primary menu.
    let about = gio::SimpleAction::new("about", None);
    about.connect_activate(glib::clone!(#[strong] state_app, move |_, _| {
        let dialog = adw::AboutDialog::builder()
            .application_name("cpvpn")
            .version(env!("CARGO_PKG_VERSION"))
            .developer_name("cpvpn")
            .comments("Native Linux VPN client — Check Point · Fortinet · F5")
            .build();
        dialog.present(Some(&state_app.window));
    }));
    let quit = gio::SimpleAction::new("quit", None);
    quit.connect_activate(glib::clone!(#[strong] state_app, move |_, _| state_app.window.close()));
    app.add_action(&about);
    app.add_action(&quit);

    state_app.init_tray();

    // Engine/tray events → UI.
    glib::spawn_future_local(glib::clone!(#[strong] state_app, async move {
        while let Ok(msg) = rx.recv().await {
            state_app.handle_msg(msg);
        }
    }));

    // Reap the engine + detect a browser-launched tunnel.
    glib::timeout_add_local(Duration::from_millis(800), glib::clone!(#[strong] state_app, move || {
        state_app.tick();
        glib::ControlFlow::Continue
    }));

    state_app.window.present();
}

fn install_css() {
    let provider = gtk::CssProvider::new();
    provider.load_from_string(CSS);
    if let Some(display) = gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

fn main() -> glib::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--dump-rgba") {
        let path = args.get(2).map(String::as_str).unwrap_or("/tmp/cpvpn.raw");
        let size: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(256);
        std::fs::write(path, icon::app_icon_rgba(size)).expect("write raw");
        eprintln!("wrote {path} ({size}x{size} rgba)");
        return glib::ExitCode::SUCCESS;
    }

    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_startup(|_| {
        install_css();
        gtk::Window::set_default_icon_name("cpvpn");
        // Sway doesn't report a system colour-scheme to libadwaita, so it would fall
        // back to light. Default to dark (the expected look for this utility); users
        // on a light desktop can still override via the usual GTK settings.
        adw::StyleManager::default().set_color_scheme(adw::ColorScheme::PreferDark);
    });
    app.connect_activate(build_ui);
    app.run()
}
