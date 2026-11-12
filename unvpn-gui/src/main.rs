//! unvpn-gui — GTK4 / libadwaita front-end with a system-tray icon. Passwords are
//! kept in the system keyring (Secret Service); 2FA tokens are single-use and
//! always asked for.
//!
//! The GUI runs as the user and drives the privileged `unvpn` engine as a
//! subprocess (see `engine.rs`).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod bundle;
mod controller;
mod editor;
mod engine;
mod form;
mod icon;
mod list;
mod notify;
mod profiles;
mod prompts;
mod session;
#[cfg(feature = "webview")]
mod sso;
mod status;
mod tray;
mod window;

use std::cell::{Cell, RefCell};
use std::rc::Weak;
use std::sync::{Arc, Mutex};

use adw::prelude::*;
use gtk::{gdk, gio, glib};

use engine::{SessionId, Tx};
use profiles::Profile;
use session::Session;

const APP_ID: &str = "io.github.unvpn.Client";

const CSS: &str = "
.statuspill { font-weight: bold; }
.st-on  { color: #2ec27e; }
.st-off { color: #9a9fab; }
.st-busy{ color: #e5a50a; }
.st-err { color: #e01b24; }
row.drop-above { box-shadow: inset 0 2px @accent_color; }
row.drop-below { box-shadow: inset 0 -2px @accent_color; }
row.dragging { opacity: 0.5; }
";

struct App {
    window: adw::ApplicationWindow,
    toast: adw::ToastOverlay,

    status_pill: gtk::Label,

    profiles_group: adw::PreferencesGroup,
    profile_rows: RefCell<Vec<adw::ActionRow>>,
    /// Each saved profile's connect/disconnect button.
    profile_buttons: RefCell<Vec<(String, gtk::Button)>>,
    profiles: RefCell<Vec<Profile>>,

    name_row: adw::EntryRow,
    backend_row: adw::ComboRow,
    forti_proto_row: adw::ComboRow,
    gateway_row: adw::EntryRow,
    browse_btn: gtk::Button,
    user_row: adw::EntryRow,
    password_row: adw::PasswordEntryRow,
    key_pass_row: adw::PasswordEntryRow,
    remember_key_pass_row: adw::SwitchRow,
    token_row: adw::EntryRow,
    /// Check Point: SecurID token or certificate login.
    cp_auth_row: adw::ComboRow,
    cert_row: adw::EntryRow,
    cert_browse_btn: gtk::Button,
    enroll_row: adw::ActionRow,
    enroll_btn: gtk::Button,
    realm_row: adw::EntryRow,
    psk_row: adw::PasswordEntryRow,
    ua_row: adw::EntryRow,
    // FortiClient IPsec "advanced" fields, tucked into a collapsible expander so the
    // common form stays short.
    advanced_row: adw::ExpanderRow,
    emssn_row: adw::EntryRow,
    fctver_row: adw::EntryRow,
    sso_row: adw::ComboRow,
    remember_row: adw::SwitchRow,
    killswitch_row: adw::SwitchRow,
    no_dtls_row: adw::SwitchRow,
    /// The gateway certificates the saved profile trusts, with a button to forget them.
    pins_row: adw::ActionRow,
    save_btn: gtk::Button,

    connect_btn: gtk::Button,

    /// One row per running connection.
    sessions_group: adw::PreferencesGroup,
    sessions: RefCell<Vec<Session>>,
    next_session: Cell<SessionId>,
    /// Ids and names of the connections that ended last.
    ended: RefCell<Vec<(SessionId, String)>>,
    /// The last connection to end failed (the header shows it until the next one).
    failed: Cell<bool>,

    prompt_group: adw::PreferencesGroup,
    prompt_rows: RefCell<Vec<gtk::Widget>>,
    /// The connection whose question the prompt card shows.
    prompt_session: Cell<Option<SessionId>>,
    #[cfg(feature = "webview")]
    sso_windows: RefCell<Vec<(SessionId, adw::Window)>>,

    log_buffer: gtk::TextBuffer,
    log_view: gtk::TextView,
    log_expander: adw::ExpanderRow,

    tray: RefCell<Option<ksni::blocking::Handle<tray::VpnTray>>>,
    /// What the tray shows. Shared with the tray thread.
    tray_view: Arc<Mutex<tray::TrayView>>,
    tx: Tx,
    /// Gateway certificates trusted in this run for connections without a saved
    /// profile (an unsaved form, an F5 link from the browser): endpoint → fingerprint.
    session_pins: RefCell<std::collections::BTreeMap<String, String>>,
    /// Set only when the user really quits (tray/menu "Quit"); otherwise closing the
    /// window just hides it to the tray (the tunnel keeps running).
    quitting: Cell<bool>,
    /// Self-reference, so `&self` handlers can clone the owning `Rc` into callbacks.
    me: RefCell<Weak<App>>,
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
        let path = args.get(2).map(String::as_str).unwrap_or("/tmp/unvpn.raw");
        let size: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(256);
        std::fs::write(path, icon::app_icon_rgba(size)).expect("write raw");
        eprintln!("wrote {path} ({size}x{size} rgba)");
        return glib::ExitCode::SUCCESS;
    }

    // Handled by the running instance (a second launch forwards its arguments):
    //   --tray               start in the tray
    //   --f5-launch <url>    connect an F5 webtop handoff link (the f5-vpn:// handler)
    let app = adw::Application::builder()
        .application_id(APP_ID)
        .flags(gio::ApplicationFlags::HANDLES_COMMAND_LINE)
        .build();
    app.connect_startup(|_| {
        install_css();
        gtk::Window::set_default_icon_name("unvpn");
        // Sway doesn't report a system colour-scheme to libadwaita, so it would fall
        // back to light. Default to dark (the expected look for this utility); users
        // on a light desktop can still override via the usual GTK settings.
        adw::StyleManager::default().set_color_scheme(adw::ColorScheme::PreferDark);
    });
    app.connect_activate(|app| {
        window::build_ui(app, false);
    });
    app.connect_command_line(|app, cmd| {
        let args: Vec<String> = cmd
            .arguments()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let launch = args
            .iter()
            .position(|a| a == "--f5-launch")
            .and_then(|i| args.get(i + 1))
            .cloned();
        let hidden = launch.is_some() || args.iter().any(|a| a == "--tray");
        let ui = window::build_ui(app, hidden);
        if let Some(url) = launch {
            ui.launch_f5(&url);
        }
        glib::ExitCode::SUCCESS
    });
    app.run_with_args(&args)
}
