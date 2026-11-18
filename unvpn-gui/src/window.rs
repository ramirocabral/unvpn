//! Building the window and wiring its widgets to the app.

use std::cell::{Cell, RefCell};
use std::rc::{Rc, Weak};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use adw::prelude::*;
use gtk::{gio, glib};

use crate::engine::{Tx, UiMsg};
use crate::profiles::Backend;
use crate::{profiles, tray, App};

impl App {
    pub(crate) fn new(app: &adw::Application, tx: Tx) -> Rc<Self> {
        let status_pill = gtk::Label::builder()
            .css_classes(["statuspill", "st-off"])
            .build();
        let header = adw::HeaderBar::new();
        header.pack_start(&status_pill);

        let menu = gio::Menu::new();
        menu.append(Some("Export Profiles…"), Some("app.export"));
        menu.append(Some("Import Profiles…"), Some("app.import"));
        menu.append(Some("About unvpn"), Some("app.about"));
        menu.append(Some("Quit"), Some("app.quit"));
        let menu_btn = gtk::MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .menu_model(&menu)
            .tooltip_text("Menu")
            .build();
        header.pack_end(&menu_btn);

        let search_btn = gtk::ToggleButton::builder()
            .icon_name("system-search-symbolic")
            .tooltip_text("Search profiles (Ctrl+F)")
            .css_classes(["flat"])
            .build();
        let search_entry = gtk::SearchEntry::builder()
            .placeholder_text("Search profiles")
            .hexpand(true)
            .build();
        let search_bar = gtk::SearchBar::builder()
            .child(
                &adw::Clamp::builder()
                    .maximum_size(536)
                    .child(&search_entry)
                    .build(),
            )
            .build();
        search_bar.connect_entry(&search_entry);
        search_btn
            .bind_property("active", &search_bar, "search-mode-enabled")
            .bidirectional()
            .sync_create()
            .build();

        let add_btn = gtk::Button::builder()
            .icon_name("list-add-symbolic")
            .css_classes(["flat"])
            .tooltip_text("New profile")
            .build();
        let profiles_group = adw::PreferencesGroup::builder().title("Profiles").build();
        let list_btns = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        list_btns.append(&search_btn);
        list_btns.append(&add_btn);
        profiles_group.set_header_suffix(Some(&list_btns));
        let profiles_empty_row = adw::ActionRow::builder()
            .sensitive(false)
            .visible(false)
            .build();
        profiles_group.add(&profiles_empty_row);

        let name_row = adw::EntryRow::builder().title("Profile name").build();

        let backend_model = gtk::StringList::new(&[
            "Check Point",
            "FortiClient",
            "F5",
            "AnyConnect (Cisco)",
            "GlobalProtect",
            "Ivanti Connect Secure",
            "OpenVPN",
            "WireGuard",
        ]);
        let backend_row = adw::ComboRow::builder()
            .title("VPN client")
            .model(&backend_model)
            .build();
        // FortiClient speaks two unrelated protocols; one dropdown entry, this
        // selector picks SSL-VPN vs IPsec (shown only for FortiClient).
        let forti_proto_model = gtk::StringList::new(&["SSL-VPN", "IPsec"]);
        let forti_proto_row = adw::ComboRow::builder().model(&forti_proto_model).build();
        forti_proto_row.set_title("Protocol");

        let gateway_row = adw::EntryRow::builder().title("Gateway").build();
        let browse_btn = gtk::Button::builder()
            .icon_name("document-open-symbolic")
            .tooltip_text("Choose the profile file")
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build();
        gateway_row.add_suffix(&browse_btn);
        let user_row = adw::EntryRow::builder().title("User").build();
        let password_row = adw::PasswordEntryRow::builder().title("Password").build();
        let key_pass_row = adw::PasswordEntryRow::builder()
            .title("Key passphrase (optional)")
            .build();
        let remember_key_pass_row = adw::SwitchRow::builder()
            .title("Remember passphrase")
            .subtitle("Store in the system keyring")
            .subtitle_lines(0)
            .build();

        let token_row = adw::EntryRow::builder()
            .title("Token code (optional)")
            .build();

        let cp_auth_model = gtk::StringList::new(&["Password / token", "Certificate"]);
        let cp_auth_row = adw::ComboRow::builder()
            .title("Authentication")
            .model(&cp_auth_model)
            .build();
        let cert_row = adw::EntryRow::builder()
            .title("Certificate file (.p12)")
            .build();
        let cert_browse_btn = gtk::Button::builder()
            .icon_name("document-open-symbolic")
            .tooltip_text("Choose the certificate file")
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build();
        cert_row.add_suffix(&cert_browse_btn);
        let enroll_btn = gtk::Button::builder()
            .label("Enroll…")
            .valign(gtk::Align::Center)
            .build();
        let enroll_row = adw::ActionRow::builder()
            .title("No certificate yet?")
            .subtitle("Get one with the registration key from your administrator")
            .subtitle_lines(0)
            .build();
        enroll_row.add_suffix(&enroll_btn);

        let auth_model = gtk::StringList::new(&["Password", "SSO / SAML"]);
        let sso_row = adw::ComboRow::builder()
            .title("Authentication")
            .model(&auth_model)
            .build();
        let realm_row = adw::EntryRow::builder().title("Realm (optional)").build();
        // FortiClient IPsec pre-shared key. Mirrors the official client, where the
        // pre-shared key is a required credential (the user auth — EAP + OTP — rides
        // on top). We also use it to verify the gateway's AUTH.
        let psk_row = adw::PasswordEntryRow::new();
        psk_row.set_title("Pre-shared key");
        let ua_row = adw::EntryRow::builder()
            .title("SSO User-Agent (optional)")
            .build();

        // FortiClient IPsec advanced settings, collapsed by default so the form isn't
        // cluttered. Deployment-specific values that most profiles leave blank.
        let emssn_row = adw::EntryRow::builder()
            .title("EMS serial (optional)")
            .build();
        let fctver_row = adw::EntryRow::builder()
            .title("FortiClient version (optional)")
            .build();
        let advanced_row = adw::ExpanderRow::builder()
            .title("Advanced")
            .subtitle("EMS serial, FortiClient version")
            .subtitle_lines(0)
            .build();
        advanced_row.add_row(&emssn_row);
        advanced_row.add_row(&fctver_row);

        let remember_row = adw::SwitchRow::builder()
            .title("Remember password")
            .subtitle("Store in the system keyring")
            .subtitle_lines(0)
            .build();

        let killswitch_row = adw::SwitchRow::builder()
            .title("Kill switch")
            .subtitle(
                "Block all traffic outside the tunnel if it drops (LAN and DHCP stay reachable)",
            )
            .subtitle_lines(0)
            .build();

        let no_dtls_row = adw::SwitchRow::builder()
            .title("Disable DTLS")
            .subtitle("Force the data channel over TLS (TCP). Turn on when the tunnel connects but no traffic flows (the network drops UDP 443)")
            .subtitle_lines(0)
            .build();

        let forget_pins_btn = gtk::Button::builder()
            .label("Forget")
            .valign(gtk::Align::Center)
            .build();
        let pins_row = adw::ActionRow::builder()
            .title("Trusted certificates")
            .subtitle_lines(0)
            .visible(false)
            .build();
        pins_row.add_suffix(&forget_pins_btn);

        let save_btn = gtk::Button::builder()
            .label("Save")
            .css_classes(["flat"])
            .build();
        let form_group = adw::PreferencesGroup::builder().title("Connection").build();
        form_group.set_header_suffix(Some(&save_btn));
        form_group.add(&name_row);
        form_group.add(&backend_row);
        form_group.add(&forti_proto_row);
        form_group.add(&sso_row);
        form_group.add(&cp_auth_row);
        form_group.add(&gateway_row);
        form_group.add(&realm_row);
        form_group.add(&cert_row);
        form_group.add(&enroll_row);
        form_group.add(&psk_row);
        form_group.add(&ua_row);
        form_group.add(&user_row);
        form_group.add(&password_row);
        form_group.add(&key_pass_row);
        form_group.add(&remember_key_pass_row);
        form_group.add(&token_row);
        form_group.add(&remember_row);
        form_group.add(&killswitch_row);
        form_group.add(&no_dtls_row);
        form_group.add(&advanced_row);
        form_group.add(&pins_row);

        let connect_btn = gtk::Button::builder()
            .label("Connect")
            .css_classes(["suggested-action", "pill"])
            .hexpand(true)
            .margin_top(4)
            .build();
        connect_btn.set_height_request(40);

        let sessions_group = adw::PreferencesGroup::builder()
            .title("Active connection")
            .visible(false)
            .build();

        let prompt_group = adw::PreferencesGroup::builder().visible(false).build();

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

        let main_content = page_content(&[
            prompt_group.upcast_ref(),
            sessions_group.upcast_ref(),
            profiles_group.upcast_ref(),
            diag_group.upcast_ref(),
        ]);
        let editor_content = page_content(&[form_group.upcast_ref(), connect_btn.upcast_ref()]);

        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&header);
        toolbar.add_top_bar(&search_bar);
        // A profiles file that doesn't load is moved aside rather than replaced
        // by the next save; say so, and where it went.
        let loaded =
            profiles::load().map_err(|e| match profiles::set_aside(&profiles::profiles_path()) {
                Ok(bad) => format!(
                    "Saved profiles couldn't be read and were moved to {} ({e})",
                    bad.display()
                ),
                Err(e2) => {
                    format!("Saved profiles couldn't be read ({e}); saving is disabled ({e2})")
                }
            });
        if let Err(msg) = &loaded {
            let banner = adw::Banner::builder()
                .title(msg.as_str())
                .button_label("Dismiss")
                .revealed(true)
                .build();
            banner.connect_button_clicked(|b| b.set_revealed(false));
            toolbar.add_top_bar(&banner);
        }
        toolbar.set_content(Some(&main_content));
        let main_page = adw::NavigationPage::builder()
            .title("unvpn")
            .tag("main")
            .child(&toolbar)
            .build();
        search_bar.set_key_capture_widget(Some(&main_page));

        let editor_toolbar = adw::ToolbarView::new();
        editor_toolbar.add_top_bar(&adw::HeaderBar::new());
        editor_toolbar.set_content(Some(&editor_content));
        let editor_page = adw::NavigationPage::builder()
            .tag("editor")
            .child(&editor_toolbar)
            .build();

        let nav = adw::NavigationView::new();
        nav.add(&main_page);
        nav.add(&editor_page);
        let toast = adw::ToastOverlay::new();
        toast.set_child(Some(&nav));

        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title("unvpn")
            .default_width(600)
            .default_height(840)
            .content(&toast)
            .build();
        window.set_size_request(360, 480);

        let this = Rc::new(App {
            window,
            toast,
            status_pill,
            nav,
            editor_page,
            search_bar,
            search_entry,
            profiles_group,
            profiles_empty_row,
            profile_rows: RefCell::new(Vec::new()),
            profile_buttons: RefCell::new(Vec::new()),
            profiles: RefCell::new(loaded.unwrap_or_default()),
            name_row,
            backend_row,
            forti_proto_row,
            gateway_row,
            browse_btn,
            user_row,
            password_row,
            key_pass_row,
            remember_key_pass_row,
            token_row,
            cp_auth_row,
            cert_row,
            cert_browse_btn,
            enroll_row,
            enroll_btn,
            realm_row,
            psk_row,
            ua_row,
            advanced_row,
            emssn_row,
            fctver_row,
            sso_row,
            remember_row,
            killswitch_row,
            no_dtls_row,
            pins_row,
            save_btn,
            connect_btn,
            sessions_group,
            sessions: RefCell::new(Vec::new()),
            next_session: Cell::new(1),
            ended: RefCell::new(Vec::new()),
            failed: Cell::new(false),
            prompt_group,
            prompt_rows: RefCell::new(Vec::new()),
            prompt_session: Cell::new(None),
            #[cfg(feature = "webview")]
            sso_windows: RefCell::new(Vec::new()),
            log_buffer,
            log_view,
            log_expander,
            tray: RefCell::new(None),
            tray_view: Arc::new(Mutex::new(Default::default())),
            tx,
            session_pins: RefCell::new(Default::default()),
            quitting: Cell::new(false),
            me: RefCell::new(Weak::new()),
        });
        *this.me.borrow_mut() = Rc::downgrade(&this);

        Self::wire(&this, &add_btn, &forget_pins_btn);
        this.refresh_profiles_list();
        this.update_form_visibility();
        this.sync_ui();
        this
    }

    pub(crate) fn wire(app: &Rc<Self>, add_btn: &gtk::Button, forget_pins: &gtk::Button) {
        app.backend_row.connect_selected_notify(glib::clone!(
            #[strong]
            app,
            move |_| {
                app.update_form_visibility();
                app.sync_ui();
            }
        ));
        app.sso_row.connect_selected_notify(glib::clone!(
            #[strong]
            app,
            move |_| {
                app.update_form_visibility();
                app.sync_ui();
            }
        ));
        app.forti_proto_row.connect_selected_notify(glib::clone!(
            #[strong]
            app,
            move |_| {
                app.update_form_visibility();
                app.sync_ui();
            }
        ));
        app.cp_auth_row.connect_selected_notify(glib::clone!(
            #[strong]
            app,
            move |_| {
                app.update_form_visibility();
                app.sync_ui();
            }
        ));
        app.cert_row.connect_changed(glib::clone!(
            #[strong]
            app,
            move |_| app.sync_ui()
        ));
        app.cert_browse_btn.connect_clicked(glib::clone!(
            #[strong]
            app,
            move |_| app.pick_cert_file()
        ));
        app.enroll_btn.connect_clicked(glib::clone!(
            #[strong]
            app,
            move |_| app.open_enroll_dialog()
        ));

        app.gateway_row.connect_changed(glib::clone!(
            #[strong]
            app,
            move |_| {
                if app.backend() == Backend::OpenVpn {
                    app.update_form_visibility(); // auth-user-pass decides the credential rows
                }
                app.sync_ui();
            }
        ));
        app.browse_btn.connect_clicked(glib::clone!(
            #[strong]
            app,
            move |_| app.pick_profile_file()
        ));
        app.user_row.connect_changed(glib::clone!(
            #[strong]
            app,
            move |_| app.sync_ui()
        ));
        app.token_row.connect_changed(glib::clone!(
            #[strong]
            app,
            move |_| app.sync_ui()
        ));
        app.password_row.connect_changed(glib::clone!(
            #[strong]
            app,
            move |_| app.sync_ui()
        ));
        app.psk_row.connect_changed(glib::clone!(
            #[strong]
            app,
            move |_| app.sync_ui()
        ));

        app.name_row.connect_changed(glib::clone!(
            #[strong]
            app,
            move |_| app.update_pins_row()
        ));
        forget_pins.connect_clicked(glib::clone!(
            #[strong]
            app,
            move |_| app.forget_pins()
        ));

        app.connect_btn.connect_clicked(glib::clone!(
            #[strong]
            app,
            move |_| app.on_connect_clicked()
        ));
        app.save_btn.connect_clicked(glib::clone!(
            #[strong]
            app,
            move |_| app.save_profile()
        ));
        add_btn.connect_clicked(glib::clone!(
            #[strong]
            app,
            move |_| app.on_new_profile()
        ));
        app.search_entry.connect_search_changed(glib::clone!(
            #[strong]
            app,
            move |_| app.apply_profile_filter()
        ));
        let search = gio::SimpleAction::new("search", None);
        search.connect_activate(glib::clone!(
            #[strong]
            app,
            move |_, _| {
                app.show_main();
                app.search_bar.set_search_mode(true);
            }
        ));
        app.window.add_action(&search);
        if let Some(a) = app.window.application() {
            a.set_accels_for_action("win.search", &["<Control>f"]);
        }

        // Closing the window keeps the app (and the tunnel) running in the tray; only
        // "Quit" exits. Without a tray, closing quits (the window would be unreachable).
        app.window.connect_close_request(glib::clone!(
            #[strong]
            app,
            move |_| {
                if app.quitting.get() {
                    app.shutdown();
                    return glib::Propagation::Proceed;
                }
                if app.tray.borrow().is_some() {
                    app.window.set_visible(false);
                    return glib::Propagation::Stop;
                }
                app.shutdown();
                glib::Propagation::Proceed
            }
        ));
    }

    pub(crate) fn rc(&self) -> Rc<App> {
        self.me
            .borrow()
            .upgrade()
            .expect("App dropped while a handler ran")
    }

    /// Show the connection form, titled `title`.
    pub(crate) fn open_editor(&self, title: &str) {
        self.editor_page.set_title(title);
        if self.nav.visible_page().as_ref() != Some(&self.editor_page) {
            self.nav.push(&self.editor_page);
        }
    }

    /// Back to the profile list.
    pub(crate) fn show_main(&self) {
        self.nav.pop_to_tag("main");
    }
}

/// A page's scrolling body: `children` stacked, at a readable width.
fn page_content(children: &[&gtk::Widget]) -> gtk::ScrolledWindow {
    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(12)
        .margin_end(12)
        .build();
    for c in children {
        content.append(*c);
    }
    let clamp = adw::Clamp::builder()
        .maximum_size(560)
        .child(&content)
        .build();
    gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&clamp)
        .build()
}

thread_local! {
    static UI: RefCell<Option<Rc<App>>> = const { RefCell::new(None) };
}

/// The app's single window and state, built on first use. Launching again (e.g.
/// from the app launcher while it sits in the tray) brings the window back unless
/// `start_hidden`.
pub(crate) fn build_ui(app: &adw::Application, start_hidden: bool) -> Rc<App> {
    if let Some(existing) = UI.with(|u| u.borrow().clone()) {
        if !start_hidden {
            existing.show_window();
        }
        return existing;
    }
    let (tx, rx) = async_channel::unbounded::<UiMsg>();
    let state_app = App::new(app, tx);
    UI.with(|u| *u.borrow_mut() = Some(state_app.clone()));

    let about = gio::SimpleAction::new("about", None);
    about.connect_activate(glib::clone!(#[strong] state_app, move |_, _| {
        let dialog = adw::AboutDialog::builder()
            .application_name("unvpn")
            .version(env!("CARGO_PKG_VERSION"))
            .developer_name("unvpn")
            .comments("Native Linux VPN client — Check Point · Fortinet · F5 · AnyConnect · GlobalProtect · Ivanti · OpenVPN · WireGuard")
            .build();
        dialog.present(Some(&state_app.window));
    }));
    let quit = gio::SimpleAction::new("quit", None);
    quit.connect_activate(glib::clone!(
        #[strong]
        state_app,
        move |_, _| state_app.request_quit()
    ));
    let export = gio::SimpleAction::new("export", None);
    export.connect_activate(glib::clone!(
        #[strong]
        state_app,
        move |_, _| state_app.export_profiles()
    ));
    let import = gio::SimpleAction::new("import", None);
    import.connect_activate(glib::clone!(
        #[strong]
        state_app,
        move |_, _| state_app.import_profiles()
    ));
    // Used by notifications: open the window, connect a saved profile.
    let show = gio::SimpleAction::new("show", None);
    show.connect_activate(glib::clone!(
        #[strong]
        state_app,
        move |_, _| state_app.show_window()
    ));
    let connect = gio::SimpleAction::new("connect-profile", Some(glib::VariantTy::STRING));
    connect.connect_activate(glib::clone!(
        #[strong]
        state_app,
        move |_, v| {
            if let Some(name) = v.and_then(|v| v.get::<String>()) {
                state_app.connect_profile(&name, true);
            }
        }
    ));
    app.add_action(&about);
    app.add_action(&quit);
    app.add_action(&export);
    app.add_action(&import);
    app.add_action(&show);
    app.add_action(&connect);

    glib::spawn_future_local(glib::clone!(
        #[strong]
        state_app,
        async move {
            while let Ok(msg) = rx.recv().await {
                state_app.handle_msg(msg);
            }
        }
    ));

    glib::timeout_add_local(
        Duration::from_millis(800),
        glib::clone!(
            #[strong]
            state_app,
            move || {
                state_app.tick();
                glib::ControlFlow::Continue
            }
        ),
    );

    if !start_hidden {
        state_app.init_tray();
        state_app.window.present();
        return state_app;
    }
    // `--tray` (autostart): stay in the tray until picked. At login the bar hosting
    // the tray may come up after us, so wait for it before falling back to a window.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let wait_tray = glib::clone!(
        #[strong]
        state_app,
        move || {
            if !tray::tray_available() && std::time::Instant::now() < deadline {
                return glib::ControlFlow::Continue;
            }
            state_app.init_tray();
            if state_app.tray.borrow().is_none() {
                state_app.window.present();
            }
            glib::ControlFlow::Break
        }
    );
    if tray::tray_available() {
        wait_tray();
    } else {
        glib::timeout_add_local(Duration::from_millis(500), wait_tray);
    }
    state_app
}
