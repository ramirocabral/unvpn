//! The connection form: which fields show, loading and saving profiles,
//! certificate enrollment and the trusted-certificate pins.

use adw::prelude::*;
use gtk::{gio, glib};

use crate::form::{Choices, Field, Layout};
use crate::profiles::{Backend, BackendSlot, Profile};
use crate::{bundle, engine, profiles, App};

impl App {
    pub(crate) fn backend(&self) -> Backend {
        let b = Backend::from_index(self.backend_row.selected());
        // The "FortiClient" entry is SSL-VPN by default; the protocol selector
        // promotes it to the IPsec backend.
        if b == Backend::Forti && self.forti_proto_row.selected() == 1 {
            Backend::FortiIpsec
        } else {
            b
        }
    }

    pub(crate) fn sso(&self) -> bool {
        self.backend().has_sso() && self.sso_row.selected() == 1
    }

    /// Check Point with certificate login selected.
    pub(crate) fn cp_cert(&self) -> bool {
        self.backend() == Backend::CheckPoint && self.cp_auth_row.selected() == 1
    }

    /// What the form shows and requires for the back-end and choices picked now.
    pub(crate) fn layout(&self) -> Layout {
        let file = self.gateway_row.text();
        let file = file.trim();
        let b = self.backend();
        Layout::of(
            b,
            Choices {
                sso: self.sso_row.selected() == 1,
                cp_cert: self.cp_auth_row.selected() == 1,
                ovpn_userpass: b == Backend::OpenVpn && profiles::ovpn_needs_userpass(file),
                ovpn_keypass: b == Backend::OpenVpn && profiles::ovpn_key_may_need_pass(file),
            },
        )
    }

    pub(crate) fn update_form_visibility(&self) {
        let l = self.layout();
        self.gateway_row.set_title(l.gateway_title);
        self.browse_btn.set_visible(l.gateway_file);
        self.forti_proto_row.set_visible(l.forti_protocol);
        self.sso_row.set_visible(l.sso_choice);
        self.ua_row.set_visible(l.sso_user_agent);
        self.cp_auth_row.set_visible(l.cp_auth_choice);
        self.user_row.set_visible(l.user.shown());
        self.password_row.set_visible(l.password.shown());
        self.password_row.set_title(l.password_title);
        self.remember_row.set_visible(l.remember_password);
        self.token_row.set_visible(l.token.shown());
        self.cert_row.set_visible(l.cert.shown());
        self.enroll_row.set_visible(l.cert.shown());
        self.realm_row.set_visible(l.realm.shown());
        self.realm_row.set_title(l.realm_title);
        self.psk_row.set_visible(l.psk.shown());
        self.advanced_row.set_visible(l.advanced);
        self.key_pass_row.set_visible(l.key_pass);
        self.remember_key_pass_row.set_visible(l.key_pass);
        self.killswitch_row.set_visible(l.killswitch);
        self.no_dtls_row.set_visible(l.no_dtls);
    }

    pub(crate) fn form_ready(&self) -> bool {
        let l = self.layout();
        let gw = self.gateway_row.text();
        let gw = gw.trim();
        let gateway = if l.gateway_must_exist {
            std::path::Path::new(gw).is_file()
        } else {
            !gw.is_empty()
        };
        gateway
            && l.user.filled(self.user_row.text().trim())
            && l.password.filled(&self.password_row.text())
            && l.token.filled(self.token_row.text().trim())
            && l.cert.filled(self.cert_row.text().trim())
            && l.psk.filled(&self.psk_row.text())
    }

    pub(crate) fn pick_cert_file(&self) {
        let filter = gtk::FileFilter::new();
        filter.set_name(Some("Certificates (PKCS#12)"));
        filter.add_pattern("*.p12");
        filter.add_pattern("*.pfx");
        let filters = gio::ListStore::new::<gtk::FileFilter>();
        filters.append(&filter);
        let dialog = gtk::FileDialog::builder()
            .title("Choose the certificate file")
            .modal(true)
            .filters(&filters)
            .build();
        let app = self.rc();
        dialog.open(Some(&self.window), gio::Cancellable::NONE, move |res| {
            if let Some(path) = res.ok().and_then(|f| f.path()) {
                app.cert_row.set_text(&path.to_string_lossy());
            }
        });
    }

    /// Ask for the one-time registration key and a password for the new
    /// certificate, then enroll with the gateway's internal CA.
    pub(crate) fn open_enroll_dialog(&self) {
        let gw = self.gateway_row.text().trim().to_string();
        if gw.is_empty() {
            self.toast("Enter the gateway first");
            self.gateway_row.grab_focus();
            return;
        }
        let key_row = adw::EntryRow::builder().title("Registration key").build();
        let pass_row = adw::PasswordEntryRow::builder()
            .title("New certificate password")
            .build();
        let again_row = adw::PasswordEntryRow::builder()
            .title("Repeat the password")
            .build();
        let list = gtk::ListBox::builder()
            .css_classes(["boxed-list"])
            .selection_mode(gtk::SelectionMode::None)
            .build();
        list.append(&key_row);
        list.append(&pass_row);
        list.append(&again_row);
        let dialog = adw::AlertDialog::builder()
            .heading("Enroll a certificate")
            .body(format!(
                "Enter the registration key your administrator sent you (it looks like 12345-abcdef). \
                 It works only once. The new certificate and its private key are stored for this \
                 profile, protected by the password you choose (6 characters or more).\n\nGateway: {gw}"
            ))
            .extra_child(&list)
            .build();
        dialog.add_responses(&[("cancel", "Cancel"), ("enroll", "Enroll")]);
        dialog.set_response_appearance("enroll", adw::ResponseAppearance::Suggested);
        dialog.set_response_enabled("enroll", false);
        dialog.set_close_response("cancel");
        let validate = glib::clone!(
            #[weak]
            dialog,
            #[weak]
            key_row,
            #[weak]
            pass_row,
            #[weak]
            again_row,
            move || {
                let k = key_row.text();
                let k = k.trim();
                let ok = k.find('-').is_some_and(|i| i > 0 && i + 1 < k.len())
                    && pass_row.text().chars().count() >= 6
                    && pass_row.text() == again_row.text();
                dialog.set_response_enabled("enroll", ok);
            }
        );
        for r in [
            key_row.upcast_ref::<gtk::Editable>(),
            pass_row.upcast_ref(),
            again_row.upcast_ref(),
        ] {
            let v = validate.clone();
            r.connect_changed(move |_| v());
        }
        let app = self.rc();
        dialog.connect_response(Some("enroll"), move |_, _| {
            app.run_enroll(
                gw.clone(),
                key_row.text().trim().to_string(),
                pass_row.text().to_string(),
                false,
            );
        });
        dialog.present(Some(&self.window));
    }

    /// Where this profile's enrolled certificate goes: a stable path, so a failed
    /// attempt can be continued (the engine keeps its state next to it).
    pub(crate) fn enroll_target(&self, gw: &str) -> std::path::PathBuf {
        let name = self.name_row.text().trim().to_string();
        let base = bundle::slug(if name.is_empty() { gw } else { &name });
        let root = profiles::files_dir();
        let out = root.join(&base).join("certificate.p12");
        let pending = out.with_extension("p12.enroll").exists();
        if out.exists() && !pending {
            bundle::fresh_dir(&root, &base).join("certificate.p12")
        } else {
            out
        }
    }

    pub(crate) fn run_enroll(&self, gw: String, regkey: String, password: String, trust_ca: bool) {
        let out = self.enroll_target(&gw);
        let staging = out.with_extension("p12.enroll");
        if let Some(dir) = out.parent() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                self.toast(&format!("Couldn't create {}: {e}", dir.display()));
                return;
            }
            let _ =
                std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
        }
        let out_s = out.to_string_lossy().into_owned();
        let bin = engine::unvpn_bin();
        let mut argv: Vec<&std::ffi::OsStr> = [
            bin.as_str(),
            "cp-enroll",
            "-g",
            gw.as_str(),
            "-o",
            out_s.as_str(),
        ]
        .into_iter()
        .map(std::ffi::OsStr::new)
        .collect();
        // Continue an interrupted attempt: a stored answer is re-read on its own;
        // a request that was sent but never answered is sent again (same bytes).
        if staging.join("sent").exists() && !staging.join("response.http").exists() {
            argv.push(std::ffi::OsStr::new("--resend"));
        }
        if trust_ca {
            argv.push(std::ffi::OsStr::new("--trust-ca"));
        }
        let proc = match gio::Subprocess::newv(
            &argv,
            gio::SubprocessFlags::STDIN_PIPE
                | gio::SubprocessFlags::STDOUT_PIPE
                | gio::SubprocessFlags::STDERR_MERGE,
        ) {
            Ok(p) => p,
            Err(e) => {
                self.toast(&format!("Couldn't run the engine: {e}"));
                return;
            }
        };
        self.append_log(&format!(
            "→ enrolling a certificate with {gw} (saving to {out_s})"
        ));
        self.toast("Enrolling the certificate…");
        self.enroll_btn.set_sensitive(false);
        let input = format!("{regkey}\n{password}\n");
        let app = self.rc();
        glib::spawn_future_local(async move {
            let res = proc.communicate_utf8_future(Some(input)).await;
            let text = match &res {
                Ok((o, _)) => o.as_ref().map(|s| s.to_string()).unwrap_or_default(),
                Err(e) => format!("enrollment failed: {e}"),
            };
            for l in text.lines() {
                app.append_log(l);
            }
            app.enroll_btn.set_sensitive(true);
            let ok = res.is_ok() && proc.is_successful() && out.is_file();
            if ok {
                app.cp_auth_row.set_selected(1);
                app.cert_row.set_text(&out_s);
                app.password_row.set_text(&password);
                app.update_form_visibility();
                app.sync_ui();
                app.toast("Certificate enrolled. Save the profile to keep it.");
                return;
            }
            if text.contains("--trust-ca") && !trust_ca {
                let fp = text
                    .lines()
                    .find_map(|l| l.strip_prefix("# internal CA fingerprint: "))
                    .unwrap_or("(unknown)")
                    .to_string();
                let d = adw::AlertDialog::builder()
                    .heading("Trust this certificate authority?")
                    .body(format!(
                        "The CA could not prove it is the gateway's. Only continue if your administrator \
                         confirms this fingerprint:\n\n{fp}"
                    ))
                    .build();
                d.add_responses(&[("cancel", "Cancel"), ("trust", "Trust and continue")]);
                d.set_response_appearance("trust", adw::ResponseAppearance::Destructive);
                d.set_close_response("cancel");
                let a = app.clone();
                d.connect_response(Some("trust"), move |_, _| {
                    a.run_enroll(gw.clone(), regkey.clone(), password.clone(), true)
                });
                d.present(Some(&app.window));
                return;
            }
            let reason = text
                .lines()
                .rev()
                .find_map(|l| l.strip_prefix("enrollment failed: "))
                .unwrap_or("see the connection log")
                .to_string();
            app.toast(&format!("Enrollment failed: {reason}"));
            app.log_expander.set_expanded(true);
        });
    }

    pub(crate) fn pick_profile_file(&self) {
        let filter = gtk::FileFilter::new();
        let title = if self.backend() == Backend::WireGuard {
            filter.set_name(Some("WireGuard profiles"));
            filter.add_pattern("*.conf");
            "Choose a WireGuard profile"
        } else {
            filter.set_name(Some("OpenVPN profiles"));
            filter.add_pattern("*.ovpn");
            filter.add_pattern("*.conf");
            "Choose an OpenVPN profile"
        };
        let filters = gio::ListStore::new::<gtk::FileFilter>();
        filters.append(&filter);
        let dialog = gtk::FileDialog::builder()
            .title(title)
            .modal(true)
            .filters(&filters)
            .build();
        let app = self.rc();
        dialog.open(Some(&self.window), gio::Cancellable::NONE, move |res| {
            if let Some(path) = res.ok().and_then(|f| f.path()) {
                app.gateway_row.set_text(&path.to_string_lossy());
                if app.name_row.text().trim().is_empty() {
                    if let Some(stem) = path.file_stem() {
                        app.name_row.set_text(&stem.to_string_lossy());
                    }
                }
            }
        });
    }

    pub(crate) fn load_profile(&self, p: &Profile) {
        self.backend_row.set_selected(p.backend.index());
        self.forti_proto_row
            .set_selected(if p.backend == Backend::FortiIpsec {
                1
            } else {
                0
            });
        self.sso_row.set_selected(if p.sso { 1 } else { 0 });
        self.cp_auth_row.set_selected(if p.cp_cert { 1 } else { 0 });
        self.cert_row.set_text(&p.cert_path);
        self.name_row.set_text(&p.name);
        self.gateway_row.set_text(&p.gateway);
        self.user_row.set_text(&p.user);
        // realm_row doubles as AnyConnect's group / GlobalProtect's gateway field.
        self.realm_row.set_text(if p.backend.uses_group() {
            &p.group
        } else {
            &p.realm
        });
        // Group PSK lives in the keyring (like the password), keyed per profile.
        self.psk_row
            .set_text(&profiles::secret_get(&profiles::psk_account(&p.name)).unwrap_or_default());
        self.ua_row.set_text(&p.sso_user_agent);
        self.emssn_row.set_text(&p.emssn);
        self.fctver_row.set_text(&p.fctver);
        self.remember_row.set_active(p.remember_password);
        self.killswitch_row.set_active(p.killswitch);
        self.no_dtls_row.set_active(p.no_dtls);
        self.token_row.set_text("");
        let secret = if p.remember_password {
            profiles::secret_get(&p.name).unwrap_or_default()
        } else {
            String::new()
        };
        self.password_row.set_text(&secret);
        let key_pass = if p.remember_key_pass {
            profiles::secret_get(&profiles::keypass_account(&p.name)).unwrap_or_default()
        } else {
            String::new()
        };
        self.key_pass_row.set_text(&key_pass);
        self.remember_key_pass_row.set_active(p.remember_key_pass);
        self.update_form_visibility();
        self.update_pins_row();
        self.sync_ui();
    }

    /// The connection the form describes: what Save stores, minus the keyring flags.
    pub(crate) fn form_profile(&self) -> Profile {
        let backend = self.backend();
        let l = self.layout();
        let realm_field = self.realm_row.text().trim().to_string();
        let name = self.name_row.text().trim().to_string();
        Profile {
            pins: self
                .profiles
                .borrow()
                .iter()
                .find(|p| p.name == name)
                .map(|p| p.pins.clone())
                .unwrap_or_default(),
            name,
            backend,
            gateway: self.gateway_row.text().trim().to_string(),
            user: self.user_row.text().trim().to_string(),
            // realm_row doubles as AnyConnect's group / GlobalProtect's gateway field.
            realm: if backend.uses_group() {
                String::new()
            } else {
                realm_field.clone()
            },
            group: if backend.uses_group() {
                realm_field
            } else {
                String::new()
            },
            sso: self.sso(),
            remember_password: false,
            remember_key_pass: false,
            sso_user_agent: self.ua_row.text().trim().to_string(),
            emssn: self.emssn_row.text().trim().to_string(),
            fctver: self.fctver_row.text().trim().to_string(),
            killswitch: l.killswitch && self.killswitch_row.is_active(),
            no_dtls: l.no_dtls && self.no_dtls_row.is_active(),
            cp_cert: self.cp_cert(),
            cert_path: if l.cert.shown() {
                self.cert_row.text().trim().to_string()
            } else {
                String::new()
            },
        }
    }

    pub(crate) fn save_profile(&self) {
        let name = self.name_row.text().trim().to_string();
        if name.is_empty() {
            self.toast("Enter a name to save the profile");
            self.name_row.grab_focus();
            return;
        }
        let creds_in_play = !self.sso();
        let remember = self.remember_row.is_active() && creds_in_play;
        let backend = self.backend();
        let key_pass = if self.key_pass_row.is_visible() && self.remember_key_pass_row.is_active() {
            self.key_pass_row.text().to_string()
        } else {
            String::new()
        };
        let key_account = profiles::keypass_account(&name);
        let remember_key_pass =
            !key_pass.is_empty() && profiles::secret_set(&key_account, &key_pass);
        if !remember_key_pass {
            if !key_pass.is_empty() {
                self.toast("Couldn't save the key passphrase to the keyring");
            }
            profiles::secret_delete(&key_account);
        }
        let p = Profile {
            remember_password: remember,
            remember_key_pass,
            ..self.form_profile()
        };

        let pw = self.password_row.text().to_string();
        if remember && !pw.is_empty() {
            if !profiles::secret_set(&name, &pw) {
                self.toast("Couldn't save to the keyring (is a Secret Service running?)");
            }
        } else {
            profiles::secret_delete(&name);
        }

        // Group PSK (FortiClient IPsec only): keep it in the keyring, keyed per
        // profile; it is config-like (shared across users) so it is always stored
        // when present, with no separate "remember" toggle.
        let psk_account = profiles::psk_account(&name);
        let psk = self.psk_row.text().to_string();
        if backend == Backend::FortiIpsec && !psk.is_empty() {
            if !profiles::secret_set(&psk_account, &psk) {
                self.toast("Couldn't save the group PSK to the keyring");
            }
        } else {
            profiles::secret_delete(&psk_account);
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
        self.update_pins_row();
        self.toast(&format!("Saved profile “{name}”"));
    }

    /// Show the saved profile's trusted gateway certificates, if any.
    pub(crate) fn update_pins_row(&self) {
        let name = self.name_row.text().trim().to_string();
        let pins: Vec<String> = self
            .profiles
            .borrow()
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.pins.keys().cloned().collect())
            .unwrap_or_default();
        self.pins_row.set_visible(!pins.is_empty());
        self.pins_row.set_subtitle(&pins.join(", "));
    }

    /// Drop the saved profile's trusted certificates: the next connect asks again.
    pub(crate) fn forget_pins(&self) {
        let name = self.name_row.text().trim().to_string();
        {
            let mut profs = self.profiles.borrow_mut();
            let Some(p) = profs.iter_mut().find(|p| p.name == name) else {
                return;
            };
            p.pins.clear();
            if let Err(e) = profiles::save(&profs) {
                drop(profs);
                self.toast(&format!("Couldn't save: {e}"));
                return;
            }
        }
        self.update_pins_row();
        self.toast(&format!(
            "“{name}” will ask again about the gateway's certificate"
        ));
    }

    /// Keep a certificate the user trusted with the profile being connected.
    pub(crate) fn remember_pin(&self, q: &profiles::TrustQuestion) {
        let name = self.active_profile.lock().unwrap().clone();
        {
            let mut profs = self.profiles.borrow_mut();
            let Some(p) = profs.iter_mut().find(|p| p.name == name) else {
                drop(profs);
                self.session_pins
                    .borrow_mut()
                    .insert(q.endpoint.clone(), q.fingerprint.clone());
                self.append_log("→ certificate trusted until unvpn quits (a saved profile for this gateway keeps it)");
                return;
            };
            p.pins.insert(q.endpoint.clone(), q.fingerprint.clone());
            if let Err(e) = profiles::save(&profs) {
                drop(profs);
                self.toast(&format!("Couldn't save: {e}"));
                return;
            }
        }
        self.append_log(&format!(
            "→ certificate of {} trusted and saved with “{name}”",
            q.endpoint
        ));
        self.update_pins_row();
    }

    pub(crate) fn on_new_profile(&self) {
        self.name_row.set_text("");
        self.gateway_row.set_text("");
        self.user_row.set_text("");
        self.password_row.set_text("");
        self.key_pass_row.set_text("");
        self.remember_key_pass_row.set_active(false);
        self.realm_row.set_text("");
        self.psk_row.set_text("");
        self.ua_row.set_text("");
        self.emssn_row.set_text("");
        self.fctver_row.set_text("");
        self.token_row.set_text("");
        self.cert_row.set_text("");
        self.cp_auth_row.set_selected(0);
        self.remember_row.set_active(false);
        self.killswitch_row.set_active(false);
        self.no_dtls_row.set_active(false);
        self.update_form_visibility();
        self.sync_ui();
        self.name_row.grab_focus();
    }

    pub(crate) fn focus_missing_field(&self) {
        let l = self.layout();
        let rows: [(&gtk::Widget, Field); 5] = [
            (self.cert_row.upcast_ref(), l.cert),
            (self.user_row.upcast_ref(), l.user),
            (self.password_row.upcast_ref(), l.password),
            (self.token_row.upcast_ref(), l.token),
            (self.psk_row.upcast_ref(), l.psk),
        ];
        if let Some((w, _)) = rows
            .into_iter()
            .find(|(w, f)| !f.filled(self.editable_text(w).trim()))
        {
            w.grab_focus();
        }
    }

    pub(crate) fn editable_text(&self, w: &gtk::Widget) -> String {
        w.downcast_ref::<gtk::Editable>()
            .map(|e| e.text().to_string())
            .unwrap_or_default()
    }
}
