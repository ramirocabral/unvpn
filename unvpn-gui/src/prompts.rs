//! Cards that ask for what the engine needs mid-connection (codes,
//! certificate trust, SSO) and the embedded SSO window.

use std::rc::Rc;

use adw::prelude::*;

use crate::engine::{AuthPrompt, SessionId, SsoWatch, State};
use crate::profiles::Backend;
#[cfg(feature = "webview")]
use crate::sso;
use crate::{profiles, App};

impl App {
    /// Show the SAML login in the embedded browser; when it reaches the final page,
    /// pipe the token cookie to the engine's pending `sso` prompt — no copy/paste.
    #[cfg(feature = "webview")]
    pub(crate) fn open_sso_window(
        &self,
        id: SessionId,
        login: &str,
        watch: &SsoWatch,
        user_agent: Option<&str>,
    ) {
        self.close_sso_window(id);
        // Fortinet's loopback flow has no token for us to hand back — the engine's
        // own listener takes it. The window only hosts the login; don't answer a
        // prompt (there is none), just let the tunnel come up.
        let loopback = matches!(watch, SsoWatch::Loopback);
        let app = self.rc();
        let win = sso::open(&self.window, login, watch, user_agent, move |r| {
            app.sso_windows.borrow_mut().retain(|(i, _)| *i != id);
            if app.session_state(id) != Some(State::Connecting) {
                return; // aborted meanwhile
            }
            match r {
                Ok(_) if loopback => app.session_log(id, "→ signed in — bringing up the tunnel…"),
                Ok(token) => {
                    app.answer(id, &token);
                    app.session_log(id, "→ SSO token captured from the sign-in window");
                    app.clear_prompt_of(id);
                }
                // Leave the prompt card up: the token can still be pasted by hand.
                Err(e) => app.session_log(id, &format!("SSO: {e} — paste the token or Disconnect")),
            }
        });
        self.sso_windows.borrow_mut().push((id, win));
        self.session_log(id, "SSO: sign in in the window that opened");
    }

    #[cfg(not(feature = "webview"))]
    pub(crate) fn open_sso_window(
        &self,
        _id: SessionId,
        login: &str,
        _watch: &SsoWatch,
        _user_agent: Option<&str>,
    ) {
        let _ = std::process::Command::new("xdg-open").arg(login).spawn();
    }

    /// Close connection `id`'s SSO window, if any, without answering the engine.
    pub(crate) fn close_sso_window(&self, id: SessionId) {
        // Take it first: closing runs the window's callback, which touches the list.
        #[cfg(feature = "webview")]
        let w = {
            let mut ws = self.sso_windows.borrow_mut();
            ws.iter()
                .position(|(i, _)| *i == id)
                .map(|i| ws.remove(i).1)
        };
        #[cfg(feature = "webview")]
        if let Some(w) = w {
            w.close();
        }
        #[cfg(not(feature = "webview"))]
        let _ = id;
    }

    pub(crate) fn sso_window_open(&self, id: SessionId) -> bool {
        #[cfg(feature = "webview")]
        return self.sso_windows.borrow().iter().any(|(i, _)| *i == id);
        #[cfg(not(feature = "webview"))]
        {
            let _ = id;
            false
        }
    }

    /// Send one line to connection `id`'s engine, answering its pending question.
    pub(crate) fn answer(&self, id: SessionId, line: &str) {
        self.with_session(id, |s| s.vpn.answer_prompt(line));
    }

    /// Ask what connection `id`'s engine wants to know. One question shows at a
    /// time; another connection's waits until the card is free.
    pub(crate) fn show_prompt(&self, id: SessionId, p: AuthPrompt) {
        if self
            .session_state(id)
            .is_none_or(|s| s == State::Disconnecting)
        {
            return;
        }
        // OpenVPN key passphrase saved in the profile: answer without asking (once —
        // if it's wrong, the engine asks again and the card below shows).
        if p.kind == "keypass" {
            if let Some(Some(k)) = self.with_session(id, |s| s.pending_key_pass.take()) {
                self.answer(id, &k);
                self.session_log(id, "→ saved key passphrase sent");
                return;
            }
        }
        match self.prompt_session.get() {
            Some(other) if other != id && self.session_state(other).is_some() => {
                self.with_session(id, |s| s.waiting_prompt = Some(p));
                let name = self.session_name(id);
                self.toast(&format!("“{name}” has a question waiting"));
                return;
            }
            _ => {}
        }
        self.clear_prompt();
        self.prompt_session.set(Some(id));
        self.show_main();
        if p.kind == "trust" {
            if let Some(q) = profiles::TrustQuestion::parse(&p.message) {
                self.show_trust_prompt(id, q);
            }
            return;
        }
        // The answer is typed in the window — bring it up if the tray started this.
        if !self.window.is_visible() {
            self.show_window();
        }
        let name = self.session_name(id);
        let backend = self.with_session(id, |s| s.backend).flatten();

        let (title, hint) = match p.kind.as_str() {
            "push" => ("Approve the sign-in", "…or type the code"),
            "newpass" => ("Password expired", "New password"),
            "renew" => ("Change your password?", "New password"),
            "answer" => ("Additional verification", "Answer"),
            "sso" if backend == Some(Backend::GlobalProtect) => (
                "Finish the browser sign-in",
                "Callback link or prelogin-cookie",
            ),
            "sso" => ("Finish the browser sign-in", "SSO token"),
            "username" => ("Sign-in name", "Username"),
            "code2" => ("Second code", "Next code"),
            "keypass" => ("Private key passphrase", "Passphrase"),
            _ => ("Two-factor authentication", "Code"),
        };
        self.prompt_group.set_title(&format!("{title} — {name}"));
        let message = if p.kind == "sso" && self.sso_window_open(id) {
            let fallback = match backend {
                Some(Backend::GlobalProtect) => {
                    "the globalprotectcallback: link or the prelogin-cookie"
                }
                Some(Backend::AnyConnect) => "the SSO token cookie",
                Some(Backend::Ivanti) => "the DSID cookie",
                _ => "the SSO token",
            };
            format!("Sign in in the window that opened — the VPN connects on its own. (Or paste {fallback} here.)")
        } else if p.kind == "keypass" && !p.message.starts_with("Wrong") {
            "The profile's private key is encrypted.".to_string()
        } else {
            p.message.clone()
        };
        self.prompt_group
            .set_description((!message.is_empty()).then_some(message.as_str()));

        let new_password = p.kind == "newpass" || p.kind == "renew";
        let masked = new_password || matches!(p.kind.as_str(), "answer" | "sso" | "keypass");

        let entry: gtk::Widget = if masked {
            adw::PasswordEntryRow::builder()
                .title(hint)
                .build()
                .upcast()
        } else {
            adw::EntryRow::builder().title(hint).build().upcast()
        };
        let confirm = new_password.then(|| {
            adw::PasswordEntryRow::builder()
                .title("Confirm password")
                .build()
        });

        self.prompt_group.add(&entry);
        self.prompt_rows.borrow_mut().push(entry.clone());
        if let Some(c) = &confirm {
            self.prompt_group.add(c);
            self.prompt_rows.borrow_mut().push(c.clone().upcast());
        }
        // Key passphrase of a saved profile: offer to remember it (stored once the
        // tunnel is up, so a mistyped one isn't kept).
        let profile = name;
        let saved = self
            .profiles
            .borrow()
            .iter()
            .find(|e| e.name == profile)
            .map(|e| e.remember_key_pass);
        let remember = (p.kind == "keypass" && saved.is_some()).then(|| {
            adw::SwitchRow::builder()
                .title("Remember passphrase")
                .subtitle("Store in the system keyring")
                .active(saved == Some(true))
                .build()
        });
        if let Some(r) = &remember {
            self.prompt_group.add(r);
            self.prompt_rows.borrow_mut().push(r.clone().upcast());
        }

        let btns = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .halign(gtk::Align::End)
            .margin_top(8)
            .build();
        let send = gtk::Button::builder()
            .label("Send")
            .css_classes(["suggested-action"])
            .build();
        let skip = (p.kind == "renew").then(|| gtk::Button::with_label("Skip"));
        if let Some(s) = &skip {
            btns.append(s);
        }
        btns.append(&send);
        self.prompt_group.add(&btns);
        self.prompt_rows.borrow_mut().push(btns.upcast());

        self.prompt_group.set_visible(true);
        entry.grab_focus();

        let app = self.rc();
        let entry_for_send = entry.clone();
        let confirm_for_send = confirm.clone();
        let kind = p.kind.clone();
        let do_send: Rc<dyn Fn()> = Rc::new(move || {
            let text = app.editable_text(&entry_for_send);
            let answer = if masked {
                text
            } else {
                text.trim().to_string()
            };
            if new_password {
                let c = confirm_for_send
                    .as_ref()
                    .map(|c| c.text().to_string())
                    .unwrap_or_default();
                if answer != c {
                    app.toast("Passwords don't match");
                    return;
                }
            }
            if answer.is_empty() && kind != "renew" {
                return;
            }
            app.answer(id, &answer);
            if remember.as_ref().is_some_and(|r| r.is_active()) {
                let keep = (profile.clone(), answer.clone());
                app.with_session(id, |s| s.key_pass_to_store = Some(keep));
            }
            app.session_log(
                id,
                match kind.as_str() {
                    "sso" => "→ SSO token sent",
                    "keypass" => "→ key passphrase sent",
                    _ if masked => "→ password sent",
                    _ => "→ answer sent",
                },
            );
            app.clear_prompt_of(id);
        });

        send.connect_clicked({
            let d = do_send.clone();
            move |_| d()
        });
        if let Some(s) = &skip {
            let app2 = self.rc();
            s.connect_clicked(move |_| {
                app2.answer(id, "");
                app2.session_log(id, "→ keeping the current password");
                app2.clear_prompt_of(id);
            });
        }
        if let Ok(er) = entry.clone().downcast::<adw::EntryRow>() {
            let d = do_send.clone();
            er.connect_entry_activated(move |_| d());
        }
    }

    /// The engine met a gateway certificate no trusted authority vouches for.
    pub(crate) fn show_trust_prompt(&self, id: SessionId, q: profiles::TrustQuestion) {
        if !self.window.is_visible() {
            self.show_window();
        }
        let name = self.session_name(id);
        self.prompt_group
            .set_title(&format!("Unknown gateway certificate — {name}"));
        self.prompt_group.set_description(Some(&format!(
            "{} presents a certificate no trusted authority vouches for. Continue only if you expect it \
             — for example, a gateway with its own certificate; your administrator can confirm the fingerprint.\n\n{}\n{}",
            q.endpoint, q.details, q.fingerprint
        )));
        let btns = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
            .halign(gtk::Align::End)
            .margin_top(8)
            .build();
        let cancel = gtk::Button::with_label("Cancel");
        let trust = gtk::Button::builder()
            .label("Trust")
            .css_classes(["suggested-action"])
            .build();
        btns.append(&cancel);
        btns.append(&trust);
        self.prompt_group.add(&btns);
        self.prompt_rows.borrow_mut().push(btns.upcast());
        self.prompt_group.set_visible(true);

        let app = self.rc();
        let q2 = q.clone();
        let profile = name.clone();
        trust.connect_clicked(move |_| {
            app.answer(id, &q2.answer(true));
            app.remember_pin(&profile, &q2);
            app.clear_prompt_of(id);
        });
        let app = self.rc();
        cancel.connect_clicked(move |_| {
            app.answer(id, &q.answer(false));
            app.session_log(id, "→ certificate not trusted");
            app.clear_prompt_of(id);
        });
    }

    /// Persist a key passphrase the user asked to remember in the prompt card — only
    /// once the tunnel came up, so it was right.
    pub(crate) fn store_key_pass(&self, id: SessionId) {
        let Some(Some((name, pass))) = self.with_session(id, |s| s.key_pass_to_store.take()) else {
            return;
        };
        if !profiles::secret_set(&profiles::keypass_account(&name), &pass) {
            self.toast("Couldn't save the key passphrase to the keyring");
            return;
        }
        {
            let mut profs = self.profiles.borrow_mut();
            let Some(slot) = profs.iter_mut().find(|e| e.name == name) else {
                return;
            };
            slot.remember_key_pass = true;
            if let Err(e) = profiles::save(&profs) {
                drop(profs);
                self.toast(&format!("Couldn't save: {e}"));
                return;
            }
        }
        if self.name_row.text().trim() == name {
            self.key_pass_row.set_text(&pass);
            self.remember_key_pass_row.set_active(true);
        }
        self.refresh_profiles_list();
        self.toast(&format!("Saved the key passphrase for “{name}”"));
    }

    /// Empty the prompt card.
    pub(crate) fn clear_prompt(&self) {
        for w in self.prompt_rows.borrow_mut().drain(..) {
            self.prompt_group.remove(&w);
        }
        self.prompt_group.set_visible(false);
        self.prompt_session.set(None);
    }

    /// Connection `id` has no question any more: drop its card (showing the next
    /// connection's waiting question, if any) or its waiting one.
    pub(crate) fn clear_prompt_of(&self, id: SessionId) {
        self.with_session(id, |s| s.waiting_prompt = None);
        if self.prompt_session.get() != Some(id) {
            return;
        }
        self.clear_prompt();
        let next = self
            .sessions
            .borrow_mut()
            .iter_mut()
            .find_map(|s| s.waiting_prompt.take().map(|p| (s.id, p)));
        if let Some((next, p)) = next {
            self.show_prompt(next, p);
        }
    }
}
