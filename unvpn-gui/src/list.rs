//! The saved-profile list: ordering, deleting, export and import.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use gtk::{gdk, gio, glib};

use crate::profiles::Profile;
use crate::{bundle, profiles, App};

impl App {
    pub(crate) fn refresh_profiles_list(&self) {
        for row in self.profile_rows.borrow_mut().drain(..) {
            self.profiles_group.remove(&row);
        }
        self.profile_buttons.borrow_mut().clear();
        let profs = self.profiles.borrow();
        for p in profs.iter() {
            let row = adw::ActionRow::builder()
                .title(&p.name)
                .subtitle(p.subtitle())
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
            let menu_btn = gtk::MenuButton::builder()
                .icon_name("view-more-symbolic")
                .css_classes(["flat"])
                .valign(gtk::Align::Center)
                .tooltip_text("More")
                .build();
            let popover = gtk::Popover::builder().build();
            let export_item = gtk::Button::builder()
                .label("Export…")
                .css_classes(["flat"])
                .build();
            let pbox = gtk::Box::new(gtk::Orientation::Vertical, 0);
            pbox.append(&export_item);
            popover.set_child(Some(&pbox));
            menu_btn.set_popover(Some(&popover));
            row.add_suffix(&conn);
            row.add_suffix(&del);
            row.add_suffix(&menu_btn);
            let handle = gtk::Image::from_icon_name("list-drag-handle-symbolic");
            handle.set_tooltip_text(Some("Drag to reorder"));
            row.add_prefix(&handle);
            self.setup_profile_dnd(&row, &p.name);

            let app_rc = self.rc();
            let p1 = p.clone();
            row.connect_activated(glib::clone!(
                #[strong]
                app_rc,
                move |_| {
                    app_rc.load_profile(&p1);
                    app_rc.open_editor(&p1.name);
                }
            ));
            let app2 = app_rc.clone();
            let name = p.name.clone();
            // Toggles this profile's connection; the others stay as they are.
            conn.connect_clicked(move |_| match app2.session_named(&name) {
                Some(id) => app2.disconnect_session(id),
                None => app2.connect_profile(&name, false),
            });
            self.profile_buttons
                .borrow_mut()
                .push((p.name.clone(), conn.clone()));
            let app3 = app_rc.clone();
            let name = p.name.clone();
            del.connect_clicked(move |_| app3.confirm_delete_profile(&name));
            let app4 = app_rc.clone();
            let name = p.name.clone();
            export_item.connect_clicked(glib::clone!(
                #[weak]
                popover,
                move |_| {
                    popover.popdown();
                    app4.export_profile_named(&name);
                }
            ));

            self.profiles_group.add(&row);
            self.profile_rows.borrow_mut().push(row);
        }
        drop(profs);
        self.apply_profile_filter();
        self.sync_ui();
    }

    /// Show only the profiles whose name or details contain every word searched.
    pub(crate) fn apply_profile_filter(&self) {
        let query = self.search_entry.text().to_lowercase();
        let words: Vec<&str> = query.split_whitespace().collect();
        let mut shown = 0;
        for row in self.profile_rows.borrow().iter() {
            let text =
                format!("{} {}", row.title(), row.subtitle().unwrap_or_default()).to_lowercase();
            let hit = words.iter().all(|w| text.contains(w));
            row.set_visible(hit);
            shown += hit as usize;
        }
        let empty = &self.profiles_empty_row;
        if self.profiles.borrow().is_empty() {
            empty.set_title("No saved profiles");
            empty.set_subtitle("Add one with the + button");
            empty.set_visible(true);
        } else if shown == 0 {
            empty.set_title("No matching profiles");
            empty.set_subtitle("");
            empty.set_visible(true);
        } else {
            empty.set_visible(false);
        }
    }

    /// Drag a profile row onto another to move it there; the order is saved.
    pub(crate) fn setup_profile_dnd(&self, row: &adw::ActionRow, name: &str) {
        let src = gtk::DragSource::new();
        src.set_actions(gdk::DragAction::MOVE);
        let hot = Rc::new(Cell::new((0.0, 0.0)));
        let n = name.to_string();
        // Moving a row next to hidden ones would land it somewhere unexpected.
        src.connect_prepare(glib::clone!(
            #[strong]
            hot,
            #[weak(rename_to = search)]
            self.search_entry,
            #[upgrade_or]
            None,
            move |_, x, y| {
                if !search.text().trim().is_empty() {
                    return None;
                }
                hot.set((x, y));
                Some(gdk::ContentProvider::for_value(&n.to_value()))
            }
        ));
        src.connect_drag_begin(glib::clone!(
            #[weak]
            row,
            move |src, _| {
                let (x, y) = hot.get();
                src.set_icon(
                    Some(&gtk::WidgetPaintable::new(Some(&row))),
                    x as i32,
                    y as i32,
                );
                row.add_css_class("dragging");
            }
        ));
        src.connect_drag_end(glib::clone!(
            #[weak]
            row,
            move |_, _, _| row.remove_css_class("dragging")
        ));
        row.add_controller(src);

        let target = gtk::DropTarget::new(String::static_type(), gdk::DragAction::MOVE);
        let set_marker = |row: &adw::ActionRow, y: f64| {
            let above = y < row.height() as f64 / 2.0;
            if above {
                row.remove_css_class("drop-below");
                row.add_css_class("drop-above");
            } else {
                row.remove_css_class("drop-above");
                row.add_css_class("drop-below");
            }
        };
        target.connect_enter(glib::clone!(
            #[weak]
            row,
            #[upgrade_or]
            gdk::DragAction::empty(),
            move |_, _, y| {
                set_marker(&row, y);
                gdk::DragAction::MOVE
            }
        ));
        target.connect_motion(glib::clone!(
            #[weak]
            row,
            #[upgrade_or]
            gdk::DragAction::empty(),
            move |_, _, y| {
                set_marker(&row, y);
                gdk::DragAction::MOVE
            }
        ));
        target.connect_leave(glib::clone!(
            #[weak]
            row,
            move |_| {
                row.remove_css_class("drop-above");
                row.remove_css_class("drop-below");
            }
        ));
        let app = self.rc();
        let dest = name.to_string();
        target.connect_drop(glib::clone!(
            #[weak]
            row,
            #[upgrade_or]
            false,
            move |_, value, _, y| {
                row.remove_css_class("drop-above");
                row.remove_css_class("drop-below");
                let Ok(moved) = value.get::<String>() else {
                    return false;
                };
                let below = y >= row.height() as f64 / 2.0;
                let (app, dest) = (app.clone(), dest.clone());
                // Rebuilding the list destroys this row; do it outside its signal.
                glib::idle_add_local_once(move || app.move_profile(&moved, &dest, below));
                true
            }
        ));
        row.add_controller(target);
    }

    pub(crate) fn move_profile(&self, moved: &str, dest: &str, below: bool) {
        if moved == dest {
            return;
        }
        {
            let mut profs = self.profiles.borrow_mut();
            let Some(from) = profs.iter().position(|p| p.name == moved) else {
                return;
            };
            let p = profs.remove(from);
            let Some(to) = profs.iter().position(|p| p.name == dest) else {
                profs.insert(from, p);
                return;
            };
            profs.insert(if below { to + 1 } else { to }, p);
            if let Err(e) = profiles::save(&profs) {
                drop(profs);
                self.toast(&format!("Couldn't save profiles: {e}"));
            }
        }
        self.refresh_profiles_list();
    }

    pub(crate) fn confirm_delete_profile(&self, name: &str) {
        let Some(p) = self
            .profiles
            .borrow()
            .iter()
            .find(|p| p.name == name)
            .cloned()
        else {
            return;
        };
        let mut body = "Its saved passwords and keys are removed too.".to_string();
        if profiles::owned_files(&p).is_some() {
            if p.uses_cp_cert() {
                body.push_str(
                    "\n\nIts enrolled certificate is deleted as well. A registration key works only once, \
                     so enrolling again needs a new key from your administrator.",
                );
            } else {
                body.push_str(" So is its imported VPN file.");
            }
        }
        let dialog = adw::AlertDialog::builder()
            .heading(format!("Delete “{name}”?"))
            .body(body)
            .build();
        dialog.add_responses(&[("cancel", "Cancel"), ("delete", "Delete")]);
        dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        let app = self.rc();
        let name = name.to_string();
        dialog.connect_response(Some("delete"), move |_, _| app.delete_profile(&name));
        dialog.present(Some(&self.window));
    }

    pub(crate) fn delete_profile(&self, name: &str) {
        if let Some(p) = self.profiles.borrow().iter().find(|p| p.name == name) {
            profiles::remove_owned_files(p);
        }
        profiles::secret_delete(name);
        profiles::secret_delete(&profiles::keypass_account(name));
        profiles::secret_delete(&profiles::psk_account(name));
        {
            let mut profs = self.profiles.borrow_mut();
            profs.retain(|e| e.name != name);
            let _ = profiles::save(&profs);
        }
        self.refresh_profiles_list();
        self.toast(&format!("Deleted profile “{name}”"));
    }

    pub(crate) fn export_profiles(&self) {
        let profs = self.profiles.borrow().clone();
        if profs.is_empty() {
            self.toast("No saved profiles to export");
            return;
        }
        self.start_export(profs, "unvpn-profiles".to_string());
    }

    /// Export a single saved profile, named on its export file.
    pub(crate) fn export_profile_named(&self, name: &str) {
        let Some(p) = self
            .profiles
            .borrow()
            .iter()
            .find(|p| p.name == name)
            .cloned()
        else {
            self.toast("Profile not found");
            return;
        };
        self.start_export(vec![p], format!("unvpn-{}", bundle::slug(name)));
    }

    /// Ask for a passphrase, then a file, and seal the given profiles into it.
    fn start_export(&self, profs: Vec<Profile>, default_name: String) {
        let n = profs.len();
        let what = if n == 1 {
            "This profile, with its saved password, PSK and VPN files,".to_string()
        } else {
            format!("{n} profiles, with their saved passwords, PSKs and VPN files,")
        };
        let pass = adw::PasswordEntryRow::builder().title("Passphrase").build();
        let confirm = adw::PasswordEntryRow::builder()
            .title("Repeat passphrase")
            .activates_default(true)
            .build();
        let dialog = passphrase_dialog(
            "Export Profiles",
            &format!(
                "{what} is exported encrypted with this passphrase (at least {} characters); \
                 you'll need it to import.",
                bundle::MIN_PASSPHRASE
            ),
            ("export", "Export…"),
            &[&pass, &confirm],
        );
        let check = glib::clone!(
            #[weak]
            dialog,
            #[weak]
            pass,
            #[weak]
            confirm,
            move |_: &adw::PasswordEntryRow| {
                let p = pass.text();
                dialog.set_response_enabled(
                    "export",
                    p.chars().count() >= bundle::MIN_PASSPHRASE && p == confirm.text(),
                );
            }
        );
        pass.connect_changed(check.clone());
        confirm.connect_changed(check);
        let app = self.rc();
        dialog.connect_response(
            Some("export"),
            glib::clone!(
                #[weak]
                pass,
                move |_, _| {
                    app.pick_export_file(pass.text().to_string(), profs.clone(), default_name.clone());
                }
            ),
        );
        dialog.present(Some(&self.window));
    }

    fn pick_export_file(&self, pass: String, profs: Vec<Profile>, default_name: String) {
        let dialog = gtk::FileDialog::builder()
            .title("Export Profiles")
            .modal(true)
            .initial_name(format!("{default_name}.{}", bundle::FILE_EXT))
            .build();
        let app = self.rc();
        dialog.save(Some(&self.window), gio::Cancellable::NONE, move |res| {
            let Some(mut path) = res.ok().and_then(|f| f.path()) else {
                return;
            };
            if path.extension().is_none() {
                path.set_extension(bundle::FILE_EXT);
            }
            app.write_export(path, pass, profs);
        });
    }

    fn write_export(&self, path: std::path::PathBuf, pass: String, profs: Vec<Profile>) {
        let (b, skipped) = bundle::collect(&profs);
        let n = b.entries.len();
        let app = self.rc();
        glib::spawn_future_local(async move {
            let res = gio::spawn_blocking(move || {
                let data = bundle::seal(&b, &pass)?;
                bundle::write_private(&path, &data)
                    .map_err(|e| format!("write {}: {e}", path.display()))
            })
            .await;
            for s in &skipped {
                app.append_log(&format!("export: skipped {s}"));
            }
            match res {
                Ok(Ok(())) if skipped.is_empty() => app.toast(&format!("Exported {n} profile(s)")),
                Ok(Ok(())) => app.toast(&format!(
                    "Exported {n} profile(s); skipped {} (see log)",
                    skipped.len()
                )),
                Ok(Err(e)) => app.toast(&format!("Export failed: {e}")),
                Err(_) => app.toast("Export failed"),
            }
        });
    }

    pub(crate) fn import_profiles(&self) {
        let filter = gtk::FileFilter::new();
        filter.set_name(Some("unvpn profile exports"));
        filter.add_pattern(&format!("*.{}", bundle::FILE_EXT));
        let filters = gio::ListStore::new::<gtk::FileFilter>();
        filters.append(&filter);
        let dialog = gtk::FileDialog::builder()
            .title("Import Profiles")
            .modal(true)
            .filters(&filters)
            .build();
        let app = self.rc();
        dialog.open(Some(&self.window), gio::Cancellable::NONE, move |res| {
            let Some(path) = res.ok().and_then(|f| f.path()) else {
                return;
            };
            match std::fs::read(&path) {
                Ok(data) if bundle::is_bundle(&data) => {
                    app.ask_import_passphrase(Rc::new(data), None)
                }
                Ok(_) => app.toast("That file isn't an unvpn profile export"),
                Err(e) => app.toast(&format!("Couldn't read {}: {e}", path.display())),
            }
        });
    }

    pub(crate) fn ask_import_passphrase(&self, data: Rc<Vec<u8>>, error: Option<&str>) {
        let pass = adw::PasswordEntryRow::builder()
            .title("Passphrase")
            .activates_default(true)
            .build();
        let body = match error {
            Some(e) => format!("{e}. Try again."),
            None => "Enter the passphrase the profiles were exported with.".to_string(),
        };
        let dialog = passphrase_dialog("Import Profiles", &body, ("import", "Import"), &[&pass]);
        pass.connect_changed(glib::clone!(
            #[weak]
            dialog,
            move |p| {
                dialog.set_response_enabled("import", !p.text().is_empty());
            }
        ));
        let app = self.rc();
        dialog.connect_response(
            Some("import"),
            glib::clone!(
                #[weak]
                pass,
                move |_, _| {
                    let pass = pass.text().to_string();
                    let bytes = (*data).clone();
                    let (app, data) = (app.clone(), data.clone());
                    glib::spawn_future_local(async move {
                        match gio::spawn_blocking(move || bundle::open(&bytes, &pass)).await {
                            Ok(Ok(b)) => app.confirm_import(b),
                            Ok(Err(bundle::OpenError::WrongPassphrase)) => {
                                app.ask_import_passphrase(data, Some("Wrong passphrase"))
                            }
                            Ok(Err(e)) => app.toast(&format!("Can't import: {e}")),
                            Err(_) => app.toast("Import failed"),
                        }
                    });
                }
            ),
        );
        dialog.present(Some(&self.window));
    }

    pub(crate) fn confirm_import(&self, b: bundle::Bundle) {
        if b.entries.is_empty() {
            self.toast("The export has no profiles");
            return;
        }
        let existing: Vec<String> = {
            let profs = self.profiles.borrow();
            b.entries
                .iter()
                .map(|e| e.profile.name.clone())
                .filter(|n| profs.iter().any(|p| &p.name == n))
                .collect()
        };
        if existing.is_empty() {
            self.apply_import(b, false);
            return;
        }
        let list: Vec<String> = existing.iter().map(|n| format!("• {n}")).collect();
        let dialog = adw::AlertDialog::builder()
            .heading("Profiles Already Exist")
            .body(format!(
                "These profiles are already saved here:\n{}",
                list.join("\n")
            ))
            .build();
        dialog.add_responses(&[
            ("cancel", "Cancel"),
            ("keep", "Keep Both"),
            ("replace", "Replace"),
        ]);
        dialog.set_response_appearance("replace", adw::ResponseAppearance::Destructive);
        dialog.set_default_response(Some("keep"));
        dialog.set_close_response("cancel");
        let app = self.rc();
        let b = RefCell::new(Some(b));
        dialog.connect_response(None, move |_, r| {
            let replace = match r {
                "keep" => false,
                "replace" => true,
                _ => return,
            };
            if let Some(b) = b.take() {
                app.apply_import(b, replace);
            }
        });
        dialog.present(Some(&self.window));
    }

    /// Adds the bundle's profiles. A name clash replaces the saved profile, or with
    /// `replace` off, imports under a free name ("work (2)").
    pub(crate) fn apply_import(&self, b: bundle::Bundle, replace: bool) {
        let root = profiles::files_dir();
        let mut imported = 0;
        let mut keyring_failed = false;
        let mut errors = Vec::new();
        {
            let mut profs = self.profiles.borrow_mut();
            for e in &b.entries {
                let base = e.profile.name.as_str();
                let clash = profs.iter().any(|p| p.name == base);
                let name = if clash && !replace {
                    free_name(&profs, base)
                } else {
                    base.to_string()
                };
                let mut p = match bundle::install_files(e, &name, &root) {
                    Ok(p) => p,
                    Err(err) => {
                        errors.push(err);
                        continue;
                    }
                };
                let slot = profs.iter().position(|q| q.name == name);
                if let Some(i) = slot {
                    profiles::remove_owned_files(&profs[i]);
                    profiles::secret_delete(&name);
                    profiles::secret_delete(&profiles::keypass_account(&name));
                    profiles::secret_delete(&profiles::psk_account(&name));
                }
                keyring_failed |= !bundle::install_secrets(e, &mut p);
                match slot {
                    Some(i) => profs[i] = p,
                    None => profs.push(p),
                }
                imported += 1;
            }
            if let Err(e) = profiles::save(&profs) {
                errors.push(format!("couldn't save profiles: {e}"));
            }
        }
        self.refresh_profiles_list();
        for e in &errors {
            self.append_log(&format!("import: {e}"));
        }
        let mut msg = format!("Imported {imported} profile(s)");
        if keyring_failed {
            msg.push_str("; some passwords couldn't be stored in the keyring");
        }
        if !errors.is_empty() {
            msg.push_str(&format!("; {} failed (see log)", errors.len()));
        }
        self.toast(&msg);
    }
}

pub(crate) fn passphrase_dialog(
    heading: &str,
    body: &str,
    ok: (&str, &str),
    rows: &[&adw::PasswordEntryRow],
) -> adw::AlertDialog {
    let list = gtk::ListBox::builder()
        .css_classes(["boxed-list"])
        .selection_mode(gtk::SelectionMode::None)
        .build();
    for r in rows {
        list.append(*r);
    }
    let dialog = adw::AlertDialog::builder()
        .heading(heading)
        .body(body)
        .extra_child(&list)
        .build();
    dialog.add_responses(&[("cancel", "Cancel"), ok]);
    dialog.set_response_appearance(ok.0, adw::ResponseAppearance::Suggested);
    dialog.set_response_enabled(ok.0, false);
    dialog.set_default_response(Some(ok.0));
    dialog.set_close_response("cancel");
    dialog
}

pub(crate) fn free_name(profs: &[Profile], base: &str) -> String {
    (2..)
        .map(|i| format!("{base} ({i})"))
        .find(|n| !profs.iter().any(|p| &p.name == n))
        .unwrap()
}
