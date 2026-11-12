//! Desktop notifications for what happens to a connection while the window
//! isn't in front: it came up, dropped, came back, failed.

use adw::prelude::*;
use gtk::gio;

use crate::App;

impl App {
    /// Notify about connection `name`, unless the window has focus (it shows the
    /// change itself). A newer notification about the same connection replaces
    /// the older one. `alert`: something went wrong — urgent, and with a
    /// "Connect" button when `name` is a saved profile.
    pub(crate) fn notify(&self, name: &str, title: &str, body: &str, alert: bool) {
        if self.window.is_active() {
            return;
        }
        let Some(app) = self.window.application() else {
            return;
        };
        let n = gio::Notification::new(title);
        if !body.is_empty() {
            n.set_body(Some(body));
        }
        n.set_icon(&gio::ThemedIcon::new("unvpn"));
        n.set_default_action("app.show");
        if alert {
            n.set_priority(gio::NotificationPriority::Urgent);
            if self.profiles.borrow().iter().any(|p| p.name == name) {
                n.add_button_with_target_value(
                    "Connect",
                    "app.connect-profile",
                    Some(&name.to_variant()),
                );
            }
        }
        app.send_notification(Some(&format!("connection-{name}")), &n);
    }
}
