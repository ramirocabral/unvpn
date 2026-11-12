//! The connection status: state pill, address, DNS, traffic, uptime and log.

use adw::prelude::*;
use gtk::glib;

use crate::engine::State;
use crate::App;

impl App {
    pub(crate) fn append_log(&self, line: &str) {
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
        self.log_view
            .scroll_to_iter(&mut b.end_iter(), 0.0, false, 0.0, 0.0);
    }

    /// A tray-started connection failed: bring the window up on the log.
    pub(crate) fn reveal_log(&self) {
        self.show_window();
        self.log_expander.set_expanded(true);
        self.log_view
            .scroll_to_iter(&mut self.log_buffer.end_iter(), 0.0, false, 0.0, 0.0);
    }

    pub(crate) fn tick(&self) {
        if self.vpn.borrow_mut().poll() {
            self.sync_ui();
        }
        self.update_stats();
    }

    /// Refresh the live-connection stats (transfer counters from the tunnel device,
    /// and how long it has been up). A no-op unless a tunnel is up.
    pub(crate) fn update_stats(&self) {
        if !matches!(
            self.vpn.borrow().state(),
            State::Connected | State::Reconnecting
        ) {
            return;
        }
        if let Some(iface) = self.iface.borrow().as_ref() {
            if let (Some(rx), Some(tx)) = (
                iface_bytes(iface, "rx_bytes"),
                iface_bytes(iface, "tx_bytes"),
            ) {
                self.transfer_row.set_subtitle(&format!(
                    "↓ {}    ↑ {}",
                    human_bytes(rx),
                    human_bytes(tx)
                ));
            }
        }
        if let Some(since) = *self.conn_since.borrow() {
            self.uptime_row
                .set_subtitle(&human_duration(since.elapsed()));
        }
    }

    pub(crate) fn sync_ui(&self) {
        let state = self.vpn.borrow().state();

        let (txt, cls) = match &state {
            State::Disconnected => ("Disconnected", "st-off"),
            State::Connecting => ("Connecting…", "st-busy"),
            State::Connected => ("Connected", "st-on"),
            State::Reconnecting => ("Reconnecting…", "st-busy"),
            State::Disconnecting => ("Disconnecting…", "st-busy"),
            State::Error(_) => ("Error", "st-err"),
        };
        self.status_pill.set_text(&format!("● {txt}"));
        self.status_pill.set_css_classes(&["statuspill", cls]);

        if state == State::Connected {
            self.store_key_pass();
        }

        if matches!(state, State::Connected | State::Reconnecting) {
            let name = self.active_profile.lock().unwrap().clone();
            self.status_pill
                .set_tooltip_text((!name.is_empty()).then_some(name.as_str()));
        } else {
            self.status_pill.set_tooltip_text(None);
        }

        if state != State::Connecting {
            self.close_sso_window();
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
                self.connect_btn
                    .set_css_classes(&["suggested-action", "pill"]);
                self.connect_btn.set_sensitive(self.form_ready());
                self.clear_prompt();
                self.status_group.set_visible(false);
                self.ip_row.set_subtitle("");
                self.dns_row.set_subtitle("");
                self.transfer_row.set_subtitle("");
                self.uptime_row.set_subtitle("");
                self.iface.replace(None);
                self.conn_since.replace(None);
            }
            State::Connecting | State::Connected | State::Reconnecting => {
                self.connect_btn.set_label("Disconnect");
                self.connect_btn
                    .set_css_classes(&["destructive-action", "pill"]);
                self.connect_btn.set_sensitive(true);
            }
            State::Disconnecting => {
                self.connect_btn.set_label("Disconnecting…");
                self.connect_btn.set_css_classes(&["pill"]);
                self.connect_btn.set_sensitive(false);
            }
        }

        let changed = self.last_state.borrow().as_ref() != Some(&state);
        if changed {
            let down = matches!(state, State::Disconnected | State::Error(_));
            let switch = if down {
                self.pending_switch.take()
            } else {
                None
            };
            // A push approved on the phone leaves its card up; the tunnel answers it.
            if state == State::Connected {
                self.clear_prompt();
            }
            if let State::Error(e) = &state {
                self.toast(e);
                if self.from_tray.get() && switch.is_none() {
                    self.reveal_log();
                }
            }
            self.update_tray();
            *self.last_state.borrow_mut() = Some(state);
            // Tray switch: the old tunnel is down, bring up the picked profile (off
            // this call — connecting re-enters sync_ui).
            if let Some(name) = switch {
                let app = self.rc();
                glib::idle_add_local_once(move || app.connect_from_tray(&name));
            }
        }
    }

    pub(crate) fn toast(&self, msg: &str) {
        self.toast.add_toast(adw::Toast::new(msg));
    }
}

/// Read a tunnel interface's byte counter from the kernel (world-readable). `iface`
/// is validated to a safe device-name charset so it can't escape the /sys path.
pub(crate) fn iface_bytes(iface: &str, which: &str) -> Option<u64> {
    if iface.is_empty()
        || !iface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return None;
    }
    std::fs::read_to_string(format!("/sys/class/net/{iface}/statistics/{which}"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

pub(crate) fn human_bytes(b: u64) -> String {
    const U: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

pub(crate) fn human_duration(d: std::time::Duration) -> String {
    let s = d.as_secs();
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{h}h {m:02}m {sec:02}s")
    } else {
        format!("{m}m {sec:02}s")
    }
}

#[cfg(test)]
mod tests {
    use super::{human_bytes, human_duration};
    use std::time::Duration;

    #[test]
    fn bytes_are_human_readable() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn durations_are_human_readable() {
        assert_eq!(human_duration(Duration::from_secs(45)), "0m 45s");
        assert_eq!(human_duration(Duration::from_secs(125)), "2m 05s");
        assert_eq!(human_duration(Duration::from_secs(3661)), "1h 01m 01s");
    }
}
