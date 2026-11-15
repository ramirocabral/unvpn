//! The connection status: header pill, the active connections, traffic, uptime
//! and the log.

use adw::prelude::*;

use crate::engine::{SessionId, State};
use crate::session::{self, Tone};
use crate::App;

impl App {
    pub(crate) fn append_log(&self, line: &str) {
        let b = &self.log_buffer;
        let mut end = b.end_iter();
        b.insert(&mut end, line);
        b.insert(&mut b.end_iter(), "\n");
        let lines = b.line_count();
        if lines > 1000 {
            if let Some(mut cut) = b.iter_at_line(lines - 1000) {
                let mut start = b.start_iter();
                b.delete(&mut start, &mut cut);
            }
        }
        self.log_view
            .scroll_to_iter(&mut b.end_iter(), 0.0, false, 0.0, 0.0);
    }

    /// A log line about connection `id`, tagged with its name.
    pub(crate) fn session_log(&self, id: SessionId, line: &str) {
        let name = self.session_name(id);
        if name.is_empty() {
            self.append_log(line);
        } else {
            self.append_log(&format!("[{name}] {line}"));
        }
    }

    /// A tray-started connection failed: bring the window up on the log.
    pub(crate) fn reveal_log(&self) {
        self.show_window();
        self.show_main();
        self.log_expander.set_expanded(true);
        self.log_view
            .scroll_to_iter(&mut self.log_buffer.end_iter(), 0.0, false, 0.0, 0.0);
    }

    pub(crate) fn tick(&self) {
        self.poll_sessions();
        self.update_stats();
    }

    /// Refresh each live connection's transfer counters (from its tunnel device)
    /// and how long it has been up.
    pub(crate) fn update_stats(&self) {
        for s in self.sessions.borrow().iter() {
            if !matches!(s.vpn.state(), State::Connected | State::Reconnecting) {
                continue;
            }
            if let Some(iface) = s.iface.as_ref() {
                if let (Some(rx), Some(tx)) = (
                    iface_bytes(iface, "rx_bytes"),
                    iface_bytes(iface, "tx_bytes"),
                ) {
                    s.row.transfer.set_subtitle(&format!(
                        "↓ {}    ↑ {}",
                        human_bytes(rx),
                        human_bytes(tx)
                    ));
                }
            }
            if let Some(since) = s.since {
                s.row.uptime.set_subtitle(&human_duration(since.elapsed()));
            }
        }
    }

    /// Bring the header, the form's button, the profile list and the tray in line
    /// with the connections.
    pub(crate) fn sync_ui(&self) {
        let (states, names): (Vec<State>, Vec<String>) = self
            .sessions
            .borrow()
            .iter()
            .map(|s| (s.vpn.state(), s.name.clone()))
            .unzip();
        let (txt, tone) = session::overall(&states, self.failed.get());
        self.status_pill.set_text(&format!("● {txt}"));
        self.status_pill
            .set_css_classes(&["statuspill", tone.css()]);
        self.status_pill
            .set_tooltip_text((!names.is_empty()).then(|| names.join("\n")).as_deref());
        self.sessions_group.set_visible(!states.is_empty());
        self.sessions_group.set_title(if states.len() > 1 {
            "Active connections"
        } else {
            "Active connection"
        });

        let form = self.form_name();
        let form_state = names
            .iter()
            .position(|n| *n == form)
            .map(|i| states[i].clone());
        match form_state {
            None | Some(State::Disconnected | State::Error(_)) => {
                let label = if self.sso() {
                    "Sign in with browser"
                } else {
                    "Connect"
                };
                self.connect_btn.set_label(label);
                self.connect_btn
                    .set_css_classes(&["suggested-action", "pill"]);
                self.connect_btn.set_sensitive(self.form_ready());
            }
            Some(State::Connecting | State::Connected | State::Reconnecting) => {
                self.connect_btn.set_label("Disconnect");
                self.connect_btn
                    .set_css_classes(&["destructive-action", "pill"]);
                self.connect_btn.set_sensitive(true);
            }
            Some(State::Disconnecting) => {
                self.connect_btn.set_label("Disconnecting…");
                self.connect_btn.set_css_classes(&["pill"]);
                self.connect_btn.set_sensitive(false);
            }
        }

        for (name, btn) in self.profile_buttons.borrow().iter() {
            let st = names.iter().position(|n| n == name).map(|i| &states[i]);
            let live = st.is_some_and(|s| session::tone(s) != Tone::Off);
            btn.set_icon_name(if live {
                "media-playback-stop-symbolic"
            } else {
                "media-playback-start-symbolic"
            });
            btn.set_tooltip_text(Some(if live { "Disconnect" } else { "Connect" }));
            btn.set_sensitive(st != Some(&State::Disconnecting));
        }
        self.update_tray();
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
