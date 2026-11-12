//! The connections the app follows, each with its row under "Active connections".

use std::time::Instant;

use adw::prelude::*;

use crate::engine::{AuthPrompt, SessionId, State, Vpn};
use crate::profiles::Backend;

pub(crate) struct Session {
    pub id: SessionId,
    /// The profile name (or gateway) the connection goes by.
    pub name: String,
    /// The back-end, when this app started the connection.
    pub backend: Option<Backend>,
    pub vpn: Vpn,
    pub row: SessionRow,
    pub iface: Option<String>,
    pub since: Option<Instant>,
    /// Started from the tray (or the browser): a failure opens the window on the log.
    pub from_tray: bool,
    /// OpenVPN: passphrase to answer the first `keypass` prompt with.
    pub pending_key_pass: Option<String>,
    /// OpenVPN: (profile, passphrase) typed with "Remember" on, kept in the
    /// keyring once the tunnel is up — i.e. once it proved right.
    pub key_pass_to_store: Option<(String, String)>,
    /// A question waiting while the prompt card shows another connection's.
    pub waiting_prompt: Option<AuthPrompt>,
    /// The state the UI last reacted to.
    pub shown: State,
    /// A "connection lost" notification went out for the current drop.
    pub drop_notified: bool,
}

pub(crate) struct SessionRow {
    pub expander: adw::ExpanderRow,
    dot: gtk::Label,
    pub stop: gtk::Button,
    pub ip: adw::ActionRow,
    pub dns: adw::ActionRow,
    pub transfer: adw::ActionRow,
    pub uptime: adw::ActionRow,
}

impl SessionRow {
    pub fn new(name: &str, expanded: bool) -> SessionRow {
        let expander = adw::ExpanderRow::builder()
            .title(name)
            .expanded(expanded)
            .build();
        let dot = gtk::Label::builder()
            .label("●")
            .css_classes(["statuspill", Tone::Busy.css()])
            .build();
        expander.add_prefix(&dot);
        let stop = gtk::Button::builder()
            .icon_name("media-playback-stop-symbolic")
            .tooltip_text("Disconnect")
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .build();
        expander.add_suffix(&stop);
        let prop = |title: &str| {
            adw::ActionRow::builder()
                .title(title)
                .css_classes(["property"])
                .build()
        };
        let row = SessionRow {
            ip: prop("Internal IP"),
            dns: prop("DNS"),
            transfer: prop("Transfer"),
            uptime: prop("Connected for"),
            expander,
            dot,
            stop,
        };
        for r in [&row.ip, &row.dns, &row.transfer, &row.uptime] {
            row.expander.add_row(r);
        }
        row
    }

    pub fn show_state(&self, st: &State) {
        let ip = self.ip.subtitle().unwrap_or_default();
        let text = match st {
            State::Connected | State::Reconnecting if !ip.is_empty() => {
                format!("{} · {ip}", label(st))
            }
            State::Error(e) => e.clone(),
            _ => label(st).to_string(),
        };
        self.expander.set_subtitle(&text);
        self.dot.set_css_classes(&["statuspill", tone(st).css()]);
        self.stop.set_sensitive(*st != State::Disconnecting);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Off,
    On,
    Busy,
    Error,
}

impl Tone {
    pub fn css(self) -> &'static str {
        match self {
            Tone::Off => "st-off",
            Tone::On => "st-on",
            Tone::Busy => "st-busy",
            Tone::Error => "st-err",
        }
    }

    pub fn rgb(self) -> [u8; 3] {
        match self {
            Tone::Off => [154, 153, 150],
            Tone::On => [46, 194, 126],
            Tone::Busy => [245, 194, 17],
            Tone::Error => [224, 27, 36],
        }
    }
}

pub fn tone(st: &State) -> Tone {
    match st {
        State::Connected => Tone::On,
        State::Connecting | State::Reconnecting | State::Disconnecting => Tone::Busy,
        State::Error(_) => Tone::Error,
        State::Disconnected => Tone::Off,
    }
}

pub fn label(st: &State) -> &'static str {
    match st {
        State::Disconnected => "Disconnected",
        State::Connecting => "Connecting…",
        State::Connected => "Connected",
        State::Reconnecting => "Reconnecting…",
        State::Disconnecting => "Disconnecting…",
        State::Error(_) => "Error",
    }
}

/// All connections as one state, for the header and the tray icon. `failed`: the
/// last connection to end failed.
pub fn overall(states: &[State], failed: bool) -> (String, Tone) {
    if states.is_empty() {
        return if failed {
            ("Error".into(), Tone::Error)
        } else {
            ("Disconnected".into(), Tone::Off)
        };
    }
    let up = states.iter().filter(|s| **s == State::Connected).count();
    let connected = |n: usize| {
        if n == 1 {
            "Connected".to_string()
        } else {
            format!("{n} connected")
        }
    };
    match states.iter().find(|s| tone(s) == Tone::Busy) {
        Some(b) if up > 0 => (format!("{} · {}", connected(up), label(b)), Tone::Busy),
        Some(b) => (label(b).to_string(), Tone::Busy),
        None if up > 0 => (connected(up), Tone::On),
        None => ("Error".into(), Tone::Error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_connections_read_as_one_state() {
        assert_eq!(overall(&[], false), ("Disconnected".into(), Tone::Off));
        assert_eq!(overall(&[], true), ("Error".into(), Tone::Error));
        assert_eq!(
            overall(&[State::Connected], false),
            ("Connected".into(), Tone::On)
        );
        assert_eq!(
            overall(&[State::Connected, State::Connected], false),
            ("2 connected".into(), Tone::On)
        );
        assert_eq!(
            overall(&[State::Connected, State::Connecting], false),
            ("Connected · Connecting…".into(), Tone::Busy)
        );
        assert_eq!(
            overall(&[State::Reconnecting], true),
            ("Reconnecting…".into(), Tone::Busy)
        );
        assert_eq!(
            overall(&[State::Error("x".into())], false),
            ("Error".into(), Tone::Error)
        );
    }
}
