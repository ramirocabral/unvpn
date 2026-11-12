//! System-tray icon (StatusNotifierItem via ksni). Runs on its own thread; its
//! menu/activate closures marshal a [`TrayCmd`] back to the GTK main loop over the
//! shared [`UiMsg`] channel. Icon, tooltip and menu come from the shared [`TrayView`].

use std::sync::{Arc, Mutex};

use crate::engine::{State, TrayCmd, Tx, UiMsg};
use crate::icon;
use crate::session::{self, Tone};

/// What the tray shows, written by the app on every change.
#[derive(Clone, Default, PartialEq)]
pub struct TrayView {
    /// The running connections: name and state.
    pub sessions: Vec<(String, State)>,
    /// Saved profile names, in the app's order — one menu entry each.
    pub profiles: Vec<String>,
    /// The last connection to end failed.
    pub failed: bool,
}

impl TrayView {
    fn state_of(&self, name: &str) -> Option<&State> {
        self.sessions
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, s)| s)
    }
}

pub struct VpnTray {
    pub view: Arc<Mutex<TrayView>>,
    pub tx: Tx,
}

impl VpnTray {
    fn send(&self, cmd: TrayCmd) {
        let _ = self.tx.try_send(UiMsg::Tray(cmd));
    }

    fn view(&self) -> TrayView {
        self.view.lock().unwrap().clone()
    }
}

fn session_line(name: &str, st: &State) -> String {
    match st {
        State::Connected => format!("Connected — {name}"),
        State::Connecting => format!("Connecting to {name}…"),
        State::Reconnecting => format!("Reconnecting — {name}…"),
        State::Disconnecting => format!("Disconnecting {name}…"),
        State::Error(_) => format!("{name} failed"),
        State::Disconnected => format!("{name} disconnected"),
    }
}

impl ksni::Tray for VpnTray {
    // A left click opens the menu (pick a profile and connect, NetworkManager-style)
    // instead of the window; "Show unvpn" is in the menu.
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        "unvpn".into()
    }
    fn title(&self) -> String {
        "unvpn".into()
    }
    fn icon_name(&self) -> String {
        String::new() // we supply a pixmap instead, so the icon is theme-independent
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let v = self.view();
        let states: Vec<State> = v.sessions.iter().map(|(_, s)| s.clone()).collect();
        icon::tray_pixmaps(session::overall(&states, v.failed).1.rgb())
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        let v = self.view();
        let description = if v.sessions.is_empty() {
            let states: Vec<State> = Vec::new();
            session::overall(&states, v.failed).0
        } else {
            v.sessions
                .iter()
                .map(|(n, s)| session_line(n, s))
                .collect::<Vec<_>>()
                .join("\n")
        };
        ksni::ToolTip {
            icon_name: String::new(),
            icon_pixmap: vec![],
            title: "unvpn".into(),
            description,
        }
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(TrayCmd::Show);
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        let v = self.view();
        let mut items: Vec<MenuItem<Self>> = Vec::new();
        let status = |label: String| -> MenuItem<Self> {
            StandardItem {
                label: label.replace('_', "__"),
                enabled: false,
                ..Default::default()
            }
            .into()
        };
        if v.sessions.is_empty() {
            items.push(status(if v.failed {
                "Connection failed".into()
            } else {
                "Disconnected".into()
            }));
        }
        for (n, s) in &v.sessions {
            items.push(status(session_line(n, s)));
        }
        items.push(MenuItem::Separator);

        if v.profiles.is_empty() {
            items.push(
                StandardItem {
                    label: "No saved profiles".into(),
                    enabled: false,
                    ..Default::default()
                }
                .into(),
            );
        }
        // Each profile toggles its own connection; the others stay as they are.
        for name in &v.profiles {
            let st = v.state_of(name);
            let checked = st.is_some_and(|s| session::tone(s) != Tone::Off);
            let name = name.clone();
            items.push(
                CheckmarkItem {
                    // `_` marks an access key in dbusmenu labels; keep it literal.
                    label: name.replace('_', "__"),
                    checked,
                    enabled: st != Some(&State::Disconnecting),
                    activate: Box::new(move |t: &mut Self| {
                        t.send(if checked {
                            TrayCmd::Disconnect(name.clone())
                        } else {
                            TrayCmd::ConnectProfile(name.clone())
                        })
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }

        items.push(MenuItem::Separator);
        if !v.sessions.is_empty() {
            items.push(
                StandardItem {
                    label: if v.sessions.len() > 1 {
                        "Disconnect All".into()
                    } else {
                        "Disconnect".into()
                    },
                    activate: Box::new(|t: &mut Self| t.send(TrayCmd::DisconnectAll)),
                    ..Default::default()
                }
                .into(),
            );
        }
        items.push(
            StandardItem {
                label: "Show unvpn".into(),
                activate: Box::new(|t: &mut Self| t.send(TrayCmd::Show)),
                ..Default::default()
            }
            .into(),
        );
        items.push(
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|t: &mut Self| t.send(TrayCmd::Quit)),
                ..Default::default()
            }
            .into(),
        );
        items
    }
}

/// True if a StatusNotifierWatcher (a tray host) is on the session bus, so it is
/// worth spawning the tray service.
pub fn tray_available() -> bool {
    use dbus::blocking::Connection;
    let Ok(c) = Connection::new_session() else {
        return false;
    };
    let proxy = c.with_proxy(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        std::time::Duration::from_millis(400),
    );
    let r: Result<(bool,), _> = proxy.method_call(
        "org.freedesktop.DBus",
        "NameHasOwner",
        ("org.kde.StatusNotifierWatcher",),
    );
    r.map(|(b,)| b).unwrap_or(false)
}
