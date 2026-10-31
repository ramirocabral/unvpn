//! System-tray icon (StatusNotifierItem via ksni). Runs on its own thread; its
//! menu/activate closures marshal a [`TrayCmd`] back to the GTK main loop over the
//! shared [`UiMsg`] channel. The icon colour is derived from the shared [`State`].

use std::sync::{Arc, Mutex};

use crate::engine::{State, Tx, TrayCmd, UiMsg};
use crate::icon;

pub struct VpnTray {
    pub state: Arc<Mutex<State>>,
    pub tx: Tx,
    /// Active profile name (tooltip while connected); set by the GUI.
    pub profile: Arc<Mutex<String>>,
    /// Saved profile names, in the GUI's order — one menu entry each.
    pub profiles: Arc<Mutex<Vec<String>>>,
}

impl VpnTray {
    fn send(&self, cmd: TrayCmd) {
        let _ = self.tx.try_send(UiMsg::Tray(cmd));
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
        let color = match &*self.state.lock().unwrap() {
            State::Connected => [46, 194, 126],
            State::Connecting | State::Reconnecting | State::Disconnecting => [245, 194, 17],
            State::Error(_) => [224, 27, 36],
            State::Disconnected => [154, 153, 150],
        };
        icon::tray_pixmaps(color)
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        let desc = match &*self.state.lock().unwrap() {
            State::Connected => {
                let p = self.profile.lock().unwrap().clone();
                if p.is_empty() { "Connected".to_string() } else { p }
            }
            State::Connecting => "Connecting…".to_string(),
            State::Reconnecting => {
                let p = self.profile.lock().unwrap().clone();
                if p.is_empty() { "Reconnecting…".to_string() } else { format!("Reconnecting — {p}") }
            }
            State::Disconnecting => "Disconnecting…".to_string(),
            State::Error(_) => "Error".to_string(),
            State::Disconnected => "Disconnected".to_string(),
        };
        ksni::ToolTip {
            icon_name: String::new(),
            icon_pixmap: vec![],
            title: "unvpn".into(),
            description: desc,
        }
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(TrayCmd::Show);
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        let state = self.state.lock().unwrap().clone();
        let active = self.profile.lock().unwrap().clone();
        let up = matches!(state, State::Connected | State::Connecting | State::Reconnecting);

        let status = match &state {
            State::Connected => format!("Connected — {active}"),
            State::Connecting => format!("Connecting to {active}…"),
            State::Reconnecting => format!("Reconnecting — {active}…"),
            State::Disconnecting => "Disconnecting…".to_string(),
            State::Error(_) => "Connection failed".to_string(),
            State::Disconnected => "Disconnected".to_string(),
        };
        let mut items: Vec<MenuItem<Self>> = vec![
            StandardItem { label: status, enabled: false, ..Default::default() }.into(),
            MenuItem::Separator,
        ];

        let profiles = self.profiles.lock().unwrap().clone();
        if profiles.is_empty() {
            items.push(
                StandardItem { label: "No saved profiles".into(), enabled: false, ..Default::default() }.into(),
            );
        }
        // Picking the active profile disconnects it; picking another one switches.
        for name in profiles {
            let checked = up && name == active;
            items.push(
                CheckmarkItem {
                    // `_` marks an access key in dbusmenu labels; keep it literal.
                    label: name.replace('_', "__"),
                    checked,
                    enabled: state != State::Disconnecting,
                    activate: Box::new(move |t: &mut Self| {
                        t.send(if checked { TrayCmd::Disconnect } else { TrayCmd::ConnectProfile(name.clone()) })
                    }),
                    ..Default::default()
                }
                .into(),
            );
        }

        items.push(MenuItem::Separator);
        if up {
            items.push(
                StandardItem {
                    label: "Disconnect".into(),
                    activate: Box::new(|t: &mut Self| t.send(TrayCmd::Disconnect)),
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
