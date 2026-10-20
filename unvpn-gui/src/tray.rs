//! System-tray icon (StatusNotifierItem via ksni). Runs on its own thread; its
//! menu/activate closures marshal a [`TrayCmd`] back to the GTK main loop over the
//! shared [`UiMsg`] channel. The icon colour is derived from the shared [`State`].

use std::sync::{Arc, Mutex};

use crate::engine::{State, Tx, TrayCmd, UiMsg};
use crate::icon;

pub struct VpnTray {
    pub state: Arc<Mutex<State>>,
    pub tx: Tx,
    /// Active profile name (shown in the tooltip while connected); set by the GUI.
    pub profile: Arc<Mutex<String>>,
}

impl VpnTray {
    fn send(&self, cmd: TrayCmd) {
        let _ = self.tx.try_send(UiMsg::Tray(cmd));
    }
}

impl ksni::Tray for VpnTray {
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
            State::Connecting | State::Disconnecting => [245, 194, 17],
            State::Error(_) => [224, 27, 36],
            State::Disconnected => [154, 153, 150],
        };
        icon::tray_pixmaps(color)
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        // While connected, show the active profile name; otherwise the status.
        let desc = match &*self.state.lock().unwrap() {
            State::Connected => {
                let p = self.profile.lock().unwrap().clone();
                if p.is_empty() { "Connected".to_string() } else { p }
            }
            State::Connecting => "Connecting…".to_string(),
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
        self.send(TrayCmd::Show); // left-click opens the window
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        let state = self.state.lock().unwrap().clone();
        let connected = matches!(state, State::Connected | State::Connecting);
        let label = match state {
            State::Connected | State::Connecting => "Disconnect",
            State::Disconnecting => "Disconnecting…",
            _ => "Connect…",
        };
        vec![
            StandardItem {
                label: "Show unvpn".into(),
                activate: Box::new(|t: &mut Self| t.send(TrayCmd::Show)),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: label.into(),
                enabled: state != State::Disconnecting,
                activate: Box::new(move |t: &mut Self| {
                    t.send(if connected { TrayCmd::Disconnect } else { TrayCmd::Connect })
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|t: &mut Self| t.send(TrayCmd::Quit)),
                ..Default::default()
            }
            .into(),
        ]
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
