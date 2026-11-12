//! What the engine reports about its session: the markers on stdout (see
//! `unvpn_profiles::marker`) and the status its control socket serves.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use unvpn_profiles::marker::{self, Marker, State, ERROR_CONNECT, ERROR_TUNNEL};

use crate::control;

static WAS_UP: AtomicBool = AtomicBool::new(false);

fn emit(m: Marker) {
    out!("{}", m.line());
}

/// The tunnel has been up at some point in this run.
pub fn was_up() -> bool {
    WAS_UP.load(Ordering::SeqCst)
}

pub fn prompt(kind: &str, message: &str) {
    emit(Marker::Prompt {
        kind: kind.to_string(),
        message: message.to_string(),
    });
}

pub fn saml_url(url: &str) {
    emit(Marker::SamlUrl(url.to_string()));
}

pub fn saml_final(url: &str) {
    emit(Marker::SamlFinal(url.to_string()));
}

pub fn saml_cookie(name: &str) {
    emit(Marker::SamlCookie(name.to_string()));
}

pub fn saml_headers(names: &str) {
    emit(Marker::SamlHeaders(names.to_string()));
}

/// The gateway, for `unvpn status`, when the command line didn't name it.
pub fn gateway(host: &str) {
    control::update(|s| {
        if s.gateway.is_empty() {
            s.gateway = host.to_string();
        }
    });
}

fn state(st: State) {
    control::update(|s| s.state = st);
    emit(Marker::State(st));
}

pub fn connecting() {
    state(State::Connecting);
}

/// The tunnel is up on `iface`, with address `ip`.
pub fn up(iface: &str, ip: Option<IpAddr>) {
    WAS_UP.store(true, Ordering::SeqCst);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    control::update(|s| {
        s.iface = iface.to_string();
        if let Some(ip) = ip {
            s.ip = ip.to_string();
        }
        if s.since == 0 {
            s.since = now;
        }
    });
    if marker::is_iface_name(iface) {
        emit(Marker::Iface(iface.to_string()));
    }
    if let Some(ip) = ip {
        emit(Marker::Ip(ip));
    }
    state(State::Up);
}

/// The gateway handed out a new address.
pub fn ip(ip: IpAddr) {
    control::update(|s| s.ip = ip.to_string());
    emit(Marker::Ip(ip));
}

/// The resolvers now in use.
pub fn dns<A: std::fmt::Display>(servers: &[A]) {
    let list: Vec<IpAddr> = servers
        .iter()
        .filter_map(|d| d.to_string().parse().ok())
        .collect();
    control::update(|s| s.dns = list.iter().map(|d| d.to_string()).collect());
    emit(Marker::Dns(list));
}

/// The tunnel dropped and is being rebuilt.
pub fn reconnecting() {
    state(State::Reconnecting);
}

/// The tunnel is back, at `ip` when that is known (or changed).
pub fn recovered(ip: Option<IpAddr>) {
    if let Some(ip) = ip {
        self::ip(ip);
    }
    state(State::Up);
}

pub fn down() {
    state(State::Down);
}

/// End the run on an error: `<what> failed: <err>` on stderr, then the `ERROR` and
/// `STATE: down` markers.
pub fn fail(what: &str, err: &str) -> ! {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "{what} failed: {err}");
    let kind = if was_up() {
        ERROR_TUNNEL
    } else {
        ERROR_CONNECT
    };
    control::update(|s| s.error = marker::one_line(err));
    emit(Marker::Error {
        kind: kind.to_string(),
        message: err.to_string(),
    });
    down();
    std::process::exit(1);
}

/// A `# ` log line whose text may start with words from the gateway: indented when
/// it would otherwise read as a marker.
pub fn note(line: &str) {
    let l = format!("# {line}");
    if marker::parse(&l).is_some() {
        out!("#   {line}");
    } else {
        out!("{l}");
    }
}
