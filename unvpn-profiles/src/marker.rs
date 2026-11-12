//! The engine's machine-readable output: `# NAME: value` lines on its stdout that
//! the app and `unvpn connect` act on. Human log lines go alongside and are only
//! ever shown.
//!
//! A marker counts only at the very start of a line, and every value is flattened
//! to one line when written, so text from a gateway can't start a marker of its own.

use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum State {
    #[default]
    Connecting,
    Up,
    /// The tunnel dropped and is being rebuilt; the engine is still running.
    Reconnecting,
    /// The engine is done (tearing down or exiting).
    Down,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Connecting => "connecting",
            State::Up => "up",
            State::Reconnecting => "reconnecting",
            State::Down => "down",
        }
    }

    pub fn parse(s: &str) -> Option<State> {
        Some(match s {
            "connecting" => State::Connecting,
            "up" => State::Up,
            "reconnecting" => State::Reconnecting,
            "down" => State::Down,
            _ => return None,
        })
    }
}

/// Why a run failed, in `ERROR` markers.
pub const ERROR_CONNECT: &str = "connect";
/// The tunnel had been up and could not be kept.
pub const ERROR_TUNNEL: &str = "tunnel";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Marker {
    /// A question for the user (`code`, `push`, `sso`, `trust`, …), answered with
    /// one stdin line.
    Prompt { kind: String, message: String },
    /// SSO: the sign-in page to open.
    SamlUrl(String),
    /// SSO in an embedded browser: the page that ends the flow…
    SamlFinal(String),
    /// …and the cookie that then holds the token.
    SamlCookie(String),
    /// SSO (GlobalProtect): the result comes back as these response headers.
    SamlHeaders(String),
    State(State),
    /// The tunnel's address (again when the gateway hands out a new one).
    Ip(IpAddr),
    /// The resolvers now in use for the tunnel.
    Dns(Vec<IpAddr>),
    /// The tunnel's network interface.
    Iface(String),
    /// The run failed; `kind` is [`ERROR_CONNECT`] or [`ERROR_TUNNEL`].
    Error { kind: String, message: String },
}

const PROMPT: &str = "AUTH-PROMPT";
const SAML_URL: &str = "SAML-URL";
const SAML_FINAL: &str = "SAML-FINAL";
const SAML_COOKIE: &str = "SAML-COOKIE";
const SAML_HEADERS: &str = "SAML-HEADERS";
const STATE: &str = "STATE";
const IP: &str = "IP";
const DNS: &str = "DNS";
const IFACE: &str = "IFACE";
const ERROR: &str = "ERROR";

impl Marker {
    /// The line to print (no trailing newline).
    pub fn line(&self) -> String {
        match self {
            Marker::Prompt { kind, message } => {
                let message = one_line(message);
                if message.is_empty() {
                    format!("# {PROMPT}: {}", word(kind))
                } else {
                    format!("# {PROMPT}: {}: {message}", word(kind))
                }
            }
            Marker::SamlUrl(u) => format!("# {SAML_URL}: {}", one_word(u)),
            Marker::SamlFinal(u) => format!("# {SAML_FINAL}: {}", one_word(u)),
            Marker::SamlCookie(c) => format!("# {SAML_COOKIE}: {}", one_word(c)),
            Marker::SamlHeaders(h) => format!("# {SAML_HEADERS}: {}", one_line(h)),
            Marker::State(s) => format!("# {STATE}: {}", s.as_str()),
            Marker::Ip(ip) => format!("# {IP}: {ip}"),
            Marker::Dns(d) => format!("# {DNS}: {}", d.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")),
            Marker::Iface(i) => format!("# {IFACE}: {}", word(i)),
            Marker::Error { kind, message } => format!("# {ERROR}: {}: {}", word(kind), one_line(message)),
        }
    }
}

/// The marker on `line`, if it is one (a trailing `\r` is ignored).
pub fn parse(line: &str) -> Option<Marker> {
    let rest = line.trim_end_matches('\r').strip_prefix("# ")?;
    let (name, value) = match rest.split_once(':') {
        Some((n, v)) => (n, v.strip_prefix(' ').unwrap_or(v)),
        None => return None,
    };
    let kind_and_text = |v: &str| {
        let (k, m) = v.split_once(": ").unwrap_or((v, ""));
        (k.trim().to_string(), m.trim().to_string())
    };
    Some(match name {
        PROMPT => {
            let (kind, message) = kind_and_text(value);
            if kind.is_empty() {
                return None;
            }
            Marker::Prompt { kind, message }
        }
        SAML_URL => Marker::SamlUrl(value.trim().to_string()),
        SAML_FINAL => Marker::SamlFinal(value.trim().to_string()),
        SAML_COOKIE => Marker::SamlCookie(value.trim().to_string()),
        SAML_HEADERS => Marker::SamlHeaders(value.trim().to_string()),
        STATE => Marker::State(State::parse(value.trim())?),
        IP => Marker::Ip(value.trim().parse().ok()?),
        DNS => {
            let list: Option<Vec<IpAddr>> =
                value.split(',').map(str::trim).filter(|s| !s.is_empty()).map(|s| s.parse().ok()).collect();
            Marker::Dns(list?)
        }
        IFACE => {
            let i = value.trim();
            if !is_iface_name(i) {
                return None;
            }
            Marker::Iface(i.to_string())
        }
        ERROR => {
            let (kind, message) = kind_and_text(value);
            Marker::Error { kind, message }
        }
        _ => return None,
    })
}

/// A Linux interface name: 1–15 of `[A-Za-z0-9_.-]`, so it is safe in a `/sys` path.
pub fn is_iface_name(s: &str) -> bool {
    (1..=15).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Text flattened to one short line for the log and markers: control characters
/// become spaces, whitespace runs collapse, cut at 300 characters.
pub fn one_line(s: &str) -> String {
    let flat: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(300).collect()
}

/// A URL or name with control and whitespace characters removed.
pub fn one_word(s: &str) -> String {
    s.chars().filter(|c| !c.is_control() && !c.is_whitespace()).collect()
}

/// A short token (a prompt or error kind): no `:` either, so it can't swallow the text after it.
fn word(s: &str) -> String {
    one_word(s).replace(':', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(m: Marker) {
        assert_eq!(parse(&m.line()).as_ref(), Some(&m), "{}", m.line());
    }

    #[test]
    fn every_marker_reads_back() {
        round_trip(Marker::Prompt { kind: "code".into(), message: "Enter the code".into() });
        round_trip(Marker::Prompt { kind: "push".into(), message: String::new() });
        round_trip(Marker::SamlUrl("https://vpn.example.com/remote/saml/start?x=1".into()));
        round_trip(Marker::SamlFinal("https://vpn.example.com/+CSCOE+/saml_ac_login.html".into()));
        round_trip(Marker::SamlCookie("acSamlv2Token".into()));
        round_trip(Marker::SamlHeaders("saml-username prelogin-cookie".into()));
        for s in [State::Connecting, State::Up, State::Reconnecting, State::Down] {
            round_trip(Marker::State(s));
        }
        round_trip(Marker::Ip("198.51.100.7".parse().unwrap()));
        round_trip(Marker::Dns(vec!["203.0.113.53".parse().unwrap(), "2001:db8::53".parse().unwrap()]));
        round_trip(Marker::Dns(Vec::new()));
        round_trip(Marker::Iface("unvpn0".into()));
        round_trip(Marker::Error { kind: ERROR_TUNNEL.into(), message: "tunnel dropped (read: EOF) and gave up".into() });
    }

    #[test]
    fn the_lines_front_ends_have_always_read() {
        assert_eq!(
            parse("# AUTH-PROMPT: code: Enter the code: now"),
            Some(Marker::Prompt { kind: "code".into(), message: "Enter the code: now".into() })
        );
        assert_eq!(parse("# AUTH-PROMPT: push"), Some(Marker::Prompt { kind: "push".into(), message: String::new() }));
        assert_eq!(
            parse("# SAML-HEADERS: saml-username prelogin-cookie portal-userauthcookie"),
            Some(Marker::SamlHeaders("saml-username prelogin-cookie portal-userauthcookie".into()))
        );
    }

    #[test]
    fn only_a_whole_marker_at_the_start_of_a_line_counts() {
        assert_eq!(parse("gateway says # AUTH-PROMPT: code: x"), None);
        assert_eq!(parse("#AUTH-PROMPT: code: x"), None);
        assert_eq!(parse("AUTH-PROMPT: code: x"), None);
        assert_eq!(parse("# TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)"), None);
        assert_eq!(parse("# DNS → [203.0.113.53]"), None);
        assert_eq!(parse("# STATE: up — try again"), None);
        assert_eq!(parse("# IP: 198.51.100.7 — try again"), None);
        assert_eq!(parse("# DNS: 203.0.113.53, nameserver"), None);
        assert_eq!(parse("# IFACE: ../../etc"), None);
        assert_eq!(parse("# IFACE: an-interface-name-too-long"), None);
    }

    #[test]
    fn values_are_flattened_when_written() {
        let m = Marker::Prompt { kind: "code".into(), message: "a\n# STATE: up".into() };
        assert_eq!(m.line(), "# AUTH-PROMPT: code: a # STATE: up");
        let m = Marker::Error { kind: "x: y".into(), message: "line\r\nERROR".into() };
        assert_eq!(m.line(), "# ERROR: xy: line ERROR");
        assert_eq!(Marker::SamlUrl("https://idp.example.com/a\n# AUTH-PROMPT: keypass: x".into()).line(),
            "# SAML-URL: https://idp.example.com/a#AUTH-PROMPT:keypass:x");
    }

    #[test]
    fn one_line_strips_controls() {
        assert_eq!(one_line("a\r\n# SAML-URL: x\tb"), "a # SAML-URL: x b");
        assert_eq!(one_line(&"x".repeat(400)).len(), 300);
    }
}
