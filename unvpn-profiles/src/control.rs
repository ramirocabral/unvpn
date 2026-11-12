//! The control socket each running engine serves, used by `unvpn status`,
//! `unvpn disconnect` and the app to find tunnels and stop them, including ones
//! the asking process didn't start. `/run/unvpn/<pid>.sock`; only the user who
//! started the engine (and root) may use it.
//!
//! A request is one line: `status`, `disconnect` or `log <after>`. The engine
//! answers and closes the connection.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::marker::State;

pub const RUN_DIR: &str = "/run/unvpn";

pub fn socket_path(pid: u32) -> PathBuf {
    Path::new(RUN_DIR).join(format!("{pid}.sock"))
}

/// What `status` reports about one engine.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub pid: u32,
    /// The engine sub-command (`ike`, `forti`, `wireguard`, …).
    pub backend: String,
    /// The front-end's name for the connection, usually the profile name.
    pub label: String,
    pub gateway: String,
    pub state: State,
    pub iface: String,
    pub ip: String,
    pub dns: Vec<String>,
    /// Unix time the tunnel first came up; 0 before that.
    pub since: u64,
    /// Why the run failed, once it has.
    pub error: String,
}

impl Status {
    /// `key=value` lines, the socket's wire format.
    pub fn encode(&self) -> String {
        let one = |s: &str| s.replace(['\n', '\r'], " ");
        format!(
            "pid={}\nbackend={}\nlabel={}\ngateway={}\nstate={}\niface={}\nip={}\ndns={}\nsince={}\nerror={}\n",
            self.pid,
            one(&self.backend),
            one(&self.label),
            one(&self.gateway),
            self.state.as_str(),
            one(&self.iface),
            one(&self.ip),
            one(&self.dns.join(",")),
            self.since,
            one(&self.error),
        )
    }

    pub fn decode(text: &str) -> Status {
        let mut s = Status::default();
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match k {
                "pid" => s.pid = v.parse().unwrap_or(0),
                "backend" => s.backend = v.to_string(),
                "label" => s.label = v.to_string(),
                "gateway" => s.gateway = v.to_string(),
                "state" => s.state = State::parse(v).unwrap_or_default(),
                "iface" => s.iface = v.to_string(),
                "ip" => s.ip = v.to_string(),
                "dns" => {
                    s.dns = v
                        .split(',')
                        .filter(|d| !d.is_empty())
                        .map(String::from)
                        .collect()
                }
                "since" => s.since = v.parse().unwrap_or(0),
                "error" => s.error = v.to_string(),
                _ => {}
            }
        }
        s
    }

    pub fn to_json(&self) -> String {
        let dns: Vec<String> = self.dns.iter().map(|d| json_str(d)).collect();
        format!(
            "{{\"pid\":{},\"backend\":{},\"label\":{},\"gateway\":{},\"state\":{},\"iface\":{},\"ip\":{},\"dns\":[{}],\"since\":{},\"error\":{}}}",
            self.pid,
            json_str(&self.backend),
            json_str(&self.label),
            json_str(&self.gateway),
            json_str(self.state.as_str()),
            json_str(&self.iface),
            json_str(&self.ip),
            dns.join(","),
            self.since,
            json_str(&self.error),
        )
    }

    /// The name to show for the connection: its label, else its gateway.
    pub fn name(&self) -> &str {
        if !self.label.is_empty() {
            &self.label
        } else if !self.gateway.is_empty() {
            &self.gateway
        } else {
            &self.backend
        }
    }
}

fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// The engines' sockets, oldest engine first. Includes sockets left behind by an
/// engine that was killed; [`status`] fails on those.
pub fn sockets() -> Vec<(u32, PathBuf)> {
    let Ok(dir) = std::fs::read_dir(RUN_DIR) else {
        return Vec::new();
    };
    let mut v: Vec<(u32, PathBuf)> = dir
        .filter_map(|e| {
            let e = e.ok()?;
            let name = e.file_name().into_string().ok()?;
            let pid = name.strip_suffix(".sock")?.parse().ok()?;
            Some((pid, e.path()))
        })
        .collect();
    v.sort();
    v
}

/// Send one request and read the whole answer.
pub fn request(path: &Path, req: &str) -> std::io::Result<String> {
    let mut s = UnixStream::connect(path)?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    s.set_write_timeout(Some(Duration::from_secs(3)))?;
    s.write_all(format!("{req}\n").as_bytes())?;
    let mut out = String::new();
    s.take(1 << 20).read_to_string(&mut out)?;
    Ok(out)
}

pub fn status(path: &Path) -> std::io::Result<Status> {
    let text = request(path, "status")?;
    if !text.starts_with("pid=") {
        return Err(std::io::Error::other(format!(
            "unexpected answer: {}",
            text.lines().next().unwrap_or("")
        )));
    }
    Ok(Status::decode(&text))
}

pub fn disconnect(path: &Path) -> std::io::Result<()> {
    match request(path, "disconnect")?.trim() {
        "ok" => Ok(()),
        other => Err(std::io::Error::other(format!("unexpected answer: {other}"))),
    }
}

/// The engine's log lines numbered above `after`, and the number to ask after next.
pub fn log(path: &Path, after: u64) -> std::io::Result<(u64, Vec<String>)> {
    let text = request(path, &format!("log {after}"))?;
    let mut lines = text.lines();
    let next = lines
        .next()
        .and_then(|l| l.strip_prefix("next="))
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| std::io::Error::other("unexpected answer to log"))?;
    Ok((next, lines.map(String::from).collect()))
}

/// Every engine answering on its socket, with its status, oldest first.
pub fn running() -> Vec<(PathBuf, Status)> {
    sockets()
        .into_iter()
        .filter_map(|(_, p)| status(&p).ok().map(|s| (p, s)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_and_renders_json() {
        let s = Status {
            pid: 4242,
            backend: "forti".into(),
            label: "office \"eu\"".into(),
            gateway: "vpn.example.com".into(),
            state: State::Up,
            iface: "unvpn0".into(),
            ip: "198.51.100.7".into(),
            dns: vec!["203.0.113.53".into(), "203.0.113.54".into()],
            since: 1_700_000_000,
            error: String::new(),
        };
        assert_eq!(Status::decode(&s.encode()), s);
        assert_eq!(
            s.to_json(),
            r#"{"pid":4242,"backend":"forti","label":"office \"eu\"","gateway":"vpn.example.com","state":"up","iface":"unvpn0","ip":"198.51.100.7","dns":["203.0.113.53","203.0.113.54"],"since":1700000000,"error":""}"#
        );
        let odd = Status {
            label: "a\nstate=down".into(),
            ..Default::default()
        };
        assert_eq!(Status::decode(&odd.encode()).state, State::Connecting);
        assert_eq!(json_str("a\u{1}b"), "\"a\\u0001b\"");
    }
}
