//! What every tunnel back-end does around its data plane: bring the tun up,
//! install routes, DNS and the leak guard, and reconnect with backoff.

use crate::sysnet::{self, NetRestore};
use crate::tun;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};

pub type Net = (Ipv4Addr, u8);

/// The routes of one tunnel.
#[derive(Debug, Default, Clone)]
pub struct RoutePlan {
    /// Pinned to its pre-VPN path, so the tunnel's own packets never loop into it.
    pub gateway: Option<Ipv4Addr>,
    /// Kept on their pre-VPN path (split-tunnel excludes).
    pub exclude: Vec<Net>,
    /// Everything into the tunnel, as 0/1 + 128/1 (which beat the real default
    /// route without replacing it, so the gateway pin holds).
    pub full: bool,
    /// Into the tunnel. A /0 here means `full`.
    pub include: Vec<Net>,
}

/// `ip -batch` lines for a plan.
#[derive(Debug, PartialEq)]
struct Lines {
    add: Vec<String>,
    /// The gateway pin's index in `add` and what it routes.
    pin: Option<(usize, String)>,
}

impl RoutePlan {
    /// Everything goes into the tunnel.
    pub fn is_full(&self) -> bool {
        self.full || self.include.iter().any(|&(_, len)| len == 0)
    }

    fn lines(&self, tun: &str, path: impl Fn(IpAddr) -> Option<String>) -> Lines {
        let mut add = Vec::new();
        let mut pin = None;
        if let Some(gw) = self.gateway {
            if let Some(p) = path(gw.into()) {
                pin = Some((add.len(), format!("{gw}/32 ({p})")));
                add.push(format!("route add {gw}/32 {p}"));
            }
        }
        for &(net, len) in &self.exclude {
            if let Some(p) = path(net.into()) {
                add.push(format!("route add {net}/{len} {p}"));
            }
        }
        if self.is_full() {
            for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                add.push(format!("route add {half} dev {tun}"));
            }
        }
        for &(net, len) in self.include.iter().filter(|&&(_, len)| len > 0) {
            add.push(format!("route add {net}/{len} dev {tun}"));
        }
        Lines { add, pin }
    }

    /// Install the plan in one `ip -batch`. Returns the `route del` lines for the
    /// routes this added (not those that already existed).
    pub fn install(&self, tun: &str) -> Vec<String> {
        let Lines { add, pin } = self.lines(tun, original_path);
        let full = self.is_full();
        let split = self.include.iter().filter(|&&(_, len)| len > 0).count();
        if full {
            out!("# full tunnel: 0.0.0.0/1 + 128.0.0.0/1 via {tun}");
        }
        if split > 0 {
            out!("# split tunnel: {split} route(s) via {tun}");
        }
        if !full && split == 0 {
            out!("# no routes into the tunnel: only its own subnet is reachable");
        }
        let failed = tun::ip_batch_failed(&add).unwrap_or_default();
        if let Some((i, what)) = pin {
            if failed.contains(&i) {
                out!("# gateway route {what} already present — left as is");
            } else {
                out!("# pinned gateway route {what}");
            }
        }
        if !failed.is_empty() {
            out!(
                "# {} route(s) already existed — not ours, kept on disconnect",
                failed.len()
            );
        }
        add.into_iter()
            .enumerate()
            .filter(|(i, _)| !failed.contains(i))
            .map(|(_, l)| l.replacen("route add ", "route del ", 1))
            .collect()
    }
}

/// `via X dev Y` (or `dev Y`) of the route the kernel picks for `dst` now.
pub fn original_path(dst: IpAddr) -> Option<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "get", &dst.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_route_get(&String::from_utf8_lossy(&out.stdout))
}

fn parse_route_get(text: &str) -> Option<String> {
    let toks: Vec<&str> = text
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .collect();
    let after = |key: &str| toks.windows(2).find(|w| w[0] == key).map(|w| w[1]);
    let dev = after("dev")?;
    Some(match after("via") {
        Some(v) => format!("via {v} dev {dev}"),
        None => format!("dev {dev}"),
    })
}

pub fn resolve_v4(host: &str, port: u16) -> Result<Ipv4Addr, String> {
    use std::net::ToSocketAddrs;
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(ip);
    }
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve {host}: {e}"))?
        .find_map(|sa| match sa.ip() {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .ok_or_else(|| format!("no IPv4 address for {host}"))
}

/// Open a tun device named like `name`, address it and bring it up.
pub fn open_tun(name: &str, addr: Net, mtu: u32) -> Result<(File, String), String> {
    let (file, dev) = tun::open_tun(name)?;
    let (ip, len) = addr;
    tun::ip(&["addr", "add", &format!("{ip}/{len}"), "dev", &dev])?;
    tun::ip(&["link", "set", "dev", &dev, "up", "mtu", &mtu.to_string()])?;
    // Our own route and address churn on it must not read as a network change.
    crate::netmon::ignore_iface(&dev);
    out!("# tun {dev} up — {ip}/{len}, mtu {mtu}");
    Ok((file, dev))
}

/// Move the tun to the address the gateway handed out on a reconnect.
pub fn readdress(dev: &str, old: Net, new: Net) {
    if old == new {
        return;
    }
    out!(
        "# gateway reassigned IP {} → {}; re-addressing {dev}",
        old.0,
        new.0
    );
    let _ = tun::ip(&["addr", "del", &format!("{}/{}", old.0, old.1), "dev", dev]);
    let _ = tun::ip(&["addr", "add", &format!("{}/{}", new.0, new.1), "dev", dev]);
}

/// From here every exit path must undo what the tunnel changes, so signals only
/// raise `stop`; a disconnect asked for while connecting means touching nothing.
pub fn arm_stop(stop: &'static AtomicBool) -> Result<(), String> {
    sysnet::install_stop_signals(stop);
    if sysnet::stop_requested() || stop.load(Ordering::SeqCst) {
        return Err("disconnect requested before the tunnel came up".into());
    }
    Ok(())
}

/// Routes, DNS and the leak guard for the tunnel on `dev`; with no plan
/// (`--no-routes`) none of them. Undone when the result drops.
pub fn configure(
    dev: &str,
    plan: Option<&RoutePlan>,
    dns: &[Ipv4Addr],
    domains: &str,
) -> Result<NetRestore, String> {
    let mut restore = NetRestore::default();
    match plan {
        None => out!("# --no-routes: installing no routes/DNS (reach hosts with `ping -I {dev}`)"),
        Some(plan) => {
            if let Some(gw) = plan.gateway {
                crate::netmon::watch_gateway(gw);
            }
            restore.routes = plan.install(dev);
            let dns = crate::dns::tunnelled_dns(dns, dev);
            restore.dns = crate::dns::set_dns(dev, &dns, domains, plan.is_full());
            let pinned: Vec<Ipv4Addr> = plan.gateway.into_iter().collect();
            restore.leak = crate::leakguard::enable(dev, &pinned)?;
        }
    }
    restore.commit(dev);
    Ok(restore)
}

pub enum Reconnect<T> {
    Up(T),
    /// The user disconnected while waiting.
    Stopped,
    /// An attempt failed in a way retrying can't fix.
    Fatal(String),
    GaveUp,
}

/// Seconds before reconnect attempt `n` (from 1).
pub fn backoff(attempt: u32) -> u64 {
    match attempt {
        1 => 1,
        2 => 2,
        3 => 5,
        _ => 10,
    }
}

/// Retry `open` up to `max` times with [`backoff`] (`first_delay` instead for
/// the first attempt).
pub fn reconnect<T>(
    stop: &AtomicBool,
    max: u32,
    first_delay: Option<u64>,
    is_fatal: impl Fn(&str) -> bool,
    mut open: impl FnMut() -> Result<T, String>,
) -> Reconnect<T> {
    for attempt in 1..=max {
        if stop.load(Ordering::SeqCst) {
            return Reconnect::Stopped;
        }
        let delay = match first_delay {
            Some(d) if attempt == 1 => d,
            _ => backoff(attempt),
        };
        if delay > 0 {
            out!("# reconnecting in {delay}s (attempt {attempt}/{max}) …");
            if sysnet::sleep_interruptible(delay, stop) {
                return Reconnect::Stopped;
            }
        }
        match open() {
            Ok(t) => return Reconnect::Up(t),
            Err(e) if is_fatal(&e) => return Reconnect::Fatal(e),
            Err(e) => out!("# reconnect attempt {attempt}/{max} failed: {e}"),
        }
    }
    Reconnect::GaveUp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(dst: IpAddr) -> Option<String> {
        match dst.to_string().as_str() {
            "198.51.100.1" => Some("via 192.0.2.1 dev eth0".into()),
            "203.0.113.0" => Some("dev wlan0".into()),
            _ => None,
        }
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn full_tunnel_with_pin_and_exclude() {
        let plan = RoutePlan {
            gateway: Some(ip("198.51.100.1")),
            exclude: vec![(ip("203.0.113.0"), 24), (ip("192.0.2.128"), 25)],
            full: true,
            include: vec![(ip("10.0.0.0"), 8)],
        };
        assert_eq!(
            plan.lines("tun0", path),
            Lines {
                add: vec![
                    "route add 198.51.100.1/32 via 192.0.2.1 dev eth0".into(),
                    "route add 203.0.113.0/24 dev wlan0".into(),
                    "route add 0.0.0.0/1 dev tun0".into(),
                    "route add 128.0.0.0/1 dev tun0".into(),
                    "route add 10.0.0.0/8 dev tun0".into(),
                ],
                pin: Some((0, "198.51.100.1/32 (via 192.0.2.1 dev eth0)".into())),
            }
        );
    }

    #[test]
    fn default_include_becomes_halves_and_unknown_gateway_is_not_pinned() {
        let plan = RoutePlan {
            gateway: Some(ip("192.0.2.9")),
            include: vec![(ip("0.0.0.0"), 0), (ip("172.16.0.0"), 12)],
            ..Default::default()
        };
        assert_eq!(
            plan.lines("tun1", path),
            Lines {
                add: vec![
                    "route add 0.0.0.0/1 dev tun1".into(),
                    "route add 128.0.0.0/1 dev tun1".into(),
                    "route add 172.16.0.0/12 dev tun1".into(),
                ],
                pin: None,
            }
        );
    }

    #[test]
    fn route_get_output() {
        assert_eq!(
            parse_route_get(
                "198.51.100.1 via 192.0.2.1 dev eth0 src 192.0.2.7 uid 0 \n    cache \n"
            )
            .as_deref(),
            Some("via 192.0.2.1 dev eth0")
        );
        assert_eq!(
            parse_route_get("192.0.2.5 dev wlan0 src 192.0.2.7 uid 1000").as_deref(),
            Some("dev wlan0")
        );
        assert_eq!(
            parse_route_get("RTNETLINK answers: Network is unreachable"),
            None
        );
    }

    #[test]
    fn reconnect_retries_then_gives_up_or_stops() {
        let stop = AtomicBool::new(false);
        let mut tries = 0;
        let r = reconnect(
            &stop,
            3,
            Some(0),
            |_| false,
            || {
                tries += 1;
                if tries == 2 {
                    stop.store(true, Ordering::SeqCst);
                }
                Err::<(), _>("refused".to_string())
            },
        );
        assert!(matches!(r, Reconnect::Stopped));
        assert_eq!(tries, 2);

        let stop = AtomicBool::new(false);
        let r = reconnect(
            &stop,
            3,
            Some(0),
            |e| e.starts_with("AUTH"),
            || Err::<(), _>("AUTH FAILED".to_string()),
        );
        assert!(matches!(r, Reconnect::Fatal(e) if e == "AUTH FAILED"));

        let r = reconnect(&stop, 1, Some(0), |_| false, || Ok(7));
        assert!(matches!(r, Reconnect::Up(7)));
        let r = reconnect(&stop, 1, Some(0), |_| false, || Err::<(), _>("x".into()));
        assert!(matches!(r, Reconnect::GaveUp));
    }
}
