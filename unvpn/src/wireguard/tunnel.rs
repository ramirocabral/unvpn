//! Bring up a kernel WireGuard interface from a parsed `.conf`: create the link,
//! load keys/peers over netlink, address it, wait for the first handshake, then
//! routes + DNS; watch it until stopped; tear everything down.
//!
//! The kernel does the protocol (handshakes, timers, roaming, crypto); this side
//! only configures it and reports — like `wg-quick`, minus the hook scripts.

use super::config::{Config, Net, Table};
use super::keys;
use super::netlink::{DeviceSet, DeviceState, PeerSet, WgNetlink};
use crate::sysnet;
use crate::tun;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static WG_STOP: AtomicBool = AtomicBool::new(false);

const IF_NAME: &str = "cpwg0";
/// wg-quick's default: 1500 minus the IPv6 + UDP + WireGuard overhead (80).
const DEFAULT_MTU: u16 = 1420;
const HANDSHAKE_WAIT: Duration = Duration::from_secs(30);
/// Once one peer is up, how much longer to wait for the others.
const OTHERS_WAIT: Duration = Duration::from_secs(5);
/// Keepalive set on peers while waiting: turning keepalive on makes the kernel
/// send a keepalive (hence a handshake) at once, without any tunnel traffic.
const KICK_KEEPALIVE: u16 = 25;
/// No handshake for this long while sending = the peer stopped answering
/// (the kernel re-keys every 2 min while traffic flows).
const STALE_HANDSHAKE: u64 = 180;
const STATS_EVERY: Duration = Duration::from_secs(30);

pub struct RunOpts {
    pub no_routes: bool,
    pub watch_stdin: bool,
    /// `--probe`: handshake, report, remove the interface.
    pub probe: bool,
}

fn stopped() -> bool {
    WG_STOP.load(Ordering::SeqCst) || sysnet::stop_requested()
}

/// Deletes the interface we created (which also drops its addresses and the
/// routes through it) — on teardown, early errors and panics alike.
struct LinkGuard(String);

impl Drop for LinkGuard {
    fn drop(&mut self) {
        let _ = tun::ip(&["link", "del", "dev", &self.0]);
    }
}

pub fn run(cfg: Config, opts: RunOpts) -> Result<(), String> {
    WG_STOP.store(false, Ordering::SeqCst);
    sysnet::install_stop_signals(&WG_STOP);
    // Nothing is ever asked on stdin, so watch it from the start: a GUI disconnect
    // must also cancel the handshake wait.
    if opts.watch_stdin {
        sysnet::spawn_stdin_disconnect(&WG_STOP);
    }
    for h in &cfg.ignored_hooks {
        out!("# note: hook not run (unvpn never executes profile commands): {h}");
    }
    for u in &cfg.unsupported {
        out!("# note: config key `{u}` is not supported and is ignored");
    }
    let iface = &cfg.interface;
    out!("# interface public key: {}", keys::to_b64(&keys::public(&iface.private_key)?));

    // Resolve endpoints now, while the system resolver is still the pre-VPN one.
    let mut endpoints: Vec<Option<SocketAddr>> = Vec::new();
    for (i, p) in cfg.peers.iter().enumerate() {
        endpoints.push(match &p.endpoint {
            Some(e) => {
                let sa = resolve(e).map_err(|err| format!("peer #{} endpoint {e}: {err}", i + 1))?;
                out!("# peer {} → {sa}", short(&p.public_key));
                Some(sa)
            }
            None => None,
        });
    }

    let ifname = create_link(IF_NAME)?;
    let link = LinkGuard(ifname.clone());
    let mut nl = WgNetlink::open()?;
    let dev = DeviceSet {
        private_key: iface.private_key,
        listen_port: iface.listen_port,
        fwmark: iface.fwmark,
        peers: cfg
            .peers
            .iter()
            .zip(&endpoints)
            .map(|(p, ep)| PeerSet {
                public_key: p.public_key,
                preshared_key: p.preshared_key,
                endpoint: *ep,
                allowed_ips: p.allowed_ips.clone(),
                // Kick a handshake on peers we can reach; restored after.
                keepalive: if ep.is_some() { p.persistent_keepalive.unwrap_or(KICK_KEEPALIVE) } else { p.persistent_keepalive.unwrap_or(0) },
            })
            .collect(),
    };
    nl.set_device(&ifname, &dev)?;
    for a in &iface.addresses {
        tun::ip(&["addr", "add", &a.to_string(), "dev", &ifname])?;
    }
    let mtu = iface.mtu.unwrap_or(DEFAULT_MTU);
    tun::ip(&["link", "set", "dev", &ifname, "mtu", &mtu.to_string(), "up"])?;
    let addrs: Vec<String> = iface.addresses.iter().map(Net::to_string).collect();
    out!("# interface {ifname} up — {} (mtu {mtu}), {} peer(s)", addrs.join(", "), cfg.peers.len());

    // First handshake: proves keys, endpoint and UDP path before we touch routes.
    let reachable: Vec<usize> = endpoints.iter().enumerate().filter(|(_, e)| e.is_some()).map(|(i, _)| i).collect();
    if reachable.is_empty() {
        out!("# note: no peer has an Endpoint — waiting for peers to connect to us");
    } else {
        wait_handshake(&mut nl, &ifname, &cfg, &reachable)?;
        for &i in &reachable {
            if cfg.peers[i].persistent_keepalive.is_none() {
                nl.set_keepalive(&ifname, &cfg.peers[i].public_key, 0)?;
            }
        }
    }

    if opts.probe {
        out!("# probe OK — removing {ifname}");
        drop(link);
        return Ok(());
    }

    let ip = iface.addresses.first().map(|a| a.addr.to_string()).unwrap_or_default();
    // This exact "— IP <ip> DNS [..]" shape is what the GUI's log parser reads.
    out!("# WireGuard up — IP {ip}  DNS {:?}  (mtu {mtu})", if opts.no_routes { &[][..] } else { &iface.dns[..] });

    let mut restore = sysnet::NetRestore::default();
    if opts.no_routes {
        out!("# --no-routes: NOT installing routes or DNS.");
    } else {
        restore.routes = setup_routes(&cfg, &ifname, &endpoints);
        restore.dns = sysnet::set_dns(&iface.dns, &iface.search.join(" "));
    }
    if stopped() {
        drop(restore);
        return Err("disconnect requested before the tunnel came up".into());
    }
    out!("# TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)");

    let result = monitor(&mut nl, &ifname);
    out!("# disconnecting — removing {ifname}, restoring DNS/routes …");
    drop(restore);
    drop(link);
    result
}

fn resolve(endpoint: &str) -> Result<SocketAddr, String> {
    endpoint
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve: {e}"))?
        .next()
        .ok_or_else(|| "resolves to no address".to_string())
}

fn short(k: &[u8; 32]) -> String {
    let s = keys::to_b64(k);
    format!("{}…{}", &s[..4], &s[s.len() - 5..])
}

/// `ip link add <name> type wireguard`, moving on to `<base>1`, `<base>2`… when
/// the name is taken (never touching an existing interface). This also autoloads
/// the `wireguard` module.
fn create_link(name: &str) -> Result<String, String> {
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit());
    for n in 0..10 {
        let candidate = format!("{base}{n}");
        match tun::ip(&["link", "add", "dev", &candidate, "type", "wireguard"]) {
            Ok(()) => return Ok(candidate),
            Err(e) if e.contains("File exists") => continue,
            Err(e) if e.contains("Unknown device type") || e.contains("not supported") => {
                return Err("this kernel has no WireGuard support (module `wireguard` not available)".into())
            }
            Err(e) => return Err(e),
        }
    }
    Err(format!("{base}0…{base}9 are all in use"))
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn peer_state<'a>(st: &'a DeviceState, key: &[u8; 32]) -> Option<&'a super::netlink::PeerState> {
    st.peers.iter().find(|p| &p.public_key == key)
}

/// Poll the kernel until every reachable peer has handshaken (or one has and the
/// others had `OTHERS_WAIT` more). Errors if none answers within `HANDSHAKE_WAIT`.
fn wait_handshake(nl: &mut WgNetlink, ifname: &str, cfg: &Config, reachable: &[usize]) -> Result<(), String> {
    out!("# handshaking with {} peer(s) …", reachable.len());
    let start = Instant::now();
    let mut first_ok: Option<Instant> = None;
    let mut done = vec![false; cfg.peers.len()];
    let mut last_note = Instant::now();
    loop {
        if stopped() {
            return Err("cancelled".into());
        }
        let st = nl.get_device(ifname)?;
        for &i in reachable {
            let p = &cfg.peers[i];
            if !done[i] && peer_state(&st, &p.public_key).is_some_and(|s| s.last_handshake != 0) {
                done[i] = true;
                first_ok.get_or_insert_with(Instant::now);
                out!("# handshake with peer {} ({} ms)", short(&p.public_key), start.elapsed().as_millis());
            }
        }
        let all = reachable.iter().all(|&i| done[i]);
        let others_timed_out = first_ok.is_some_and(|t| t.elapsed() >= OTHERS_WAIT);
        if all || others_timed_out {
            for &i in reachable.iter().filter(|&&i| !done[i]) {
                out!("# warning: no handshake yet with peer {} — continuing (the kernel keeps retrying)", short(&cfg.peers[i].public_key));
            }
            return Ok(());
        }
        if start.elapsed() >= HANDSHAKE_WAIT {
            return Err(format!(
                "no handshake response after {}s — check the keys (PublicKey / PresharedKey), the Endpoint, and that UDP to it isn't blocked",
                HANDSHAKE_WAIT.as_secs()
            ));
        }
        if last_note.elapsed() >= Duration::from_secs(5) {
            out!("#   still waiting for a handshake ({}s) …", start.elapsed().as_secs());
            last_note = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Periodic stats, and a warning when a peer we keep sending to stops completing
/// handshakes.
fn monitor(nl: &mut WgNetlink, ifname: &str) -> Result<(), String> {
    let mut last_stats = Instant::now();
    let mut prev: Option<DeviceState> = None;
    let mut warned = false;
    loop {
        for _ in 0..10 {
            if stopped() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if last_stats.elapsed() < STATS_EVERY {
            continue;
        }
        last_stats = Instant::now();
        let st = nl.get_device(ifname).map_err(|e| format!("interface {ifname} gone? ({e})"))?;
        let (rx, tx): (u64, u64) = st.peers.iter().fold((0, 0), |a, p| (a.0 + p.rx_bytes, a.1 + p.tx_bytes));
        let newest = st.peers.iter().map(|p| p.last_handshake).max().unwrap_or(0);
        let age = if newest == 0 { None } else { Some(now_secs().saturating_sub(newest)) };
        out!(
            "#  stats: rx={} tx={} last handshake {}",
            human(rx),
            human(tx),
            age.map(|a| format!("{a}s ago")).unwrap_or_else(|| "never".into())
        );
        // Sending but nothing coming back, and no fresh handshake: peer unreachable.
        if let Some(p) = &prev {
            let (prx, ptx): (u64, u64) = p.peers.iter().fold((0, 0), |a, p| (a.0 + p.rx_bytes, a.1 + p.tx_bytes));
            let silent = tx > ptx && rx == prx && age.is_none_or(|a| a > STALE_HANDSHAKE);
            if silent && !warned {
                out!("# warning: peer not answering (no reply / handshake for a while) — the kernel keeps retrying");
                warned = true;
            } else if !silent && warned && rx > prx {
                out!("# peer answering again");
                warned = false;
            }
        }
        prev = Some(st);
    }
}

fn human(b: u64) -> String {
    match b {
        b if b >= 1 << 30 => format!("{:.1}GiB", b as f64 / (1u64 << 30) as f64),
        b if b >= 1 << 20 => format!("{:.1}MiB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.1}KiB", b as f64 / 1024.0),
        b => format!("{b}B"),
    }
}

/// The `route add` lines for a profile: every peer's AllowedIPs through the
/// interface (a /0 becomes the two halves, so the original default route stays
/// and comes back untouched), and each endpoint those cover pinned to its
/// pre-VPN path. `Table = <n>` puts the AllowedIPs in that table as-is (the user's
/// policy routing decides); `Table = off` installs nothing.
fn route_plan(cfg: &Config, ifname: &str, endpoints: &[Option<SocketAddr>], path: impl Fn(IpAddr) -> Option<String>) -> Vec<String> {
    let mut nets: Vec<Net> = Vec::new();
    let mut push = |n: Net| {
        if !nets.contains(&n) {
            nets.push(n);
        }
    };
    let table = match cfg.interface.table {
        Table::Off => return Vec::new(),
        Table::Auto => None,
        Table::Id(t) => Some(t),
    };
    for p in &cfg.peers {
        for n in &p.allowed_ips {
            match (n.is_default(), n.addr, table) {
                (true, IpAddr::V4(_), None) => {
                    push(Net::parse("0.0.0.0/1").unwrap());
                    push(Net::parse("128.0.0.0/1").unwrap());
                }
                (true, IpAddr::V6(_), None) => {
                    push(Net::parse("::/1").unwrap());
                    push(Net::parse("8000::/1").unwrap());
                }
                _ => push(*n),
            }
        }
    }
    let mut lines = Vec::new();
    if table.is_none() {
        for ep in endpoints.iter().flatten() {
            let ip = ep.ip();
            if nets.iter().any(|n| n.contains(ip)) {
                if let Some(via) = path(ip) {
                    let host = if ip.is_ipv4() { 32 } else { 128 };
                    lines.push(format!("route add {ip}/{host} {via}"));
                }
            }
        }
    }
    let suffix = table.map(|t| format!(" table {t}")).unwrap_or_default();
    for n in &nets {
        lines.push(format!("route add {n} dev {ifname}{suffix}"));
    }
    lines
}

/// Install the routes in one `ip -batch`; returns the `route del` lines for the
/// ones we actually added (an already-present route isn't ours to remove).
fn setup_routes(cfg: &Config, ifname: &str, endpoints: &[Option<SocketAddr>]) -> Vec<String> {
    let add = route_plan(cfg, ifname, endpoints, original_path);
    match cfg.interface.table {
        Table::Off => out!("# Table = off: not installing routes"),
        Table::Id(t) => out!("# routes go to table {t} (policy routing is up to you)"),
        Table::Auto => {}
    }
    for l in &add {
        let what = l.trim_start_matches("route add ");
        if !what.contains(&format!("dev {ifname}")) {
            out!("# pinned endpoint route {what}");
        }
    }
    let full4 = add.iter().any(|l| l.contains("route add 0.0.0.0/1 "));
    let full6 = add.iter().any(|l| l.contains("route add ::/1 "));
    if full4 || full6 {
        out!("# full tunnel ({}) via {ifname}", [full4.then_some("IPv4"), full6.then_some("IPv6")].into_iter().flatten().collect::<Vec<_>>().join(" + "));
    }
    let split = add.iter().filter(|l| l.contains(&format!("dev {ifname}"))).count();
    out!("# {split} route(s) via {ifname}");
    let failed = tun::ip_batch_failed(&add).unwrap_or_default();
    if !failed.is_empty() {
        out!("# {} route(s) already existed (or this host lacks IPv6) — left as is", failed.len());
    }
    add.into_iter()
        .enumerate()
        .filter(|(i, _)| !failed.contains(i))
        .map(|(_, l)| l.replacen("route add ", "route del ", 1))
        .collect()
}

/// `via X dev Y` / `dev Y` of the current route to `dst` (`ip route get`).
fn original_path(dst: IpAddr) -> Option<String> {
    let out = std::process::Command::new("ip").args(["route", "get", &dst.to_string()]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let toks: Vec<&str> = text.lines().next().unwrap_or("").split_whitespace().collect();
    let via = toks.windows(2).find(|w| w[0] == "via").map(|w| w[1]);
    let dev = toks.windows(2).find(|w| w[0] == "dev").map(|w| w[1])?;
    Some(match via {
        Some(v) => format!("via {v} dev {dev}"),
        None => format!("dev {dev}"),
    })
}

#[cfg(test)]
mod tests {
    use super::super::config::parse;
    use super::*;

    const K1: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const K2: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn cfg(extra_iface: &str, allowed: &str) -> Config {
        parse(&format!(
            "[Interface]\nPrivateKey = {K1}\nAddress = 10.8.0.2/24\n{extra_iface}\n[Peer]\nPublicKey = {K2}\nEndpoint = 192.0.2.10:51820\nAllowedIPs = {allowed}\n"
        ))
        .unwrap()
    }

    fn ep() -> Vec<Option<SocketAddr>> {
        vec![Some("192.0.2.10:51820".parse().unwrap())]
    }

    #[test]
    fn full_tunnel_pins_endpoint_and_splits_default() {
        let c = cfg("", "0.0.0.0/0, ::/0");
        let r = route_plan(&c, "cpwg0", &ep(), |_| Some("via 198.51.100.1 dev eth0".into()));
        assert_eq!(
            r,
            vec![
                "route add 192.0.2.10/32 via 198.51.100.1 dev eth0",
                "route add 0.0.0.0/1 dev cpwg0",
                "route add 128.0.0.0/1 dev cpwg0",
                "route add ::/1 dev cpwg0",
                "route add 8000::/1 dev cpwg0",
            ]
        );
    }

    #[test]
    fn split_tunnel_needs_no_pin() {
        let c = cfg("", "10.8.0.0/24, 172.16.0.0/12");
        let r = route_plan(&c, "cpwg0", &ep(), |_| panic!("no pin needed"));
        assert_eq!(r, vec!["route add 10.8.0.0/24 dev cpwg0", "route add 172.16.0.0/12 dev cpwg0"]);
    }

    #[test]
    fn table_off_and_custom() {
        assert!(route_plan(&cfg("Table = off", "0.0.0.0/0"), "cpwg0", &ep(), |_| None).is_empty());
        let r = route_plan(&cfg("Table = 1234", "0.0.0.0/0"), "cpwg0", &ep(), |_| panic!("no pin with a custom table"));
        assert_eq!(r, vec!["route add 0.0.0.0/0 dev cpwg0 table 1234"]);
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human(512), "512B");
        assert_eq!(human(1536), "1.5KiB");
        assert_eq!(human(5 << 20), "5.0MiB");
    }
}
