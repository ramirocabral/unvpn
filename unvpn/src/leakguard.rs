//! Fail-closed network protection for the data plane, via one nftables table per
//! tunnel (`inet unvpn_<tun>`):
//!
//! - Kill switch (opt-in, `--killswitch`): an `output` chain with `policy drop`
//!   that only lets through loopback, the tunnel interface, the VPN gateway, DHCP
//!   and the local LAN — so if the tunnel drops (or while it reconnects) nothing
//!   leaks out the physical link in clear.
//! - IPv6 leak block (on by default, `--allow-ipv6` to keep it): every tunnel but
//!   WireGuard carries IPv4 only, so a host with IPv6 on its physical link would
//!   send IPv6 straight past the tunnel. We drop all IPv6 egress for the session,
//!   leaving loopback and link-local/multicast (ND) alone.
//!
//! Per-tun table names keep teardown self-contained — each session removes only
//! its own table on drop, with no cross-process bookkeeping — and let several
//! IPv6-blocking sessions coexist. A kill switch is fail-closed by nature, so a
//! second simultaneous tunnel's traffic is blocked while one is active; that is
//! the point of the switch, not a regression.

use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

static KILLSWITCH: AtomicBool = AtomicBool::new(false);
/// The v4-only tunnels leak IPv6 by default, so blocking it is the safe default.
static BLOCK_IPV6: AtomicBool = AtomicBool::new(true);

/// Set the session-wide policy from the top-level flags, before any back-end runs.
pub fn configure(killswitch: bool, block_ipv6: bool) {
    KILLSWITCH.store(killswitch, Ordering::SeqCst);
    BLOCK_IPV6.store(block_ipv6, Ordering::SeqCst);
}

pub fn killswitch_requested() -> bool {
    KILLSWITCH.load(Ordering::SeqCst)
}

/// Removes the table it installed on drop — on teardown, an early error return, or
/// a panic unwinding through a back-end's `run`. A SIGKILL (or power loss) can't run
/// this; the printed `nft delete table …` line is the manual recovery.
pub struct LeakGuard {
    table: String,
}

impl Drop for LeakGuard {
    fn drop(&mut self) {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", &self.table])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

struct Params<'a> {
    table: &'a str,
    tun: &'a str,
    gateways: &'a [Ipv4Addr],
    lan: &'a [String],
    killswitch: bool,
    block_ipv6: bool,
}

/// Install the leak protection the session policy calls for, allowing `tun` and the
/// control-channel `gateways` (plus the LAN and DHCP under the kill switch). Returns
/// `Ok(None)` when nothing is asked for, or when only the IPv6 block is wanted and
/// `nft` is missing; `Err` only when a kill switch was explicitly requested but can't
/// be installed — connecting without it would defeat the point.
pub fn enable(tun: &str, gateways: &[Ipv4Addr]) -> Result<Option<LeakGuard>, String> {
    let killswitch = KILLSWITCH.load(Ordering::SeqCst);
    let block_ipv6 = BLOCK_IPV6.load(Ordering::SeqCst);
    if !killswitch && !block_ipv6 {
        return Ok(None);
    }
    if !nft_available() {
        if killswitch {
            return Err("--killswitch needs nftables, but `nft` was not found (install nftables)".into());
        }
        out!("# note: `nft` not found — IPv6 leak block skipped (install nftables, or --allow-ipv6 to silence)");
        return Ok(None);
    }

    let table = table_name(tun);
    let lan = if killswitch { lan_subnets(tun) } else { Vec::new() };
    let rules = ruleset(&Params { table: &table, tun, gateways, lan: &lan, killswitch, block_ipv6 });
    apply(&rules).map_err(|e| format!("could not install leak protection: {e}"))?;

    if killswitch {
        let gws = gateways.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(", ");
        out!("# kill switch ON — only {tun}, gateway {gws}, LAN and DHCP allowed (fail-closed)");
        out!("#   (if unvpn is killed hard, clear it with: nft delete table inet {table})");
    }
    if block_ipv6 {
        out!("# IPv6 egress blocked for the session (--allow-ipv6 to keep it)");
    }
    Ok(Some(LeakGuard { table }))
}

/// nftables identifiers allow alphanumerics and `_`; tun names are already in that
/// set, but sanitise defensively so the table name can never be malformed.
fn table_name(tun: &str) -> String {
    let safe: String = tun.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    format!("unvpn_{safe}")
}

fn nft_available() -> bool {
    Command::new("nft")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The nft ruleset, as fed to `nft -f -`. `add` then `delete` guarantees the table
/// exists before we drop any stale copy from a crashed session, then it is defined
/// fresh — all in one atomic transaction.
fn ruleset(p: &Params) -> String {
    let policy = if p.killswitch { "drop" } else { "accept" };
    let mut r = String::new();
    r.push_str(&format!("add table inet {t}\n", t = p.table));
    r.push_str(&format!("delete table inet {t}\n", t = p.table));
    r.push_str(&format!("table inet {t} {{\n", t = p.table));
    r.push_str("  chain output {\n");
    r.push_str(&format!("    type filter hook output priority 0; policy {policy};\n"));
    r.push_str("    oifname \"lo\" accept\n");
    r.push_str(&format!("    oifname \"{tun}\" accept\n", tun = p.tun));
    if p.block_ipv6 {
        // Keep loopback and the link-local/multicast ranges ND needs; drop the rest.
        r.push_str("    ip6 daddr ::1 accept\n");
        r.push_str("    ip6 daddr fe80::/10 accept\n");
        r.push_str("    ip6 daddr ff00::/8 accept\n");
        r.push_str("    meta nfproto ipv6 drop\n");
    }
    if p.killswitch {
        // Keep the DHCP lease on the physical link.
        r.push_str("    udp dport 67 accept\n");
        r.push_str("    udp dport 68 accept\n");
        for gw in p.gateways {
            r.push_str(&format!("    ip daddr {gw} accept\n"));
        }
        for net in p.lan {
            r.push_str(&format!("    ip daddr {net} accept\n"));
        }
    }
    r.push_str("  }\n}\n");
    r
}

fn apply(ruleset: &str) -> Result<(), String> {
    use std::io::Write;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn nft: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("nft: no stdin")?
        .write_all(ruleset.as_bytes())
        .map_err(|e| format!("write to nft: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("nft wait: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// The directly-connected IPv4 subnets to keep reachable under the kill switch
/// (printers, the router, the LAN resolver, SSH to a box on the same network),
/// taken from the kernel's link-scope routes, minus the tunnel's own.
fn lan_subnets(tun: &str) -> Vec<String> {
    let out = Command::new("ip").args(["-4", "route", "show", "scope", "link"]).output();
    let text = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        _ => return Vec::new(),
    };
    parse_link_subnets(&text, tun)
}

fn parse_link_subnets(route_output: &str, tun: &str) -> Vec<String> {
    let mut nets = Vec::new();
    for line in route_output.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let Some(cidr) = toks.first() else { continue };
        if !cidr.contains('/') {
            continue;
        }
        let dev = toks.windows(2).find(|w| w[0] == "dev").map(|w| w[1]);
        if dev == Some(tun) || dev == Some("lo") {
            continue;
        }
        let net = cidr.to_string();
        if !nets.contains(&net) {
            nets.push(net);
        }
    }
    nets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gw() -> Vec<Ipv4Addr> {
        vec![Ipv4Addr::new(203, 0, 113, 10)]
    }

    #[test]
    fn killswitch_ruleset_drops_and_allowlists() {
        let lan = vec!["192.168.1.0/24".to_string()];
        let r = ruleset(&Params {
            table: "unvpn_cpfg0",
            tun: "cpfg0",
            gateways: &gw(),
            lan: &lan,
            killswitch: true,
            block_ipv6: true,
        });
        assert!(r.contains("add table inet unvpn_cpfg0\ndelete table inet unvpn_cpfg0\n"));
        assert!(r.contains("policy drop;"));
        assert!(r.contains("oifname \"lo\" accept"));
        assert!(r.contains("oifname \"cpfg0\" accept"));
        assert!(r.contains("ip daddr 203.0.113.10 accept"));
        assert!(r.contains("ip daddr 192.168.1.0/24 accept"));
        assert!(r.contains("udp dport 67 accept"));
        assert!(r.contains("meta nfproto ipv6 drop"));
    }

    #[test]
    fn ipv6_only_keeps_v4_open() {
        // No kill switch: policy accept (v4 untouched), only IPv6 egress dropped,
        // and no gateway/LAN/DHCP allow-list lines.
        let r = ruleset(&Params {
            table: "unvpn_cpfg0",
            tun: "cpfg0",
            gateways: &gw(),
            lan: &[],
            killswitch: false,
            block_ipv6: true,
        });
        assert!(r.contains("policy accept;"));
        assert!(r.contains("meta nfproto ipv6 drop"));
        assert!(!r.contains("ip daddr 203.0.113.10"));
        assert!(!r.contains("udp dport 67"));
    }

    #[test]
    fn killswitch_without_ipv6_block_still_closes_v6_by_policy() {
        let r = ruleset(&Params {
            table: "unvpn_cpfg0",
            tun: "cpfg0",
            gateways: &gw(),
            lan: &[],
            killswitch: true,
            block_ipv6: false,
        });
        assert!(r.contains("policy drop;"));
        assert!(!r.contains("meta nfproto ipv6 drop"));
    }

    #[test]
    fn link_subnets_skip_tun_and_lo() {
        let out = "\
192.168.1.0/24 dev wlan0 proto kernel scope link src 192.168.1.23 metric 600
10.5.0.0/16 dev cpfg0 proto kernel scope link src 10.5.0.9
169.254.0.0/16 dev wlan0 scope link";
        assert_eq!(parse_link_subnets(out, "cpfg0"), vec!["192.168.1.0/24", "169.254.0.0/16"]);
    }

    #[test]
    fn link_subnets_dedup() {
        let out = "\
192.168.1.0/24 dev wlan0 scope link
192.168.1.0/24 dev eth0 scope link";
        assert_eq!(parse_link_subnets(out, "tun0"), vec!["192.168.1.0/24"]);
    }

    #[test]
    fn table_name_sanitised() {
        assert_eq!(table_name("cpfg0"), "unvpn_cpfg0");
        assert_eq!(table_name("tun%d"), "unvpn_tun_d");
    }
}
