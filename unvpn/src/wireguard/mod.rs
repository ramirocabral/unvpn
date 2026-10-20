//! WireGuard back-end for unvpn — on the Linux kernel's own WireGuard.
//!
//! WireGuard is in the kernel (5.6+), so instead of re-implementing the protocol
//! we drive the in-kernel implementation directly: the interface is created over
//! rtnetlink (`ip link add … type wireguard`) and configured over generic netlink
//! (the `wireguard` family `wg(8)` uses) — no `wg`/`wg-quick` binaries. The kernel
//! does the handshakes, timers and crypto; we add the client side: wg-quick
//! `.conf` profiles, addresses, routes (endpoint pinned outside a full tunnel),
//! DNS, a handshake check before routes go in, stats, and a clean teardown.
//! See docs/wireguard-notes.md.
//!
//! Subcommand: `unvpn wireguard -c <profile.conf> [...]`
//!   --connect    bring up the tunnel (needs root)
//!   --probe      bring up the interface, wait for a handshake, remove it (root)
//!   --pubkey     print the profile's public key (to register on the server)
//!   --genkey     print a new private key and its public key

pub mod config;
pub mod keys;
pub mod netlink;
pub mod tunnel;

use std::path::PathBuf;

#[derive(PartialEq)]
enum Action {
    Connect,
    Probe,
    Pubkey,
    Genkey,
}

struct Args {
    config: Option<PathBuf>,
    action: Option<Action>,
    no_routes: bool,
}

pub fn cmd_wireguard(args: &[String]) {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            usage();
            std::process::exit(2);
        }
    };
    if let Err(e) = run(parsed) {
        eprintln!("wireguard failed: {e}");
        std::process::exit(1);
    }
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut a = Args { config: None, action: None, no_routes: false };
    let mut it = args.iter();
    while let Some(x) = it.next() {
        let act = match x.as_str() {
            "--config" | "-c" => {
                a.config = Some(PathBuf::from(it.next().ok_or("--config needs a path")?));
                continue;
            }
            "--no-routes" => {
                a.no_routes = true;
                continue;
            }
            "--connect" => Action::Connect,
            "--probe" => Action::Probe,
            "--pubkey" => Action::Pubkey,
            "--genkey" => Action::Genkey,
            other => return Err(format!("unknown argument: {other}")),
        };
        if a.action.replace(act).is_some() {
            return Err("give only one of --connect / --probe / --pubkey / --genkey".into());
        }
    }
    match a.action {
        None => Err("say what to do: --connect, --probe, --pubkey or --genkey".into()),
        Some(Action::Genkey) => Ok(a),
        Some(_) if a.config.is_none() => Err("wireguard requires --config <profile.conf>".into()),
        Some(_) => Ok(a),
    }
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  unvpn wireguard -c <profile.conf> --connect [--no-routes]   # bring up the tunnel (sudo)");
    eprintln!("  unvpn wireguard -c <profile.conf> --probe                   # handshake check, then remove (sudo)");
    eprintln!("  unvpn wireguard -c <profile.conf> --pubkey                  # this profile's public key");
    eprintln!("  unvpn wireguard --genkey                                    # new private + public key");
    eprintln!("      [--no-routes]   tunnel up but install no routes/DNS (safe data-plane test)");
}

fn run(a: Args) -> Result<(), String> {
    if a.action == Some(Action::Genkey) {
        let (sk, pk) = keys::generate()?;
        println!("PrivateKey = {}", keys::to_b64(&sk));
        println!("PublicKey  = {}", keys::to_b64(&pk));
        return Ok(());
    }
    let path = a.config.expect("checked in parse_args");
    let cfg = config::load(&path)?;
    match a.action {
        Some(Action::Pubkey) => {
            println!("{}", keys::to_b64(&keys::public(&cfg.interface.private_key)?));
            Ok(())
        }
        Some(Action::Probe) => tunnel::run(cfg, tunnel::RunOpts { no_routes: true, watch_stdin: false, probe: true }),
        _ => tunnel::run(cfg, tunnel::RunOpts { no_routes: a.no_routes, watch_stdin: true, probe: false }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn args() {
        let a = parse_args(&s(&["-c", "wg0.conf", "--connect", "--no-routes"])).unwrap();
        assert!(a.action == Some(Action::Connect) && a.no_routes);
        assert!(parse_args(&s(&["--genkey"])).is_ok());
        assert!(parse_args(&s(&["--connect"])).is_err(), "needs a config");
        assert!(parse_args(&s(&["-c", "x", "--connect", "--probe"])).is_err());
        assert!(parse_args(&s(&["-c", "x"])).is_err(), "needs an action");
    }
}
