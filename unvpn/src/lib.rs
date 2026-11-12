//! unvpn — native Linux multi-vendor VPN client (Check Point, Fortinet, F5, AnyConnect, GlobalProtect, OpenVPN).

/// `println!` that never panics. Once the GUI is gone our stdout is a broken pipe,
/// and a panicking print on a teardown path would skip restoring DNS and routes.
macro_rules! out {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}

mod anyconnect;
mod checkpoint;
mod connect;
mod control;
mod dns;
mod f5;
mod forti;
mod forti_ipsec;
#[doc(hidden)]
pub mod fuzz;
mod gnutls;
mod gp;
mod ike;
mod ivanti;
mod leakguard;
mod net;
mod netmon;
mod openvpn;
mod ppp;
mod replay;
mod report;
mod sysnet;
mod tun;
mod tunnel_common;
mod wireguard;

use std::io::Write;

/// The `unvpn` command line.
pub fn main() {
    // Session-wide leak protection, parsed out before the sub-command so every
    // back-end sees the same policy without each parsing these itself.
    //   --killswitch   fail-closed firewall (default off)
    //   --allow-ipv6   keep IPv6 egress (default: blocked, since the tunnels are v4)
    //   --pin [<host>:<port>=]sha256:<hex>   trust that gateway certificate (repeatable)
    //   --insecure     trust any gateway certificate
    //   --label <name> the connection's name in `unvpn status`
    //   --detachable   once up, keep the tunnel when stdin closes
    let mut killswitch = false;
    let mut block_ipv6 = true;
    let mut tls_flags: Vec<String> = Vec::new();
    let mut pins: Vec<String> = Vec::new();
    let mut insecure = false;
    let mut label = String::new();
    let mut args: Vec<String> = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--killswitch" => killswitch = true,
            "--allow-ipv6" => block_ipv6 = false,
            "--detachable" => sysnet::set_detachable(true),
            "--label" => {
                let Some(v) = it.next() else {
                    eprintln!("--label needs a value");
                    std::process::exit(2);
                };
                label = v;
            }
            "--insecure" => {
                insecure = true;
                tls_flags.push(a);
            }
            "--pin" => {
                let Some(v) = it.next() else {
                    eprintln!("--pin needs a value: [<host>:<port>=]sha256:<hex>");
                    std::process::exit(2);
                };
                pins.push(v.clone());
                tls_flags.extend([a, v]);
            }
            _ => match a.strip_prefix("--pin=") {
                Some(v) => {
                    pins.push(v.to_string());
                    tls_flags.extend(["--pin".to_string(), v.to_string()]);
                }
                None => args.push(a),
            },
        }
    }
    leakguard::configure(killswitch, block_ipv6);
    if let Err(e) = net::trust::configure(&pins, insecure) {
        eprintln!("{e}");
        std::process::exit(2);
    }

    let tunnel = match args.first().map(String::as_str) {
        Some("ike") => Some("ike"),
        Some("tunnel-up") => Some("ike"),
        Some("forti") => Some("forti"),
        Some("forti-ipsec" | "fortiipsec") => Some("forti-ipsec"),
        Some("f5") => Some("f5"),
        Some("anyconnect") => Some("anyconnect"),
        Some("gp" | "globalprotect") => Some("gp"),
        Some("ivanti" | "pulse") => Some("ivanti"),
        Some("openvpn") => Some("openvpn"),
        Some("wireguard" | "wg") => Some("wireguard"),
        _ => None,
    };
    if let Some(backend) = tunnel {
        control::start(backend, &label, &args[1..]);
        report::connecting();
    }

    match args.first().map(String::as_str) {
        Some("connect") => connect::cmd_connect(&args[1..], killswitch, !block_ipv6, &tls_flags),
        Some("status") => control::cmd_status(&args[1..]),
        Some("disconnect") => control::cmd_disconnect(&args[1..]),
        Some("recover") => control::cmd_recover(&args[1..]),
        Some("hello") => checkpoint::cmd_hello(&args[1..]),
        Some("login") => checkpoint::cmd_login(&args[1..]),
        Some("deob") => checkpoint::cmd_deob(&args[1..]),
        Some("tunnel") => checkpoint::cmd_tunnel(&args[1..]),
        Some("ike") => checkpoint::cmd_ike(&args[1..]),
        Some("cp-enroll") => checkpoint::cert::cmd_enroll(&args[1..]),
        Some("tunnel-up") => checkpoint::cmd_tunnel_up(&args[1..]),
        Some("forti") => forti::cmd_forti(&args[1..]),
        Some("forti-ipsec") | Some("fortiipsec") => forti_ipsec::cmd_forti_ipsec(&args[1..]),
        Some("f5") => f5::cmd_f5(&args[1..]),
        Some("anyconnect") => anyconnect::cmd_anyconnect(&args[1..]),
        Some("gp") | Some("globalprotect") => gp::cmd_gp(&args[1..]),
        Some("ivanti") | Some("pulse") => ivanti::cmd_ivanti(&args[1..]),
        Some("openvpn") => openvpn::cmd_openvpn(&args[1..]),
        Some("wireguard") | Some("wg") => wireguard::cmd_wireguard(&args[1..]),
        Some("pins") => cmd_pins(&args[1..]),
        Some("--version" | "-V" | "version") => println!("unvpn {}", env!("CARGO_PKG_VERSION")),
        Some("--help" | "-h" | "help") => usage(&mut std::io::stdout()),
        _ => {
            usage(&mut std::io::stderr());
            std::process::exit(2);
        }
    }
    if tunnel.is_some() {
        report::down();
    }
}

/// Print, one per line, the `--pin=` flags the saved profiles keep for a gateway
/// (`host[:port]`, or the gateway of an `f5-vpn://` link) — for a launcher that
/// starts the engine without a front-end to ask. Run as the user.
fn cmd_pins(args: &[String]) {
    let [target] = args else {
        eprintln!("usage: unvpn pins <host[:port] | f5-vpn://…>");
        std::process::exit(2);
    };
    let endpoint = match unvpn_profiles::f5_launch_endpoint(target) {
        Some(e) => e,
        None if target.starts_with("f5-vpn:") => {
            eprintln!("no server= in the f5-vpn:// link");
            std::process::exit(2);
        }
        None => unvpn_profiles::gateway_endpoint(target),
    };
    let profiles = unvpn_profiles::load().unwrap_or_else(|e| {
        eprintln!("can't read the saved profiles: {e}");
        std::process::exit(1);
    });
    for pin in unvpn_profiles::pins_for(&profiles, &endpoint) {
        println!("--pin={pin}");
    }
}

fn usage(out: &mut dyn Write) {
    let _ = writeln!(out, "unvpn — native multi-vendor VPN client\n");
    let _ = writeln!(out, "usage:");
    let _ = writeln!(out, "  unvpn connect <profile>          # connect a profile saved in the app (run as your user)");
    let _ = writeln!(
        out,
        "  unvpn connect --list             # the saved profiles"
    );
    let _ = writeln!(
        out,
        "  unvpn status [--json]            # the running tunnels"
    );
    let _ = writeln!(
        out,
        "  unvpn disconnect [<name> | --all]  # stop a running tunnel (the app's too)"
    );
    let _ = writeln!(out, "  sudo unvpn recover               # undo what a killed engine left behind (routes, kill switch, DNS)");
    let _ = writeln!(out, "  unvpn hello [--gateway <host>] [--send]");
    let _ = writeln!(
        out,
        "  unvpn login --gateway <host> [--user <u>] [--realm <r>] [--passcode <p>] [--probe]"
    );
    let _ = writeln!(
        out,
        "  unvpn tunnel --gateway <host> --active-key <obfuscated-hex> [--om-ip <ip>]"
    );
    let _ = writeln!(
        out,
        "  unvpn ike --gateway <host> [--passcode <PIN+tokencode>] [--connect [--no-routes]]"
    );
    let _ = writeln!(
        out,
        "       # M3/M4: IKEv1 handshake; with --connect (sudo) brings up the tun tunnel"
    );
    let _ = writeln!(
        out,
        "  unvpn ike --gateway <host> --cert <file.p12> [--realm <login-option>] [--connect]"
    );
    let _ = writeln!(
        out,
        "       # certificate login; the file password is read from stdin"
    );
    let _ = writeln!(
        out,
        "  unvpn cp-enroll -g <host> -r <registration-key> -o <file.p12>"
    );
    let _ = writeln!(
        out,
        "       # get a Check Point user certificate with a one-time registration key"
    );
    let _ = writeln!(
        out,
        "  unvpn forti -g <host[:port]> -u <user> [--connect]   # Fortinet SSL-VPN back-end"
    );
    let _ = writeln!(out, "  unvpn forti-ipsec -g <host> -u <user> [--localid <group>] [--connect]  # FortiClient IPsec (IKEv2) back-end");
    let _ = writeln!(
        out,
        "  unvpn f5 -g <host[:port]> -u <user> [--connect]      # F5 BIG-IP APM SSL-VPN back-end"
    );
    let _ = writeln!(out, "  unvpn anyconnect -g <url> -u <user> [--connect]       # Cisco AnyConnect SSL-VPN back-end");
    let _ = writeln!(out, "  unvpn gp -g <portal> -u <user> [--connect]            # Palo Alto GlobalProtect back-end");
    let _ = writeln!(out, "  unvpn ivanti -g <host> -u <user> [--connect]          # Ivanti Connect Secure (Pulse) back-end");
    let _ = writeln!(
        out,
        "  unvpn openvpn -c <profile.ovpn> [-u <user>] [--connect] # OpenVPN back-end"
    );
    let _ = writeln!(
        out,
        "  unvpn wireguard -c <profile.conf> --connect            # WireGuard (kernel) back-end"
    );
    let _ = writeln!(out, "  unvpn pins <host:port | f5-vpn://…>                    # the --pin flags your profiles keep for it");
    let _ = writeln!(out, "  unvpn --version");
    let _ = writeln!(out, "\nglobal flags (any back-end):");
    let _ = writeln!(out, "  --killswitch   fail-closed firewall: block all egress but the tunnel, gateway, LAN and DHCP");
    let _ = writeln!(
        out,
        "  --allow-ipv6   keep IPv6 egress (default: blocked, since the tunnels are IPv4-only)"
    );
    let _ = writeln!(out, "  --pin [<host>:<port>=]sha256:<hex>");
    let _ = writeln!(out, "                 trust this gateway certificate when no system CA vouches for it (repeatable);");
    let _ = writeln!(
        out,
        "                 without one, an unknown certificate is shown and you are asked"
    );
    let _ = writeln!(
        out,
        "  --insecure     accept any gateway certificate without checking it"
    );
    let _ = writeln!(
        out,
        "  --label <name> the connection's name in `unvpn status`"
    );
    let _ = writeln!(out, "  --detachable   once connected, stay up when stdin closes (for front-ends that may restart)");
}
