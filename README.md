<div align="center">

<img src="packaging/icons/unvpn-128.png" width="96" alt="unvpn"/>

# unvpn

A native Linux client for corporate VPNs, written in Rust.

</div>

Supported VPNs:

- Check Point
- Fortinet FortiGate SSL-VPN
- Fortinet FortiClient IPsec (IKEv2 + EAP)
- F5 BIG-IP APM
- Cisco AnyConnect
- Palo Alto GlobalProtect
- OpenVPN
- WireGuard

<p align="center">
  <img src="screenshots/dark.png" width="420" alt="unvpn"/>
</p>

## Features

- GTK4 app with saved connection profiles.
- Tray icon showing the connection state.
- Several VPNs at once.
- Desktop notifications when a connection drops or fails.
- Encrypted export / import of all profiles, to move them between machines.
- Auto-reconnect after sleep or a network change, without re-auth.
- Leak protection: optional kill switch and an IPv6 egress block.
- Split DNS through systemd-resolved.

## Install

Install dependencies:

```sh
# Arch
sudo pacman -S --needed rust base-devel perl gtk4 libadwaita webkitgtk-6.0 polkit iproute2 nftables

# Debian 13, Ubuntu 24.04 or newer
sudo apt install build-essential perl pkg-config curl libssl-dev libdbus-1-dev \
    libgtk-4-dev libadwaita-1-dev libwebkitgtk-6.0-dev pkexec iproute2 nftables
curl https://sh.rustup.rs -sSf | sh

# Fedora
sudo dnf install gcc make perl pkgconf-pkg-config openssl-devel dbus-devel \
    gtk4-devel libadwaita-devel webkitgtk6.0-devel polkit iproute nftables
curl https://sh.rustup.rs -sSf | sh

# RHEL, AlmaLinux, Rocky 10: enable CRB and EPEL, then as Fedora
sudo dnf install epel-release && sudo dnf config-manager --set-enabled crb
```

Build and install:

```sh
./install.sh
```

It also adds a polkit rule, so connecting doesn't ask for a password.

Uninstall:

```sh
./install.sh --uninstall
```

## Command line

Profiles saved in the app connect by name. Run it as your user: it reads the
profile and the keyring, then starts the engine as root. Codes, SSO tokens and any
password the keyring doesn't have are asked on the terminal; Ctrl-C disconnects.

```sh
unvpn connect --list               # the saved profiles
unvpn connect office               # by name (or a unique start of it)
unvpn connect office --dry-run     # print the engine command instead of running it
```

Any running tunnel, wherever it was started (the app, `unvpn connect`, the F5
**Start** button), shows up in `unvpn status` and stops with `unvpn disconnect`:

```sh
unvpn status                       # the running tunnels (--json for scripts)
unvpn disconnect office            # by name, gateway or interface; --all stops them all
sudo unvpn recover                 # after a crash or kill -9: undo leftover routes, kill switch and DNS
```

Or give the details directly:

```sh
sudo unvpn ike -g 203.0.113.10 -u alice --connect                    # Check Point
sudo unvpn ike -g 203.0.113.10 --cert alice.p12 --connect            # Check Point, certificate login
sudo unvpn forti -g vpn.example.com -u alice --connect               # Fortinet
sudo unvpn forti -g vpn.example.com --saml --connect                 # Fortinet with SSO
sudo unvpn forti-ipsec -g vpn.example.com -u alice --connect         # Fortinet IPsec (FortiClient)
sudo unvpn f5 -g vpn.example.com -u alice --connect                  # F5
sudo unvpn anyconnect -g https://vpn.example.com -u alice --connect  # AnyConnect
sudo unvpn gp -g vpn.example.com -u alice --connect                  # GlobalProtect
sudo unvpn openvpn -c profile.ovpn --connect                         # OpenVPN
sudo unvpn wireguard -c wg0.conf --connect                           # WireGuard
```

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The parsers that read gateway data have fuzz targets: see [fuzz/](fuzz/README.md).

## Legal

Only use unvpn to connect to VPNs you are allowed to use.

## License

unvpn is free software, licensed under the [GNU General Public License v3.0 or
later](LICENSE).