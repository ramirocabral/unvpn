<div align="center">

<img src="packaging/icons/unvpn-128.png" width="96" alt="unvpn"/>

# unvpn

A native Linux client for corporate VPNs written in Rust.

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

- GTK4 / libadwaita app with saved connection profiles.
- Passwords are stored in the system keyring.
- Export / import of all profiles (with their passwords and VPN files) as one passphrase-encrypted file, to move them to another machine.
- Tray icon that shows the connection state.
- Leak protection: an optional kill switch and, by default, an IPv6 egress block (see below).
- Auto-reconnect: the Fortinet SSL, F5, GlobalProtect, AnyConnect and OpenVPN back-ends rebuild a dropped tunnel on their own, and react within about a second to a resume from sleep or a network change (Wi-Fi ↔ cable) instead of waiting for a keepalive to time out. The session is reused, so no re-auth — unless the gateway has expired it, in which case unvpn reports it and you reconnect. The Check Point (IKEv1) and FortiClient IPsec (IKEv2) back-ends recover the data plane under the live IKE SA without re-auth — Check Point with a fresh Quick Mode, FortiClient IPsec with a CREATE_CHILD_SA rekey (PFS) — and use dead-peer detection (IKEv2 DPD for FortiClient IPsec) to notice a silent drop; only if the IKE SA itself is gone do they end with a clear error to reconnect.

## Leak protection

Every back-end except WireGuard carries IPv4 only, so while connected unvpn blocks
all IPv6 egress (leaving loopback and link-local alone) so IPv6 traffic can't slip
past the tunnel. Pass `--allow-ipv6` to keep IPv6 as is.

The **kill switch** (`--killswitch`, or the per-profile toggle in the GUI; off by
default) installs a fail-closed `nftables` table: while connected — and while the
tunnel reconnects — nothing leaves the host except the tunnel itself, the VPN
gateway, the local LAN and DHCP. It is removed on disconnect. If unvpn is killed
hard (SIGKILL / power loss) the table can linger; clear it with
`sudo nft delete table inet unvpn_<iface>` (unvpn prints the exact command when it
enables the switch). Not available for WireGuard — use its `AllowedIPs` / `Table` /
`fwmark` instead.

## Install

Build dependencies:

- Rust and cargo.
- A C compiler, `perl` and `make`.
- GTK4 and libadwaita.
- `webkitgtk-6.0` (for the built-in SSO sign-in window).

Runtime dependencies:

- `pkexec` (polkit).
- `iproute2`.
- `nftables` (for the kill switch and the IPv6 leak block).
- A system tray, like Waybar's or GNOME's AppIndicator extension (optional).

On Arch:

```sh
sudo pacman -S --needed rust base-devel perl gtk4 libadwaita webkitgtk-6.0 polkit iproute2 nftables
```

Then:

```sh
./install.sh                    # installs to /usr/local (asks for sudo)
PREFIX=~/.local ./install.sh    # or just for your user
./install.sh --uninstall
```

## Command line

```sh
sudo unvpn ike -g 203.0.113.10 -u alice --connect                    # Check Point
sudo unvpn forti -g vpn.example.com -u alice --connect               # Fortinet
sudo unvpn forti -g vpn.example.com --saml --connect                 # Fortinet with SSO
sudo unvpn forti-ipsec -g vpn.example.com -u alice --connect         # Fortinet IPsec (FortiClient)
sudo unvpn f5 -g vpn.example.com -u alice --connect                  # F5
sudo unvpn anyconnect -g https://vpn.example.com -u alice --connect  # AnyConnect
sudo unvpn gp -g vpn.example.com -u alice --connect                  # GlobalProtect
sudo unvpn openvpn -c profile.ovpn --connect                         # OpenVPN
sudo unvpn wireguard -c wg0.conf --connect                           # WireGuard
```

Global flags (any back-end): `--killswitch` enables the fail-closed firewall;
`--allow-ipv6` keeps IPv6 egress instead of blocking it for the session.

## Legal

Only use unvpn to connect to VPNs you are allowed to use.
