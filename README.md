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

- GTK4 app with saved connection profiles; passwords in the system keyring.
- Tray icon showing the connection state.
- Encrypted export / import of all profiles, to move them between machines.
- Auto-reconnect after sleep or a network change, without re-auth.
- Leak protection: optional kill switch and an IPv6 egress block.

## Install

Needs Rust, a C toolchain, GTK4, libadwaita, webkitgtk-6.0, polkit, iproute2 and
nftables. On Arch:

```sh
sudo pacman -S --needed rust base-devel perl gtk4 libadwaita webkitgtk-6.0 polkit iproute2 nftables
```

```sh
./install.sh                    # installs to /usr/local (asks for sudo)
PREFIX=~/.local ./install.sh    # or just for your user
./install.sh --uninstall
```

The installer also registers unvpn to start in the system tray at login.

## Command line

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

`--killswitch` enables a fail-closed firewall; `--allow-ipv6` keeps IPv6 instead of blocking it.

### Check Point certificates

A Check Point user certificate is obtained once with the registration key the
administrator sends (`<reference>-<code>`); it works only once. In the app, pick
"Certificate" as the authentication of a Check Point profile and click **Enroll…**.
From the command line (no root needed):

```sh
unvpn cp-enroll -g 203.0.113.10 -r 12345-abcdefgh -o alice.p12
```

The new key and the request are saved before anything is sent, and the CA's answer
before it is processed, so an interrupted enrollment can be finished with `--resume`
(or `--resend` when no answer arrived) instead of needing a new key.

## Legal

Only use unvpn to connect to VPNs you are allowed to use.
