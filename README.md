<div align="center">

<img src="packaging/icons/unvpn-128.png" width="96" alt="unvpn"/>

# unvpn

A native Linux client for corporate VPNs.

</div>

unvpn speaks each VPN protocol itself, written from scratch in Rust. You don't need the
vendor's client (FortiClient, AnyConnect, the F5 or Check Point clients, `openvpn`,
`wg-quick`) installed.

Supported VPNs:

- Check Point (Endpoint Connect / SNX, with RSA SecurID)
- Fortinet FortiGate SSL-VPN (password, OTP, SAML/SSO)
- F5 BIG-IP APM
- Cisco AnyConnect (password, 2FA, SAML/SSO)
- OpenVPN (`.ovpn` profiles)
- WireGuard (`wg-quick` `.conf` files, using the kernel's WireGuard)

<p align="center">
  <img src="screenshots/dark.png" width="420" alt="unvpn"/>
</p>

## Features

- GTK4 / libadwaita app with saved connection profiles.
- Passwords are stored in the system keyring, never in plain text. One-time codes are never stored.
- Tray icon that shows the connection state. Closing the window keeps the VPN running.
- Sets the VPN's DNS servers while connected and restores yours when you disconnect.
- Reconnects on its own if the connection drops (AnyConnect, F5, Fortinet, OpenVPN).
- The app runs as your user. Only the VPN engine runs as root, started through `pkexec`.
- Also works as a plain command-line tool.

## Install

Build dependencies:

- Rust and cargo
- A C compiler, `perl` and `make` (OpenSSL is built into the binary)
- GTK4 and libadwaita
- `webkitgtk-6.0` (for the built-in SSO sign-in window)

Runtime dependencies:

- `pkexec` (polkit)
- `iproute2`
- A system tray, like Waybar's or GNOME's AppIndicator extension (optional)

On Arch:

```sh
sudo pacman -S --needed rust base-devel perl gtk4 libadwaita webkitgtk-6.0 polkit iproute2
```

Then:

```sh
./install.sh                    # installs to /usr/local (asks for sudo)
PREFIX=~/.local ./install.sh    # or just for your user
./install.sh --uninstall
```

The installer builds everything and adds the app to your menu. It can also add a polkit
rule, so you type your admin password once and it is remembered for a while.

Without `webkitgtk-6.0`, build the app with `cargo build --release --no-default-features`
in `unvpn-gui/`. SSO then opens in your browser and you paste the token by hand.

## Using the app

Open **unvpn** from your app menu. Pick the VPN type, fill in the gateway and user, and
click **Save** to keep it as a profile. Next time, click the play button next to the
profile to connect.

## Command line

```sh
sudo unvpn ike -g 203.0.113.10 -u alice --connect                    # Check Point
sudo unvpn forti -g vpn.example.com -u alice --connect               # Fortinet
sudo unvpn forti -g vpn.example.com --saml --connect                 # Fortinet with SSO
sudo unvpn f5 -g vpn.example.com -u alice --connect                  # F5
sudo unvpn anyconnect -g https://vpn.example.com -u alice --connect  # AnyConnect
sudo unvpn openvpn -c profile.ovpn --connect                         # OpenVPN
sudo unvpn wireguard -c wg0.conf --connect                           # WireGuard
```

Passwords and codes are read from stdin. Type `disconnect` or press Ctrl+C to close the
tunnel cleanly. Most VPN types also have `--probe`, which checks the gateway without
logging in. Run `unvpn` with no arguments to see all options.

## Legal

Only use unvpn to connect to VPNs you are allowed to use.
