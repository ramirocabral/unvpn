# WireGuard back-end — notes

`unvpn wireguard -c <profile.conf> …` (`unvpn/src/wireguard/`).

## Design: drive the kernel, don't re-implement it

Unlike the other back-ends, WireGuard is not reverse-engineered or re-implemented:
it is part of the Linux kernel (5.6+, a module on most distros), and the in-kernel
implementation is faster and better reviewed than anything userspace could offer. So
unvpn does what `wg-quick` does, natively and without the `wg`/`wg-quick` binaries:

| step | how |
|---|---|
| create the interface | `ip link add cpwg0 type wireguard` (rtnetlink via iproute2, like every back-end's addressing); this also autoloads the module. A taken name moves on to `cpwg1…9` — an existing interface is never touched. |
| keys, peers, endpoints, allowed IPs | generic netlink, family `wireguard` (`WG_CMD_SET_DEVICE`), resolved through the genl controller — `wireguard/netlink.rs` |
| stats, last handshake | `WG_CMD_GET_DEVICE` (a dump) |
| addresses, MTU, routes, DNS | `ip` + the shared `sysnet` DNS handling, as in the other back-ends |

The kernel does the protocol: Noise IKpsk2 handshakes, rekeying, timers, cookies,
roaming, the data plane.

## Generic netlink, the parts that matter

From `include/uapi/linux/wireguard.h`:

- `WG_CMD_GET_DEVICE` = 0 (must be sent with `NLM_F_DUMP`), `WG_CMD_SET_DEVICE` = 1, version 1.
- Device: `IFINDEX` 1, `IFNAME` 2, `PRIVATE_KEY` 3, `PUBLIC_KEY` 4, `FLAGS` 5
  (`REPLACE_PEERS` = 1), `LISTEN_PORT` 6 (u16), `FWMARK` 7 (u32), `PEERS` 8.
- Peer: `PUBLIC_KEY` 1, `PRESHARED_KEY` 2 (all-zero clears it), `FLAGS` 3
  (`REMOVE_ME` 1, `REPLACE_ALLOWEDIPS` 2, `UPDATE_ONLY` 4), `ENDPOINT` 4 (a raw
  `sockaddr_in`/`sockaddr_in6`), `PERSISTENT_KEEPALIVE_INTERVAL` 5 (u16),
  `LAST_HANDSHAKE_TIME` 6 (`__kernel_timespec`), `RX_BYTES` 7, `TX_BYTES` 8,
  `ALLOWEDIPS` 9, `PROTOCOL_VERSION` 10.
- Allowed IP: `FAMILY` 1 (u16), `IPADDR` 2 (4/16 bytes), `CIDR_MASK` 3 (u8).
- Nested attributes carry `NLA_F_NESTED`; list elements (peers, allowed IPs) use
  type 0.
- Large allowed-IP sets are split: the first message replaces the peers, the rest go
  as `UPDATE_ONLY` messages for the same peer (1000 allowed IPs per message), the way
  `wg` chunks them.
- A GET dump can split one peer across two messages (continuation under the same
  public key).

## Connect sequence

1. Parse the `.conf`; resolve every `Endpoint` while the pre-VPN resolver is still in place.
2. Create the link, `SET_DEVICE` (replace peers), add the addresses, `mtu` (default 1420) + `up`.
3. **Handshake check before routes.** WireGuard never handshakes without traffic, so
   peers with an endpoint get a temporary `PersistentKeepalive` (25 s): enabling it makes
   the kernel send a keepalive, hence a handshake, at once. We poll `GET_DEVICE` for a
   non-zero last-handshake time. Once every peer has answered (or one has and the others
   had 5 s more), keepalive goes back to the profile's value (off unless set). No answer
   within 30 s means an error that names the likely causes (keys / PSK / endpoint /
   blocked UDP), and everything is removed. This turns "the interface is up but nothing
   works" into a clear failure before any route or DNS change.
4. Routes (`Table = auto`): every peer's AllowedIPs via the interface. A `/0` becomes the
   two halves (`0.0.0.0/1` + `128.0.0.0/1`, `::/1` + `8000::/1`), so the original default
   route stays and comes back untouched. Each endpoint covered by those routes is pinned
   to its pre-VPN path (`ip route get`). `Table = off` installs nothing; `Table = <n>`
   puts the AllowedIPs, as-is, in that table and leaves policy routing to the user.
   Routes that already existed are not removed on teardown. Unlike wg-quick we don't
   use fwmark policy routing, which keeps this consistent with the other back-ends.
5. DNS: IPs in `DNS =` become resolvers (IPv4 or IPv6), names become search domains.
6. Watch: stats every 30 s. When we keep sending, nothing comes back, and the last
   handshake is older than 180 s, we warn that the peer isn't answering. We keep running
   — the kernel keeps retrying, and WireGuard has no session to "reconnect".
7. Teardown (stdin `disconnect`/EOF, SIGTERM/INT/HUP/QUIT, errors, panics): routes and
   DNS restored, interface deleted.

## Profile handling

- wg-quick format, keys case-insensitive, `#` comments, comma lists, repeated
  `Address`/`AllowedIPs`/`DNS` lines accumulate.
- `PreUp`/`PostUp`/`PreDown`/`PostDown` are **never executed**: the engine runs as root
  and a profile is data. They're listed as ignored. `SaveConfig` is ignored.
- `--pubkey` prints the interface's public key, the one to register on the server;
  `--genkey` makes a new pair. Both run without root.

## Validation

Lab with two network namespaces, connected by a veth: a kernel WireGuard "server"
(configured by this same engine, `--no-routes`, no endpoint for its peer) and the client.
All runs used a preshared key.

- `--probe`: handshake in ~100 ms; interface removed afterwards; a `PostUp` hook
  provably not run.
- `--connect` full tunnel v4+v6: endpoint pinned, halves installed, DNS + search written
  (via `/etc/netns/<ns>/resolv.conf`, so the host's resolv.conf is untouched); ping over
  IPv4 and IPv6; iperf3 ~3.1 Gbit/s each way (vs ~1.1 for the userspace OpenVPN data
  plane on the same box).
- Teardown on stdin EOF: v4 and v6 route tables identical byte-for-byte to before,
  resolv.conf restored, interface gone.
- Wrong peer public key: clean failure after 30 s with the diagnostic, nothing left behind.
- `disconnect` during the handshake wait: cancelled at once, cleaned up.

Live, against a real WireGuard server on a remote VPS (full tunnel IPv4, PSK,
`PersistentKeepalive`): handshake in ~200–300 ms, the public IP becomes the VPS's, ping and
DNS through the tunnel, endpoint pinned to the LAN gateway; on teardown the route tables and
resolv.conf were identical byte-for-byte to before.
A/B against `wg-quick` on the same profile, back to back: same throughput (~155 Mbit/s
down / ~30 up both, limited by the path to the server) — expected, the data plane is the
kernel's either way. `wg show` on our interface lists exactly what the profile says.

## Not done

- A userspace fallback (an own Noise IKpsk2 + tun data plane) for hosts without the
  kernel module (old kernels, some containers).
- Re-resolving a DNS endpoint whose address changes (wg-quick doesn't either).
