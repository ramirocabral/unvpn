# Fortinet IPsec (IKEv2) back-end — protocol notes

Native IKEv2 back-end for **FortiGate dialup managed by FortiClient EMS / ZTNA**.
Distinct from the existing Fortinet **SSL-VPN** back-end (`src/forti/`, PPP over
TLS/DTLS): this is IPsec.

Subcommand: `unvpn forti-ipsec -g <host[:port]> -u <user> [--password p]
[--code otp] [--emssn SN] [--probe|--login|--connect] [--no-routes]`.

## Where this came from (RE)

Reverse-engineered from the FortiClient 7.4.3 Linux package on this box
(`/opt/forticlient/iked`, the IKE daemon) with Ghidra/REA, cross-checked against
RFC 7296 (IKEv2), RFC 2759 (MS-CHAP-v2), RFC 3079 (MPPE/MSK), RFC 3748 (EAP).

Decisive findings from `iked` (strings + symbols):

- **IKEv2, not IKEv1**: the live path is `ikev2_*` (`ikev2_add_header`,
  `ikev2_add_certreq`, `ikev2_add_auth`, …) plus `CHILDLESS_IKEV2_SUPPORTED`.
  `ikev1_recv` exists but is not the dialup path.
- **EAP user auth**: `EAP-MSCHAPV2` (username/password) and **`EAP-GTC`** (the
  token/OTP — `EAP-GTC: Challenge`, `Response`). The full wpa_supplicant EAP state
  machine is embedded.
- **In-band EMS gate** (the important one): the IKE_AUTH exchange carries
  FortiClient-private payloads `ikev2_add_forticlient_connect` (`FORTICLIENT_CONNECT`)
  and **`ikev2_add_adc_emssn`** — the **EMS serial number** (`EMSSN=`, `fct_get_emssn`).
  The gateway validates it; the binary carries the literal error:
  *"IPsec VPN login failed due to mismatched pre-shared key, client certificate, or
  EMS serial number"*. So the EMS serial is a mandatory credential alongside the
  gateway PSK/cert. It is only issued by the EMS to a registered endpoint and cannot
  be fabricated — connecting to an EMS-enforcing FortiGate requires legitimate
  onboarding + registration (see `emssn.rs`).
- Profile schema (from `confighandler`, protobuf): `vpn.ipsecvpn.connections.
  connection` with `ike_settings{server, fgt, authentication_method, certificate,
  xauth{enabled,prompt_username}, sso_enabled, ike_saml_port}` and
  `ipsec_settings{proposals, remote_networks}`.

A representative deployment: a public IKEv2 gateway (`203.0.113.2`) plus a separate
EMS host (`203.0.113.3`, e.g. `ems.example.com`) for telemetry/registration; data
plane over UDP 500/4500 + ESP; user/password + OTP token.

## Protocol implemented

Standard IKEv2 initiator (RFC 7296), MODP2048 / AES-CBC-256 / HMAC-SHA256 /
PRF-SHA256 (FortiGate's common dialup default):

1. **IKE_SA_INIT** — SA (one proposal), KEi, Ni, NAT-D source/destination hashes.
   Handles `COOKIE` (resend) and `INVALID_KE_PAYLOAD`; detects NAT and floats to
   UDP/4500. Derives SKEYSEED and the seven SK_* keys via `prf+`.
2. **IKE_AUTH** (SK-encrypted) — IDi (RFC822 user), CP(CFG_REQUEST), SAi2 (ESP
   proposal), TSi/TSr (0.0.0.0/0), INITIAL_CONTACT, and the FortiClient/EMS Notify
   payloads. No AUTH on the first message ⇒ request EAP.
3. **EAP loop** — EAP-Identity, EAP-MSCHAPV2 (challenge → NT-Response, then Success),
   EAP-GTC (OTP prompt via `# AUTH-PROMPT: code:`), Nak to steer method. On
   EAP-Success, send the final AUTH keyed by the MSCHAPv2 MSK (RFC 7296 §2.16), else
   SK_pi.
4. **CHILD SA** — read the gateway's ESP SPI from SAr2; KEYMAT = `prf+(SK_d, Ni|Nr)`;
   build the ESP SA (reusing `ike::esp::EspSa`). Parse the CP(CFG_REPLY) for the
   internal IP, DNS, split subnets (`INTERNAL_IP4_SUBNET`) and domains; fall back to
   the responder TSr ranges for routes.
5. **Data plane** — ESP over UDP-encap (NAT-T, 4500): poll(2) pump between the tun
   device (`cpfi0`) and the socket, split/full routes + DNS via `sysnet`, NAT-T
   keepalive, clean teardown via `NetRestore`.

## Module layout (`src/forti_ipsec/`)

- `model.rs` — IKEv2 numeric registries + FortiClient extension tags.
- `wire.rs` — IKEv2 message + payload chain codec (SA/KE/Nonce/ID/AUTH/Notify/
  Delete/TS/CP/EAP), round-trip tested.
- `crypto.rs` — PRF / `prf+`, SA key derivation, SK encrypt/decrypt + ICV, AUTH,
  CHILD keymat. DH reused from `ike::crypto` (MODP groups).
- `eap.rs` — EAP framing, EAP-GTC, EAP-MSCHAPv2 (hand MD4 + hand DES, since OpenSSL
  3's default provider dropped both) + MSK. Tested against RFC 2759/3079 vectors.
- `config.rs` — CP reply + TSr → IP/DNS/routes/domains.
- `session.rs` — IKEv2 state machine + SK framing.
- `emssn.rs` — FortiClient `FORTICLIENT_CONNECT` + EMS-serial payloads (see status).
- `mod.rs` — CLI, connect orchestration, ESP data plane.

## Status

- **Offline-tested**: 35 unit tests — wire framing, IKEv2 crypto ladder, EAP RFC
  vectors (MD4/DES/NT-Response/MasterKey), SK encrypt+ICV round-trip, config parse.
- **`--probe`** (IKE_SA_INIT only) is ready to run against any FortiGate IPsec
  gateway and report its proposal + NAT state.
- **NOT yet live-validated**: the EAP auth + ESP data plane are implemented per RFC
  but unverified against a real gateway. No FortiGate IPsec gateway/creds on hand.

## Open items / roadmap (need a live gateway or onboarding)

- **EMS serial** (`emssn.rs`): the two private Notify numeric types and the exact
  `EMSSN=` payload framing are PROVISIONAL — pending decompilation of
  `ikev2_add_adc_emssn` and a packet capture. `read_local_forticlient_emssn()` is a
  stub: once the box is EMS-registered, read the serial the real FortiClient holds
  (`epctrl_ems_serial` in shm / the config DB) instead of guessing. Override today
  via `--emssn` / `UNVPN_EMSSN`.
- **AUTH-key selection under EAP**: MSK vs SK_pi — confirm against a capture which
  one FortiGate expects, and whether the gateway authenticates by cert or group PSK
  (then verify its AUTH instead of only logging).
- **DH agility**: only MODP2048 is wired; add MODP1024/1536 and ECP256/384 if a
  gateway demands them (INVALID_KE currently just errors with the wanted group).
- **ESP**: ESN, AES-GCM, rekey (CREATE_CHILD_SA), DPD via INFORMATIONAL, Delete-SA
  on teardown, transparent reconnect — mirror the SSL-VPN back-end once the base is
  validated live.
- Connecting to an **EMS/ZTNA-enforcing** gateway additionally requires legitimate
  EMS onboarding: the gateway rejects an unknown EMS serial in-band, and it cannot
  be fabricated. The native client becomes usable there only once the endpoint is
  registered and holds a valid serial.
