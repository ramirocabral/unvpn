# Fortinet IPsec (IKEv2) back-end — protocol notes

Native IKEv2 back-end for **FortiGate dialup managed by FortiClient EMS / ZTNA**.
Distinct from the existing Fortinet **SSL-VPN** back-end (`src/forti/`, PPP over
TLS/DTLS): this is IPsec.

Subcommand: `unvpn forti-ipsec -g <host[:port]> -u <user> [--password p]
[--code otp] [--emssn SN] [--localid id] [--id-type fqdn|rfc822|keyid]
[--psk key] [--probe|--auth-probe|--login|--connect] [--no-routes]`.

`--psk` is the dialup group pre-shared key. It is *not* needed to authenticate
(the client's final AUTH is keyed by the EAP MSK), but when supplied it verifies
the gateway's own AUTH (shared-key, method 2): a mismatch aborts, which detects a
wrong gateway or a man-in-the-middle.

Modes: `--probe` does IKE_SA_INIT only; `--auth-probe` additionally sends the first
IKE_AUTH with a throwaway identity and no credentials, then dumps the gateway's
reply (which EAP method it offers, PSK vs cert, or whether an EMS/ZTNA gate drops
it first); `--login` authenticates and negotiates the CHILD SA but stops before the
data plane; `--connect` runs the tunnel. `UNVPN_VERBOSE=1` dumps every parsed
payload chain (structure only, no key material).

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

- **Offline-tested**: 36 unit tests — wire framing, IKEv2 crypto ladder, EAP RFC
  vectors (MD4/DES/NT-Response/MasterKey + the MSK known-answer), SK encrypt+ICV
  round-trip, config parse.
- **Live-validated against strongSwan** (a local IKEv2 responder, EAP-MSCHAPv2):
  IKE_SA_INIT → first IKE_AUTH → full EAP-MSCHAPv2 loop → final AUTH → CHILD SA with
  an assigned internal IP from the pool. This exercises the real SK crypto
  (SKEYSEED/prf+/SK_* keys, AES-CBC, ICV), the EAP state machine, the MSK, the
  EAP-keyed AUTH, and the CP(CFG_REPLY) parse against an independent implementation.
- **MSK ordering fixed here**: the EAP-MSCHAPv2 MSK is `MasterSendKey |
  MasterReceiveKey | 32 zero octets`. A `recv|send` ordering lets EAP-MSCHAPv2
  *succeed* (the server establishes the MSK) but makes the final `AUTH` fail
  verification — charon logs exactly that. Now pinned by a known-answer test.
- **Against the live managed FortiGate**: `--probe` succeeds — the gateway accepts
  the single offered suite (AES-CBC-256 / PRF-SHA256 / SHA256-128 / MODP2048),
  returns a 16-byte nonce, no VendorID, and signals NAT (→ NAT-T 4500). The first
  **IKE_AUTH then starts the EAP exchange**: the gateway replies with its `IDr`,
  an `AUTH` of method 2 (**shared-key MIC — it authenticates by PSK**), and an
  **EAP-Request/Identity** — i.e. it accepts the message and asks for the user
  identity, before any credential or EMS serial is presented (we sent none).
- **The dialup group ID (`IDi`) is what the gateway keys on.** An earlier probe
  that sent the username as an `IDi` of type RFC822 was *silently dropped* — a
  FortiGate dialup selects the phase1-interface by the peer ID, and an ID that
  matches no configured group gets no reply at all. Sending the profile's
  `<localid>` (the dialup group name) as the `IDi` — `--localid <group>`, type
  KEY_ID (also accepted as FQDN) — makes the same gateway proceed to EAP. So the
  silent drop was **ID selection, not an EMS/ZTNA policy gate**: no FortiClient/EMS
  serial is required at the IKE layer to begin EAP on this gateway. (The EMS serial
  machinery still exists in `iked`/the profile and a gateway *can* be configured to
  enforce it; this particular dialup does not, pre-EAP.)
- **ESP data plane** is not yet live-validated, but reuses `ike::esp::EspSa`, which
  is exercised in production by the Check Point IKEv1 back-end.

### NAT-T note (fixed)

Floating to UDP/4500 now reuses the *same* socket (keeps the source port) via
`IkeUdp::float_to_natt`, instead of opening a fresh socket with a new ephemeral
port. A strict responder tracks the half-open IKE SA by the NAT mapping of the
SA_INIT source; a new source port breaks it (the gateway never replies to the
IKE_AUTH). Our NAT-D *source* hash still claims port 500 while we send from an
ephemeral port, so a peer always flags NAT on us — harmless (we are behind NAT to
any real gateway anyway), but it also trips NAT-T on loopback tests.

## FortiClient profile secret de-obfuscation (`Enc ` fields)

A provisioned FortiClient installer/profile stores secrets — the dialup group
pre-shared key, saved passwords — as `Enc <hex>` (also seen as `EncX <hex>`).
This is Fortinet's *obfuscation*, not security: the scheme and its key are baked
into the shipped binaries.

- The routine is `forticlient::crypto::gladman::{encrypt,decrypt}` in
  `confighandler`. The exported C-ABI wrappers are
  `int decrypt_buffer(const u8 *in, i32 in_len, u8 *out, i32 *out_cap_inout,
  const char *key)` and the matching `encrypt_buffer` (a 3-instruction stub that
  flips an encrypt/decrypt flag and tail-calls the shared worker). `decrypt_buffer`
  operates on the **raw ciphertext bytes** — stripping the `Enc `/`EncX ` tag and
  hex-decoding happens one layer up, in the config-field reader — and returns 0 on
  success with `*out_cap` set to the plaintext length.
- When the caller passes no per-profile key, gladman falls back to a **fixed
  default key compiled into every FortiClient build**: the pangram string
  `fc_1A2Brown3Fox4Jumped5Over6A7Lazy8Dog` (38 bytes, recovered from
  `confighandler`'s `.rodata`). It is a vendor constant, identical across
  installs — not a per-customer secret.
- Ciphertext carries a fixed **24-byte overhead** (a random prefix/IV); an
  *n*-byte secret encrypts to *n*+24 bytes. So a 41-byte blob decrypts to a
  17-byte secret.
- Verified by running the vendor's own `decrypt_buffer` as an oracle (under a
  debugger: break after libc init, `strcpy` the key, call with the hex-decoded
  bytes) and by an `encrypt → decrypt` round-trip. A given deployment's group PSK
  recovers cleanly this way (kept out of this repo; a real one is a site secret,
  referenced here as `<group-psk>`).
- Not yet reimplemented natively in Rust: `unvpn` takes the recovered PSK via
  `--psk` instead (used to verify the gateway's AUTH). A pure-Rust `gladman` port
  would make the client fully self-contained (identify the worker's exact
  cipher/mode and the 24-byte prefix layout first).

## Open items / roadmap (need a live gateway or onboarding)

- **EMS serial** (`emssn.rs`): the payload is now RE-confirmed from `iked`'s
  `.rodata` and disassembly — a single Notify **`0xF100` (FORTICLIENT_CONNECT)**
  whose data is a `\n`-separated `KEY=value` text blob, fields in order `TVER` `UID`
  `IP` `HOST` `OSVER` `REG_STATUS` `EMSID` `USER` `EMSSN`, with `TVER=7.4.3.5411`,
  `HOST` from `gethostname(2)`, and `EMSSN=<serial>` the validated field. (Other
  recovered private Notify types: `VPN_NETWORK_ID 0xF050`, `DEV_ID_NOTIFY 0xF103`,
  `CLIENT_RESUME 0xF118` — the last confirmed as a real code immediate.) Still to
  confirm with a capture: which exchange carries it (implemented in the first
  IKE_AUTH request; could be IKE_SA_INIT) and whether `DEV_ID_NOTIFY` /
  `VPN_NETWORK_ID` must accompany it. `read_local_forticlient_emssn()` is still a
  stub: once the box is EMS-registered, read the serial the real FortiClient holds
  (`fct_get_emssn` → `epctrl_ems_serial` in shm / the config DB). Override today via
  `--emssn` / `UNVPN_EMSSN`.
- **AUTH-key selection under EAP** — *resolved*: the final AUTH is keyed by the
  EAP MSK (RFC 7296 §2.16), MSK = `MasterSendKey | MasterReceiveKey`, confirmed live
  against strongSwan. `SK_pi` is only the fallback when no EAP method ran.
- **Gateway AUTH verification** — *implemented* for the shared-key case: with
  `--psk <group-key>` we recompute the responder's signed octets
  (`RealMessage2 | Ni | prf(SK_pr, IDr')`) and compare `prf(prf(PSK, pad), octets)`
  to the gateway's method-2 AUTH; a mismatch aborts. Without a PSK (or against a
  cert-authenticated gateway) we only log the method — handling a gateway
  CERT/CERTREQ is still open.
- **DH agility**: only MODP2048 is wired; add MODP1024/1536 and ECP256/384 if a
  gateway demands them (INVALID_KE currently just errors with the wanted group).
- **ESP**: ESN, AES-GCM, rekey (CREATE_CHILD_SA), DPD via INFORMATIONAL, Delete-SA
  on teardown, transparent reconnect — mirror the SSL-VPN back-end once the base is
  validated live.
- Connecting to an **EMS/ZTNA-enforcing** gateway additionally requires legitimate
  EMS onboarding: the gateway rejects an unknown EMS serial in-band, and it cannot
  be fabricated. The native client becomes usable there only once the endpoint is
  registered and holds a valid serial.
