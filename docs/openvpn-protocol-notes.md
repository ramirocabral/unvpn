# OpenVPN 2.x — spec de protocolo (cliente nativo)

> Quinto back-end del cliente nativo (`cpvpn openvpn -c perfil.ovpn …`): habla el
> protocolo OpenVPN 2.x contra un servidor `openvpn` (2.4 / 2.5 / 2.6 / 2.7) o un
> Access Server, desde Linux, **sin** el binario `openvpn` ni plugins de
> NetworkManager. Todo en Rust: `checkpoint-client/src/openvpn/`.
>
> A diferencia de los otros back-ends no hubo que reversear un binario cerrado:
> OpenVPN es open-source y el protocolo está "documentado" por el código. La
> fuente de verdad fue **OpenVPN 2.6.14** (`ssl.c`, `ssl_pkt.c`, `reliable.c`,
> `crypto.c`, `tls_crypt.c`, `push.c`, `ping.c`, `occ.c`, `comp*.c`). La interop
> se validó contra el `openvpn` 2.7.8 de Arch corriendo como servidor en un
> network namespace (ver "Validación").

## Módulos

| archivo | qué |
|---|---|
| `config.rs` | parser `.ovpn`: remotes/`<connection>`, inline `<ca>/<cert>/<key>/<tls-auth>/<tls-crypt>`, paths relativos al .ovpn, `pkcs12`, crypto, verify, timers, rutas cliente |
| `crypto.rs` | static key V1, PRF TLS1.0, wrap tls-auth / tls-crypt, ciphers del data channel, replay window |
| `packet.rs` | opcodes, codec de paquetes de control, capa *reliable* (ACK/retransmit/reorden) |
| `tls.rs` | contexto OpenSSL (CA, cert/key o PKCS#12, `verify-x509-name`, `remote-cert-tls`), `MemPipe` |
| `session.rs` | `Engine`: session ids, key states, TLS sobre P_CONTROL, key-method 2, derivación de claves, renegociación |
| `push.rs` | `PUSH_REPLY` → `PushConfig` |
| `link.rs` | transporte UDP / TCP (prefijo de longitud u16) |
| `tunnel.rs` | establish (PUSH/AUTH_*), tun + rutas + DNS, data loop, ping, reconexión, `--probe` |

## Paquetes

Primer byte: `opcode << 3 | key_id` (key_id 0..7).

| op | nombre |
|---|---|
| 3 | `P_CONTROL_SOFT_RESET_V1` (renegociación, nuevo key_id) |
| 4 | `P_CONTROL_V1` (bytes TLS) |
| 5 | `P_ACK_V1` |
| 6 | `P_DATA_V1` |
| 7 / 8 | `P_CONTROL_HARD_RESET_CLIENT_V2` / `…_SERVER_V2` |
| 9 | `P_DATA_V2` (con peer-id de 24 bits) |

Control (después del wrapping):

```
op | session_id(8) | n_acks(1) | acks(4·n) | remote_sid(8, sólo si n>0)
   | message_id(4, no en P_ACK_V1) | payload
```

- Cada key state numera sus mensajes desde 0; el reset propio es el id 0.
- La capa reliable entrega en orden, ACKea todo lo recibido (también duplicados)
  y retransmite lo no-ACKeado (2 s inicial, back-off ×2 hasta 16 s). En TCP no
  se retransmite. Máximo **4 ACKs por paquete** (SoftEther descarta más).
- TLS arranca cuando llegó el reset del peer **y** nos ACKearon el nuestro.
- Los bytes TLS van en trozos de ≤1100 B por `P_CONTROL_V1`.

### Wrapping del control channel

- **ninguno**: `op | sid | rest`.
- **tls-auth**: `op | sid | HMAC | pid(4) | time(4) | rest`, HMAC (`auth`,
  default SHA1) sobre `pid | time | op | sid | rest`. Clave = primeros
  `digest_len` bytes de la mitad HMAC. Dirección: sin `key-direction` ambos usan
  la key 0; `key-direction 1` (cliente típico) → out key 1 / in key 0.
- **tls-crypt**: `op | sid | pid | time | TAG(32) | AES-256-CTR(rest)`,
  `TAG = HMAC-SHA256(op…time | rest)`, IV = TAG[0..16]. El cliente siempre usa
  dirección inversa (out key 1 / in key 0).
- `pid` es un contador propio del wrapping (arranca en 1); `time` = epoch fijo al
  crear la sesión.
- **tls-crypt-v2**: no soportado todavía (`HARD_RESET_CLIENT_V3` + WKc).

Static key V1: 256 bytes hex = `key[0]{cipher 64, hmac 64} key[1]{cipher 64, hmac 64}`.

## Key method 2 (dentro de TLS)

Cliente → servidor:

```
u32 0 | u8 2 | pre_master(48) | random1(32) | random2(32)
| str(options) | str(user) | str(pass) | str(peer_info)
```

`str` = `u16 len (incluye NUL) | bytes | 0`. Sin credenciales: dos `u16 0`.
El servidor responde igual pero sin `pre_master`. El mensaje del server llega en
su propio registro TLS (lo parseamos del primer `SSL_read`).

`peer_info` que mandamos:

```
IV_VER=2.6.14  IV_PLAT=linux  IV_TCPNL=1  IV_MTU=1600  IV_NCP=2
IV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305[:cipher del perfil]
IV_PROTO=478   (DATA_V2|REQUEST_PUSH|TLS_KEY_EXPORT|AUTH_PENDING_KW|DNS_OPTION|CC_EXIT_NOTIFY|AUTH_FAIL_TEMP)
IV_LZO_STUB=1 IV_COMP_STUB=1 IV_COMP_STUBv2=1   (sabemos el framing, no comprimimos)
IV_SSO=openurl,webauth,crtext  IV_GUI_VER=cpvpn <ver>
```

**No** anunciamos `DYN_TLS_CRYPT` (bit 9). El options string es sólo
informativo (el server sólo lo compara con `--opt-verify`).

## Claves del data channel

256 bytes = `key2` (misma forma que la static key). Cliente: **encrypt key[0],
decrypt key[1]**. Dos métodos:

- **TLS-EKM** (2.6+, si el push trae `key-derivation tls-ekm` o
  `protocol-flags … tls-ekm`): `SSL_export_keying_material(label
  "EXPORTER-OpenVPN-datakeys", sin contexto, 256)`.
- **PRF TLS1.0** (servers viejos): `master = PRF(pre_master, "OpenVPN master
  secret" | c.r1 | s.r1, 48)`; `key2 = PRF(master, "OpenVPN key expansion" |
  c.r2 | s.r2 | client_sid | server_sid, 256)`. PRF = P_MD5(S1) ⊕ P_SHA1(S2).
  Test knob: `CPVPN_OVPN_NO_EKM=1` deja de anunciar EKM y fuerza este camino.

El método y el cipher se fijan con el **primer PUSH_REPLY**; recién ahí se
derivan las claves de key_id 0. Las renegociaciones derivan apenas termina su
key exchange.

## Data channel

- **AEAD** (AES-128/192/256-GCM, CHACHA20-POLY1305):
  `hdr | pid(4) | TAG(16) | ct`. Nonce = `pid | implicit_iv(8)`, donde
  `implicit_iv` = primeros 8 bytes de la mitad HMAC de la key. AAD = `hdr` (sólo
  en V2: op+peer-id, 4 bytes) `| pid`.
- **CBC** (AES-*-CBC): `hdr | HMAC | IV(16) | E(pid | payload)` con PKCS#7; HMAC
  (`auth`) sobre `IV | ct`, sin el header.
- `P_DATA_V2` si el push trae `peer-id`, si no `P_DATA_V1`.
- Replay: ventana deslizante de 64 ids.
- Compresión (nunca comprimimos; sólo framing): `comp-lzo` → byte `0xFA`;
  `compress`/`stub`/`lz4` → swap `0xFB` (el 1er byte va al final);
  `stub-v2`/`lz4-v2` → nada salvo que el paquete empiece con `0x50`
  (`0x50 0x00` delante). Paquetes comprimidos entrantes se descartan.
- **Ping**: payload mágico de 16 bytes `2a187bf3641eb4cb07ed2d0a981fc748`; se
  manda si no transmitimos en `ping` segundos; sin nada del server durante
  `ping-restart` → reconexión.
- **OCC exit**: `287f346bd4ef7a812d56b8d3afc5459c | 06` — lo mandamos al
  desconectar por UDP (además de `EXIT` en el control channel); si llega del
  server, reconectamos.

## Mensajes de control (texto, NUL-terminados)

- `PUSH_REQUEST` → se reenvía cada 3 s (5 s con `AUTH_PENDING`) hasta el reply.
- `PUSH_REPLY,…[,push-continuation 2|1]` — opciones usadas: `ifconfig`,
  `topology`, `route [mask] [gw|net_gateway]`, `route-gateway`,
  `redirect-gateway`, `dhcp-option DNS/DOMAIN/DOMAIN-SEARCH`, `dns server N
  address …`, `dns search-domains`, `peer-id`, `cipher`, `auth`, `ping`,
  `ping-restart`, `tun-mtu`, `comp-lzo`/`compress`, `key-derivation`,
  `protocol-flags`, `auth-token`, `auth-token-user` (base64).
- `AUTH_FAILED[,motivo]`; `AUTH_FAILED,CRV1:<flags>:<state>:<b64 user>:<texto>`
  = challenge dinámico → se pregunta y se reconecta con password
  `CRV1::<state>::<respuesta>`.
- `static-challenge` en el perfil → password `SCRV1:<b64 pass>:<b64 resp>`.
- `AUTH_PENDING[,timeout N]` + `INFO_PRE,WEB_AUTH::<url>` / `OPEN_URL:<url>` →
  `# SAML-URL:` (la GUI todavía no la abre sola: sólo abre URLs del gateway
  tipeado); `CR_TEXT:<flags>:<texto>` → `CR_RESPONSE,<b64>`.
- `RESTART` / `HALT` / `EXIT` → reconexión / fin.
- `auth-token` pusheado reemplaza la password en reconexiones y renegociaciones
  (la original pudo ser un OTP).

## Renegociación

- Server-iniciada: llega `SOFT_RESET_V1` con un key_id nuevo → nuevo key state
  (reliable desde 0, mismo par de session ids), mandamos nuestro `SOFT_RESET`,
  TLS completo + key-method 2 (credenciales o auth-token otra vez) → claves
  nuevas → pasan a cifrar; la anterior queda "lame duck" 60 s para descifrar.
- Cliente-iniciada: sólo si el perfil fija `reneg-sec > 0` (si no, la maneja el
  server, default 3600 s). key_id siguiente: 1..7, nunca vuelve a 0.

## Verificación del servidor (como OpenVPN)

Cadena hasta `<ca>` (o las CA del PKCS#12 si no hay `<ca>`), **sin** chequeo de
hostname ni SNI. Depth 0: `verify-x509-name` (`subject` en el formato de OpenVPN
`C=AR, ST=…, CN=…`, `name` = CN exacto, `name-prefix`) y `remote-cert-tls
server` (EKU "TLS Web Server Authentication"). Security level 1
(`tls-cert-profile legacy`), TLS ≥ 1.2 salvo `tls-version-min`.

## Red

- tun `cpovpn0` (fallback del kernel si está ocupado). `topology subnet` →
  `addr local/prefix`; net30/p2p → `addr local peer remote`.
- MTU del tun = min(pushed/`tun-mtu`, **1400**): reemplaza al `mssfix` de
  OpenVPN, evita fragmentar el UDP externo.
- Rutas en un `ip -batch`: server pineado por su camino original, `net_gateway`
  fuera del túnel, `redirect-gateway` → `0/1 + 128/1`, resto `dev cpovpn0`.
  `route-nopull` ignora rutas/DNS pusheados. DNS vía `sysnet::set_dns`.

## Validación (20/10/2026)

Lab: `openvpn` 2.7.8 como servidor dentro de un netns (`cpvlab`, veth
10.250.0.0/30, red "interna" dummy 10.98.0.0/24), PKI propia, verificación de
user/pass por script.

| caso | resultado |
|---|---|
| UDP + tls-crypt + AES-256-GCM + TLS-EKM + P_DATA_V2, topology subnet | ✅ ping 0% pérdida |
| 3 renegociaciones iniciadas por el server (`reneg-sec 20`) bajo tráfico | ✅ 0% pérdida, 0 decrypt errors |
| TCP + tls-auth (`key-direction 1`) + AES-256-CBC/HMAC-SHA256 + **PRF** + comp-lzo + net30 | ✅ pings de 1300 B, 0% pérdida |
| renegociación iniciada por el cliente (`reneg-sec 15`) | ✅ |
| password incorrecta | ✅ `AUTH FAILED: credentials rejected` |
| key PKCS#8 cifrada | ✅ pide passphrase (`AUTH-PROMPT: answer`) |
| teardown | ✅ tun/rutas borradas, server ve el exit-notify |
| throughput (iperf3, release) | **1.06 / 1.23 Gbit/s** vs 0.70 / 0.77 del `openvpn` 2.7.8 oficial (sin DCO) |

Gateways reales (sólo `--probe`, sin credenciales):
- `vpn3.example.org:1196` (gw-ovpn2, tls-crypt) → TLS 1.3 OK, cert `CN=example.org`.
- `vpn1.example.org` / `vpn2.example.org` → la CA de los
  perfiles **venció (13/09/2026)** o fue renovada; el `openvpn` oficial falla
  exactamente igual → hay que pedir perfiles nuevos.

## Pendiente
- tls-crypt-v2; `auth-user-pass` + WEB_AUTH abierto desde la GUI;
  IPv6 (`ifconfig-ipv6`, `route-ipv6`); proxies HTTP/SOCKS; `fragment`;
  PKCS#11; DCO (kernel `ovpn`) como fast-path opcional.
