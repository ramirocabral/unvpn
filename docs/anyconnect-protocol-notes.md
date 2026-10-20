# Cisco AnyConnect SSL-VPN — spec de protocolo (reverse engineering)

> Cuarto back-end del cliente nativo (`cpvpn anyconnect …`): interoperar con un
> Cisco ASA / Secure Firewall que habla **AnyConnect / Cisco Secure Client**
> (protocolo "aggregate auth" + CSTP), desde Linux, sin binarios de Cisco.
> Evidencia: **prior-art open-source interoperable** (openconnect, backend
> `anyconnect` por defecto — ya habla con ASAs reales) + el instalador oficial
> `~/vendor/AnyConnect Installer.exe` para verificación de strings/UA.
> NO confundir con el back-end Check Point (IKE/ESP) ni con los SSL/PPP de
> Fortinet y F5: AnyConnect/CSTP es su propio framing, sin PPP.

## Prior-art / fuentes
- **openconnect** (fuente primaria del control+data plane): `auth.c`
  (`xmlpost_*`, `parse_xml_response`, `process_auth_form`, `cstp_obtain_cookie`),
  `cstp.c` (`start_cstp_connection`, `cstp_mainloop`, `cstp_bye`, framing STF),
  `http.c`/`cstp.c` (headers comunes), `hpke.c` + `openssl.c` (SSO external-browser).
- Instalador oficial `~/vendor/AnyConnect Installer.exe` — para strings/UA/versión
  (no hace falta para el core; openconnect ya interopera con ASAs de verdad).
- Gateways reales disponibles para probar (NetworkManager, plugin openconnect
  `protocol=anyconnect`): **gw-a** `203.0.113.20` (user `alice`, grupos
  `GROUP_A`/`GROUP_B`, password+form) y **gw-b**
  `vpn-sso.example.com/SSOGROUP` (SSO/SAML `sso-v2`). Interop corporativo
  autorizado.

## Aggregate auth (control plane) — XML sobre HTTPS
Todo el login es un diálogo de documentos `<config-auth>` POSTeados a la URL del
gateway (o a su URL de grupo, p.ej. `/SSOGROUP`):

1. **init** → el cliente POSTea
   `<config-auth client="vpn" type="init" aggregate-auth-version="2">` con
   `<version who="vpn">`, `<device-id>linux-64</device-id>`, `<capabilities>`
   (`single-sign-on-v2`, opcional `single-sign-on-external-browser`) y
   `<group-access>https://host[/grupo]</group-access>`. `Content-Type:
   application/xml; charset=utf-8`; headers `X-Transcend-Version: 1`,
   `X-Aggregate-Auth: 1`, `Accept-Encoding: identity`.
2. **auth-request** ← el gateway responde con:
   - `<opaque is-for="sg">…</opaque>` — blob opaco (tunnel-group, aggauth-handle,
     config-hash). **Se reenvía verbatim** en cada reply. (Por eso el parser XML
     guarda el span de bytes de cada elemento: así echo el `<opaque>` tal cual.)
   - `<auth id="main|challenge|success">` con `<title>`/`<message>`/`<banner>`/
     `<error>` y un `<form>` con `<input>`s y a veces `<select name="group_list">`.
   - Tipos de `<input>`: `text` (username…), `password`, `hidden` (se devuelve su
     `value`), `sso` (token SAML, no se tipea — ver §SSO).
3. **auth-reply** → el cliente POSTea
   `<config-auth type="auth-reply">` + `<opaque>` + `<auth>` con los campos
   contestados + opcional `<group-select>`. **Mapeo de nombres (de openconnect):**
   `group_list` → `<group-select>` (fuera de `<auth>`); `answer`/`whichpin`/
   `new_password` → `<password>`; `verify_pin`/`verify_password` se descartan;
   el resto → `<nombre>valor</nombre>` dentro de `<auth>`.
4. Se repite (challenge/2FA, cambio de password, grupo) hasta
   **`type="complete"`** con `<auth id="success">` y `<session-token>` =
   **cookie `webvpn`** para el túnel.

### Grupos (authgroup / NEWGROUP)
Si el form trae `<select name="group_list">`, el cliente elige (default = `option
selected`, o el `--group` pedido) y **reinicia** el init con `<group-select>` —
porque la policy del grupo puede pedir factores distintos (openconnect:
`OC_FORM_RESULT_NEWGROUP`). Implementado: primera vez que veo el dropdown,
re-POSTeo `init` con el grupo; la segunda, relleno el form de ese grupo.

### 2FA / challenge
`<auth id="challenge">` con un `<input type="password" name="answer">` (y
`<message>` con la consigna). El engine emite `# AUTH-PROMPT: code: <msg>` y lee
una línea de stdin (el GUI muestra la tarjeta de prompt; en TTY se tipea).
`new_password` → `# AUTH-PROMPT: newpass:`. Password rechazada = el gateway
re-muestra el form inicial con `<error>` → lo detecto y corto (no reintento).

### SSO / SAML (`sso-v2`) — PARCIAL
Gateways tipo gw-b responden con `<auth>` que trae `<sso-v2-login>` (URL del
IdP), `<sso-v2-login-final>`, `<sso-v2-token-cookie-name>` (ej. `acSamlv2Token`) y
un `<input type="sso">`. El cliente oficial abre un webview, el usuario se
autentica y lee la cookie del token al llegar a `login-final`. **Acá, sin
webview**: emito `# SAML-URL: <login>` (el GUI/usuario abre el browser) + `#
AUTH-PROMPT: answer:` para **pegar el valor de la cookie del token** (obtenible por
DevTools). Vía CLI: `--sso-token <valor>`. _Follow-up: automatizar la captura con
un webview (webkit2gtk-4.1 está instalado) o el loopback-listener
`single-sign-on-external-browser` + HPKE (ECDH P-256 / HKDF-SHA256 / AES-256-GCM,
ver openconnect `hpke.c`) — gw-b ofrece `sso-v2`, no external-browser._

## CSTP (data plane) — framing STF sobre el mismo TLS
Con la cookie `webvpn`, el cliente manda `CONNECT /CSCOSSLC/tunnel HTTP/1.1` con
headers de request `X-CSTP-*` (Version, Hostname, Base-MTU/MTU, Address-Type,
Address para reconexión) y `X-DTLS-*`. El gateway responde `HTTP/1.1 200` + headers
`X-CSTP-*`/`X-DTLS-*` con la config (IP, máscara, rutas, DNS, MTU, timers). De ahí
en más el **mismo stream TLS** lleva frames:

```
  'S' 'T' 'F' 0x01   <be16 payload-len>   <type>   0x00    <payload…>
```

Tipos (de openconnect `cstp.c`): `0`=DATA (paquete IPv4 crudo), `3`=DPD-request,
`4`=DPD-reply, `5`=disconnect (cliente/servidor; payload = `[code][msg]`),
`7`=keepalive, `8`=compressed (no negociamos compresión), `9`=server-kick.
No hay PPP: el payload de DATA es el paquete IP directo.

### Config headers (parseados, openconnect `start_cstp_connection`)
`X-CSTP-Address`/`Netmask` (IP asignada), `Split-Include`/`Split-Exclude`
(`addr/prefix` o `addr/dotted-mask`; sin includes ⇒ túnel por defecto `0.0.0.0/1`
+ `128.0.0.0/1`), `DNS`, `NBNS`, `Default-Domain`, `Split-DNS`, `MTU`,
`Keepalive`, `DPD`, `Rekey-Time`/`Rekey-Method`, `Idle-Timeout`,
`Session-Timeout`, `Disconnected-Timeout`, `Banner` (URL-encoded). DTLS: `X-DTLS-*`
(Port, CipherSuite, Keepalive, DPD) — parseados, data-plane DTLS pendiente.
Nombres de header tratados **case-insensitive**.

### Liveness + reconexión
DPD bidireccional (type 3→4) y keepalive (type 7) con los intervalos del gateway,
acotados. Sin RX por `2×DPD` (≥90s) ⇒ dead peer ⇒ **reconexión transparente**:
re-`CONNECT` reusando la cookie `webvpn` (sin re-auth), pidiendo la misma IP con
`X-CSTP-Address`; backoff 1→2→5→10s, hasta 10 intentos; se mantienen tun/rutas/DNS.
Teardown: frame `5` (BYE, `0xb0`) + `POST /+webvpn+/webvpn_logout.html`, y
`sysnet::NetRestore` (Drop) restaura DNS y borra sólo las rutas que agregamos.

### tun / rutas / DNS
Device **`cpac0`** (distinto de `cpvpn0`/`cpfg0`/`f5vpn0` → los 4 back-ends
coexisten; `open_tun` cae a `<base>%d` en EBUSY). Pin del gateway a su ruta
pre-VPN, excludes en esa ruta, includes/default por el tun — todo en un
`ip -batch`; en teardown se borra sólo lo que agregamos (`ip_batch_failed`).
IPv4-only (se descartan paquetes no-v4; IPv6 deshabilitado en el tun).

## DTLS (implementado parcial — `anyconnect/dtls.rs`)
Cisco AnyConnect DTLS = **resumen de sesión falso**: cliente y server ya comparten
el master-secret (`X-DTLS-Master-Secret` que mandó el cliente en el CONNECT +
`X-DTLS-Session-ID` que devolvió el server), así que el cliente "resume" una sesión
que nunca existió. Implementado vía **FFI de openssl-sys** (native-tls no lo
expresa): se fabrica un `SSL_SESSION` ASN.1 (`d2i_SSL_SESSION`) con id+secret+cipher
y se hace `SSL_connect` sobre un BIO datagram. Dos variantes:
- **Clásico** (`DTLS1_BAD_VER` + `SSL_OP_CISCO_ANYCONNECT`, cipher `AES256-SHA`…).
- **DTLS 1.2** (min/max proto = DTLS1.2, cipher `AES256-GCM-SHA384` id 0x009D…),
  cuando el gateway manda `X-DTLS12-CipherSuite` (se ofrece en el CONNECT).

Frames DTLS: **1 byte de tipo** (mismos códigos que CSTP: 0 DATA, 3/4 DPD, 7 KA,
5 disconnect) + payload — sin el header STF de 8 bytes. Data plane **best-effort**:
si el handshake no cierra, el cliente se queda en CSTP (fallback limpio); DTLS lleva
sólo DATA, CSTP sigue con el control (DPD/keepalive) y es el ancla de liveness +
reconexión. DTLS-DPD propio: si el UDP se calla, se cae a CSTP sin matar el túnel.

### ✅ RESUELTO con GnuTLS (gw-a, live, 19/10)
El data-plane DTLS **funciona end-to-end contra gw-a** usando **GnuTLS** para el
socket DTLS (OpenSSL sigue para el TLS/CSTP). `anyconnect/dtls.rs` reescrito a FFI
de **libgnutls**: `gnutls_init(CLIENT|DATAGRAM|NONBLOCK|NO_DEFAULT_EXTENSIONS)` —
el flag `NO_DEFAULT_EXTENSIONS` es la clave (produce el ClientHello mínimo sin
`supported_groups`/`ec_point_formats`/EMS que OpenSSL agrega sí o sí) —
`gnutls_priority_set_direct` con el priority de openconnect, `gnutls_record_disable_padding`,
`gnutls_session_set_premaster(CLIENT, version, kx, cipher, mac, COMP_NULL, master{48},
session_id{32})`, `gnutls_transport_set_int2(fd,fd)`, `gnutls_handshake` (NONBLOCK +
poll). Tabla cipher→(prio,version,kx,cipher,mac) espejo de openconnect `gnutls-dtls.c`
(DTLS1.2 ECDHE-RSA-AES-GCM + clásicos DTLS1.0). El CONNECT ofrece
`X-DTLS12-CipherSuite: ECDHE-RSA-AES256-GCM-SHA384:…` (ECDHE primero, nombres estilo
GnuTLS) y el ASA elige/eco `ECDHE-RSA-AES256-GCM-SHA384`. **Medido vs CSTP: 100 dig
paralelos 287ms (DTLS) vs 2087ms (CSTP) — 7× más rápido, empata openconnect (294ms);
ping 0% loss, estable, sin fallback.** libgnutls se linkea dinámico (dev ok);
follow-up: feature-gate para el build estático/musl (CSTP anda sin gnutls).

Lo que sigue abajo es el **registro del diagnóstico** que llevó a GnuTLS (por qué
OpenSSL no alcanza), se deja por valor de RE:

**⚠ MURO contra ASAs modernos (gw-a, 19/10) — diagnosticado con captura (tcpdump +
tshark) del ClientHello de openconnect vs el mío.** El mecanismo es **resume**
(session_id + master-secret), NO full-handshake: confirmado. openconnect (GnuTLS)
manda este ClientHello que el ASA **acepta**: record version **0xfefd**, 1 cipher
**`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (0xC030)**, session_id = el
`X-DTLS-Session-ID`, extensiones = {session_ticket, signature_algorithms,
record_size_limit, renegotiation_info} — **sin `supported_groups` ni
`ec_point_formats`, sin `extended_master_secret`**. Mis fixes a partir de eso:
(1) usar **0xC030** (no 0x009D RSA — el header Cisco `AES256-GCM-SHA384` significa la
variante ECDHE; con 0x009D → `handshake_failure` alert 40); (2) **EMS off**
(`SSL_OP_NO_EXTENDED_MASTER_SECRET = SSL_OP_BIT(0) = 0x1`; en un resume ofrecer EMS
fuerza al server a rechazar por RFC 7627). Con esos dos: alert 40 → **alert 47
(illegal_parameter)**. **Lo que queda y NO se puede arreglar con OpenSSL:** OpenSSL
**siempre agrega `supported_groups` + `ec_point_formats`** al ClientHello cuando hay
un cipher ECDHE (openconnect/GnuTLS no los manda en un resume), y usa **record
version 0xfeff** (GnuTLS 0xfefd); restringir las curvas a P-256 no alcanzó (es la
*presencia* de las extensiones y/o el record version). No hay API pública de OpenSSL
para suprimir esas extensiones ni fijar el record version del ClientHello. ⇒ **Para
DTLS contra este ASA hay que usar GnuTLS** (`gnutls_session_set_premaster`, que
produce exactamente ese ClientHello mínimo) para el socket DTLS, manteniendo OpenSSL
para el TLS. Ver openconnect `gnutls-dtls.c`. El resume OpenSSL implementado sirve
para ASAs clásicos/menos estrictos; en gw-a cae a CSTP (fallback limpio, <1s).

## Estado
- **VALIDADO END-TO-END contra un ASA real (gw-a `203.0.113.20`, 19/10/2026)** con
  credenciales reales (`alice`, grupo `GROUP_A`): auth → selección de grupo →
  re-init → form → auth-reply → `type=complete` + cookie `webvpn` → `CONNECT
  /CSCOSSLC/tunnel` → IP **10.20.62.187/25**, DNS 10.20.2.43/.177, **72 rutas
  split**, MTU 1287 → **data-plane CSTP real bidireccional** (`dig @10.20.2.43
  www.example.com` → NOERROR con answers vía el resolver corp; `ping 10.20.2.43` 3/3
  0% loss ~196ms) → **split tunnel correcto** (corp `→ dev cpac0`, `8.8.8.8 →
  enp10s0`) → stats rx_frames=60 tun_in=59 → **teardown limpio** (BYE + logout +
  `resolv.conf` y tabla de rutas restaurados **idénticos** byte a byte). El
  `--no-routes` daba rx=0 sólo porque sin rutas nada llegaba a hosts vivos (los
  servidores DNS no responden ICMP pero sí queries): es comportamiento esperado, no
  bug. gw-a y gw-b probados con `curl` a nivel init (gw-a→form, gw-b→sso-v2).
- Unit tests: XML (parse/span/entidades/tolerancia), auth (gw-a/sso/complete,
  mapeo de reply, grupos/noaaa/challenge), config (full/split/banner/case), CSTP
  (framing STF split/roundtrip/magic, disconnect-reason, clamp de intervalos),
  args.
- SSO: paste manual del token (CLI `--sso-token` o prompt); webview automático
  pendiente.
- GUI: AnyConnect es un back-end más en el selector; el row "Realm" se reusa como
  "Group (optional)"; password por stdin + 2FA por `# AUTH-PROMPT: code:`. SSO
  desde el GUI aún no cableado (usar CLI).
