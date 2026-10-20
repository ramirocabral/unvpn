# F5 BIG-IP APM SSL-VPN — spec de protocolo (reverse engineering)

> Tercer back-end del cliente nativo (`unvpn f5 …`): interoperar con un F5 BIG-IP
> **APM** (Access Policy Manager) "Network Access" SSL-VPN autorizado, desde Linux,
> sin binarios de F5.
> Evidencia: **prior-art open-source interoperable** (openconnect `f5.c` + `ppp.c`,
> que ya hablan con BIG-IP APM reales) + el instalador oficial para verificación.
> `F5` acá = **F5 Networks el vendor**, NO "Flavor 5 / DTLS de Fortinet" (otra cosa;
> ver docs/forti-protocol-notes.md §DTLS). No confundir.

## Binarios target + prior-art
- `~/vendor/f5vpn_setup.exe` — **RE hecho** (18/10/2026). NO es InstallShield (file(1)
  miente): es un **7-Zip SFX** (`7zS.sfx.exe`). Extraído con `7z x`: contiene el
  **componente de navegador** de APM clients **7.2.5.x** — `urSuperHost.dll`, `f5vpn.exe`
  (ActiveX "Dynamic Application Tunnel Control"), `f5LogViewer.exe`, + helpers de
  instalación (`f5instd.exe`, `F5InstH.exe`, `F5InstP.dll`, `cabinstaller.exe`,
  `uregsvr.exe`, `f5unistall.exe`). PDB: `…apmclients725x-win…\TerminalProxy\SuperHost\…\f5vpn.pdb`.
  **El engine real del túnel es `TunnelServer.exe` / `TunnelServerX.dll`** (referenciado en
  `f5vpn.exe`/`urSuperHost.dll`, **NO incluido** en este paquete) → el data-plane
  (`/myvpn`, framing) no se puede verificar desde acá; vale openconnect/gof5.
  - **Confirmado del binario (`f5vpn.exe`, strings UTF-16LE):** cookie `MRHSession`;
    endpoints `/vdesk/hangup.php3` (= teardown `f5_bye`), `get_sessid_for_token.php3` /
    `get_token_for_sessid.php3` (token/SSO), `resource_all_info.eui?resourcename=&resourcetype=`,
    `/my.logout.php3`, `/my.report.{eps,na}`.
  - **User-Agent oficial (verificado):**
    `Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0; F5 Networks Client)`
    → ahora es el default de `f5/http.rs` (APM a veces gatea la policy por UA).
- Prior-art de protocolo (open source, interoperan con BIG-IP reales) — **ambos usados**:
  - openconnect `f5.c` (handshake HTTP) + `ppp.c`/`ppp.h` (framing F5 / F5-HDLC) — fuente primaria.
  - **kayrus/gof5** (cliente F5 en Go) — 2ª implementación independiente, para cross-check.

## Verificación cruzada del data-plane (gof5 `pkg/link/f5.go`, `pkg/config/types.go`)
- **Framing F5 confirmado**: read `buf[0]==0xf5 && buf[1]==0x00` + u16 BE len; write
  `{0xf5,0x00}` + u16 BE len. Idéntico a lo implementado.
- **⚠ Frames de datos van ACFC+PFC comprimidos**: `[0xf500][len][0x21|0x57][IP]` — **sin
  `FF 03`, proto de 1 byte** (`0x21` IPv4 / `0x57` IPv6). Control (LCP/IPCP) sí va
  `FF 03`+proto 2B. ⇒ ajustado: `PppConn::send` comprime protos <0x100 (datos) y deja
  control sin comprimir. La lectura ya toleraba ambos (detección octeto-impar=PFC).
- **Formato de rutas confirmado**: `net/máscara-dotted` (ej. `10.0.0.0/255.0.0.0`),
  separados por espacio/coma. Mi parser maneja dotted y prefijo.
- **DNS/sufijos**: F5 puede mandar varios por tag (separados) y/o `DNS0/DNS1/…` → ahora
  spliteo cada tag.
- **Diferencia de modelo de rutas**: gof5 **ignora `LAN<n>`** y computa rutas como el
  *inverso de ExcludeSubnets* (full-tunnel menos excludes + reservados RFC8190).
  openconnect (lo que seguí) usa `LAN<n>`=include, `ExcludeSubnets<n>`=exclude,
  `UseDefaultGateway0`=default — más fiel al modelo de F5 (split-include real). Mantengo
  el de openconnect; con default-route+excludes el resultado efectivo coincide (los
  exclude quedan pineados al path original).
- Campos extra que ve gof5 (no críticos para el túnel básico, anotados): `host0`/`port0`/
  `tunnel_host0`/`tunnel_port0`, `DNS_SPLIT0`, `TrafficControl0` (QoS flows, URL-encoded
  XML), `Add2Hosts0`, `AllowLocal{Subnet,DNSServers,DHCP}Access0`. Además postea un
  `<agent_info>` (telemetría de cliente) que openconnect no necesita → no implementado.
- Teardown: `GET /vdesk/hangup.php3?hangup_error=1` (openconnect + binario) — pendiente de
  cablear en el teardown (hoy solo mando LCP Terminate).

---

## Plano de control — HTTPS (TCP 443)
Todo sobre TLS al gateway. Cookie jar acumulado. Cert: aceptamos el del gateway
(CAs corporativas no suelen estar en el store); pinning `--trusted-cert` = hardening
posterior (igual que CP/Forti).

### Auth — cadena de forms HTML (NO hay API `ret=` estilo Fortinet)
1. `GET /` (siguiendo redirects) → página de logon con `<form id="auth_form">`
   (campos username + password). Algunos portales arman el form por JavaScript y no
   hay HTML estático → fallback a un form plano username+password (igual que
   openconnect).
2. `POST <form action>` (normalmente `/my.policy`, `application/x-www-form-urlencoded`)
   con **todos** los inputs del form (hidden preservados) + username + password.
3. La respuesta puede ser:
   - **Éxito**: se setean las cookies `MRHSession` **y** `F5_ST`.
   - **Otro form**: 2FA/OTP (otro campo password), selección de grupo, etc. → repetir.
   - **Falla**: vuelve la página de logon (con campo username) → credenciales malas.
4. **Señal de autenticado = `MRHSession` + `F5_ST` juntas.** `MRHSession` sola NO
   alcanza: APM la re-setea varias veces durante el flujo. `F5_ST` = cookie de
   "session timeout" (F5 KB K15387); su formato `%dz%dz%dz<start>z<dur>` da la
   expiración (`start+dur`). (verificado en openconnect `check_cookie_success`.)

### Perfil VPN + opciones del túnel (XML; datos en **texto de elementos**, no atributos)
5. `GET /vdesk/vpn/index.php3?outform=xml&client_version=2.0` →
   `<favorites type="VPN"><favorite><params>resourcename=/Common/…</params></favorite>`
   → extraer el texto de `<params>` (el recurso Network Access).
6. `GET /vdesk/vpn/connect.php3?<params>&outform=xml&client_version=2.0` →
   `<favorite><object>…</object></favorite>` con (nombres con sufijo numérico):
   - `Session_ID` → token `sess=` del request de túnel.
   - `ur_Z` → token `Z=` del request de túnel.
   - `IPV4_0` / `IPV6_0` (yes/no/1/0) → familias habilitadas.
   - `hdlc_framing` (yes/no) → framing PPP (ver plano de datos).
   - `tunnel_dtls` + `tunnel_port_dtls` + `dtls_v1_2_supported` → DTLS (aceleración).
   - `idle_session_timeout` (seg).
   - `UseDefaultGateway0` → full tunnel (default route) vs split-only.
   - `DNS<n>` / `DNS6_<n>` (hasta 3), `WINS<n>`, `DNSSuffix<n>` (search domains).
   - `LAN<n>` / `LAN6_<n>` → **split-include** (lista separada por espacios de
     `net/mask`, mask dotted o prefijo). ⚠ formato exacto del "word" a confirmar en vivo.
   - `ExcludeSubnets<n>` / `ExcludeSubnets6_<n>` → **split-exclude**.

---

## Plano de datos — PPP sobre TLS
7. `GET /myvpn?sess=<Session_ID>&hdlc_framing=<yes|no>&ipv4=<y/n>&ipv6=<y/n>&Z=<ur_Z>&hostname=<base64(hostname)> HTTP/1.1`
   **sin cookies** (el `sess`+`Z` autentican el request; openconnect oculta las cookies
   acá a propósito). En éxito el server responde **HTTP 200/201** y el **mismo socket**
   pasa a PPP. Headers de la respuesta traen la IP asignada:
   - `X-VPN-client-IP` → IPv4 interna. `X-VPN-client-IPv6` → IPv6.
   - (`X-VPN-server-IP[v6]` también, pero se ignora — es un túnel, no hay gateway útil.)
   - 504 → permiso denegado; otro ≠200/201 → error.
8. **Framing F5** (no-HDLC; `hdlc_framing=no`) — 4 bytes por paquete (verificado vs
   openconnect `PPP_ENCAP_F5`):
   ```text
   [u16 be 0xf500]        magic
   [u16 be payload_len]   = len(frame PPP)
   [frame PPP]
   ```
   (compará con Fortinet: 6B `[len+6][0x5050][len]`.)
9. **Framing F5-HDLC** (`hdlc_framing=yes`) — RFC1662 async-HDLC clásico: flags `7e`,
   byte-stuffing `7d`/`^0x20`, FCS-16 (init 0xFFFF, poly 0x8408, se transmite
   complementado LE; residual receptor = `0xf0b8`). openconnect **deshabilita DTLS**
   en este modo (HDLC hace el MTU impredecible); el data-plane TLS sí lo soporta.
10. **Frame PPP**: `FF 03` (addr+control) + `[proto]` (1 ó 2 bytes) + payload.
    Mandamos siempre `FF 03` + proto de 2 bytes (siempre aceptado); al recibir
    toleramos `FF 03` ausente y proto PFC-comprimido de 1 byte (octeto impar = proto
    de 1 byte; par = high byte de proto de 2).
    - Protos: `0xC021` LCP, `0x8021` IPCP, `0x0021` IPv4, `0x8057`/`0x0057` IPv6.
11. **LCP**: Config-Request con MRU + Magic-Number. **IPCP**: pedir la IP del header
    `X-VPN-client-IP` (el GW la ACK-ea) + DNS opt 129/131 (si el GW las REJ, re-request
    solo IP). DNS/dominios/rutas reales vienen del XML de opciones, no de IPCP.
12. **MTU**: overhead F5 no-HDLC = 8B (4 encap + FF03 + proto). MTU ~1400.
13. **Keepalive**: LCP Echo-Request periódico (derivado de `idle_session_timeout`).

## Aceleración — DTLS (UDP)   ✅ IMPLEMENTADO (20/10/2026; NO live-tested aún)
- Si `tunnel_dtls` && `tunnel_port_dtls` && **no** HDLC → DTLS cert-based al
  `tunnel_port_dtls` (DTLS 1.2 si `dtls_v1_2_supported`, si no DTLS 1.0 — los BIG-IP
  viejos crashean si se les ofrece 1.2). El **mismo** `GET /myvpn?…` (sin cookies) se
  manda como primer datagrama de aplicación sobre DTLS ("HTTP over DTLS"), reenviado
  cada 1s hasta la respuesta `HTTP/.. 200` + `X-VPN-client-IP`, que se parsea igual
  (openconnect `f5_dtls_catch_probe`). Luego PPP (framing F5), **un frame por record**.
- NO es PSK — handshake DTLS con cert como el lado TLS (server cert no verificado, igual
  que el TLS). Vía `crate::gnutls` (dlopen de libgnutls en runtime, módulo compartido con
  AnyConnect/Forti; `DtlsSession::connect_cert`). `--no-dtls` fuerza TLS.
- **Opportunistic + fallback**: igual que Forti — si el handshake/`/myvpn` falla o el data
  loop no recibe IP en `DTLS_TRIAL`=5s (`tin==0` con `tout≥8`), cae a TLS transparente y
  reconecta reusando sess/Z + cookies sin re-auth.
- **PENDIENTE: validación en vivo** (no hay gateway F5 con DTLS a mano ahora). El handshake
  cert quedó verificado contra un `gnutls-serv --udp` local; la ruta `/myvpn`-over-DTLS y el
  framing F5 por UDP faltan probar contra un BIG-IP real. OJO: a diferencia de Fortinet, F5
  **no** intercala records de control `GF` en el stream PPP (ese demux es sólo de Forti).

---

## Plan de construcción (Rust, nativo Linux) — back-end `f5`
Subcomando `unvpn f5 …` en el mismo binario; reusa `tun.rs`, `sysnet` (DNS/stop-flag)
y el modelo de hilos del data-plane. Módulos: `src/f5/{mod,http,auth,config,ppp,tunnel}.rs`.

- **1** ✅ Control HTTPS + auth form (password → `MRHSession`+`F5_ST`).
  `unvpn f5 -g <gw> -u <user> [--password p] [--code otp] [--probe|--login|--connect]`.
- **2** ✅ 2FA/OTP: el loop de forms pide el código en el 2º form (campo password extra).
- **3** ✅ Perfil + opciones (`index.php3` / `connect.php3`) → `F5Options`.
- **4** ✅ Túnel: `GET /myvpn` → PPP (LCP/IPCP, framing F5 **y** F5-HDLC) → `tun f5vpn0`
  + rutas (default/split + exclude) + DNS. Data-plane TLS. `--connect` (sudo).
- **5** ✅ DTLS (cert-based) como aceleración (`--no-dtls` fuerza TLS). Implementado, no live.
- **6** ⏳ GUI: selector de cliente F5 (user/pass + OTP), lanzar engine por pkexec.
- **7** ⏳ SAML/SSO (IdP externo, redirect cross-host) + selección de grupo (`<select>`).

## Estado
- **Recon ✅** (handshake + framing derivados de openconnect `f5.c`/`ppp.c`,
  interoperables con BIG-IP reales).
- **Auth password + OTP ✅**, **perfil/opciones ✅**, **túnel PPP (F5 + HDLC) + tun +
  rutas + DNS, data-plane TLS ✅** — compila + **19 unit tests** (parse de form HTML,
  parse XML de perfil/opciones, framing F5 round-trip, HDLC round-trip + residual FCS
  `0xf0b8`, PFC, split de la respuesta HTTP del túnel, base64, path `/myvpn`).
- Smoke-test del control-path (TLS/HTTP/redirect/probe/form-parse) OK contra host real.
- Módulos: `src/f5/{mod,http,auth,config,ppp,tunnel}.rs` (self-contained; `http` es una
  copia adaptada del de `forti` + seguir-redirects — candidato a factorizar a compartido).

## Pendiente / a validar en vivo
- **Live test contra un BIG-IP APM real** (como gw-forti fue para Forti) — **falta un
  gateway F5 + credenciales**. Es el gap grande; necesita input del usuario.
- Formato exacto del "word" de `LAN<n>`/`ExcludeSubnets<n>` (asumido `net/mask`).
- UA del cliente oficial (¿APM gatea por User-Agent? openconnect usa el suyo y anda).
- DTLS (F5-5), GUI (F5-6), SAML/SSO + grupo (F5-7), IPv6 (parseado, no cableado a tun).
- RE binaria del engine dentro de `f5vpn_setup.exe` si aparece una quirk específica del
  gateway que el prior-art no cubra.

## Seguridad / alcance
- Interoperabilidad autorizada, análoga a openconnect (que interopera con BIG-IP APM).
- Credenciales/OTP/cookies = secretos: van por stdin (no argv), no se loguean.
  `MRHSession`/`F5_ST` = token de sesión; tratar como la `active_key` de Check Point.
- El request `/myvpn` se manda **sin** cookies a propósito (lo autentican `sess`+`Z`).
