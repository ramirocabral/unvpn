# FortiClient SSL-VPN — spec de protocolo (reverse engineering)

> Segundo back-end del cliente nativo (`cpvpn`): interoperar con un FortiGate
> SSL-VPN autorizado desde Linux, sin binarios de Fortinet.
> Target: FortiClient VPN **7.4.3.5411** para Linux (`/opt/forticlient/`).
> Evidencia: strings/decompilado de los binarios nativos (REA) + prior-art
> open-source **interoperable** (openfortivpn 1.24.1, openconnect) + captura en vivo.

## Binarios target (RE)
- `/opt/forticlient/vpn` (ELF x86-64, C++, **stripped**, 11.8 MB) — **el motor del
  wire SSL-VPN**. Tiene todas las URLs `/remote/*`, `SVPNCOOKIE`, el framing PPP y el
  DTLS. sha256 `f6ef5eb4…cefa991`. Ruta de build filtrada: `/home/devops/code/src/vpn/src/`.
- `/opt/forticlient/iked` — daemon IKE (modo IPsec; para F7, fuera de alcance inicial).
- `/opt/forticlient/forticlient-cli` (Go, stripped) — la CLI `forticlient vpn …`.
- `/opt/forticlient/gui/FortiClient` (CEF/Chromium, 177 MB) — GUI; usa un websocket
  interno (`FCT_VPN_*`) + listener **SAML** local (ver captura).
- Prior-art de protocolo (open source, ya interopera con FortiGates reales):
  openfortivpn (`io.c`/`http.c`/`tunnel.c`), openconnect (`fortinet.c` + `ppp.c`).

## Captura del cliente oficial (GUI, `~/.config/FortiClient/logs/main.log`)
- En cada arranque: `Saml - init` → `Saml - listenSamlLoginRequest` (abre un puerto
  local efímero para recibir el redirect del IdP) + `Server init() port number is <efímero>`.
- Websocket interno: `FCT_VPN_CONNECTING` / `FCT_VPN_DISCONNECTED` /
  **`FCT_VPN_XAUTH_TOKEN`** / `FCT_VPN_XAUTH_CREDENTIALS` → el setup del usuario usa
  **SAML + token**. ⇒ hay que cubrir password, FortiToken/OTP y SAML/SSO.

---

## Plano de control — HTTPS (TCP 443)   ✅ endpoints VERIFICADOS en el binario
Todo sobre TLS al gateway. Headers comunes (de `vpn` + openconnect):
`User-Agent: Mozilla/5.0 SV1` (openconnect; el oficial usa un UA FortiClient — confirmar),
`Host: <gw>`, cookies acumuladas. El GW **tolera** UA; openfortivpn manda defaults.

### Endpoints (strings del binario `vpn`)
- `POST /remote/logincheck` — login (password) y respuesta al challenge 2FA.
- `GET  /remote/login` — página de login (HTML form flavor).
- `GET  /remote/fortisslvpn` / `GET /remote/fortisslvpn_xml[?dual_stack=1]` — config del túnel.
- `GET  /remote/sslvpn-tunnel` (con `Host: sslvpn`) — **abre el túnel PPP**.
- `GET  /remote/saml/login`, `GET /remote/saml/auth_id?id=…`, `/remote/saml/` — SSO/SAML.
- `GET  /remote/info`, `GET /remote/portal`, `GET /remote/logout`.

### Auth con usuario+password  (format strings EXACTOS del binario `vpn`)
1. `POST /remote/logincheck`  body:
   ```
   username=<u>&credential=<pass>&realm=<realm>&ajax=1&redir=%2Fremote%2Findex&just_logged_in=1
   ```
   (format string real: `username=%s&credential=%s&realm=%s%s`; el sufijo `%s` =
   `&ajax=1&redir=%2Fremote%2Findex&just_logged_in=1`, o `…&ftmpush=1` para FortiToken push.)
   Credenciales **URL-encoded**. `realm` puede ir vacío.
2. Respuesta (text/plain, estilo `ret=N,...`):
   - **OK**: `ret=1,redir=/remote/portal…` + `Set-Cookie: SVPNCOOKIE=<val>` → autenticado.
   - **2FA**: `ret=2,reqid=<r>,polid=<p>,grp=<g>,tokeninfo=<…>` (a veces `chal_msg`) →
     el server pide el segundo factor.
   - **Falla**: `ret=0` / `permission denied` → credenciales inválidas.

### Segundo factor — FortiToken / OTP  (format strings EXACTOS)
Respuesta al challenge, `POST /remote/logincheck`:
```
username=%s&reqid=%s&polid=%s&grp=%s&realm=%s&peer=%s&code=%s&code2=%s%s   (con código OTP)
username=%s&reqid=%s&polid=%s&grp=%s&realm=%s&peer=%s%s                    (FTM push, sin código)
```
- `code` = el OTP (FortiToken / email / SMS). `code2` normalmente vacío.
- `peer` = normalmente vacío (cert peer). El sufijo `%s` = `&ajax=1&redir=…&just_logged_in=1`.
- **FTM push**: `ftm_push` / `FTM_PUSH_CLICKED` / `&ftmpush=1` → el server espera la
  aprobación en la app; se reintenta/espera (`use_otp` marca si pide código manual).
- **Flavor HTML form** (otros FortiGate): la respuesta es HTML con
  `<INPUT NAME="magic|reqid|grpid|polid">` + `credential`/`credential2`; el POST va:
  ```
  magic=%s&username=%s&reqid=%s&grpid=%s&credential=%s&credential2=%s&realm=%s
  magic=%s&username=%s&reqid=%s&grpid=%s&idx=%s&credential=%s&realm=%s%s
  ```
  (implementar el flavor `ajax` primero — es el de openfortivpn; el `magic/grpid` como fallback.)
- Éxito → `Set-Cookie: SVPNCOOKIE=<val>`. Error → "Two-factor Authentication failed".

### SSO / SAML   (endpoints VERIFICADOS; flujo de openconnect + captura GUI)
1. `GET /remote/saml/start?redirect=1` (o `/remote/saml/login`) → el GW responde **302**
   a la URL del IdP (`Location: https://<idp>/…`), con un `id`/`SAMLRequest`.
2. El cliente **abre el navegador** del usuario en esa URL (xdg-open). Levanta un
   **listener HTTP local** en `127.0.0.1:<port>` (el oficial: `listenSamlLoginRequest`).
3. El usuario se autentica en el IdP; el IdP redirige de vuelta al GW
   (`/remote/saml/auth_id?id=<id>`), el GW setea `SVPNCOOKIE` y redirige a una página
   de éxito / al `redirect` local → el cliente **captura el `id`/cookie**.
4. Con el `SVPNCOOKIE` → igual que password (saltear a config + túnel).
- openconnect: `--token-mode`? no; SAML = `/remote/saml/…`. Ver flujo exacto de
  `fortinet.c` (`fortinet_obtain_cookie` / `SAML`).

---

## Plano de datos — túnel PPP sobre TLS   ✅ framing VERIFICADO (openconnect) 
1. `GET /remote/sslvpn-tunnel HTTP/1.1` + `Host: sslvpn` + `Cookie: SVPNCOOKIE=<val>`
   (+ `Connection: Upgrade` — string en el binario). En **éxito el server NO manda
   respuesta HTTP**: arranca PPP directo. En error manda HTTP (manejar ambos).
2. **Framing Fortinet** (por paquete, sobre el stream TLS; `encap_len = 6`):
   ```
   [0..2]  u16 be  total_len = len(frame_ppp) + 6
   [2..4]  u16     0x5050            (magic 'PP')   (openconnect PPP_ENCAP_FORTINET)
   [4..6]  u16 be  len(frame_ppp)
   [6..]   frame PPP
   ```
   Decode: `magic==0x5050 && be16[0]==be16[4]+6`; si no → bad_encap.
3. **Frame PPP** (NO es HDLC: sin flags 0x7e, sin byte-stuffing, sin FCS):
   `FF 03` (address+control, **siempre** — Fortinet limpia ACCOMP) + **proto 2 bytes** +
   payload. Fortinet **rechaza** asyncmap/ACCM, PFC y ACFC (no mandar). Al recibir,
   aceptar FF03 opcional y proto de 1 ó 2 bytes.
   - Protos: `0xC021` LCP, `0x8021` IPCP, `0x0021` IPv4, `0x8057` IPV6CP, `0x0057` IPv6.
4. **LCP** (negociación): Config-Request con **solo MRU + Magic-Number** (4 bytes random).
   Nada de ACCM/PFC/ACFC. Si el server manda MRU más chico, NAK una vez con el MTU local.
5. **IPCP**: Config-Request con IP-Address (0.0.0.0 para que el GW lo NAK-ee con la real),
   DNS1 (**opción 129 / 0x81**) y DNS2 (**opción 131 / 0x83**) en cero para solicitarlos.
   El server NAK-ea con la IP y los DNS → re-request con esos valores → Config-Ack.
6. **MTU**: overhead sobre TLS = **10 bytes** (6 encap + 2 addr/ctrl + 2 proto). MTU ~1400.
7. Datos: IPv4 del `tun` → frame PPP `0x0021` → framing 6B → TLS. Y al revés.
8. **Keepalive/DPD**: `dtls-config heartbeat-interval` del XML; mandar echo LCP / heartbeat.
   `idle-timeout` y `auth-timeout` del XML.

## Config del túnel — `GET /remote/fortisslvpn_xml?dual_stack=1`  (campos de openconnect)
XML root `<sslvpn-tunnel>`; parsear:
- `<auth-timeout val>`, `<idle-timeout val>`, `<dtls-config heartbeat-interval>`.
- `<fos …>` (versión FortiOS; log).
- `<ipv4>`: `<assigned-addr ipv4>` = IP interna; `<dns ip=…>` (hasta 3) + `<dns domain=…>`
  = DNS + dominio de búsqueda; `<split-tunnel-info><addr ip mask negate>` = rutas
  include/exclude. Sin split → ruta default (`0.0.0.0/0`).
- `<ipv6>`: análogo (`assigned-addr ipv6 prefix-len`, `dns ipv6`). (Fase 2.)
- Atributo root `dtls="1"` → DTLS habilitado (`dtls12=1`).

## Aceleración — DTLS (UDP)   ⏳ F5 (opcional; TLS-only primero)
- `dtls="1"` en el XML → intentar DTLS en el **mismo puerto** que TLS (443/udp) —
  "always uses same port as TLS?" (openconnect, a confirmar con REA).
- **Client hello DTLS** (payload del primer datagrama; VERIFICADO en openconnect, tokens
  `clthello`/`svrhello` presentes en el binario):
  ```
  [u16 be len = 2 + 27 + len(cookie) + 1]
  "GFtype\0clthello\0SVPNCOOKIE"   (27 bytes, incluye el NUL final)
  <cookie>\0
  ```
- **Server hello**: `be16[0]==len`, luego `"GFtype\0svrhello\0handshake"` (26B), estado
  `"ok"` en offset 28. Si no → `DTLS_DISABLED`, seguir por TLS.
- PSK: openconnect dice que el "secreto" es el `SVPNCOOKIE`. Ciphers PSK del binario:
  `DHE-PSK-AES256-GCM-SHA384` etc. Derivación exacta del PSK → **RE con REA** (pendiente).
- El binario tiene además stack **QUIC** (`clthello-tun2`, `quic_do_handshake`) → variante
  de transporte más nueva (7.4); fuera de alcance inicial.
- DTLS necesita el crate `openssl` directo (native-tls no expone DTLS).

---

## Plan de construcción (Rust, nativo Linux) — back-end `forti`
Un subcomando nuevo `cpvpn forti …` en el mismo binario; reusa `tun.rs`, `sysnet` (DNS),
y el modelo de hilos del data-plane. Módulos: `forti/{http,auth,saml,config,ppp,tunnel}.rs`.

- **F1** 🔧 Control HTTPS + auth password → `SVPNCOOKIE`.
  `cpvpn forti -g <gw> -u <user> [--realm r] [--password p|stdin] [--probe]`.
  `--probe` valida formato sin consumir OTP.
- **F2** ⏳ 2FA: challenge `ret=2` → OTP (`code`) / FTM push (`ftmpush=1`).
- **F3** ⏳ SAML/SSO: GET `/remote/saml/login` → browser (xdg-open) + listener local →
  capturar `id` → `SVPNCOOKIE`. (La GUI pasa la URL; CLI imprime/abre.)
- **F4** ⏳ Túnel: `fortisslvpn_xml` → PPP (LCP/IPCP) in-process + framing 6B → `tun` +
  rutas + DNS (`sysnet`). `--connect` (sudo). Data-plane TLS.
- **F5** ⏳ DTLS (PSK) como aceleración (`--no-dtls` para forzar TLS).
- **F6** ⏳ GUI: selector de cliente (FortiClient), campos por método (user/pass, OTP,
  botón SAML), lanzar el engine por pkexec (passcode/OTP por stdin; SAML por browser).
- **F7** ⏳ (después) Modo IPsec/IKEv2 Fortinet reusando el módulo `ike`.

## Validación en vivo — gateway real `gw-forti` (203.0.113.40, openconnect+fortinet)
FortiGate SSL-VPN real, **password-only** (sin SAML), autorizado por el usuario para testear.
- `cpvpn forti -g 203.0.113.40 --probe` ✅: `GET /remote/info` → **HTTP 200**; SAML
  (`/remote/saml/start`) → **HTTP 400** ⇒ detecta bien que es password-path (sin SSO).
- `GET /remote/login?lang=en` + `POST /remote/logincheck` ✅ el gateway procesa el POST
  (1er intento: página de login HTML con `fgt_lang`). ⇒ **este GW usa el flavor HTML**
  (no `ret=`): auth OK/2FA vendrían como form con `reqid/magic/grpid` → soportado
  (`parse_html_challenge` + `answer_challenge` rama `html_form`).
- ⚠ Tras varios intentos con user inexistente, el GW devuelve **HTTP 405** = throttle de
  login por IP (se limpia solo en minutos). NO es bug del cliente (el 1er POST entró bien).
  Lección: no repetir logins fallidos contra un GW productivo.
- Pendiente (necesita credenciales reales del usuario, 1 intento, sin throttle): camino de
  **éxito** (`ret=1`+`SVPNCOOKIE` o form→cookie) y **túnel PPP** end-to-end.

## Seguridad / alcance
- Interoperabilidad autorizada, análogo a openfortivpn/openconnect (ambos interoperан con
  FortiGate). Credenciales/OTP/cookies = secretos; nunca en argv (van por stdin), no lognear.
- `SVPNCOOKIE` = token de sesión; tratar como la `active_key` de Check Point.

## Estado
- Recon ✅ (endpoints + auth + framing + DTLS hello verificados vs binario real `vpn`
  (Ghidra/REA: `sslvpn-tunnel`@0xbf7728, func túnel `FUN_0045a660`) y openconnect).
- **F1 auth password ✅** · **F2 2FA/OTP + FTM push ✅** · **F3 SAML/SSO ✅** ·
  **F4 túnel PPP (LCP/IPCP) + tun + rutas + DNS, data-plane TLS ✅** — compilado + unit
  tests (framing PPP, parser XML). Falta el **test en vivo contra un FortiGate real**.
- **F6 GUI ✅**: selector FortiClient; form por método (password+OTP / SSO-SAML); lanza
  `cpvpn forti … --connect` por pkexec; stdin para password/OTP; abre el browser con el
  marker `# SAML-URL:`. Parser de stdout compartido (IP / DNS / TUNNEL UP / fallos).
- Pendiente: **live test** (probe + connect), **F5 DTLS** (aceleración UDP/PSK; TLS-only
  anda), **F7 IPsec/IKEv2** Fortinet (reusar `ike`), pinning de cert (`--trusted-cert`),
  flavor HTML-form del 2FA (`magic/grpid`), IPv6.
- Módulos: `src/forti/{mod,http,auth,saml,config,ppp,tunnel}.rs` + `src/sysnet.rs`
  (DNS + stop-flag compartidos con el back-end Check Point).
