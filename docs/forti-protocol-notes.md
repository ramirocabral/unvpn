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

### Segundo factor (no-SAML)   ✅ VERIFICADO (motor `vpn` + portal `login.js` + openfortivpn/openconnect, 18/10/2026)
Fuentes (workflow de RE con verificación adversarial, 11 hallazgos confirmados): el motor
FortiClient 7.4 `/opt/forticlient/vpn` (Ghidra/REA; `http_login_check_handler` 0x462170, builders
0x463ca0/0x463720/0x463960, parser de token 0x458ae0), el **`/sslvpn/js/login.js` del propio
gateway** (máquina de estados del portal), la GUI Electron (`FCT_VPN_XAUTH_TOKEN/_RSA/_NEW_PWD`),
openfortivpn `http.c` y openconnect `fortinet.c` + capturas reales de sus issues.

**Respuesta al login** (ajax, `ret=…` separado por comas; `chal_msg=` se lleva **todo el resto**
del body, comas/`&`/saltos incluidos — `login.js`: `e.substring(indexOf("chal_msg=")+9)`). El motor
despacha por el **primer carácter de `ret`**:

| ret | qué pide | mensaje (texto del motor) | respuesta |
|---|---|---|---|
| 1 | — | — | sin `SVPNCOOKIE` = **falla** (portal con host-check, ofv#774) |
| 2 | FortiToken; si `tokeninfo=ftm_push` → **push** | "A FortiToken code is required for SSL-VPN login authentication." | código o push |
| 3 | token por **email** | "An email message containing a Token Code will be sent to <%s> in a moment." (`%s` = tokeninfo percent-decoded) | código |
| 4 | token por **SMS** | "An SMS message …" | código |
| 5 | **clock drift** | "FortiToken clock drift detected. Please input the next code and continue." | código anterior + siguiente |
| 6 | challenge RADIUS (`is_chal_rsp=1`) o **renovar password** (`pass_renew=1`, `allow_cancel`→Skip) | `chal_msg` | ver abajo |

Éxito = **solo** `Set-Cookie: SVPNCOOKIE=<no vacío>` (no `ret=1`). Fallas: `ret=0,redir=…&err=<código>`
(`sslvpn_login_permission_denied`, `…_password_expired`, `sslvpn_logindisable_errmsg`…), HTML con
`Two-factor Authentication failed` / `<!--sslvpnerrmsg=…-->`, **HTTP 405 = credenciales malas o
throttle** (no es un error de método; openconnect #484), 7.6.2 manda `401 Unauthorized` (matchear
el número, no la frase).

**Bodies EXACTOS** (POST `/remote/logincheck`):
```
login (validado):  username=%s&credential=%s&realm=%s&ajax=1&redir=%2Fremote%2Findex&just_logged_in=1
código (motor 0xbf92a8): username=%s&reqid=%s&polid=%s&grp=%s&realm=%s&peer=%s&code=%s&code2=%s&redir=%2Fremote%2Findex&just_logged_in=1
push   (motor 0xbf9090+0xbf90c8): username=%s&reqid=%s&polid=%s&grp=%s&realm=%s&peer=%s&redir=%2Fremote%2Findex&just_logged_in=1&ftmpush=1
ret=6 respuesta (login.js): ajax=1&username=&realm=&magic=<m>&reqid=<reqid>,<polid>&grpid=<grpid>,<pid>,<is_chal_rsp>[&peer=]&credential=<password>&credential2=<respuesta>
ret=6 renovar  (login.js): …mismo prefijo…&credential=<password nueva>          (sin credential2)
ret=6 skip     (login.js try_skip): ajax=1&username=&magic=&realm=&credential=<password>&reqid=<reqid>&grpid=<compuesto>&skip=1[&peer=]
HTML legado RSA/SMS (motor 0xbf9210): magic=&username=&reqid=&grpid=[&idx=]&credential=<respuesta>&realm=&redir=%2Fremote%2Findex&just_logged_in=1
HTML legado password nueva (0xbf9258): magic=&username=&reqid=&grpid=&credential=<nueva>&credential2=<confirmación>&realm=
```
- **Push FortiToken Mobile**: un request **único** que el gateway deja **abierto** hasta que el
  usuario aprueba en el teléfono (o vence `remoteauthtimeout`). Sin `code` y **sin `magic`**
  (`magic`+`ftmpush=1` ⇒ HTTP 405, openconnect #555 / openfortivpn #728). **Nunca** `ftmpush` en el
  login inicial. El portal lo dispara solo y deja tipear el código (un código tipeado aborta el push).
  `tokeninfo=remote_token_auth` NO lleva `ftmpush=1` (el portal manda `ftmpush=0`) → se trata como código.
- **Drift**: el portal manda `code=<el ya enviado>&code2=<el siguiente>` (placeholder "Next Token
  Code"); el motor lo manda al revés (code=nuevo, code2=anterior, 0x463d82/0x463dff). Usamos el
  orden del portal (es el formulario del propio gateway).
- `peer` se devuelve **tal cual** (el motor no lo url-encodea); los compuestos de ret=6 van crudos
  como en `login.js`; `polid`/`peer` persisten entre rondas si una respuesta los omite (globals del portal).
- **Timeout**: el motor usa `remoteauthtimeout` (de `/remote/info` o del comentario
  `<!--remoteauthtimeout=N-->` de `/remote/login`), **clamp [30,300] s**, como read-timeout de
  **todos** los POST de logincheck (un push o un MFA RADIUS se quedan abiertos ese tiempo). `to=`
  (opcional, segundos) es el plazo del portal para tipear; nunca acorta el push.
- **Detección del formulario HTML legado**: el tag exacto `<FORM ACTION="/remote/logincheck" method="POST"`
  + `magic` no vacío + reqid/grpid. La página de login moderna (`<form class="prompt legacy-prompt" …>`,
  `magic=""`) **no** es un challenge — antes un password incorrecto se tomaba por un pedido de 2FA.
- GUI oficial: los 4 tipos de token llegan como un solo `FCT_VPN_XAUTH_TOKEN` (cambia solo el
  `message`); RSA → `FCT_VPN_XAUTH_RSA`, password → `FCT_VPN_XAUTH_NEW_PWD`; el botón "FTM Push" de la
  GUI está muerto en este build (`old_token` siempre ""); el secreto viaja por keyring, no por el socket.

**cpvpn** (`forti/auth.rs` + `forti/mod.rs::do_login`): loop de hasta 8 rondas; cada pregunta se
anuncia en stdout como `# AUTH-PROMPT: <kind>: <mensaje>` (kinds `code`, `code2`, `answer`, `newpass`,
`renew` (vacío = Skip), `push`) y se contesta con una línea de stdin (la GUI muestra una tarjeta; en
TTY se pregunta en stderr, con eco apagado para secretos). `disconnect`/EOF cancela sin mandar nada.
`--code` contesta la primera pregunta de código; `--no-push` desactiva el push automático. Un único
lector de stdin para todo el proceso (`sysnet::stdin_next`) evita que el push, el prompt, la espera
SAML y el `disconnect` del túnel se roben líneas. Validado contra un FortiGate simulado
(`scratchpad/mock2fa`): 17/17 escenarios (token, push aprobado, push + código tipeado, `--no-push`,
`--code`, email, drift, RADIUS con comas, renovar, skip, HTML legado 401, host-check, código malo,
cancelación, EOF) con los bodies exactos de arriba.

### SSO / SAML — modo "navegador externo"   ✅ VERIFICADO (GUI oficial + GW real, 18/10/2026)
Fuente primaria: la GUI Electron de FortiClient 7.4 (`/opt/forticlient/gui/resources/app.asar`
→ `src/main/saml/saml.js`, `src/app/components/vpn/vpn.js`). El engine `vpn` solo hace el
canje final (`/remote/saml/auth_id?id=`, `/remote/saml/login`, "samldata").
1. `GET /remote/info` → XML `<info><api encmethod='0' salt='…' remoteauthtimeout='240'
   sso_port='8020' f='3cdf' /></info>`. `sso_port` = puerto local al que el GW devuelve el
   navegador (FortiOS `saml-redirect-port`, default **8020** = `SAML_DEFAULT_SSO_PORT`);
   `remoteauthtimeout` = cuánto esperar (default GUI 300 s). La GUI **solo usa navegador
   externo si `use_external_browser` && `sso_port`**; si no, usa el webview embebido (abajo).
   ⚠ El GW real devuelve **403** a `/remote/info` con UA de curl; con nuestro UA (`Mozilla/5.0
   SV1`) o el oficial (`FortiSSLVPN (Linux; SV1 [SV{v=02.01; f=05;}])`) → 200.
2. Escuchar en `127.0.0.1:<sso_port>` (la GUI: `http.createServer().listen(sso_port)`; si el
   puerto no coincide → `REDIRECT_UNAVAILABLE`) y abrir el navegador del usuario en
   `https://<gw>:<port>/remote/saml/start?[realm=<r>&]redirect=1` (`redirect=1` lo agrega
   `handleExternalSaml`). El GW **no** responde 302: responde **200 con
   `<script>window.location='https://<idp>/…?SAMLRequest=…&RelayState=magic%3D2-<hex>&SigAlg=…&Signature=…'`**
   (HTTP-Redirect binding firmado). El IdP del GW de prueba es Authentik
   (`/application/saml/<slug>/sso/binding/redirect/`); el MFA lo resuelve el IdP.
3. IdP → POST `SAMLResponse` al ACS del GW (`/remote/saml/login`); como el flujo arrancó con
   `redirect=1`, el GW manda el navegador a **`http://127.0.0.1:<sso_port>/?id=<auth_id>`**
   (auth_id de 35 chars en el GW de prueba). La GUI contesta una página "You may close the browser".
4. `GET /remote/saml/auth_id?id=<auth_id>` → `Set-Cookie: SVPNCOOKIE=…` (1936 B en el GW de
   prueba) → igual que password (config XML + túnel).
- **Modo webview embebido** (sin `sso_port` / navegador externo deshabilitado): la GUI
  intercepta el POST del IdP a `*://*/remote/saml/login*` (`onBeforeRequest`), toma el body
  (`SAMLResponse=…&RelayState=…` = "samldata") y se lo pasa al engine, que lo POSTea él mismo
  a `/remote/saml/login` (`saml_type` INTERNAL=1 / EXTERNAL=2 / AZURE_AUTOLOGIN=4). No lo
  implementamos (no tenemos webview); el modo externo cubre los GW con `sso_port`.
- `/remote/login` muestra el botón "SSO Login" si `<input name=saml_login value="1">`
  (portal: `launchSamlLogin()` → `/remote/saml/start?realm=`).
- **cpvpn** (`forti/saml.rs`): lee `/remote/info` (puerto + timeout), escucha en `127.0.0.1` y
  `[::1]` (best-effort), imprime `# SAML-URL: <url>` (la GUI lo abre como el usuario y pasa
  `--no-browser`); por CLI abre el navegador **como el usuario real** aunque corra con sudo/pkexec
  (`runuser -u $SUDO_USER -- env -i HOME… XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS WAYLAND_DISPLAY
  DISPLAY xdg-open`). Fallback sin listener alcanzable: pegar en stdin la URL final
  `http://127.0.0.1:8020/?id=…` (o el id). `disconnect`/EOF en stdin cancela. Sin `-u`,
  `--connect` detecta SAML solo (`/remote/saml/start` → IdP). `--probe` reporta IdP + `sso_port`.

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

## Aceleración — DTLS (UDP)   ✅ IMPLEMENTADO + VALIDADO EN VIVO (20/10/2026)
DTLS es **opportunistic y on-by-default**: si el XML trae `dtls="1"` se intenta DTLS;
si algo falla o el gateway no reenvía datos, se cae a TLS de forma transparente. NO es
PSK — es un **handshake DTLS con certificado normal** (igual que el lado TLS; openconnect
`start_dtls_anon_handshake` usa el mismo cred store, sin verificar el cert del server).
El SVPNCOOKIE NO es el secreto DTLS: va *dentro* del hello de aplicación.

- **Puerto**: el mismo que TLS (443/udp, acá 10443/udp). Confirmado.
- **Transporte**: `crate::gnutls` (dlopen de libgnutls en runtime, binario único; el mismo
  módulo que usa AnyConnect para su DTLS). `DtlsSession::connect_cert`. OpenSSL/native-tls
  no exponen DTLS; GnuTLS sí. Validado contra un `gnutls-serv --udp` local (DTLS1.2 AES-GCM).
- **Hello de aplicación** (primer datagrama, tras el handshake DTLS):
  ```
  [u16 be len = 2 + 27 + len(cookie) + 1]
  "GFtype\0clthello\0SVPNCOOKIE\0"   (27 bytes, incluye el NUL final)
  <cookie>\0
  ```
  Reenviado cada 1s hasta recibir el **svrhello** (≤5s). El cookie SAML pesa ~2KB → el
  datagrama excede la MTU; se manda con `send_oversized` (GnuTLS fragmenta el record).
- **Server hello**: `[be16 len]"GFtype\0svrhello\0handshake\0ok\0"`. En FortiOS 7.x
  moderno el `type` es **`svrhello-tun`** (no `svrhello`); el parser acepta ambos y lee los
  campos como pares `clave\0valor\0` (como el FortiClient). `handshake != ok` → cae a TLS.
- **⚠ HALLAZGO CLAVE (lo que hacía fallar DTLS):** una vez establecido, el stream DTLS
  **intercala records de control `GF…` (heartbeats `svrhello-tun`) ENTRE los frames PPP**.
  openconnect los tolera porque lee **un datagrama = un frame** y descarta el que no empieza
  con `0x5050` sin desincronizar. Nuestro `PppConn` bufferea bytes y parseaba el `GF`
  (`magic=0x4746`) como framing PPP corrupto → desincronizaba → el túnel moría (a veces al
  toque, a veces tras unos segundos, según cuándo cayera el primer heartbeat — por eso
  parecía "intermitente / data-plane roto"). **Fix:** `take_frame` detecta `[be16 len]"GF"`,
  drena `len` bytes y lo reporta como `FORTI_CTRL` (proto pseudo 0xffff, ignorado por el data
  loop pero cuenta como RX/liveness). Nuestro keepalive propio sigue siendo el eco LCP (como
  el `dtls_times.dpd` de openconnect = `heartbeat-interval` del XML). No hace falta responder
  el heartbeat del gateway.
- **Fallback robusto**: el handshake + la negociación PPP pueden andar aunque el gateway
  después no reenvíe IP; por eso hay un *trial* en el data loop — si en `DTLS_TRIAL`=5s se
  mandó data (`tout≥8`) y no volvió ni un frame IP (`tin==0`), se declara DTLS muerto y se
  reconecta por TLS (acota el blackhole; auto-cura). El reconnect reusa sess/cookies sin
  re-auth; una reconexión fallida NO re-corre el data loop sobre la conexión muerta (bug
  arreglado). `--no-dtls` fuerza TLS.
- **MEDIDO EN VIVO vs `SSO test GW` 203.0.113.30:10443 (SAML, 20/10/2026):** DTLS up,
  estable 20s+ (varios heartbeats de 3s atravesados, `frame_err=0`), 0% loss; **50 pings
  paralelos de 1200B: 79ms (DTLS) vs 253ms (TLS) ≈ 3.2× más rápido** (sin HOL blocking de
  TCP, misma clase que el 7× de AnyConnect). Teardown limpio, resolv.conf restaurado.
- El binario `vpn` tiene además `create_ssl_tunnel_dtls2` y stack **QUIC** (`clthello-tun2`,
  `quic_do_handshake`) → transporte más nuevo (7.4); fuera de alcance.

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
- ✅✅✅ **VALIDADO END-TO-END con credenciales reales (18/10/2026)**: auth OK
  (`SVPNCOOKIE` ~372 B) → `fortisslvpn_xml` parseado (XML crudo verificado: **404 rutas
  split reales, 0 `<dns>`** → `dns=[]`/`routes=404` eran correctos, no bugs; el GW ofrece
  `tunnel-method ppp/tun/websocket`) → **PPP LCP/IPCP** (IP `10.100.17.x`, **frame_err=0**) →
  tun `cpfg0` + gateway pin + 404 rutas → **TUNNEL UP**. **Data-plane real probado**: `ping`
  a hosts internos (100.64.10.1, 100.64.10.2, 172.30.0.1) **responde por el túnel**
  (`tun_in>0`, `frame_err=0`). Teardown limpio, sin leftovers, sin colisión con el túnel CP
  (device distinto `cpfg0`). Camino password + túnel SSL/PPP **completo y funcionando**.
- 2FA: implementado según la spec verificada (arriba) y probado contra un FortiGate simulado;
  falta un GW real con token (gw-forti es password-only). SAML ya validado contra otro GW (ver abajo).

## Validación en vivo — SAML/SSO, gateway `SSO test GW` (203.0.113.30:10443)
FortiGate con "SSO para túnel VPN" + "navegador externo para SAML" (IdP Authentik en
203.0.113.31:19000), autorizado por el usuario.
- `--probe` ✅ → `remote info: sso_port=8020 remoteauthtimeout=240s`, `SAML/SSO is ENABLED →
  IdP 203.0.113.31:19000`, `external-browser SSO ✓` (antes del fix el probe lo daba como
  password-path porque el GW responde 200+JS, no 302).
- `sudo cpvpn forti -g 203.0.113.30:10443 --saml --connect --no-routes` ✅✅ (18/10/2026):
  navegador abierto como el usuario (Brave/Sway) → login IdP + MFA → redirect a
  `127.0.0.1:8020/?id=<35 chars>` → `auth_id` → **SVPNCOOKIE 1936 B** → `fortisslvpn_xml`
  (`dtls='1'`, `tunnel-method ppp/tun/websocket`, `auth-ses check-src-ip='1'`, 4 rutas split /32
  10.30.51.230-233, sin DNS) → **PPP up, IP 10.30.8.73, frame_err=0** → tun `cpfg0` →
  **TUNNEL UP**. Data-plane: `ping -I cpfg0` a 10.30.51.231/.232/.233 **responde (~65 ms)**
  (.230 devuelve ICMP error = host caído del otro lado). Teardown limpio (`cpfg0` borrado,
  resolv.conf intacto, exit 0).
- ✅ **E2E desde la GUI (19/10/2026)**, ya con los arreglos de la revisión: FortiClient → SSO/SAML →
  "Sign in with browser" → login IdP + MFA → **Connected**. Engine `sudo -n cpvpn forti … --saml
  --no-browser --connect`; `cpfg0` 10.30.8.73/32 **sin link-local IPv6** (`disable_ipv6=1`); rutas
  instaladas (4 split /32 vía `cpfg0` + pin del gateway `203.0.113.30 via 192.168.9.1 dev enp10s0`, la IP
  del socket real); `ping` a 10.30.51.231-.233 **por las rutas** (sin `-I`) ~65 ms; internet sigue por
  `enp10s0`; DNS intacto (el GW no manda DNS). **Disconnect desde la GUI**: engine termina, `cpfg0`
  borrado, pin y las 4 rutas borradas, **tabla de rutas idéntica a la foto previa**, resolv.conf intacto.
- Hallazgo en la prueba: al levantar el tun el kernel autoconfigura IPv6 link-local y manda
  RS/MLD por el túnel, y el loop los enviaba como PPP **IPv4** (lo mismo en F5 y en el ESP de
  Check Point). Fix: `tun::open_tun` pone `disable_ipv6=1` en la interfaz antes de subirla y
  los tres data-loops descartan todo lo que no sea IPv4 (`tun::is_ipv4`).

## Revisión adversarial del back-end (18-19/10/2026) — arreglos aplicados
Revisión multi-agente (protocolo, concurrencia, plano de datos, GUI; cada hallazgo con un verificador
que intentó refutarlo — los 15 verificados se confirmaron, ninguno refutado). Arreglado y cubierto por
tests (83 unit + 24 escenarios contra el FortiGate simulado + 4 SAML):
- **Push rechazado** (HTTP 405 al `ftmpush=1` aunque el GW anuncie `ftm_push`, openfortivpn #947/#1019):
  antes terminaba el login; ahora re-loguea con el push desactivado y pide el código. Un 405 en un paso
  de 2FA ya no culpa a usuario/contraseña.
- **Push vs código**: `Cancel` es *sticky* (un código tipeado antes de que el push conecte evita que
  salga el push); si el push ya fue aprobado cuando llega el código, se usa la sesión del push; si el
  hilo del push muere, error en vez de esperar para siempre.
- `--code` también contesta el challenge RADIUS (`ret=6`) y el formulario HTML legado; límite de rondas
  sin off-by-one; texto del prompt correcto con `--no-push`; confirmación de password nueva en TTY.
- **Disconnect durante un login retenido** (MFA RADIUS fuera de banda: el GW retiene el POST hasta
  `remoteauthtimeout`): el lector de stdin levanta un flag global al ver `disconnect`/EOF y el POST se
  cancela en ~100 ms (antes: hasta ~5 min de GUI congelada, y si se aprobaba en el teléfono se levantaba
  el túnel igual). `connect` con timeout por dirección (antes ~2 min contra un GW caído).
- **Teardown a prueba de GUI muerta**: con la GUI caída, stdout es un pipe roto y `println!` entraba en
  pánico antes de restaurar DNS/rutas. Ahora: macro `out!` que no entra en pánico en todo camino
  posterior a tocar la red, guard `sysnet::NetRestore` (Drop restaura DNS + rutas también en error o
  pánico), SIGHUP/SIGQUIT además de SIGTERM/SIGINT (Forti, F5 y Check Point).
- **Escritura en socket no bloqueante**: `write_all` devolvía `WouldBlock` con el buffer lleno (subida
  grande) y se caía el túnel; ahora `sysnet::write_all_polling` espera `POLLOUT` y reintenta los mismos
  bytes (OpenSSL lo exige). Forti y F5.
- **Rutas**: solo se borran al desconectar las rutas que agregamos con éxito (`ip -force -batch`
  reporta `Command failed -:N`): antes se borraba p. ej. la ruta de la LAN si estaba en la lista de
  exclusión. El pin del gateway usa la IP a la que conectó el socket real (no una segunda resolución DNS:
  GW dual-WAN/HA).
- `try_dechunk_complete` (Forti y F5): sin pánico con un chunk cortado antes de su CRLF o un tamaño absurdo.
- **GUI**: `disconnect` ya no bloquea el hilo de UI (estado *Disconnecting…*, el proceso se cosecha en
  `poll_exit`; al cerrar espera ≤3 s); generación por conexión (las líneas tardías de un engine viejo no
  tocan la sesión nueva); marcadores solo desde **stdout** y al inicio de línea; `SAML-URL` se abre una
  vez y solo si es el punto de entrada del gateway escrito por el usuario; el texto del gateway llega
  siempre aplanado a una línea (no puede inyectar `SAML-URL:`/`TUNNEL UP`); tarjeta de prompt arriba de
  todo, con foco, y la columna scrollea (antes quedaba fuera de pantalla en ventanas bajas); número de
  secuencia por prompt (no arrastra lo tipeado al siguiente); respuestas de challenge enmascaradas y sin
  recortar; Enter en "confirmar password". Las etiquetas `Password:`/`Passcode:` solo con TTY (en el
  pipe de la GUI se pegaban a la línea de error y ocultaban `forti failed`/`IKE failed`).

## Seguridad / alcance
- Riesgo aceptado (igual que FortiClient): durante la espera SAML, cualquier proceso local o página
  web puede pedir `http://127.0.0.1:<sso_port>/?id=<id>` y hacernos canjear un `auth_id` ajeno (el
  túnel quedaría en la sesión de otro usuario del mismo GW). El listener sólo vive esa ventana
  (`remoteauthtimeout`) y su parser es a prueba de entradas hostiles.
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
