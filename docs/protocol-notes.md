# Check Point VPN — spec de protocolo (reverse engineering)

> Cliente Linux nativo independiente, para interoperar con un gateway autorizado.
> Target: E84.30_CheckPointVPN.msi → "Endpoint Connect / Trac" v98.61.02307 (PE32 i386).
> Evidencia: binarios (strings/RTTI) + captura dinámica (trac.log/helpdesk.log + pcap).

## Gateway real (de la captura)
- Gateway IP: 203.0.113.10 ; site: `site-a` ; realm: `vpn` ; user: `u-123456`.
- Auth: **RSA SecurID** (`authentication_method = securIDKeyFob`, `securID_type = pin_pad`).
- Machine authentication: enabled.
- `site_uses_login_options = true`.

## Flujo de conexión (TR_FLOW_STEP, orden observado)
ResolveGwName → CheckNetwork → PokeGW → ProxyDetection → **ClientHello (CCC)** →
VerifyEpsServer → **GetAuthInfo** → RealmConfig → **ConnEngineConnect (IKE)** →
DownloadClSetting → Scv → Firewall → (CONNECTED / Office Mode IP set).
- helpdesk.log: "No reply for quick mode 1 packet" + "Office mode IP was set successfully".

## Plano de control — CCC (HTTPS / TCP 443)   ✅ M1 VERIFICADO contra el GW real
- HTTP: `POST /clients/` → `HTTP/1.0 200 OK`, `Server: Check Point SVN foundation`,
  `Content-Type: text/plain`. (cert-auth usa `/clients/cert/`.)
- Headers del request: el GW es TOLERANTE con headers (snx-rs manda defaults de reqwest
  y anda). Igual mandamos los del cliente real: `User-Agent: Mozilla/5.0 (compatible;
  CPSC 5.0; Windows NT 5.0)`, `Content-Type: application/x-www-form-urlencoded`.
- **FORMATO DEL BODY (crítico):** el parser del GW EXIGE el S-expression **multilínea
  con indentación por TABs**. Body en una sola línea → `return_code (504)` con el header
  ECHO VACÍO (no logra extraer ni `type`). Multilínea → `600`. (snx-rs serializa así.)
- **El RequestHeader NO lleva `protocol_version`** (solo `id`/`type`/`session_id`).
  Mandarlo dispara el "bad protocol version number". `protocol_version` lo devuelve el
  SERVER, anidado: `:protocol_version (:protocol_version (100) :features (0x1))`.
- Escalares **bare** (sin comillas), salvo paths/strings con chars especiales → `"..."`.
  Arrays = claves vacías repetidas: `(: (IPSec) : (SSL) : (L2TP))`.
- ClientHello (request, VERIFICADO → 600):
  ```
  (CCCclientRequest
  	:RequestHeader ( :id (<n>) :type (ClientHello) :session_id () )
  	:RequestData ( :client_info (
  		:client_type (TRAC) :client_version (1) :client_support_saml (true) )))
  ```
- Respuesta ClientHello (ResponseData del GW real, return_code 600):
  - `connectivity_info`: `connectivity_type (IPSec)`, `server_ip (203.0.113.10)`,
    `ipsec_transport (auto_detect)`, `tcpt_port (443)`, `natt_port (4500)`,
    `cookie_name (CPCVPN_SESSION_ID)`, `connect_with_certificate_url (/clients/cert/)`,
    `internal_ca_fingerprint :1 (<hex 108 chars>)`, protos = IPSec/SSL/L2TP,
    `default_authentication_method (client_decide)`.
  - `login_options_data :login_options_list :0`: `id (vpn)`, `display_name (Standard)`,
    `show_realm (1)`, `secondary_realm_hash (c4ca…)`, `factors :0 :factor_type (user_defined)`.
  - `login_options_md5 (5fa927f808843186e5aa3d9230b15dd7)`.
  - `end_point_security :ics :run_ics (false)` → sin compliance/ICS obligatorio.
- Requests siguientes (de snx-rs `gateway.rs`): `UserPass` (auth; user+pass/passcode +
  `selectedLoginOption (vpn)`), `MultiChallange` (sic, mal escrito — next-token SecurID),
  `ClientSettings`, `Signout`. **username/password van OFUSCADOS en hex**.
- Clases RTTI (binario): CccClientRequest, CccRequestHeader::Init, TrClientHelloStep.
- Mapa de referencia: snx-rs `crates/snxcore/src/{model/proto.rs,tunnel/gateway.rs,sexpr.rs}`.

## Auth por CCC — SecurID (M2)   ✅ UserPass VALIDADO (falta passcode en vivo)
- Ofuscación (snx-rs `util.rs` → portada a `ccc::obfuscate/deobfuscate`): hex de un XOR
  por índice contra una tabla fija de 77 bytes, con el orden de bytes invertido.
  username/password/prompt/active_key/error_* viajan así. Verificada en ambos sentidos.
- Flujo (verificado contra el GW real):
  1. `UserPass`: `:client_type (TRAC) :username (<obf>) :password () :selectedLoginOption (vpn)`.
     user `u-123456` → obf `72707d757b756258`. GW responde `return_code (600)`,
     `authn_status (continue)`.
  2. La respuesta trae `prompt` (ofuscado) = **"PASSCODE: "** y `session_id` (64 hex).
  3. `MultiChallange` (sic, así escrito): header `:type (MultiChallange) :session_id (<sid>)`;
     data `:client_type (TRAC) :auth_session_id (<sid>) :user_input (<obf passcode>)`.
  4. Respuesta final esperada: `authn_status (done)`, `is_authenticated (true)`,
     `active_key` (ofuscado) = la session key → cookie `CPCVPN_SESSION_ID` para el túnel.
- AuthResponse (campos bajo ResponseData): authn_status, is_authenticated, active_key,
  session_id, prompt, prompt_id, auth_state, error_message/error_id/error_code.
- VERIFICADO en vivo: UserPass → `continue` + prompt "PASSCODE: " (prompt_id
  `CPSC_SECURID_PASSCODE`) + session_id (64 hex). MultiChallange con el passcode → `done`.
  Con passcode inválido: `is_authenticated (false)`, `error_code (101)`, error_id
  `CPSC_SECURID_USER_DENIED`, error_message "Access denied - wrong user name or password".
  → protocolo 100% OK (ofuscación byte-exacta: `u-123456`→`72707d757b756258`).
- ✅ **AUTH EXITOSA** (PASSCODE = PIN+tokencode): `is_authenticated (true)`, token de sesión =
  **`active_key`** en el body (64 bytes tras desofuscar) + `active_key_timeout (32400)` = 9 h +
  `session_id` (32 hex). Ese `active_key` es el secreto de sesión para el túnel (M3). Sin cookie
  Set-Cookie: el token viaja en el body. M2 COMPLETO de punta a punta.
- ⚠ El 2º factor es **RSA SecurID On-Demand: tokencode de UN SOLO USO que llega por EMAIL**
  (no es token físico). El usuario lo pide en el self-service
  `https://securid.example.net/console-selfservice/` (login con user+token) → le llega al mail.
  En el prompt `PASSCODE:` va **PIN + tokencode** (RSA: PASSCODE = PIN+TOKENCODE) — p.ej.
  `<PIN>` + el código del mail. Mandar SOLO el tokencode ⇒ `error_code 101` /
  `CPSC_SECURID_USER_DENIED` "Access denied". El código es de un solo uso; cada intento
  necesita uno NUEVO. Request del código: self-service `OnDemandOTTLogin.do` pide User ID +
  PIN (`<PIN>`) → lo manda al mail. Flujo: pedir código → leer mail → `unvpn login` passcode=PIN+code.
- `unvpn deob <hex>...` desofusca strings del server (prompt/error_*) para debug.
- bin: `unvpn login --gateway <h> [--user u-123456] [--realm vpn] [--probe|--passcode <p>] [--verbose]`.

## Plano de datos — IPsec/IKEv1 (confirmado)
- `conn_type = "IPSec"` ; IKEv1 Main Mode + Quick Mode (IkeV1Tunnel).
- Office Mode: IP interna asignada vía IKE config-mode ("Office mode IP was set").
- Transporte `Auto-Detect`:
  - NAT-T **UDP 4500** (NatT_Transport) — probado.
  - **Visitor Mode / TCPT: TCP 443** (IKE+ESP dentro de TLS) — **el que usó el túnel**.
- ESP: una vez negociadas las SA → en Linux se puede delegar al kernel (XFRM) o
  procesar en userspace (necesario en Visitor Mode, ESP-in-TLS → /dev/net/tun).

## Pendiente (completar durante el build)
- [ ] Suite IKE exacta (cipher/DH/hash/lifetime) — la dicta el GW; sacar de pcap TLS-desc o .elg.
- [ ] Cuerpo CCC exacto de GetAuthInfo + multichallenge SecurID.
- [ ] Ofuscación del passcode (one-time; menos crítica). Prior art: snx-rs.
- [ ] Framing exacto del Visitor Mode (ESP sobre TCP 443/TLS).

## Plan de construcción (Rust, nativo Linux)
- M1: ✅ crate `ccc` — serializer S-expr (multilínea/tab) + ClientHello + parser
      login_options. VERIFICADO contra el GW (600 + login_options). bin `unvpn hello`.
- M2: ✅ auth por CCC: `UserPass` (`selectedLoginOption vpn`, user `u-123456`) → challenge
      `PASSCODE:` → `MultiChallange` con passcode=PIN+ondemand-tokencode ofuscado → `done`
      + `active_key` (clave de sesión, 9h). VERIFICADO en vivo. bin `unvpn login`.
- M3: 🔧 IKEv1/IPSec nativo (crate `unvpn::ike`: model/wire/crypto/session/service/transport).
      ✅ Phase 1 (Main Mode) + hybrid auth VERIFICADO en vivo sobre **UDP 500** (no hace falta
      Visitor Mode — UDP abierto). Falta: responder passcode SecurID → Quick Mode → Office
      Mode → ESP → tun/rutas.
  Hallazgos IKE en vivo:
  - Suite elegida por el GW: **AES-256-CBC / SHA1 / DH group 2 / 28800s**. Hay que ofrecer una
    MATRIZ de transforms (enc×hash×grupo, hybrid auth 0xfadd); un solo transform → notify CP
    9101 `VPN_NO_COMMON_METHODS_MM`. El GW usa **SHA1**, no SHA256.
  - Codec ISAKMP validado byte-exacto contra `mm.bin`. Cripto (OpenSSL): DH g2, SKEYID=prf(Ni|Nr,
    g^xy) [20B SHA1], SKEYID_e 32B (AES256), IV chaining por message_id, padding ISAKMP (1..n,n).
  - NAT-D: hash(spi_i|spi_r|gw_ip|4500) y hash(spi_i|spi_r|local_ip|0).
  - msg5 (cifrado) = Hash(HASH_I) + ID(UserFQDN vacío) + Notify(**CccAuth 0x8004**, auth_blob
    S-expr: clientType TRAC, protocolVersion 100, client_mode endpoint_security, selected_realm_id vpn).
  - msg6 = ID_R + SIG_R + CERT del GW (~1932B). **SIG_R verificado** (RSA public_decrypt vs HASH_R).
    El GW **retransmite msg6** hasta que el cliente avanza → saltar los duplicados (comparar bytes).
  - Post-Phase1: el GW abre **Transaction (exchange 6, config-mode)** kind=1 Request con
    `AuthType` + `UserName` (vacío) → el cliente responde user, luego llega el challenge PASSCODE.
  - ✅ **AUTH COMPLETA por IKE** (Status=1): PASSCODE = PIN+tokencode en atributo `UserPassword`
    (challenge id `CPSC_SECURID_PASSCODE`). Reply config = [Hash(SKEYID_a), Attributes(Reply,
    AuthType+valor)] cifrado.
  - ✅ **Office Mode** (config Request: Ipv4Address/Netmask/Ipv4Dns/InternalDomainName/CccSessionId/
    CccVariableLeaseTime/CccOfficeModeAllowed/CccConnectAllowed + Mac) → GW asigna IP interna
    (ej. **10.40.248.36/21**), DNS (10.40.9.171/.172, 10.40.64.9), dominio **intranet.example.net**.
  - Quick Mode: [Hash(1), SA(ESP matrix, **doi=0 sin situation**), Nonce, IDci(ip), IDcr(subnet)]
    cifrado exchange=32; HASH(1)=prf(SKEYID_a,msgid|payloads); QM3 ack HASH(3)=prf(SKEYID_a,0|msgid|
    Ni|Nr). KEYMAT ESP=prf(SKEYID_d,[3]|SPI|Ni|Nr), por SA (SPI propio=inbound, SPI del GW=outbound).
  - ⚠ El GW **retransmite** mensajes; filtrar respuestas por `message_id` esperado (si no, IV viejo
    → basura). ⚠ La SA de QM **debe** ser `doi=1 + situation=1` (SIT_IDENTITY_ONLY); con `doi=0`
    sin situation el GW responde NOTIFY 3 `SITUATION_NOT_SUPPORTED`.
  - ✅✅✅ **HANDSHAKE COMPLETO verificado en vivo**. SA ESP elegida por el GW: **3DES-CBC +
    HMAC-SHA1-96**, encap **UDP_TUNNEL** (ESP sobre UDP 4500 / NAT-T). KEYMAT 44B (24 cifrado +
    20 auth) por SA. SPIs: propio=inbound, del GW=outbound. QM3 ack HASH(3). IP interna asignada.
  - bin: `unvpn ike --gateway <h> [--passcode <PIN+tokencode>]`.

## Plano de datos — ESP (M4, en construcción)
- Encap `UDP_TUNNEL`: paquete ESP crudo sobre UDP **4500** (sin non-ESP marker; el SPI != 0 lo
  distingue de IKE). Formato ESP: `[SPI(4)][seq(4)][IV(8, 3DES)][cifrado: IP + pad + pad_len +
  next_header][ICV(12, HMAC-SHA1-96)]`.
- Outbound: leer IP de `tun` → ESP (SPI=gw, seq++, 3DES-CBC enc, HMAC-SHA1-96) → UDP a gw:4500.
- Inbound: UDP de gw:4500 → ESP (SPI propio) → verificar ICV, descifrar, quitar pad → `tun`.
- `tun` con la IP de Office Mode (/21), rutas por el túnel, DNS corporativo. Necesita sudo.
- ⚠ **IKE + ESP DEBEN usar el MISMO socket UDP 4500** (misma asociación NAT-T). Si el IKE va por
  500 y el ESP por otro puerto, el gateway descarta nuestro ESP (manda 0 de vuelta). Por eso
  `--connect` hace el handshake entero en 4500 y clona ese socket para el ESP.
- ✅✅✅ **TÚNEL VERIFICADO END-TO-END** (18/10/2026): `ping` y `ssh` (TCP 22) a un host interno
  (10.50.3.37) funcionan a través del túnel nativo; ESP bidireccional (udp_in>0, dec_err=0).
  Los DNS internos filtran ICMP (por eso fallaba el ping a 10.40.9.171) — no era bug del cliente.
  bins: `unvpn ike -g <h> --passcode <PIN+code> --connect` (handshake+túnel en 4500, sudo);
  `unvpn ike ... --save-session <f>` + `unvpn tunnel-up --session <f>` (datos sin re-auth, mismo host).

## Estado del proyecto
- M1 CCC ✅ · M2 auth SecurID ✅ · M3 IKEv1+hybrid+OfficeMode+QuickMode ✅ · M4 ESP/tun ✅ (túnel real andando).
- M4.5 pulido motor ✅: DNS (resolv.conf, symlink-aware systemd-resolved), teardown limpio
  (SIGTERM + `disconnect` por stdin, restaura DNS), passcode por stdin, sesión guarda DNS/dominios.
- M5 GUI + tray ✅: `unvpn-gui` (egui, columna centrada, tema oscuro, ícono shield propio),
  tray StatusNotifierItem (ksni, pixmap por estado, detección de host de bandeja vía DBus),
  selector de cliente (CheckPoint activo; OpenVPN/F5 "soon"), passcode por stdin. Escalada de privilegios
  **autodetectada**: `sudo -n` si hay sudo sin password (WM mínimos sin agente polkit, p.ej. Sway), si no `pkexec`
  (override `UNVPN_PRIV`). Cerrar la ventana = desconectar limpio + salir (antes hide-to-tray, confundía).
  Verificado: conecta end-to-end por la GUI en Sway/Wayland (handshake + tráfico real).
- Portabilidad ✅: OpenSSL **vendored/estático** (feature `vendored`; motor solo depende de glibc),
  `install.sh` (+`.desktop`, iconos hicolor, regla polkit opcional), README. Opción musl documentada.
- Rekey de ESP ✅ (validado live): hilo de control IKE renegocia la SA con un Quick Mode nuevo bajo
  la misma IKE SA (sin re-auth) antes del lifetime (3600s; `UNVPN_REKEY_SECS` para test). Hot-swap de la
  SA (`RwLock<Arc<EspSa>>`) bajo los threads vivos; demux IKE/ESP en el socket 4500 compartido;
  retransmite QM1 si no llega QM2. Test: ping 3/3 antes y después de cada rekey, `dec_err=0`, y fallo
  de rekey degrada con gracia (mantiene SA vieja). **DPD: NO hace falta** — la impl de referencia (cliente
  CP funcional) no lo implementa, y el gateway no manda R-U-THERE (sí un `exchange 6` Transaction, ignorado).
- **Keepalive de tunnel-test ✅ (CRÍTICO para estabilidad)**: Check Point tira el túnel a los ~15-20 min
  si no ve su keepalive propietario, aunque fluya ESP. Es un paquete UDP de 12 bytes
  (`counter(4 BE) | 0x0003 | 0x0002 | 0x000c`) al gateway en **puerto 18234**, **por dentro del túnel**
  (IP+UDP cifrado en ESP), cada 20s (de snx-rs `ipsec/keepalive.rs`; `trac.exe` tiene el token `keepalive`).
  El NAT-T keepalive (0xFF en 4500) NO alcanza — solo mantiene el NAT, no es el tunnel-test.
  Confirmado: test de supervivencia SIN keepalive murió limpio en seq 15→16 (~16 min, 10 timeouts seguidos).
- Pendiente: validación live del keepalive (en curso); IKE SA rekey (>8h, raro);
  `Delete`-SA al desconectar (cosmético); scope de rutas fino; back-ends OpenVPN/F5.
- M4: Visitor Mode (ESP-in-TLS, TCP 443) o NAT-T (UDP 4500) + /dev/net/tun + rutas/DNS.

## Seguridad / evidencia
- captures/ contiene credenciales (passcode one-time, cookies) → tratar como secreto, borrar al cerrar.
