//! OpenVPN session orchestration: establish (reset → TLS → key exchange →
//! PUSH_REQUEST/PUSH_REPLY, handling AUTH_PENDING / AUTH_FAILED / CRV1), then the
//! data plane: tun ⇄ encrypted P_DATA packets, OpenVPN pings + ping-restart,
//! compression framing, renegotiation and transparent reconnection.

use super::config::{Compress, Config, Remote};
use super::crypto::{self, Key2, Wrap};
use super::link::Link;
use super::push::{self, PushConfig, Topology};
use super::session::{Creds, DataParams, Engine, Event};
use super::tls::{self, PeerInfo};
use crate::sysnet;
use crate::tun;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static OV_STOP: AtomicBool = AtomicBool::new(false);

const TUN_NAME: &str = "cpovpn0";
const MAX_RECONNECT_TRIES: u32 = 10;
/// Data-channel keepalive magic (`ping.c`): a 16-byte payload, not an IP packet.
const PING_MAGIC: [u8; 16] = [0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48];
/// OCC message prefix (`occ.c`); `OCC_EXIT` (6) after it = explicit exit notify.
const OCC_MAGIC: [u8; 16] = [0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c];
const OCC_EXIT: u8 = 6;
const DEFAULT_CIPHERS: &str = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305";
const VERSION: &str = "2.6.14";

/// Interactive questions during authentication (implemented by the CLI/GUI front).
pub trait Prompter {
    /// Ask for a secret / answer: `kind` is a GUI marker class (`password`,
    /// `code`, `keypass`, …), `message` the human text.
    fn ask(&mut self, kind: &str, message: &str, echo: bool) -> Result<String, String>;
    /// A web login the user must complete (AUTH_PENDING with WEB_AUTH/OPEN_URL).
    fn open_url(&mut self, url: &str);
}

pub struct RunOpts {
    pub no_routes: bool,
    pub watch_stdin: bool,
    /// `--login`: authenticate + read the PUSH_REPLY, then exit (no tun).
    pub login_only: bool,
}

/// What a finished establish phase hands to the data plane.
struct Established {
    engine: Engine,
    push: PushConfig,
    server: Ipv4Addr,
}

/// Failure modes of the establish phase that need special handling.
enum EstablishError {
    /// AUTH_FAILED with a CRV1 dynamic challenge: answer, then reconnect.
    Challenge { state: String, user: String, text: String, echo: bool },
    AuthFailed(String),
    Other(String),
}

impl From<String> for EstablishError {
    fn from(s: String) -> Self {
        EstablishError::Other(s)
    }
}

/// Everything fixed for the whole run (re-used across reconnects).
pub struct Prepared {
    pub cfg: Config,
    ctx: openssl::ssl::SslContext,
    peer: Arc<Mutex<PeerInfo>>,
    tls_wrap_key: Option<(Key2, bool)>,
    pub creds: Option<Creds>,
}

/// Load keys/certs and build the TLS context. `key_pass` unlocks an encrypted key.
pub fn prepare(cfg: Config, creds: Option<Creds>, key_pass: Option<&str>) -> Result<Prepared, String> {
    let id = tls::load_client_id(&cfg, key_pass)?;
    let peer = Arc::new(Mutex::new(PeerInfo::default()));
    let ctx = tls::build_context(&cfg, &id, peer.clone())?;
    let tls_wrap_key = if let Some(t) = &cfg.tls_crypt {
        Some((Key2::from_static_pem(t).map_err(|e| format!("tls-crypt key: {e}"))?, true))
    } else if let Some(t) = &cfg.tls_auth {
        Some((Key2::from_static_pem(t).map_err(|e| format!("tls-auth key: {e}"))?, false))
    } else {
        None
    };
    Ok(Prepared { cfg, ctx, peer, tls_wrap_key, creds })
}

impl Prepared {
    fn make_wrap(&self) -> Result<Wrap, String> {
        match &self.tls_wrap_key {
            Some((k, true)) => Wrap::tls_crypt(k),
            Some((k, false)) => Wrap::tls_auth(k, self.cfg.key_direction, &self.cfg.auth),
            None => Ok(Wrap::None),
        }
    }

    /// Ciphers we offer (IV_CIPHERS): `data-ciphers` (or the default AEADs) plus the
    /// legacy `cipher`, limited to what we implement.
    fn offered_ciphers(&self) -> Vec<String> {
        let mut v: Vec<String> = if self.cfg.data_ciphers.is_empty() {
            DEFAULT_CIPHERS.split(':').map(str::to_string).collect()
        } else {
            self.cfg.data_ciphers.clone()
        };
        if let Some(c) = &self.cfg.cipher {
            if !v.contains(c) {
                v.push(c.clone());
            }
        }
        v.retain(|c| crypto::cipher_by_name(c).is_some());
        v
    }

    fn options_string(&self, remote: &Remote) -> String {
        let cipher = self.cfg.cipher.clone().unwrap_or_else(|| "AES-256-GCM".into());
        let keysize = crypto::cipher_by_name(&cipher).map(|(_, k, _)| k * 8).unwrap_or(256);
        let proto = match remote.proto {
            super::config::Proto::Udp => "UDPv4",
            super::config::Proto::Tcp => "TCPv4_CLIENT",
        };
        let mut s = format!("V4,dev-type tun,link-mtu 1559,tun-mtu 1500,proto {proto}");
        if matches!(self.cfg.compress, Some(Compress::Lzo)) {
            s.push_str(",comp-lzo");
        }
        if self.cfg.tls_auth.is_some() {
            if let Some(d) = self.cfg.key_direction {
                s.push_str(&format!(",keydir {d}"));
            }
        }
        s.push_str(&format!(",cipher {cipher},auth {},keysize {keysize}", self.cfg.auth));
        if self.cfg.tls_auth.is_some() {
            s.push_str(",tls-auth");
        }
        s.push_str(",key-method 2,tls-client");
        s
    }

    fn peer_info(&self) -> String {
        // IV_PROTO: DATA_V2 | REQUEST_PUSH | TLS_KEY_EXPORT | AUTH_PENDING_KW | DNS_OPTION
        //          | CC_EXIT_NOTIFY | AUTH_FAIL_TEMP.
        let mut iv_proto = 2 | 4 | 8 | 16 | 64 | 128 | 256;
        // Test knob: don't offer TLS-EKM, forcing the legacy TLS1.0-PRF key expansion.
        if std::env::var_os("CPVPN_OVPN_NO_EKM").is_some() {
            iv_proto &= !8;
        }
        format!(
            "IV_VER={VERSION}\nIV_PLAT=linux\nIV_TCPNL=1\nIV_MTU=1600\nIV_NCP=2\nIV_CIPHERS={}\nIV_PROTO={iv_proto}\n\
             IV_LZO_STUB=1\nIV_COMP_STUB=1\nIV_COMP_STUBv2=1\nIV_SSO=openurl,webauth,crtext\nIV_GUI_VER=cpvpn {}\n",
            self.offered_ciphers().join(":"),
            env!("CARGO_PKG_VERSION")
        )
    }
}

fn stopped() -> bool {
    OV_STOP.load(Ordering::SeqCst) || sysnet::stop_requested()
}

/// Bring up one session against `remote`: through to the final PUSH_REPLY with
/// data keys installed. `creds` are what goes in the key-method message.
fn establish(p: &Prepared, remote: &Remote, creds: Option<Creds>, prompter: &mut dyn Prompter) -> Result<Established, EstablishError> {
    out!("# connecting to {}:{} ({}) …", remote.host, remote.port, remote.proto.as_str());
    let (link, server) = Link::open(remote, Duration::from_secs(15))?;
    *p.peer.lock().unwrap() = PeerInfo::default();
    let mut eng = Engine::new(link, p.make_wrap()?, p.ctx.clone(), p.peer.clone(), creds, p.options_string(remote), p.peer_info())?;
    out!("# {server}:{} — control channel wrap: {}", remote.port, eng.wrap_name());

    let mut deadline = Instant::now() + Duration::from_secs(60);
    let mut push = PushConfig::default();
    let mut push_sent: Option<Instant> = None;
    let mut auth_pending = false;
    let mut pkts = Vec::new();

    loop {
        if stopped() {
            return Err(EstablishError::Other("cancelled".into()));
        }
        if Instant::now() > deadline {
            let what = if push_sent.is_some() { "no PUSH_REPLY (authentication not completed)" } else { "TLS handshake timed out" };
            return Err(EstablishError::Other(format!("{what} — is the server reachable on {}?", remote.proto.as_str())));
        }
        eng.pump()?;
        wait_readable(eng.link.fd(), 200);
        pkts.clear();
        eng.link.recv_all(&mut pkts)?;
        for pk in &pkts {
            eng.handle_packet(pk)?;
        }
        eng.pump()?;

        while let Some(ev) = eng.events.pop_front() {
            match ev {
                Event::TlsUp { version, cipher, .. } => {
                    let pi = p.peer.lock().unwrap().clone();
                    out!("# TLS up ({version}, {cipher}) — server \"{}\"", pi.subject);
                    if !pi.issuer.is_empty() {
                        out!("#   issued by \"{}\"", pi.issuer);
                    }
                }
                Event::KeyExchanged { key_id: 0 } => {
                    out!("# key exchange done — requesting configuration (PUSH_REQUEST) …");
                    eng.send_text("PUSH_REQUEST")?;
                    push_sent = Some(Instant::now());
                }
                Event::Message(m) => {
                    if m.starts_with("PUSH_REPLY") {
                        if push.merge(&m) {
                            return finish(p, eng, push, server).map_err(EstablishError::Other);
                        }
                    } else if let Some(r) = m.strip_prefix("AUTH_FAILED") {
                        return Err(parse_auth_failed(r.trim_start_matches(',')));
                    } else if let Some(r) = m.strip_prefix("AUTH_PENDING") {
                        auth_pending = true;
                        let timeout = r
                            .split(',')
                            .find_map(|kv| kv.trim().strip_prefix("timeout ").and_then(|s| s.trim().parse::<u64>().ok()))
                            .unwrap_or(300);
                        deadline = Instant::now() + Duration::from_secs(timeout.clamp(60, 900));
                        out!("# server: authentication pending (up to {timeout}s) — complete it to continue");
                    } else if let Some(info) = m.strip_prefix("INFO_PRE,").or_else(|| m.strip_prefix("INFO,")) {
                        handle_info(&mut eng, info, prompter)?;
                    } else if m.starts_with("RESTART") || m.starts_with("HALT") {
                        return Err(EstablishError::Other(format!("server: {m}")));
                    } else {
                        out!("# server says: {m}");
                    }
                }
                _ => {}
            }
        }

        // Keep asking until the reply comes (a server may still be authenticating).
        if let Some(t) = push_sent {
            let every = if auth_pending { 5 } else { 3 };
            if t.elapsed() >= Duration::from_secs(every) {
                eng.send_text("PUSH_REQUEST")?;
                push_sent = Some(Instant::now());
            }
        }
    }
}

/// `INFO[_PRE],WEB_AUTH::<url>` / `OPEN_URL:<url>` / `CR_TEXT:<flags>:<text>`.
fn handle_info(eng: &mut Engine, info: &str, prompter: &mut dyn Prompter) -> Result<(), String> {
    if let Some(url) = info.strip_prefix("WEB_AUTH:").map(|r| r.splitn(2, ':').nth(1).unwrap_or(r)).or_else(|| info.strip_prefix("OPEN_URL:")) {
        out!("# server requests a web login: {url}");
        prompter.open_url(url);
    } else if let Some(r) = info.strip_prefix("CR_TEXT:") {
        // CR_TEXT:<flags>:<challenge> → answer with CR_RESPONSE,<base64>.
        let (flags, text) = r.split_once(':').unwrap_or(("", r));
        let resp = prompter.ask("code", text, flags.contains('E'))?;
        eng.send_text(&format!("CR_RESPONSE,{}", openssl::base64::encode_block(resp.as_bytes())))?;
    } else {
        out!("# server info: {info}");
    }
    Ok(())
}

/// `AUTH_FAILED[,reason]`, incl. the `CRV1:<flags>:<state>:<b64 user>:<text>` challenge.
fn parse_auth_failed(r: &str) -> EstablishError {
    if let Some(c) = r.strip_prefix("CRV1:") {
        let parts: Vec<&str> = c.splitn(4, ':').collect();
        if parts.len() == 4 {
            let user = openssl::base64::decode_block(parts[2]).ok().and_then(|v| String::from_utf8(v).ok()).unwrap_or_default();
            return EstablishError::Challenge {
                state: parts[1].to_string(),
                user,
                text: parts[3].to_string(),
                echo: parts[0].split(',').any(|f| f == "E"),
            };
        }
    }
    EstablishError::AuthFailed(if r.is_empty() { "credentials rejected".into() } else { r.to_string() })
}

/// After the last PUSH_REPLY: fix data parameters and derive the data keys.
fn finish(p: &Prepared, mut eng: Engine, push: PushConfig, server: Ipv4Addr) -> Result<Established, String> {
    let cipher = push
        .cipher
        .clone()
        .or_else(|| p.cfg.data_ciphers_fallback.clone())
        .or_else(|| p.cfg.cipher.clone())
        .unwrap_or_else(|| "BF-CBC".into());
    if crypto::cipher_by_name(&cipher).is_none() {
        return Err(format!("server uses data cipher {cipher}, which is not supported"));
    }
    let auth = push.auth.clone().unwrap_or_else(|| p.cfg.auth.clone());
    eng.peer_id = push.peer_id;
    eng.install_initial_keys(DataParams { cipher: cipher.clone(), auth, ekm: push.tls_ekm })?;
    out!(
        "# data channel: {cipher}{} · key derivation {} · {}",
        if crypto::cipher_by_name(&cipher).map(|c| c.2) == Some(crypto::CipherKind::Cbc) { format!("+HMAC-{}", eng.params.as_ref().unwrap().auth) } else { String::new() },
        if push.tls_ekm { "TLS-EKM" } else { "TLS1-PRF" },
        match push.peer_id {
            Some(id) => format!("P_DATA_V2 (peer-id {id})"),
            None => "P_DATA_V1".into(),
        }
    );
    Ok(Established { engine: eng, push, server })
}

/// Establish against the configured remotes in order (one pass), answering a
/// CRV1 challenge if the server raises one.
fn establish_any(p: &mut Prepared, prompter: &mut dyn Prompter, start_at: usize) -> Result<(Established, usize), String> {
    let n = p.cfg.remotes.len();
    let mut last_err = String::new();
    for k in 0..n {
        let idx = (start_at + k) % n;
        let remote = p.cfg.remotes[idx].clone();
        let mut creds = p.creds.clone();
        // A CRV1 challenge round re-runs the handshake with the answer as password.
        for _round in 0..3 {
            match establish(p, &remote, creds.clone(), prompter) {
                Ok(e) => return Ok((e, idx)),
                Err(EstablishError::Challenge { state, user, text, echo }) => {
                    out!("# server challenge: {text}");
                    let answer = prompter.ask("code", &text, echo)?;
                    creds = Some(Creds { user, pass: format!("CRV1::{state}::{answer}") });
                }
                Err(EstablishError::AuthFailed(why)) => return Err(format!("AUTH FAILED: {why}")),
                Err(EstablishError::Other(e)) => {
                    if stopped() {
                        return Err(e);
                    }
                    out!("# {}:{} failed: {e}", remote.host, remote.port);
                    last_err = e;
                    break;
                }
            }
        }
    }
    Err(last_err)
}

/// Full client run. Blocks until stopped (or `login_only` finishes).
pub fn run(mut p: Prepared, prompter: &mut dyn Prompter, opts: RunOpts) -> Result<(), String> {
    OV_STOP.store(false, Ordering::SeqCst);
    sysnet::install_stop_signals(&OV_STOP);
    if let Some(u) = &p.cfg.unsupported.first() {
        out!("# note: config option `{u}` is not supported and is ignored");
    }

    let (est, mut remote_idx) = establish_any(&mut p, prompter, 0)?;
    // After the first login, reconnects authenticate with the pushed auth-token
    // (the original password may have been a one-time code).
    adopt_auth_token(&mut p, &est.push);
    print_push(&est.push);

    if opts.login_only {
        out!("# ✅ authenticated — configuration received (--login: not bringing up the tunnel).");
        let mut eng = est.engine;
        say_goodbye(&mut eng);
        return Ok(());
    }

    let Established { mut engine, mut push, server, .. } = est;
    let (ifc_local, ifc_peer) = push.ifconfig.ok_or("server pushed no `ifconfig` address")?;
    let topology = push.topology();
    let mtu = tun_mtu(&p.cfg, &push);
    let compress = push.compress.or(p.cfg.compress).unwrap_or(Compress::None);
    let dns = if p.cfg.route_nopull { Vec::new() } else { push.dns.clone() };
    // This exact "— IP <ip>  DNS [..]" shape is what the GUI's log parser reads.
    out!("# ✅ OpenVPN up — IP {ifc_local}  DNS {:?}  (mtu {mtu})", dns);

    // tun device.
    let (mut tun_file, tun_name) = tun::open_tun(TUN_NAME)?;
    tun::set_nonblocking(&tun_file);
    configure_addr(&tun_name, topology, ifc_local, ifc_peer, true)?;
    tun::ip(&["link", "set", "dev", &tun_name, "up", "mtu", &mtu.to_string()])?;
    out!("# tun {tun_name} up — {}", addr_desc(topology, ifc_local, ifc_peer));

    if stopped() {
        say_goodbye(&mut engine);
        return Err("disconnect requested before the tunnel came up".into());
    }

    let mut restore = sysnet::NetRestore::default();
    if opts.no_routes {
        out!("# --no-routes: NOT installing routes or DNS.");
    } else {
        restore.routes = setup_routes(server, &tun_name, &p.cfg, &push);
        let mut domains = push.domains.clone();
        for o in &p.cfg.dhcp_options {
            let mut tmp = PushConfig::default();
            tmp.dhcp_option(&o.iter().map(String::as_str).collect::<Vec<_>>());
            domains.extend(tmp.domains);
        }
        restore.dns = sysnet::set_dns(&dns, &domains.join(" "));
    }
    if opts.watch_stdin {
        sysnet::spawn_stdin_disconnect(&OV_STOP);
    }

    let ping = push.ping.or(p.cfg.ping).unwrap_or(10).clamp(1, 60);
    let ping_restart = push.ping_restart.or(p.cfg.ping_restart).unwrap_or(120).max(ping * 3);
    let reneg = p.cfg.reneg_sec.filter(|&s| s > 0);
    out!("# liveness: ping {ping}s, ping-restart {ping_restart}s{}", reneg.map(|r| format!(", reneg {r}s")).unwrap_or_default());
    out!("# ✅ TUNNEL UP. (send 'disconnect' on stdin or SIGTERM to stop)");

    let mut fail_streak = 0u32;
    let result: Result<(), String> = 'session: loop {
        let outcome = data_loop(&mut engine, &mut tun_file, compress, ping, ping_restart, reneg);
        if stopped() {
            break 'session Ok(());
        }
        let reason = match outcome {
            Ok(()) => "closed".to_string(),
            Err(e) => e,
        };
        out!("# tunnel dropped ({reason})");
        let explicit_restart = reason.contains("RESTART") || reason.contains("server exiting");
        let mut reconnected = false;
        while fail_streak < MAX_RECONNECT_TRIES {
            if stopped() {
                break 'session Ok(());
            }
            fail_streak += 1;
            let delay = if explicit_restart && fail_streak == 1 { 2 } else { reconnect_delay(fail_streak) };
            out!("# reconnecting in {delay}s (attempt {fail_streak}/{MAX_RECONNECT_TRIES}) …");
            if sleep_interruptible(delay) {
                break 'session Ok(());
            }
            match establish_any(&mut p, prompter, remote_idx) {
                Ok((est, idx)) => {
                    remote_idx = idx;
                    adopt_auth_token(&mut p, &est.push);
                    if let Some((l, r)) = est.push.ifconfig {
                        if (l, r) != (ifc_local, ifc_peer) {
                            out!("# server assigned a new address {l}; re-addressing {tun_name}");
                            let _ = configure_addr(&tun_name, topology, ifc_local, ifc_peer, false);
                            let _ = configure_addr(&tun_name, est.push.topology(), l, r, true);
                        }
                    }
                    engine = est.engine;
                    push = est.push;
                    out!("# ✅ reconnected — tunnel back up (IP {})", push.ifconfig.map(|x| x.0).unwrap_or(ifc_local));
                    reconnected = true;
                    break;
                }
                Err(e) if e.starts_with("AUTH FAILED") => {
                    break 'session Err(format!("{e} (session expired — reconnect with fresh credentials)"));
                }
                Err(e) => out!("# reconnect attempt {fail_streak} failed: {e}"),
            }
        }
        if !reconnected {
            break 'session Err(format!("tunnel dropped ({reason}) and gave up after {MAX_RECONNECT_TRIES} attempts"));
        }
        fail_streak = 0;
    };

    out!("# disconnecting — notifying the server, restoring DNS/routes …");
    say_goodbye(&mut engine);
    drop(restore);
    result
}

/// Tell the server we're leaving: explicit-exit-notify over the data channel
/// (UDP; servers then free the session at once) and `EXIT` on the control channel.
fn say_goodbye(eng: &mut Engine) {
    let mut occ = OCC_MAGIC.to_vec();
    occ.push(OCC_EXIT);
    if !eng.link.is_tcp() {
        for _ in 0..2 {
            let _ = eng.send_data(&occ);
        }
    }
    let _ = eng.send_text("EXIT");
    let _ = eng.pump();
}

fn adopt_auth_token(p: &mut Prepared, push: &PushConfig) {
    if let Some(tok) = &push.auth_token {
        if let Some(c) = p.creds.as_mut() {
            if let Some(u) = &push.auth_token_user {
                c.user = u.clone();
            }
            c.pass = tok.clone();
            out!("# server issued an auth-token — reconnects will use it (no re-prompt)");
        }
    }
}

fn print_push(push: &PushConfig) {
    if let Some((a, b)) = push.ifconfig {
        out!("# pushed: ifconfig {a} {b} (topology {:?})", push.topology());
    }
    out!(
        "# pushed: {} route(s){}, DNS {:?}{}",
        push.routes.len(),
        if push.redirect_gateway { " + redirect-gateway (full tunnel)" } else { "" },
        push.dns,
        if push.domains.is_empty() { String::new() } else { format!(", domains {}", push.domains.join(" ")) }
    );
}

fn tun_mtu(cfg: &Config, push: &PushConfig) -> u16 {
    // Lower than OpenVPN's 1500 to stand in for its default `mssfix`: keeps the
    // encrypted UDP packets under a 1500-byte path MTU without IP fragmentation.
    push.tun_mtu.or(cfg.tun_mtu).unwrap_or(1500).clamp(576, 1400)
}

fn configure_addr(dev: &str, topo: Topology, local: Ipv4Addr, other: Ipv4Addr, add: bool) -> Result<(), String> {
    let verb = if add { "add" } else { "del" };
    match topo {
        Topology::Subnet => tun::ip(&["addr", verb, &format!("{local}/{}", tun::mask_to_prefix(other)), "dev", dev]),
        _ => tun::ip(&["addr", verb, &local.to_string(), "peer", &other.to_string(), "dev", dev]),
    }
}

fn addr_desc(topo: Topology, local: Ipv4Addr, other: Ipv4Addr) -> String {
    match topo {
        Topology::Subnet => format!("{local}/{}", tun::mask_to_prefix(other)),
        _ => format!("{local} peer {other}"),
    }
}

/// Compression framing for an outgoing payload (we never actually compress).
fn frame_out(c: Compress, pkt: &[u8]) -> Vec<u8> {
    match c {
        Compress::None => pkt.to_vec(),
        Compress::Lzo => [&[0xfa][..], pkt].concat(),
        Compress::Stub => {
            if pkt.is_empty() {
                return vec![0xfb];
            }
            let mut v = Vec::with_capacity(pkt.len() + 1);
            v.push(0xfb);
            v.extend_from_slice(&pkt[1..]);
            v.push(pkt[0]);
            v
        }
        Compress::StubV2 => {
            if pkt.first() == Some(&0x50) {
                [&[0x50, 0x00][..], pkt].concat()
            } else {
                pkt.to_vec()
            }
        }
    }
}

/// Undo the compression framing of an incoming payload. `None` = compressed
/// (unsupported) or malformed: drop it.
fn frame_in(c: Compress, pkt: Vec<u8>) -> Option<Vec<u8>> {
    match c {
        Compress::None => Some(pkt),
        Compress::Lzo | Compress::Stub => match pkt.first()? {
            0xfa => Some(pkt[1..].to_vec()),
            0xfb => {
                let mut v = pkt;
                let last = v.pop()?;
                v[0] = last;
                Some(v)
            }
            _ => None,
        },
        Compress::StubV2 => {
            if pkt.first() == Some(&0x50) {
                (pkt.get(1) == Some(&0)).then(|| pkt[2..].to_vec())
            } else {
                Some(pkt)
            }
        }
    }
}

/// Wait until `fd` is readable or `ms` elapse.
fn wait_readable(fd: i32, ms: i32) {
    let mut p = [libc::pollfd { fd, events: libc::POLLIN, revents: 0 }];
    unsafe { libc::poll(p.as_mut_ptr(), 1, ms) };
}

/// The packet pump. Ok on stop; Err → reconnect.
fn data_loop(
    eng: &mut Engine,
    tun_file: &mut std::fs::File,
    compress: Compress,
    ping: u64,
    ping_restart: u64,
    reneg: Option<u64>,
) -> Result<(), String> {
    let tun_fd = tun_file.as_raw_fd();
    let mut buf = [0u8; 2048];
    let mut pkts: Vec<Vec<u8>> = Vec::with_capacity(64);
    let (mut tin, mut tout) = (0u64, 0u64);
    let mut last_tx = Instant::now();
    let mut last_stats = Instant::now();
    let mut key_born = Instant::now();
    eng.last_rx = Instant::now();

    loop {
        if stopped() {
            return Ok(());
        }
        let timeout_ms = eng
            .next_deadline()
            .map(|d| d.saturating_duration_since(Instant::now()).as_millis().clamp(10, 1000) as i32)
            .unwrap_or(1000);
        let mut fds = [
            libc::pollfd { fd: tun_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: eng.link.fd(), events: libc::POLLIN, revents: 0 },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("poll: {e}"));
        }

        // tun → server.
        if fds[0].revents & libc::POLLIN != 0 {
            for _ in 0..64 {
                match tun_file.read(&mut buf) {
                    Ok(0) => return Err("tun closed".into()),
                    Ok(m) if tun::is_ipv4(&buf[..m]) => {
                        if eng.send_data(&frame_out(compress, &buf[..m]))? {
                            tout += 1;
                            last_tx = Instant::now();
                        }
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(format!("tun read: {e}")),
                }
            }
        }

        // server → tun (+ control packets).
        if fds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            pkts.clear();
            let r = eng.link.recv_all(&mut pkts);
            for pk in &pkts {
                if let Some(payload) = eng.handle_packet(pk)? {
                    if payload == PING_MAGIC {
                        continue;
                    }
                    if payload.len() == 17 && payload[..16] == OCC_MAGIC {
                        if payload[16] == OCC_EXIT {
                            return Err("server exiting (explicit-exit-notify)".into());
                        }
                        continue;
                    }
                    if let Some(ip) = frame_in(compress, payload) {
                        if tun::is_ipv4(&ip) && tun_file.write_all(&ip).is_ok() {
                            tin += 1;
                        }
                    }
                }
            }
            r?;
        }

        eng.pump()?;
        while let Some(ev) = eng.events.pop_front() {
            match ev {
                Event::Message(m) => {
                    if m.starts_with("RESTART") || m.starts_with("HALT") || m.starts_with("EXIT") {
                        return Err(format!("server sent {m}"));
                    } else if m.starts_with("AUTH_FAILED") {
                        return Err(format!("server revoked the session ({m})"));
                    } else if m.starts_with("PUSH_REPLY") {
                        // Re-push after renegotiation: nothing to change for us.
                    } else {
                        out!("# server says: {m}");
                    }
                }
                Event::NewKeyActive { key_id } => {
                    key_born = Instant::now();
                    out!("# ✅ data keys renegotiated (key id {key_id})");
                }
                Event::TlsUp { key_id, version, .. } if key_id != 0 => out!("# renegotiation: TLS up ({version})"),
                _ => {}
            }
        }

        // OpenVPN ping: keep the server's ping-restart timer fed.
        if last_tx.elapsed().as_secs() >= ping {
            eng.send_data(&PING_MAGIC)?;
            last_tx = Instant::now();
        }
        if eng.last_rx.elapsed().as_secs() >= ping_restart {
            return Err(format!("nothing from the server for {ping_restart}s (ping-restart)"));
        }
        if let Some(r) = reneg {
            if key_born.elapsed().as_secs() >= r {
                eng.renegotiate()?;
                key_born = Instant::now();
            }
        }
        if !eng.has_data_key() {
            return Err("no usable data key".into());
        }
        if last_stats.elapsed().as_secs() >= 10 {
            out!("#  stats: tun_in={tin} tun_out={tout} decrypt_err={}", eng.stats_decrypt_errors);
            last_stats = Instant::now();
        }
    }
}

fn reconnect_delay(attempt: u32) -> u64 {
    match attempt {
        1 => 1,
        2 => 2,
        3 => 5,
        _ => 10,
    }
}

fn sleep_interruptible(secs: u64) -> bool {
    for _ in 0..(secs * 10) {
        if stopped() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    stopped()
}

/// Pin the server to its pre-VPN path, keep `net_gateway` routes outside the
/// tunnel, then install the tunnel routes — one `ip -batch`. Returns the
/// `route del` lines for teardown (minus routes that already existed).
fn setup_routes(server: Ipv4Addr, tun: &str, cfg: &Config, push: &PushConfig) -> Vec<String> {
    let mut add: Vec<String> = Vec::new();
    let mut del: Vec<String> = Vec::new();
    fn pair(add: &mut Vec<String>, del: &mut Vec<String>, net: String, suffix: &str) {
        add.push(format!("route add {net} {suffix}"));
        del.push(format!("route del {net} {suffix}"));
    }
    let via = |dst: Ipv4Addr| {
        original_path(dst).map(|(via, dev)| via.map(|v| format!("via {v} dev {dev}")).unwrap_or_else(|| format!("dev {dev}")))
    };

    let mut routes: Vec<push::Route> = if cfg.route_nopull { Vec::new() } else { push.routes.clone() };
    for r in &cfg.routes {
        if let Some(rt) = push::parse_route(&r.iter().map(String::as_str).collect::<Vec<_>>()) {
            routes.push(rt);
        }
    }
    let full = cfg.redirect_gateway || (!cfg.route_nopull && push.redirect_gateway);

    let mut pin: Option<(usize, String)> = None;
    if let Some(s) = via(server) {
        pin = Some((add.len(), format!("{server}/32 ({s})")));
        pair(&mut add, &mut del, format!("{server}/32"), &s);
    }
    for r in routes.iter().filter(|r| r.bypass) {
        if let Some(s) = via(r.net) {
            pair(&mut add, &mut del, r.to_cidr(), &s);
        }
    }
    let dev = format!("dev {tun}");
    if full {
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            pair(&mut add, &mut del, net.to_string(), &dev);
        }
        out!("# full tunnel: 0.0.0.0/1 + 128.0.0.0/1 via {tun}");
    }
    let split: Vec<_> = routes.iter().filter(|r| !r.bypass).collect();
    for r in &split {
        pair(&mut add, &mut del, r.to_cidr(), &dev);
    }
    if !split.is_empty() {
        out!("# split tunnel: {} route(s) via {tun}", split.len());
    }
    if !full && split.is_empty() {
        out!("# note: server pushed no routes — only the tunnel subnet is reachable");
    }

    let failed = tun::ip_batch_failed(&add).unwrap_or_default();
    if let Some((i, what)) = pin {
        if failed.contains(&i) {
            out!("# server route {what} already present — left as is");
        } else {
            out!("# pinned server route {what}");
        }
    }
    if !failed.is_empty() {
        out!("# {} route(s) already existed — not ours, kept on disconnect", failed.len());
    }
    del.into_iter().enumerate().filter(|(i, _)| !failed.contains(i)).map(|(_, d)| d).collect()
}

/// Parse `ip route get <ip>` for the current `via`/`dev` of a destination.
fn original_path(dst: Ipv4Addr) -> Option<(Option<String>, String)> {
    let out = std::process::Command::new("ip").args(["route", "get", &dst.to_string()]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let toks: Vec<&str> = text.lines().next().unwrap_or("").split_whitespace().collect();
    let via = toks.windows(2).find(|w| w[0] == "via").map(|w| w[1].to_string());
    let dev = toks.windows(2).find(|w| w[0] == "dev").map(|w| w[1].to_string())?;
    Some((via, dev))
}

/// `--probe`: reset + TLS handshake only, no credentials. Reports the server cert,
/// the TLS parameters and whether the control-channel wrap key is right.
pub fn probe(p: &Prepared) -> Result<(), String> {
    for remote in &p.cfg.remotes {
        out!("# probing {}:{} ({}) …", remote.host, remote.port, remote.proto.as_str());
        let r = (|| -> Result<(), String> {
            let (link, server) = Link::open(remote, Duration::from_secs(10))?;
            let mut eng = Engine::new(link, p.make_wrap()?, p.ctx.clone(), p.peer.clone(), None, p.options_string(remote), p.peer_info())?;
            eng.probe_only = true;
            out!("#   {server} — wrap {}", eng.wrap_name());
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut pkts = Vec::new();
            let mut got_reset = false;
            while Instant::now() < deadline {
                eng.pump()?;
                wait_readable(eng.link.fd(), 200);
                pkts.clear();
                eng.link.recv_all(&mut pkts)?;
                for pk in &pkts {
                    eng.handle_packet(pk)?;
                    if !got_reset {
                        got_reset = true;
                        out!("#   server answered the reset — control channel OK");
                    }
                }
                eng.pump()?;
                while let Some(ev) = eng.events.pop_front() {
                    if let Event::TlsUp { version, cipher, .. } = ev {
                        let pi = p.peer.lock().unwrap().clone();
                        out!("#   ✅ TLS up: {version} {cipher}");
                        out!("#   server cert: {}", pi.subject);
                        out!("#   issuer:      {}", pi.issuer);
                        return Ok(());
                    }
                }
            }
            Err(if got_reset { "TLS handshake did not complete".into() } else { "no answer (wrong port/proto, or tls-auth/tls-crypt key mismatch)".into() })
        })();
        if let Err(e) = r {
            out!("#   ✗ {e}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_framing_roundtrips() {
        let pkt = vec![0x45, 1, 2, 3, 0x50];
        for c in [Compress::None, Compress::Lzo, Compress::Stub, Compress::StubV2] {
            assert_eq!(frame_in(c, frame_out(c, &pkt)).as_deref(), Some(&pkt[..]), "{c:?}");
        }
        assert_eq!(frame_out(Compress::Stub, &pkt), vec![0xfb, 1, 2, 3, 0x50, 0x45]);
        let v2 = vec![0x50, 9];
        assert_eq!(frame_out(Compress::StubV2, &v2), vec![0x50, 0, 0x50, 9]);
        assert_eq!(frame_in(Compress::Lzo, vec![0x66, 1, 2]), None); // LZO-compressed: dropped
    }

    #[test]
    fn auth_failed_crv1() {
        let user = openssl::base64::encode_block(b"alice");
        match parse_auth_failed(&format!("CRV1:R,E:abc123:{user}:Enter OTP")) {
            EstablishError::Challenge { state, user, text, echo } => {
                assert_eq!((state.as_str(), user.as_str(), text.as_str(), echo), ("abc123", "alice", "Enter OTP", true));
            }
            _ => panic!("expected challenge"),
        }
        assert!(matches!(parse_auth_failed(""), EstablishError::AuthFailed(_)));
    }

    #[test]
    fn magic_lengths() {
        assert_eq!(PING_MAGIC.len(), 16);
        assert_eq!(OCC_MAGIC.len(), 16);
    }
}
