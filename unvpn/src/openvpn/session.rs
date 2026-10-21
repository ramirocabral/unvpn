//! The OpenVPN control-channel engine: session ids, per-key reliability, TLS
//! over P_CONTROL_V1, the key-method-2 exchange, data-channel key derivation,
//! and renegotiation (SOFT_RESET → new key_id, old key kept as "lame duck").
//!
//! It is transport-driven: the caller feeds every received packet to
//! [`Engine::handle_packet`] and calls [`Engine::pump`] after each poll wakeup;
//! things the caller must react to (TLS up, key exchanged, control messages like
//! `PUSH_REPLY`/`AUTH_FAILED`) come out of [`Engine::events`].

use super::crypto::{self, DataCrypto, Key2, Wrap};
use super::link::Link;
use super::packet::*;
use super::tls::{MemPipe, PeerInfo};
use openssl::ssl::{ErrorCode, Ssl, SslContext, SslStream};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Max TLS bytes per P_CONTROL_V1 (keeps control packets under ~1250 bytes).
const CONTROL_CHUNK: usize = 1100;
/// `hand-window`: a key negotiation must finish within this.
const HAND_WINDOW: Duration = Duration::from_secs(60);
/// `transition-window`: how long a retired key still decrypts.
const TRANSITION_WINDOW: Duration = Duration::from_secs(60);
const EKM_LABEL: &str = "EXPORTER-OpenVPN-datakeys";

/// Negotiated data-channel parameters (known after the first PUSH_REPLY).
#[derive(Clone, Debug)]
pub struct DataParams {
    pub cipher: String,
    pub auth: String,
    /// Keys from the TLS exporter (RFC 5705) instead of the TLS1.0-PRF expansion.
    pub ekm: bool,
}

#[derive(Debug)]
pub enum Event {
    TlsUp { key_id: u8, version: String, cipher: String },
    /// The server's key-method-2 message arrived (key negotiation complete).
    KeyExchanged { key_id: u8 },
    /// A NUL-terminated text message on the control channel.
    Message(String),
    /// A renegotiated key now carries outgoing data.
    NewKeyActive { key_id: u8 },
}

#[derive(Clone)]
pub struct Creds {
    pub user: String,
    pub pass: String,
}

struct KeySource {
    pre_master: [u8; 48],
    r1: [u8; 32],
    r2: [u8; 32],
}

struct KeyState {
    key_id: u8,
    rel: Reliable,
    tls: Option<SslStream<MemPipe>>,
    /// Peer's reset (HARD_RESET_SERVER or SOFT_RESET) delivered.
    peer_reset: bool,
    hs_done: bool,
    sent_key: bool,
    got_key: bool,
    local: KeySource,
    remote_r1: [u8; 32],
    remote_r2: [u8; 32],
    /// Undelimited text from the server after its key message.
    text: Vec<u8>,
    data: Option<DataCrypto>,
    born: Instant,
    /// Lame duck: drop after this.
    expire: Option<Instant>,
}

impl KeyState {
    fn new(key_id: u8, initial_op: u8, tcp: bool) -> Result<KeyState, String> {
        let mut local = KeySource { pre_master: [0; 48], r1: [0; 32], r2: [0; 32] };
        openssl::rand::rand_bytes(&mut local.pre_master).map_err(|e| e.to_string())?;
        openssl::rand::rand_bytes(&mut local.r1).map_err(|e| e.to_string())?;
        openssl::rand::rand_bytes(&mut local.r2).map_err(|e| e.to_string())?;
        let mut rel = Reliable::default();
        rel.no_retransmit = tcp;
        rel.queue(initial_op, Vec::new()); // our reset is always message id 0
        Ok(KeyState {
            key_id,
            rel,
            tls: None,
            peer_reset: false,
            hs_done: false,
            sent_key: false,
            got_key: false,
            local,
            remote_r1: [0; 32],
            remote_r2: [0; 32],
            text: Vec::new(),
            data: None,
            born: Instant::now(),
            expire: None,
        })
    }
}

pub struct Engine {
    pub link: Link,
    wrap: Wrap,
    local_sid: [u8; 8],
    remote_sid: Option<[u8; 8]>,
    ctx: SslContext,
    keys: Vec<KeyState>,
    last_key_id: u8,
    pub creds: Option<Creds>,
    options_string: String,
    peer_info: String,
    pub params: Option<DataParams>,
    pub peer_id: Option<u32>,
    pub events: VecDeque<Event>,
    pub peer: Arc<Mutex<PeerInfo>>,
    /// Last authenticated packet from the server (liveness).
    pub last_rx: Instant,
    pub stats_decrypt_errors: u64,
    /// `--probe`: stop after the TLS handshake (never send credentials/key material).
    pub probe_only: bool,
}

impl Engine {
    pub fn new(
        link: Link,
        wrap: Wrap,
        ctx: SslContext,
        peer: Arc<Mutex<PeerInfo>>,
        creds: Option<Creds>,
        options_string: String,
        peer_info: String,
    ) -> Result<Engine, String> {
        let mut local_sid = [0u8; 8];
        openssl::rand::rand_bytes(&mut local_sid).map_err(|e| e.to_string())?;
        let tcp = link.is_tcp();
        let k0 = KeyState::new(0, P_CONTROL_HARD_RESET_CLIENT_V2, tcp)?;
        Ok(Engine {
            link,
            wrap,
            local_sid,
            remote_sid: None,
            ctx,
            keys: vec![k0],
            last_key_id: 0,
            creds,
            options_string,
            peer_info,
            params: None,
            peer_id: None,
            events: VecDeque::new(),
            peer,
            last_rx: Instant::now(),
            stats_decrypt_errors: 0,
            probe_only: false,
        })
    }

    pub fn wrap_name(&self) -> &'static str {
        self.wrap.name()
    }

    /// Returns the decrypted payload of a data packet.
    pub fn handle_packet(&mut self, pkt: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let Some(&first) = pkt.first() else { return Ok(None) };
        let (op, kid) = (opcode(first), key_id(first));
        if is_data(op) {
            let hdr_len = if op == P_DATA_V2 { 4 } else { 1 };
            let Some(ks) = self.keys.iter_mut().find(|k| k.key_id == kid && k.data.is_some()) else {
                return Ok(None); // data for a key we don't (yet/anymore) have
            };
            return match ks.data.as_mut().unwrap().decrypt(pkt, hdr_len, op == P_DATA_V2) {
                Ok(p) => {
                    self.last_rx = Instant::now();
                    Ok(Some(p))
                }
                Err(_) => {
                    self.stats_decrypt_errors += 1;
                    Ok(None)
                }
            };
        }

        let (op_b, sid, rest) = match self.wrap.unwrap(pkt) {
            Ok(v) => v,
            Err(e) => {
                // Before the server has answered at all, an auth failure is a config
                // problem worth surfacing; later it's just a stray packet.
                if self.remote_sid.is_none() {
                    return Err(e);
                }
                return Ok(None);
            }
        };
        let op = opcode(op_b);
        let c = decode_rest(op, &rest)?;
        match self.remote_sid {
            None if op == P_CONTROL_HARD_RESET_SERVER_V2 => self.remote_sid = Some(sid),
            Some(r) if r == sid => {}
            _ => return Ok(None), // not our server session
        }
        if c.remote_sid.is_some_and(|r| r != self.local_sid) {
            return Ok(None); // ACKs addressed to another session
        }
        self.last_rx = Instant::now();

        // A SOFT_RESET for a key we don't have = server-initiated renegotiation.
        if op == P_CONTROL_SOFT_RESET_V1 && !self.keys.iter().any(|k| k.key_id == kid) {
            out!("# server renegotiating — new key id {kid}");
            let ks = KeyState::new(kid, P_CONTROL_SOFT_RESET_V1, self.link.is_tcp())?;
            self.last_key_id = kid;
            self.keys.insert(0, ks);
        }
        let Some(ks) = self.keys.iter_mut().find(|k| k.key_id == kid) else { return Ok(None) };
        ks.rel.acked(&c.acks);
        if let Some(id) = c.msg_id {
            for (mop, payload) in ks.rel.receive(id, op, c.payload) {
                match mop {
                    P_CONTROL_HARD_RESET_SERVER_V2 | P_CONTROL_SOFT_RESET_V1 => ks.peer_reset = true,
                    P_CONTROL_V1 => {
                        if let Some(t) = ks.tls.as_mut() {
                            t.get_mut().rx.extend_from_slice(&payload);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(None)
    }

    pub fn pump(&mut self) -> Result<(), String> {
        let now = Instant::now();
        // Retire expired lame ducks and stalled renegotiations.
        let before = self.keys.len();
        self.keys.retain(|k| {
            k.expire.map_or(true, |t| now < t) && (k.data.is_some() || k.key_id == 0 || now.duration_since(k.born) < HAND_WINDOW)
        });
        if self.keys.len() < before {
            out!("# retired {} old/stalled key(s)", before - self.keys.len());
        }

        for i in 0..self.keys.len() {
            self.drive_key(i)?;
        }
        self.flush(now)
    }

    fn drive_key(&mut self, i: usize) -> Result<(), String> {
        let ctx = self.ctx.clone();
        let ks = &mut self.keys[i];
        // TLS starts once the peer's reset arrived and ours was acknowledged.
        if ks.tls.is_none() && ks.peer_reset && !ks.rel.pending(0) {
            let mut ssl = Ssl::new(&ctx).map_err(|e| e.to_string())?;
            ssl.set_connect_state();
            ks.tls = Some(SslStream::new(ssl, MemPipe::default()).map_err(|e| e.to_string())?);
        }
        let Some(tls) = ks.tls.as_mut() else { return Ok(()) };

        if !ks.hs_done {
            match tls.do_handshake() {
                Ok(()) => {
                    ks.hs_done = true;
                    let s = tls.ssl();
                    self.events.push_back(Event::TlsUp {
                        key_id: ks.key_id,
                        version: s.version_str().to_string(),
                        cipher: s.current_cipher().map(|c| c.name().to_string()).unwrap_or_default(),
                    });
                }
                Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {}
                Err(e) => {
                    let why = self.peer.lock().unwrap().error.clone().unwrap_or_else(|| e.to_string());
                    return Err(format!("TLS handshake failed: {why}"));
                }
            }
        }

        if ks.hs_done && !ks.sent_key && !self.probe_only {
            let msg = key_method_2(&ks.local, &self.options_string, self.creds.as_ref(), &self.peer_info);
            tls.ssl_write(&msg).map_err(|e| format!("TLS write: {e}"))?;
            ks.sent_key = true;
        }

        if ks.hs_done {
            let mut buf = vec![0u8; 17 * 1024];
            loop {
                match tls.ssl_read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if !ks.got_key {
                            let (r1, r2) = parse_key_method_2(&buf[..n])?;
                            ks.remote_r1 = r1;
                            ks.remote_r2 = r2;
                            ks.got_key = true;
                            self.events.push_back(Event::KeyExchanged { key_id: ks.key_id });
                        } else {
                            ks.text.extend_from_slice(&buf[..n]);
                        }
                    }
                    Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => break,
                    Err(e) if e.code() == ErrorCode::ZERO_RETURN => return Err("server closed the TLS session".into()),
                    Err(e) => return Err(format!("TLS read: {e}")),
                }
            }
            while let Some(z) = ks.text.iter().position(|&b| b == 0) {
                let m: Vec<u8> = ks.text.drain(..=z).collect();
                let s = String::from_utf8_lossy(&m[..m.len() - 1]).trim().to_string();
                if !s.is_empty() {
                    self.events.push_back(Event::Message(s));
                }
            }
        }

        // Renegotiated keys derive their data keys as soon as the exchange completes.
        if ks.got_key && ks.data.is_none() && ks.key_id != 0 {
            if let Some(p) = self.params.clone() {
                let kid = ks.key_id;
                self.install_keys_at(i, &p)?;
                self.activate(kid);
            }
        }

        let ks = &mut self.keys[i];
        if let Some(tls) = ks.tls.as_mut() {
            let tx = std::mem::take(&mut tls.get_mut().tx);
            for chunk in tx.chunks(CONTROL_CHUNK) {
                ks.rel.queue(P_CONTROL_V1, chunk.to_vec());
            }
        }
        Ok(())
    }

    fn flush(&mut self, now: Instant) -> Result<(), String> {
        let remote = self.remote_sid.unwrap_or([0; 8]);
        let mut out_pkts = Vec::new();
        for ks in &mut self.keys {
            for (id, op, payload) in ks.rel.due(now) {
                let acks = if self.remote_sid.is_some() { ks.rel.take_acks() } else { Vec::new() };
                let rest = encode_rest(&acks, &remote, Some(id), &payload);
                out_pkts.push(self.wrap.wrap(op_byte(op, ks.key_id), &self.local_sid, &rest));
            }
            while !ks.rel.to_ack.is_empty() && self.remote_sid.is_some() {
                let acks = ks.rel.take_acks();
                let rest = encode_rest(&acks, &remote, None, &[]);
                out_pkts.push(self.wrap.wrap(op_byte(P_ACK_V1, ks.key_id), &self.local_sid, &rest));
            }
        }
        for p in out_pkts {
            self.link.send(&p)?;
        }
        Ok(())
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.keys.iter().filter_map(|k| k.rel.next_deadline()).min()
    }

    /// Derive and install the data keys of the initial key (key_id 0) once the
    /// PUSH_REPLY fixed the cipher/key-derivation. Later keys do this by themselves.
    pub fn install_initial_keys(&mut self, params: DataParams) -> Result<(), String> {
        self.params = Some(params.clone());
        let i = self.keys.iter().position(|k| k.key_id == 0 && k.got_key).ok_or("initial key exchange not complete")?;
        self.install_keys_at(i, &params)
    }

    fn install_keys_at(&mut self, i: usize, p: &DataParams) -> Result<(), String> {
        let remote_sid = self.remote_sid.ok_or("no server session id")?;
        let ks = &mut self.keys[i];
        let material = if p.ekm {
            let tls = ks.tls.as_ref().ok_or("no TLS session")?;
            let mut out = vec![0u8; 256];
            tls.ssl().export_keying_material(&mut out, EKM_LABEL, None).map_err(|e| format!("TLS EKM: {e}"))?;
            out
        } else {
            crypto::openvpn_prf_keys(
                &ks.local.pre_master,
                &ks.local.r1,
                &ks.remote_r1,
                &ks.local.r2,
                &ks.remote_r2,
                &self.local_sid,
                &remote_sid,
            )
        };
        let key2 = Key2::from_bytes(&material)?;
        ks.data = Some(DataCrypto::new(&key2, &p.cipher, &p.auth)?);
        Ok(())
    }

    /// Make `kid` the outgoing key; the previous one becomes a lame duck.
    fn activate(&mut self, kid: u8) {
        let now = Instant::now();
        for k in &mut self.keys {
            if k.key_id != kid && k.data.is_some() && k.expire.is_none() {
                k.expire = Some(now + TRANSITION_WINDOW);
            }
        }
        if let Some(pos) = self.keys.iter().position(|k| k.key_id == kid) {
            let k = self.keys.remove(pos);
            self.keys.insert(0, k);
        }
        self.events.push_back(Event::NewKeyActive { key_id: kid });
    }

    /// Client-initiated renegotiation (`reneg-sec`).
    pub fn renegotiate(&mut self) -> Result<(), String> {
        if self.keys.iter().any(|k| k.data.is_none()) {
            return Ok(()); // one already in progress
        }
        let kid = if self.last_key_id >= 7 { 1 } else { self.last_key_id + 1 };
        self.last_key_id = kid;
        out!("# renegotiating data keys (key id {kid}) …");
        let ks = KeyState::new(kid, P_CONTROL_SOFT_RESET_V1, self.link.is_tcp())?;
        self.keys.insert(0, ks);
        Ok(())
    }

    pub fn has_data_key(&self) -> bool {
        self.keys.iter().any(|k| k.data.is_some() && k.expire.is_none())
    }

    pub fn encrypt(&mut self, payload: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let peer_id = self.peer_id;
        let Some(ks) = self.keys.iter_mut().find(|k| k.data.is_some() && k.expire.is_none()) else { return Ok(None) };
        let kid = ks.key_id;
        let d = ks.data.as_mut().unwrap();
        match peer_id {
            Some(pid) => {
                let hdr = [op_byte(P_DATA_V2, kid), (pid >> 16) as u8, (pid >> 8) as u8, pid as u8];
                d.encrypt(&hdr, true, payload).map(Some)
            }
            None => d.encrypt(&[op_byte(P_DATA_V1, kid)], false, payload).map(Some),
        }
    }

    pub fn send_data(&mut self, payload: &[u8]) -> Result<bool, String> {
        match self.encrypt(payload)? {
            Some(p) => {
                self.link.send(&p)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Send a NUL-terminated text message (`PUSH_REQUEST`, `EXIT`, …) over the
    /// newest key whose TLS session is up.
    pub fn send_text(&mut self, msg: &str) -> Result<(), String> {
        let ks = self.keys.iter_mut().find(|k| k.got_key).ok_or("control channel not ready")?;
        let tls = ks.tls.as_mut().ok_or("control channel not ready")?;
        let mut b = msg.as_bytes().to_vec();
        b.push(0);
        tls.ssl_write(&b).map_err(|e| format!("TLS write: {e}"))?;
        let tx = std::mem::take(&mut tls.get_mut().tx);
        for chunk in tx.chunks(CONTROL_CHUNK) {
            ks.rel.queue(P_CONTROL_V1, chunk.to_vec());
        }
        self.flush(Instant::now())
    }
}

/// Our key-method-2 message: 4 zero bytes, method 2, pre_master + 2 randoms, the
/// options string, username + password (or two empty strings), peer-info.
fn key_method_2(k: &KeySource, options: &str, creds: Option<&Creds>, peer_info: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(512);
    b.extend_from_slice(&[0, 0, 0, 0, 2]);
    b.extend_from_slice(&k.pre_master);
    b.extend_from_slice(&k.r1);
    b.extend_from_slice(&k.r2);
    write_string(&mut b, options);
    match creds {
        Some(c) => {
            write_string(&mut b, &c.user);
            write_string(&mut b, &c.pass);
        }
        None => b.extend_from_slice(&[0, 0, 0, 0]),
    }
    write_string(&mut b, peer_info);
    b
}

fn write_string(b: &mut Vec<u8>, s: &str) {
    b.extend_from_slice(&((s.len() + 1) as u16).to_be_bytes());
    b.extend_from_slice(s.as_bytes());
    b.push(0);
}

/// Returns the server's (random1, random2).
fn parse_key_method_2(m: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    if m.len() < 4 + 1 + 64 {
        return Err(format!("short key-method message ({} bytes)", m.len()));
    }
    if m[..4] != [0, 0, 0, 0] {
        return Err("unexpected data before the key-method message".into());
    }
    if m[4] & 0x0f != 2 {
        return Err(format!("unsupported key method {}", m[4]));
    }
    let mut r1 = [0u8; 32];
    let mut r2 = [0u8; 32];
    r1.copy_from_slice(&m[5..37]);
    r2.copy_from_slice(&m[37..69]);
    Ok((r1, r2))
}

#[cfg(test)]
fn read_options(m: &[u8]) -> Option<String> {
    let l = u16::from_be_bytes([*m.get(69)?, *m.get(70)?]) as usize;
    let s = m.get(71..71 + l)?;
    Some(String::from_utf8_lossy(s).trim_end_matches('\0').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_method_layout() {
        let k = KeySource { pre_master: [1; 48], r1: [2; 32], r2: [3; 32] };
        let m = key_method_2(&k, "V4,dev-type tun", Some(&Creds { user: "u".into(), pass: "p".into() }), "IV_VER=x\n");
        assert_eq!(&m[..5], &[0, 0, 0, 0, 2]);
        assert_eq!(m[5], 1);
        assert_eq!(m[5 + 48], 2);
        assert_eq!(m[5 + 48 + 32], 3);
        let o = 5 + 48 + 64;
        assert_eq!(u16::from_be_bytes([m[o], m[o + 1]]), 16); // "V4,dev-type tun" + NUL
        assert_eq!(&m[o + 2..o + 17], b"V4,dev-type tun");
        assert_eq!(m[o + 17], 0);
        assert_eq!(&m[o + 18..o + 22], &[0, 2, b'u', 0]);
    }

    #[test]
    fn server_key_message() {
        // Server side carries no pre_master: zeros | 2 | r1 | r2 | options | 3 empty strings.
        let mut m = vec![0, 0, 0, 0, 2];
        m.extend_from_slice(&[0xaa; 32]);
        m.extend_from_slice(&[0xbb; 32]);
        write_string(&mut m, "V4,dev-type tun,tls-server");
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        let (r1, r2) = parse_key_method_2(&m).unwrap();
        assert_eq!((r1[0], r2[31]), (0xaa, 0xbb));
        assert_eq!(read_options(&m).as_deref(), Some("V4,dev-type tun,tls-server"));
        assert!(parse_key_method_2(&m[..40]).is_err());
    }
}
