//! OpenVPN cryptography: static keys, the TLS 1.0 PRF key expansion, control-
//! channel wrapping (`tls-auth` HMAC / `tls-crypt` SIV-style AES-CTR+HMAC) and
//! the data-channel ciphers (AEAD: AES-GCM / ChaCha20-Poly1305; legacy CBC+HMAC).
//!
//! Wire layouts (OpenVPN 2.6):
//!
//! ```text
//! tls-auth   op|sid|HMAC|pid(4)|time(4)|rest        HMAC over pid|time|op|sid|rest
//! tls-crypt  op|sid|pid(4)|time(4)|TAG(32)|E(rest)  TAG = HMAC-SHA256(op..time|rest),
//!                                                   E = AES-256-CTR, IV = TAG[0..16]
//! AEAD data  hdr|pid(4)|TAG(16)|E(payload)          nonce = pid | implicit_iv(8),
//!                                                   AAD = hdr (V2 only) | pid
//! CBC data   hdr|HMAC|IV(16)|E(pid|payload)         HMAC over IV|ciphertext
//! ```

use openssl::cipher::{Cipher, CipherRef};
use openssl::cipher_ctx::CipherCtx;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;

/// One direction of an OpenVPN `struct key`: 64 bytes cipher key + 64 bytes HMAC key.
#[derive(Clone)]
pub struct Key {
    pub cipher: [u8; 64],
    pub hmac: [u8; 64],
}

impl Key {
    fn from_slice(b: &[u8]) -> Key {
        let mut k = Key { cipher: [0; 64], hmac: [0; 64] };
        k.cipher.copy_from_slice(&b[..64]);
        k.hmac.copy_from_slice(&b[64..128]);
        k
    }
}

/// `struct key2`: two keys (256 bytes), from a static key file or the key expansion.
#[derive(Clone)]
pub struct Key2 {
    pub keys: [Key; 2],
}

impl Key2 {
    pub fn from_bytes(b: &[u8]) -> Result<Key2, String> {
        if b.len() < 256 {
            return Err(format!("key material too short ({} bytes, need 256)", b.len()));
        }
        Ok(Key2 { keys: [Key::from_slice(&b[..128]), Key::from_slice(&b[128..256])] })
    }

    /// Parse an `OpenVPN Static key V1` PEM-ish block (hex lines between markers).
    pub fn from_static_pem(text: &str) -> Result<Key2, String> {
        let begin = "-----BEGIN OpenVPN Static key V1-----";
        let end = "-----END OpenVPN Static key V1-----";
        let start = text.find(begin).ok_or("not an OpenVPN static key (no BEGIN marker)")? + begin.len();
        let stop = text[start..].find(end).ok_or("static key: no END marker")? + start;
        let hex: String = text[start..stop].chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let bytes = hex_decode(&hex)?;
        if bytes.len() != 256 {
            return Err(format!("static key is {} bytes, expected 256", bytes.len()));
        }
        Key2::from_bytes(&bytes)
    }

    /// Pick (out, in) keys for a key-direction: None = bidirectional (key 0 both
    /// ways), Some(0) = normal (out 0 / in 1), Some(1) = inverse (out 1 / in 0).
    pub fn directional(&self, dir: Option<u8>) -> (Key, Key) {
        match dir {
            None => (self.keys[0].clone(), self.keys[0].clone()),
            Some(0) => (self.keys[0].clone(), self.keys[1].clone()),
            Some(_) => (self.keys[1].clone(), self.keys[0].clone()),
        }
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}

pub fn digest(name: &str) -> Result<MessageDigest, String> {
    Ok(match name.to_ascii_uppercase().as_str() {
        "SHA1" | "SHA-1" => MessageDigest::sha1(),
        "SHA224" | "SHA-224" => MessageDigest::sha224(),
        "SHA256" | "SHA-256" => MessageDigest::sha256(),
        "SHA384" | "SHA-384" => MessageDigest::sha384(),
        "SHA512" | "SHA-512" => MessageDigest::sha512(),
        "MD5" => MessageDigest::md5(),
        other => return Err(format!("unsupported auth digest {other}")),
    })
}

fn hmac_with(md: MessageDigest, pkey: &PKey<Private>, parts: &[&[u8]]) -> Vec<u8> {
    let mut s = Signer::new(md, pkey).expect("hmac signer");
    for p in parts {
        s.update(p).expect("hmac update");
    }
    s.sign_to_vec().expect("hmac final")
}

/// TLS 1.0 PRF (RFC 2246 §5): P_MD5(S1, seed) XOR P_SHA1(S2, seed). OpenVPN's
/// pre-2.6 key expansion; still what a server without `key-derivation tls-ekm` uses.
pub fn tls1_prf(secret: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let half = secret.len().div_ceil(2);
    let s1 = &secret[..half];
    let s2 = &secret[secret.len() - half..];
    let a = p_hash(MessageDigest::md5(), s1, seed, out_len);
    let b = p_hash(MessageDigest::sha1(), s2, seed, out_len);
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn p_hash(md: MessageDigest, secret: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let key = PKey::hmac(secret).expect("prf key");
    let mut out = Vec::with_capacity(out_len + 64);
    let mut a = hmac_with(md, &key, &[seed]);
    while out.len() < out_len {
        out.extend_from_slice(&hmac_with(md, &key, &[&a, seed]));
        a = hmac_with(md, &key, &[&a]);
    }
    out.truncate(out_len);
    out
}

/// OpenVPN's PRF-based data-channel key expansion (`generate_key_expansion_openvpn_prf`).
pub fn openvpn_prf_keys(
    pre_master: &[u8; 48],
    client_r1: &[u8; 32],
    server_r1: &[u8; 32],
    client_r2: &[u8; 32],
    server_r2: &[u8; 32],
    client_sid: &[u8; 8],
    server_sid: &[u8; 8],
) -> Vec<u8> {
    let mut seed = b"OpenVPN master secret".to_vec();
    seed.extend_from_slice(client_r1);
    seed.extend_from_slice(server_r1);
    let master = tls1_prf(pre_master, &seed, 48);
    let mut seed = b"OpenVPN key expansion".to_vec();
    seed.extend_from_slice(client_r2);
    seed.extend_from_slice(server_r2);
    seed.extend_from_slice(client_sid);
    seed.extend_from_slice(server_sid);
    tls1_prf(&master, &seed, 256)
}

pub enum Wrap {
    None,
    Auth { md: MessageDigest, out: PKey<Private>, inp: PKey<Private>, hlen: usize, pid: u32, time: u32 },
    Crypt { out_cipher: [u8; 32], out_hmac: PKey<Private>, in_cipher: [u8; 32], in_hmac: PKey<Private>, pid: u32, time: u32 },
}

const TLS_CRYPT_TAG: usize = 32;

impl Wrap {
    /// `tls-auth`: HMAC keys are the first digest-size bytes of each key's hmac half.
    pub fn tls_auth(key: &Key2, dir: Option<u8>, auth: &str) -> Result<Wrap, String> {
        let md = digest(auth)?;
        let hlen = md.size();
        let (o, i) = key.directional(dir);
        Ok(Wrap::Auth {
            md,
            out: PKey::hmac(&o.hmac[..hlen]).map_err(|e| e.to_string())?,
            inp: PKey::hmac(&i.hmac[..hlen]).map_err(|e| e.to_string())?,
            hlen,
            pid: 0,
            time: now_secs(),
        })
    }

    /// `tls-crypt`: the client always uses the inverse direction (out = key 1).
    pub fn tls_crypt(key: &Key2) -> Result<Wrap, String> {
        let (o, i) = key.directional(Some(1));
        let mut oc = [0u8; 32];
        oc.copy_from_slice(&o.cipher[..32]);
        let mut ic = [0u8; 32];
        ic.copy_from_slice(&i.cipher[..32]);
        Ok(Wrap::Crypt {
            out_cipher: oc,
            out_hmac: PKey::hmac(&o.hmac[..32]).map_err(|e| e.to_string())?,
            in_cipher: ic,
            in_hmac: PKey::hmac(&i.hmac[..32]).map_err(|e| e.to_string())?,
            pid: 0,
            time: now_secs(),
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Wrap::None => "none",
            Wrap::Auth { .. } => "tls-auth",
            Wrap::Crypt { .. } => "tls-crypt",
        }
    }

    /// `rest` = everything after op|sid (acks, msg id, payload).
    pub fn wrap(&mut self, op: u8, sid: &[u8; 8], rest: &[u8]) -> Vec<u8> {
        match self {
            Wrap::None => {
                let mut v = Vec::with_capacity(9 + rest.len());
                v.push(op);
                v.extend_from_slice(sid);
                v.extend_from_slice(rest);
                v
            }
            Wrap::Auth { md, out, hlen, pid, time, .. } => {
                *pid += 1;
                let pt = [pid.to_be_bytes(), time.to_be_bytes()].concat();
                let mac = hmac_with(*md, out, &[&pt, &[op], sid, rest]);
                let mut v = Vec::with_capacity(9 + *hlen + 8 + rest.len());
                v.push(op);
                v.extend_from_slice(sid);
                v.extend_from_slice(&mac);
                v.extend_from_slice(&pt);
                v.extend_from_slice(rest);
                v
            }
            Wrap::Crypt { out_cipher, out_hmac, pid, time, .. } => {
                *pid += 1;
                let mut v = Vec::with_capacity(17 + TLS_CRYPT_TAG + rest.len());
                v.push(op);
                v.extend_from_slice(sid);
                v.extend_from_slice(&pid.to_be_bytes());
                v.extend_from_slice(&time.to_be_bytes());
                let tag = hmac_with(MessageDigest::sha256(), out_hmac, &[&v, rest]);
                let ct = aes256_ctr(out_cipher, &tag[..16], rest);
                v.extend_from_slice(&tag);
                v.extend_from_slice(&ct);
                v
            }
        }
    }

    pub fn unwrap(&self, pkt: &[u8]) -> Result<(u8, [u8; 8], Vec<u8>), String> {
        if pkt.len() < 9 {
            return Err("short control packet".into());
        }
        let op = pkt[0];
        let mut sid = [0u8; 8];
        sid.copy_from_slice(&pkt[1..9]);
        match self {
            Wrap::None => Ok((op, sid, pkt[9..].to_vec())),
            Wrap::Auth { md, inp, hlen, .. } => {
                if pkt.len() < 9 + hlen + 8 {
                    return Err("short tls-auth packet".into());
                }
                let mac = &pkt[9..9 + hlen];
                let pt = &pkt[9 + hlen..9 + hlen + 8];
                let rest = &pkt[9 + hlen + 8..];
                let want = hmac_with(*md, inp, &[pt, &[op], &sid, rest]);
                if !openssl::memcmp::eq(mac, &want) {
                    return Err("tls-auth HMAC mismatch (wrong ta.key or key-direction?)".into());
                }
                Ok((op, sid, rest.to_vec()))
            }
            Wrap::Crypt { in_cipher, in_hmac, .. } => {
                if pkt.len() < 17 + TLS_CRYPT_TAG {
                    return Err("short tls-crypt packet".into());
                }
                let header = &pkt[..17];
                let tag = &pkt[17..17 + TLS_CRYPT_TAG];
                let pt = aes256_ctr(in_cipher, &tag[..16], &pkt[17 + TLS_CRYPT_TAG..]);
                let want = hmac_with(MessageDigest::sha256(), in_hmac, &[header, &pt]);
                if !openssl::memcmp::eq(tag, &want) {
                    return Err("tls-crypt authentication failed (wrong tls-crypt key?)".into());
                }
                Ok((op, sid, pt))
            }
        }
    }
}

fn aes256_ctr(key: &[u8; 32], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut ctx = CipherCtx::new().expect("ctx");
    ctx.encrypt_init(Some(Cipher::aes_256_ctr()), Some(key), Some(iv)).expect("ctr init");
    let mut out = vec![0u8; data.len() + 16];
    let n = ctx.cipher_update(data, Some(&mut out)).expect("ctr update");
    out.truncate(n);
    out
}

fn now_secs() -> u32 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherKind {
    Aead,
    Cbc,
}

/// Returns (OpenSSL cipher, key length, mode).
pub fn cipher_by_name(name: &str) -> Option<(&'static CipherRef, usize, CipherKind)> {
    Some(match name.to_ascii_uppercase().as_str() {
        "AES-128-GCM" => (Cipher::aes_128_gcm(), 16, CipherKind::Aead),
        "AES-192-GCM" => (Cipher::aes_192_gcm(), 24, CipherKind::Aead),
        "AES-256-GCM" => (Cipher::aes_256_gcm(), 32, CipherKind::Aead),
        "CHACHA20-POLY1305" => (Cipher::chacha20_poly1305(), 32, CipherKind::Aead),
        "AES-128-CBC" => (Cipher::aes_128_cbc(), 16, CipherKind::Cbc),
        "AES-192-CBC" => (Cipher::aes_192_cbc(), 24, CipherKind::Cbc),
        "AES-256-CBC" => (Cipher::aes_256_cbc(), 32, CipherKind::Cbc),
        _ => return None,
    })
}

/// Sliding-window replay protection (64 packets), as `packet_id_test` does.
#[derive(Default)]
pub struct Replay {
    top: u32,
    bits: u64,
}

impl Replay {
    /// True if `id` is new (and records it); false for a replay / too-old packet.
    pub fn check(&mut self, id: u32) -> bool {
        if id == 0 {
            return false;
        }
        if id > self.top {
            let shift = id - self.top;
            self.bits = if shift >= 64 { 0 } else { self.bits << shift };
            self.bits |= 1;
            self.top = id;
            return true;
        }
        let back = self.top - id;
        if back >= 64 {
            return false;
        }
        let m = 1u64 << back;
        if self.bits & m != 0 {
            return false;
        }
        self.bits |= m;
        true
    }
}

/// Data-channel keys for one key_id: encrypt (client→server) + decrypt contexts.
pub struct DataCrypto {
    kind: CipherKind,
    enc: CipherCtx,
    dec: CipherCtx,
    enc_iv: [u8; 8],
    dec_iv: [u8; 8],
    // CBC only:
    md: Option<MessageDigest>,
    enc_hmac: Option<PKey<Private>>,
    dec_hmac: Option<PKey<Private>>,
    send_pid: u32,
    replay: Replay,
}

const AEAD_TAG: usize = 16;

impl DataCrypto {
    /// Client: encrypt = key 0, decrypt = key 1.
    pub fn new(key2: &Key2, cipher_name: &str, auth: &str) -> Result<DataCrypto, String> {
        let (cipher, klen, kind) =
            cipher_by_name(cipher_name).ok_or_else(|| format!("unsupported data cipher {cipher_name}"))?;
        let (ek, dk) = (&key2.keys[0], &key2.keys[1]);
        let mut enc = CipherCtx::new().map_err(|e| e.to_string())?;
        let mut dec = CipherCtx::new().map_err(|e| e.to_string())?;
        enc.encrypt_init(Some(cipher), Some(&ek.cipher[..klen]), None).map_err(|e| format!("cipher init: {e}"))?;
        dec.decrypt_init(Some(cipher), Some(&dk.cipher[..klen]), None).map_err(|e| format!("cipher init: {e}"))?;
        let mut enc_iv = [0u8; 8];
        let mut dec_iv = [0u8; 8];
        let (mut md, mut enc_hmac, mut dec_hmac) = (None, None, None);
        match kind {
            CipherKind::Aead => {
                // The unused HMAC half supplies the implicit (per-session) IV part.
                enc_iv.copy_from_slice(&ek.hmac[..8]);
                dec_iv.copy_from_slice(&dk.hmac[..8]);
            }
            CipherKind::Cbc => {
                let d = digest(auth)?;
                let hl = d.size();
                enc_hmac = Some(PKey::hmac(&ek.hmac[..hl]).map_err(|e| e.to_string())?);
                dec_hmac = Some(PKey::hmac(&dk.hmac[..hl]).map_err(|e| e.to_string())?);
                md = Some(d);
            }
        }
        Ok(DataCrypto {
            kind,
            enc,
            dec,
            enc_iv,
            dec_iv,
            md,
            enc_hmac,
            dec_hmac,
            send_pid: 0,
            replay: Replay::default(),
        })
    }

    /// Encrypt `payload` into a full data packet starting with `hdr` (1 byte for
    /// P_DATA_V1, 4 bytes for P_DATA_V2). `aad_hdr`: authenticate the header too (V2).
    pub fn encrypt(&mut self, hdr: &[u8], aad_hdr: bool, payload: &[u8]) -> Result<Vec<u8>, String> {
        self.send_pid = self.send_pid.checked_add(1).ok_or("data packet-id wrapped (renegotiate)")?;
        let pid = self.send_pid.to_be_bytes();
        match self.kind {
            CipherKind::Aead => {
                let mut iv = [0u8; 12];
                iv[..4].copy_from_slice(&pid);
                iv[4..].copy_from_slice(&self.enc_iv);
                let mut out = Vec::with_capacity(hdr.len() + 4 + AEAD_TAG + payload.len() + 16);
                out.extend_from_slice(hdr);
                out.extend_from_slice(&pid);
                let tag_at = out.len();
                out.extend_from_slice(&[0u8; AEAD_TAG]);
                let ct_at = out.len();
                out.resize(ct_at + payload.len() + 16, 0);
                let e = &mut self.enc;
                e.encrypt_init(None, None, Some(&iv)).map_err(|e| e.to_string())?;
                if aad_hdr {
                    e.cipher_update(hdr, None).map_err(|e| e.to_string())?;
                }
                e.cipher_update(&pid, None).map_err(|e| e.to_string())?;
                let n = e.cipher_update(payload, Some(&mut out[ct_at..])).map_err(|e| e.to_string())?;
                let f = e.cipher_final(&mut out[ct_at + n..]).map_err(|e| e.to_string())?;
                out.truncate(ct_at + n + f);
                e.tag(&mut out[tag_at..tag_at + AEAD_TAG]).map_err(|e| e.to_string())?;
                Ok(out)
            }
            CipherKind::Cbc => {
                let mut iv = [0u8; 16];
                openssl::rand::rand_bytes(&mut iv).map_err(|e| e.to_string())?;
                let mut pt = Vec::with_capacity(4 + payload.len());
                pt.extend_from_slice(&pid);
                pt.extend_from_slice(payload);
                let mut ct = vec![0u8; pt.len() + 32];
                let e = &mut self.enc;
                e.encrypt_init(None, None, Some(&iv)).map_err(|e| e.to_string())?;
                let n = e.cipher_update(&pt, Some(&mut ct)).map_err(|e| e.to_string())?;
                let f = e.cipher_final(&mut ct[n..]).map_err(|e| e.to_string())?;
                ct.truncate(n + f);
                let mac = hmac_with(self.md.unwrap(), self.enc_hmac.as_ref().unwrap(), &[&iv, &ct]);
                let mut out = Vec::with_capacity(hdr.len() + mac.len() + 16 + ct.len());
                out.extend_from_slice(hdr);
                out.extend_from_slice(&mac);
                out.extend_from_slice(&iv);
                out.extend_from_slice(&ct);
                Ok(out)
            }
        }
    }

    pub fn decrypt(&mut self, pkt: &[u8], hdr_len: usize, aad_hdr: bool) -> Result<Vec<u8>, String> {
        match self.kind {
            CipherKind::Aead => {
                if pkt.len() < hdr_len + 4 + AEAD_TAG {
                    return Err("short data packet".into());
                }
                let hdr = &pkt[..hdr_len];
                let pid = &pkt[hdr_len..hdr_len + 4];
                let tag = &pkt[hdr_len + 4..hdr_len + 4 + AEAD_TAG];
                let ct = &pkt[hdr_len + 4 + AEAD_TAG..];
                let mut iv = [0u8; 12];
                iv[..4].copy_from_slice(pid);
                iv[4..].copy_from_slice(&self.dec_iv);
                let d = &mut self.dec;
                d.decrypt_init(None, None, Some(&iv)).map_err(|e| e.to_string())?;
                if aad_hdr {
                    d.cipher_update(hdr, None).map_err(|e| e.to_string())?;
                }
                d.cipher_update(pid, None).map_err(|e| e.to_string())?;
                let mut out = vec![0u8; ct.len() + 16];
                let n = d.cipher_update(ct, Some(&mut out)).map_err(|e| e.to_string())?;
                d.set_tag(tag).map_err(|e| e.to_string())?;
                let f = d.cipher_final(&mut out[n..]).map_err(|_| "data packet authentication failed".to_string())?;
                out.truncate(n + f);
                let id = u32::from_be_bytes([pid[0], pid[1], pid[2], pid[3]]);
                if !self.replay.check(id) {
                    return Err(format!("replayed data packet id {id}"));
                }
                Ok(out)
            }
            CipherKind::Cbc => {
                let md = self.md.unwrap();
                let hl = md.size();
                if pkt.len() < hdr_len + hl + 16 + 16 {
                    return Err("short data packet".into());
                }
                let mac = &pkt[hdr_len..hdr_len + hl];
                let iv = &pkt[hdr_len + hl..hdr_len + hl + 16];
                let ct = &pkt[hdr_len + hl + 16..];
                let want = hmac_with(md, self.dec_hmac.as_ref().unwrap(), &[iv, ct]);
                if !openssl::memcmp::eq(mac, &want) {
                    return Err("data packet HMAC mismatch".into());
                }
                let d = &mut self.dec;
                d.decrypt_init(None, None, Some(iv)).map_err(|e| e.to_string())?;
                let mut out = vec![0u8; ct.len() + 32];
                let n = d.cipher_update(ct, Some(&mut out)).map_err(|e| e.to_string())?;
                let f = d.cipher_final(&mut out[n..]).map_err(|_| "data packet padding error".to_string())?;
                out.truncate(n + f);
                if out.len() < 4 {
                    return Err("short decrypted packet".into());
                }
                let id = u32::from_be_bytes([out[0], out[1], out[2], out[3]]);
                if !self.replay.check(id) {
                    return Err(format!("replayed data packet id {id}"));
                }
                out.drain(..4);
                Ok(out)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key2_seq() -> Key2 {
        let b: Vec<u8> = (0..256u32).map(|i| i as u8).collect();
        Key2::from_bytes(&b).unwrap()
    }

    /// Swap directions: what the server would use (encrypt = key 1, decrypt = key 0).
    fn server_side(k: &Key2) -> Key2 {
        Key2 { keys: [k.keys[1].clone(), k.keys[0].clone()] }
    }

    #[test]
    fn prf_rfc2246_shape() {
        let a = tls1_prf(b"secret-secret", b"seed", 100);
        let b = tls1_prf(b"secret-secret", b"seed", 100);
        assert_eq!(a, b);
        assert_eq!(a.len(), 100);
        assert_ne!(tls1_prf(b"secret-secreT", b"seed", 100), a);
    }

    #[test]
    fn prf_known_vector() {
        // TLS 1.0 PRF test vector (secret 48×0xab, label+seed "PRF Testvector" + 64×0xcd),
        // first bytes of the 104-byte output: d3 d4 d1 e3 49 b5 d5 15 04 46 66 d5 1d e3 2b ab.
        let secret = [0xabu8; 48];
        let mut seed = b"PRF Testvector".to_vec();
        seed.extend_from_slice(&[0xcd; 64]);
        let out = tls1_prf(&secret, &seed, 104);
        assert_eq!(&out[..16], &[0xd3, 0xd4, 0xd1, 0xe3, 0x49, 0xb5, 0xd5, 0x15, 0x04, 0x46, 0x66, 0xd5, 0x1d, 0xe3, 0x2b, 0xab]);
    }

    #[test]
    fn static_key_parse_and_direction() {
        let hex: String = (0..256u32).map(|i| format!("{:02x}", i as u8)).collect::<Vec<_>>().chunks(16).map(|c| c.concat() + "\n").collect();
        let pem = format!("#\n-----BEGIN OpenVPN Static key V1-----\n{hex}-----END OpenVPN Static key V1-----\n");
        let k = Key2::from_static_pem(&pem).unwrap();
        assert_eq!(k.keys[1].cipher[0], 128);
        let (o, i) = k.directional(Some(1));
        assert_eq!((o.cipher[0], i.cipher[0]), (128, 0));
        let (o, i) = k.directional(None);
        assert_eq!((o.cipher[0], i.cipher[0]), (0, 0));
    }

    #[test]
    fn tls_auth_roundtrip() {
        let k = key2_seq();
        let mut client = Wrap::tls_auth(&k, Some(1), "SHA256").unwrap();
        let server = Wrap::tls_auth(&k, Some(0), "SHA256").unwrap();
        let sid = [7u8; 8];
        let pkt = client.wrap(0x38, &sid, b"rest-of-packet");
        let (op, s, rest) = server.unwrap(&pkt).unwrap();
        assert_eq!((op, s, rest.as_slice()), (0x38, sid, &b"rest-of-packet"[..]));
        let mut bad = pkt.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(server.unwrap(&bad).is_err());
        // Same-direction key can't verify (proves the direction matters).
        assert!(Wrap::tls_auth(&k, Some(1), "SHA256").unwrap().unwrap(&pkt).is_err());
    }

    #[test]
    fn tls_crypt_roundtrip() {
        let k = key2_seq();
        let mut client = Wrap::tls_crypt(&k).unwrap();
        let server = Wrap::tls_crypt(&server_side(&k)).unwrap();
        let sid = [9u8; 8];
        let pkt = client.wrap(0x20, &sid, b"\x00\x00\x00\x00\x01hello");
        assert_ne!(&pkt[pkt.len() - 5..], b"hello");
        let (op, s, rest) = server.unwrap(&pkt).unwrap();
        assert_eq!((op, s, rest.as_slice()), (0x20, sid, &b"\x00\x00\x00\x00\x01hello"[..]));
    }

    #[test]
    fn aead_roundtrip_v2_and_replay() {
        let k = key2_seq();
        for c in ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"] {
            let mut cl = DataCrypto::new(&k, c, "SHA1").unwrap();
            let mut sv = DataCrypto::new(&server_side(&k), c, "SHA1").unwrap();
            let hdr = [0x48, 0, 0, 5];
            let pkt = cl.encrypt(&hdr, true, b"ip packet bytes").unwrap();
            assert_eq!(&pkt[..4], &hdr);
            assert_eq!(&pkt[4..8], &[0, 0, 0, 1]); // packet id 1
            assert_eq!(sv.decrypt(&pkt, 4, true).unwrap(), b"ip packet bytes");
            assert!(sv.decrypt(&pkt, 4, true).is_err(), "{c}: replay must be rejected");
            let mut t = cl.encrypt(&hdr, true, b"x").unwrap();
            t[0] ^= 1; // header is authenticated
            assert!(sv.decrypt(&t, 4, true).is_err());
        }
    }

    #[test]
    fn cbc_roundtrip_v1() {
        let k = key2_seq();
        let mut cl = DataCrypto::new(&k, "AES-256-CBC", "SHA256").unwrap();
        let mut sv = DataCrypto::new(&server_side(&k), "AES-256-CBC", "SHA256").unwrap();
        let pkt = cl.encrypt(&[0x30], false, b"payload that spans more than one block").unwrap();
        assert_eq!(pkt.len(), 1 + 32 + 16 + 48);
        assert_eq!(sv.decrypt(&pkt, 1, false).unwrap(), b"payload that spans more than one block");
    }

    #[test]
    fn replay_window() {
        let mut r = Replay::default();
        assert!(r.check(1) && r.check(3) && r.check(2));
        assert!(!r.check(2) && !r.check(0));
        assert!(r.check(100));
        assert!(!r.check(30));
        assert!(r.check(99));
    }
}
