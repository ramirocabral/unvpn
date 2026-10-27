//! EAP (RFC 3748) carried in IKEv2 IKE_AUTH, with the two methods used for VPN user
//! authentication: **EAP-GTC** (RFC 2284, the token/OTP challenge/response) and
//! **EAP-MSCHAPV2** (RFC 2759; its MSK keys the final IKE AUTH per RFC 7296 §2.16).
//!
//! MD4 (the NT hash) and DES (the MS-CHAP-v2 challenge response) are implemented
//! here because OpenSSL 3's default provider moved them to the legacy provider,
//! which a single static binary cannot assume is loaded. SHA1/MD5 come from OpenSSL.

#![allow(dead_code)]

use openssl::hash::{Hasher, MessageDigest};

// EAP codes (RFC 3748 §4).
pub const EAP_REQUEST: u8 = 1;
pub const EAP_RESPONSE: u8 = 2;
pub const EAP_SUCCESS: u8 = 3;
pub const EAP_FAILURE: u8 = 4;

// EAP method types.
pub const EAP_TYPE_IDENTITY: u8 = 1;
pub const EAP_TYPE_NOTIFICATION: u8 = 2;
pub const EAP_TYPE_NAK: u8 = 3;
pub const EAP_TYPE_GTC: u8 = 6;
pub const EAP_TYPE_MSCHAPV2: u8 = 26;

// MS-CHAP-v2 opcodes (RFC 2759 §2).
pub const MSCHAP_CHALLENGE: u8 = 1;
pub const MSCHAP_RESPONSE: u8 = 2;
pub const MSCHAP_SUCCESS: u8 = 3;
pub const MSCHAP_FAILURE: u8 = 4;

/// A parsed EAP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eap {
    pub code: u8,
    pub id: u8,
    /// `None` for Success/Failure (no type field).
    pub method: Option<u8>,
    /// Type-data (everything after the type byte), or empty for Success/Failure.
    pub data: Vec<u8>,
}

impl Eap {
    pub fn parse(buf: &[u8]) -> Result<Eap, String> {
        if buf.len() < 4 {
            return Err("short EAP packet".into());
        }
        let code = buf[0];
        let id = buf[1];
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        if len < 4 || len > buf.len() {
            return Err(format!("bad EAP length {len} (have {})", buf.len()));
        }
        let body = &buf[4..len];
        if code == EAP_SUCCESS || code == EAP_FAILURE {
            return Ok(Eap { code, id, method: None, data: Vec::new() });
        }
        if body.is_empty() {
            return Err("EAP request/response without a type".into());
        }
        Ok(Eap { code, id, method: Some(body[0]), data: body[1..].to_vec() })
    }

    /// Serialise an EAP Response for `method` with `data` as its type-data.
    pub fn response(id: u8, method: u8, data: &[u8]) -> Vec<u8> {
        let len = (5 + data.len()) as u16;
        let mut out = Vec::with_capacity(len as usize);
        out.push(EAP_RESPONSE);
        out.push(id);
        out.extend_from_slice(&len.to_be_bytes());
        out.push(method);
        out.extend_from_slice(data);
        out
    }
}

/// EAP-Identity response: the username as type-data.
pub fn identity_response(id: u8, username: &str) -> Vec<u8> {
    Eap::response(id, EAP_TYPE_IDENTITY, username.as_bytes())
}

/// EAP-GTC response: the typed value (token/OTP or password), UTF-8, no NUL.
pub fn gtc_response(id: u8, value: &str) -> Vec<u8> {
    Eap::response(id, EAP_TYPE_GTC, value.as_bytes())
}

/// EAP legacy-Nak: ask the peer to switch to `desired` method types.
pub fn nak_response(id: u8, desired: &[u8]) -> Vec<u8> {
    Eap::response(id, EAP_TYPE_NAK, desired)
}

// ---------------------------------------------------------------------------
// MS-CHAP-v2 (RFC 2759)
// ---------------------------------------------------------------------------

/// A parsed MS-CHAP-v2 Challenge (opcode 1): the 16-byte authenticator challenge
/// and the server name.
#[derive(Debug, Clone)]
pub struct MschapChallenge {
    pub mschap_id: u8,
    pub challenge: [u8; 16],
    pub name: Vec<u8>,
}

pub fn parse_mschap_challenge(type_data: &[u8]) -> Result<MschapChallenge, String> {
    // OpCode(1) | MS-CHAPv2-ID(1) | MS-Length(2) | Value-Size(1) | Challenge(16) | Name
    if type_data.len() < 5 || type_data[0] != MSCHAP_CHALLENGE {
        return Err("not an MS-CHAP-v2 Challenge".into());
    }
    let value_size = type_data[4] as usize;
    if value_size != 16 || type_data.len() < 5 + 16 {
        return Err("MS-CHAP-v2 Challenge value-size must be 16".into());
    }
    let mut challenge = [0u8; 16];
    challenge.copy_from_slice(&type_data[5..21]);
    Ok(MschapChallenge { mschap_id: type_data[1], challenge, name: type_data[21..].to_vec() })
}

/// Build the MS-CHAP-v2 Response type-data (RFC 2759 §2.2) given the parsed
/// challenge and the credentials. Returns `(type_data, nt_response)`; `nt_response`
/// is kept for later MSK derivation and for checking the server's Success.
pub fn mschap_response(
    ch: &MschapChallenge,
    username: &str,
    password: &str,
    peer_challenge: &[u8; 16],
) -> (Vec<u8>, [u8; 24]) {
    let nt = generate_nt_response(&ch.challenge, peer_challenge, username, password);
    // Response value (49): Peer-Challenge(16) | Reserved(8) | NT-Response(24) | Flags(1)
    let mut value = Vec::with_capacity(49);
    value.extend_from_slice(peer_challenge);
    value.extend_from_slice(&[0u8; 8]);
    value.extend_from_slice(&nt);
    value.push(0); // Flags
    // Type-data: OpCode | MS-CHAPv2-ID | MS-Length | Value-Size(49) | Value | Name
    let name = username.as_bytes();
    let ms_len = (4 + 1 + 49 + name.len()) as u16;
    let mut out = Vec::new();
    out.push(MSCHAP_RESPONSE);
    out.push(ch.mschap_id);
    out.extend_from_slice(&ms_len.to_be_bytes());
    out.push(49);
    out.extend_from_slice(&value);
    out.extend_from_slice(name);
    (out, nt)
}

/// GenerateNTResponse (RFC 2759 §8.1).
pub fn generate_nt_response(
    authenticator_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
    username: &str,
    password: &str,
) -> [u8; 24] {
    let challenge = challenge_hash(peer_challenge, authenticator_challenge, username);
    let password_hash = nt_password_hash(password);
    challenge_response(&challenge, &password_hash)
}

/// ChallengeHash (RFC 2759 §8.2): SHA1(PeerChallenge | AuthChallenge | UserName)[0..8].
fn challenge_hash(peer: &[u8; 16], auth: &[u8; 16], username: &str) -> [u8; 8] {
    let mut h = Hasher::new(MessageDigest::sha1()).expect("sha1");
    h.update(peer).unwrap();
    h.update(auth).unwrap();
    // The username is the bare account name (no domain), ASCII.
    h.update(username.as_bytes()).unwrap();
    let digest = h.finish().unwrap();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// NtPasswordHash (RFC 2759 §8.3): MD4(UnicodeLittleEndian(password)).
pub fn nt_password_hash(password: &str) -> [u8; 16] {
    let unicode = unicode_le(password);
    md4(&unicode)
}

/// HashNtPasswordHash (RFC 2759 §8.4): MD4 of the 16-byte NT hash.
pub fn nt_password_hash_hash(password_hash: &[u8; 16]) -> [u8; 16] {
    md4(password_hash)
}

/// ChallengeResponse (RFC 2759 §8.5): three DES encryptions of the 8-byte challenge
/// with 7-byte slices of the password hash (padded to 21 bytes).
fn challenge_response(challenge: &[u8; 8], password_hash: &[u8; 16]) -> [u8; 24] {
    let mut zpwd = [0u8; 21];
    zpwd[..16].copy_from_slice(password_hash);
    let mut out = [0u8; 24];
    for i in 0..3 {
        let key = des_key_from_7(&zpwd[i * 7..i * 7 + 7]);
        let block = des_ecb_encrypt(&key, challenge);
        out[i * 8..i * 8 + 8].copy_from_slice(&block);
    }
    out
}

/// Expand a 7-byte key to the 8-byte DES key (each byte shifted left 1, low bit is
/// parity — ignored by DES). RFC 2759 §8.6 DesEncrypt key schedule.
fn des_key_from_7(k7: &[u8]) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0] = k7[0] & 0xfe;
    k[1] = ((k7[0] << 7) | (k7[1] >> 1)) & 0xfe;
    k[2] = ((k7[1] << 6) | (k7[2] >> 2)) & 0xfe;
    k[3] = ((k7[2] << 5) | (k7[3] >> 3)) & 0xfe;
    k[4] = ((k7[3] << 4) | (k7[4] >> 4)) & 0xfe;
    k[5] = ((k7[4] << 3) | (k7[5] >> 5)) & 0xfe;
    k[6] = ((k7[5] << 2) | (k7[6] >> 6)) & 0xfe;
    k[7] = (k7[6] << 1) & 0xfe;
    k
}

fn des_ecb_encrypt(key: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    des::encrypt_block(u64::from_be_bytes(*key), u64::from_be_bytes(*block)).to_be_bytes()
}

/// Single-block DES (FIPS 46-3), ECB — the one block MS-CHAP-v2 needs. Local because
/// OpenSSL 3 moved DES to the legacy provider.
mod des {
    // All tables are 1-based bit positions counted from the MSB of the input word.
    const IP: [u8; 64] = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ];
    const FP: [u8; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
    ];
    const E: [u8; 48] = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17,
        18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
    ];
    const P: [u8; 32] = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
        13, 30, 6, 22, 11, 4, 25,
    ];
    const PC1: [u8; 56] = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
        60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4,
    ];
    const PC2: [u8; 48] = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41,
        52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ];
    const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
    const SBOX: [[u8; 64]; 8] = [
        [
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6,
            12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2,
            4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
        ],
        [
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0,
            1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1,
            3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
        ],
        [
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5,
            14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0,
            6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
        ],
        [
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
            12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10,
            1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
        ],
        [
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0,
            15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7,
            1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
        ],
        [
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1,
            13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12,
            9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
        ],
        [
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3,
            5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8,
            1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
        ],
        [
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5,
            6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4,
            10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
        ],
    ];

    fn permute(src: u64, table: &[u8], src_bits: u32) -> u64 {
        let mut out = 0u64;
        for &pos in table {
            out = (out << 1) | ((src >> (src_bits - pos as u32)) & 1);
        }
        out
    }

    fn feistel(r: u32, subkey: u64) -> u32 {
        let x = permute(r as u64, &E, 32) ^ subkey; // 48 bits
        let mut out = 0u32;
        for i in 0..8 {
            let six = ((x >> (42 - 6 * i)) & 0x3f) as u8;
            let row = ((six & 0x20) >> 4) | (six & 0x01);
            let col = (six >> 1) & 0x0f;
            out = (out << 4) | SBOX[i as usize][(row * 16 + col) as usize] as u32;
        }
        permute(out as u64, &P, 32) as u32
    }

    pub fn encrypt_block(key: u64, block: u64) -> u64 {
        let key56 = permute(key, &PC1, 64);
        let mut c = (key56 >> 28) & 0x0fff_ffff;
        let mut d = key56 & 0x0fff_ffff;
        let mut subkeys = [0u64; 16];
        for (i, sk) in subkeys.iter_mut().enumerate() {
            let s = SHIFTS[i];
            c = ((c << s) | (c >> (28 - s))) & 0x0fff_ffff;
            d = ((d << s) | (d >> (28 - s))) & 0x0fff_ffff;
        *sk = permute((c << 28) | d, &PC2, 56);
        }
        let ip = permute(block, &IP, 64);
        let mut l = (ip >> 32) as u32;
        let mut r = ip as u32;
        for sk in subkeys {
            let nl = r;
            r = l ^ feistel(r, sk);
            l = nl;
        }
        // Pre-output is R16 || L16 (the final swap is undone).
        permute(((r as u64) << 32) | l as u64, &FP, 64)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn des_fips_known_answer() {
            // FIPS 46-3 test vector.
            assert_eq!(encrypt_block(0x133457799BBCDFF1, 0x0123456789ABCDEF), 0x85E813540F0AB405);
        }
    }
}

/// UTF-16LE encode (NT passwords are hashed as little-endian Unicode).
fn unicode_le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// MSK derivation (RFC 3079) — keys the final IKE AUTH when EAP-MSCHAPv2 is used.
// ---------------------------------------------------------------------------

const MAGIC1: &[u8] = b"This is the MPPE Master Key";
const MAGIC2: &[u8] = b"On the client side, this is the send key; on the server side, it is the receive key.";
const MAGIC3: &[u8] = b"On the client side, this is the receive key; on the server side, it is the send key.";
const SHA_PAD1: [u8; 40] = [0x00; 40];
const SHA_PAD2: [u8; 40] = [0xf2; 40];

/// GetMasterKey (RFC 3079 §3.3): SHA1(NtPasswordHashHash | NtResponse | Magic1)[0..16].
pub fn get_master_key(password_hash_hash: &[u8; 16], nt_response: &[u8; 24]) -> [u8; 16] {
    let mut h = Hasher::new(MessageDigest::sha1()).expect("sha1");
    h.update(password_hash_hash).unwrap();
    h.update(nt_response).unwrap();
    h.update(MAGIC1).unwrap();
    let d = h.finish().unwrap();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// GetAsymmetricStartKey (RFC 3079 §3.4): SHA1(MasterKey | pad1 | magic | pad2)[0..16].
fn get_asymmetric_start_key(master_key: &[u8; 16], magic: &[u8]) -> [u8; 16] {
    let mut h = Hasher::new(MessageDigest::sha1()).expect("sha1");
    h.update(master_key).unwrap();
    h.update(&SHA_PAD1).unwrap();
    h.update(magic).unwrap();
    h.update(&SHA_PAD2).unwrap();
    let d = h.finish().unwrap();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// The EAP-MSCHAPv2 MSK (64 bytes): MasterReceiveKey(16) | MasterSendKey(16) | zeros.
/// Used as the shared secret in the IKEv2 AUTH (RFC 7296 §2.16). From the client's
/// perspective MAGIC2 yields the send key and MAGIC3 the receive key.
pub fn derive_msk(password: &str, nt_response: &[u8; 24]) -> [u8; 64] {
    let ph = nt_password_hash(password);
    let phh = nt_password_hash_hash(&ph);
    let master = get_master_key(&phh, nt_response);
    let send = get_asymmetric_start_key(&master, MAGIC2);
    let recv = get_asymmetric_start_key(&master, MAGIC3);
    // MSK = MasterSendKey | MasterReceiveKey | 32 zero octets. The send key comes
    // first: validated live against strongSwan (and this is what an RFC 7296 §2.16
    // responder — FortiGate included — verifies the EAP-keyed AUTH against). A
    // recv|send ordering makes EAP-MSCHAPv2 succeed but the final AUTH fail.
    let mut msk = [0u8; 64];
    msk[..16].copy_from_slice(&send);
    msk[16..32].copy_from_slice(&recv);
    msk
}

// ---------------------------------------------------------------------------
// MD4 (RFC 1320) — the NT hash primitive, avoided in OpenSSL 3's legacy provider.
// ---------------------------------------------------------------------------

fn md4(input: &[u8]) -> [u8; 16] {
    let mut a: u32 = 0x6745_2301;
    let mut b: u32 = 0xefcd_ab89;
    let mut c: u32 = 0x98ba_dcfe;
    let mut d: u32 = 0x1032_5476;

    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let f = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
    let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
    let h = |x: u32, y: u32, z: u32| x ^ y ^ z;

    for chunk in msg.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, w) in chunk.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        let (aa, bb, cc, dd) = (a, b, c, d);

        // Round 1
        let r1 = |a: &mut u32, b: u32, c: u32, d: u32, k: usize, s: u32| {
        *a = a.wrapping_add(f(b, c, d)).wrapping_add(x[k]).rotate_left(s);
        };
        for &(k, s) in &[(0, 3), (1, 7), (2, 11), (3, 19), (4, 3), (5, 7), (6, 11), (7, 19),
                         (8, 3), (9, 7), (10, 11), (11, 19), (12, 3), (13, 7), (14, 11), (15, 19)] {
            // a,b,c,d rotate each step: use explicit ordering
            match k % 4 {
                0 => r1(&mut a, b, c, d, k, s),
                1 => r1(&mut d, a, b, c, k, s),
                2 => r1(&mut c, d, a, b, k, s),
                _ => r1(&mut b, c, d, a, k, s),
            }
        }

        // Round 2
        let r2 = |a: &mut u32, b: u32, c: u32, d: u32, k: usize, s: u32| {
        *a = a.wrapping_add(g(b, c, d)).wrapping_add(x[k]).wrapping_add(0x5a82_7999).rotate_left(s);
        };
        for (i, &(k, s)) in [(0, 3), (4, 5), (8, 9), (12, 13), (1, 3), (5, 5), (9, 9), (13, 13),
                             (2, 3), (6, 5), (10, 9), (14, 13), (3, 3), (7, 5), (11, 9), (15, 13)]
            .iter()
            .enumerate()
        {
            match i % 4 {
                0 => r2(&mut a, b, c, d, k, s),
                1 => r2(&mut d, a, b, c, k, s),
                2 => r2(&mut c, d, a, b, k, s),
                _ => r2(&mut b, c, d, a, k, s),
            }
        }

        // Round 3
        let r3 = |a: &mut u32, b: u32, c: u32, d: u32, k: usize, s: u32| {
        *a = a.wrapping_add(h(b, c, d)).wrapping_add(x[k]).wrapping_add(0x6ed9_eba1).rotate_left(s);
        };
        for (i, &(k, s)) in [(0, 3), (8, 9), (4, 11), (12, 15), (2, 3), (10, 9), (6, 11), (14, 15),
                             (1, 3), (9, 9), (5, 11), (13, 15), (3, 3), (11, 9), (7, 11), (15, 15)]
            .iter()
            .enumerate()
        {
            match i % 4 {
                0 => r3(&mut a, b, c, d, k, s),
                1 => r3(&mut d, a, b, c, k, s),
                2 => r3(&mut c, d, a, b, k, s),
                _ => r3(&mut b, c, d, a, k, s),
            }
        }

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes());
    out[12..16].copy_from_slice(&d.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn md4_rfc1320_vectors() {
        assert_eq!(hex(&md4(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hex(&md4(b"a")), "bde52cb31de33e46245e05fbdbd6fb24");
        assert_eq!(hex(&md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(hex(&md4(b"message digest")), "d9130a8164549fe818874806e1c7014b");
    }

    #[test]
    fn eap_parse_request_and_success() {
        // Request / Identity
        let req = [EAP_REQUEST, 7, 0, 5, EAP_TYPE_IDENTITY];
        let e = Eap::parse(&req).unwrap();
        assert_eq!(e.code, EAP_REQUEST);
        assert_eq!(e.method, Some(EAP_TYPE_IDENTITY));
        // Success (no type)
        let succ = [EAP_SUCCESS, 7, 0, 4];
        assert_eq!(Eap::parse(&succ).unwrap().method, None);
    }

    #[test]
    fn eap_response_builders() {
        let r = identity_response(3, "user");
        assert_eq!(&r[..4], &[EAP_RESPONSE, 3, 0, 9]);
        assert_eq!(r[4], EAP_TYPE_IDENTITY);
        assert_eq!(&r[5..], b"user");
        let g = gtc_response(4, "123456");
        assert_eq!(g[4], EAP_TYPE_GTC);
        assert_eq!(&g[5..], b"123456");
    }

    // RFC 2759 §9.2 test vectors.
    const USER: &str = "User";
    const PASS: &str = "clientPass";
    const AUTH_CH: [u8; 16] = [
        0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E, 0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28,
    ];
    const PEER_CH: [u8; 16] = [
        0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E,
    ];

    #[test]
    fn mschap_password_hashes() {
        let ph = nt_password_hash(PASS);
        assert_eq!(hex(&ph), "44ebba8d5312b8d611474411f56989ae");
        let phh = nt_password_hash_hash(&ph);
        assert_eq!(hex(&phh), "41c00c584bd2d91c4017a2a12fa59f3f");
    }

    #[test]
    fn mschap_challenge_hash_and_nt_response() {
        let ch = challenge_hash(&PEER_CH, &AUTH_CH, USER);
        assert_eq!(hex(&ch), "d02e4386bce91226");
        let nt = generate_nt_response(&AUTH_CH, &PEER_CH, USER, PASS);
        assert_eq!(hex(&nt), "82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df");
    }

    #[test]
    fn mschap_master_key_rfc3079() {
        let ph = nt_password_hash(PASS);
        let phh = nt_password_hash_hash(&ph);
        let nt = generate_nt_response(&AUTH_CH, &PEER_CH, USER, PASS);
        let mk = get_master_key(&phh, &nt);
        // RFC 3079 §4.5.3 expected Master Key.
        assert_eq!(hex(&mk), "fdece3717a8c838cb388e527ae3cdd31");
        let msk = derive_msk(PASS, &nt);
        assert_eq!(msk.len(), 64);
        assert_ne!(&msk[..16], &msk[16..32]); // send != recv
        // MSK = MasterSendKey | MasterReceiveKey | 32 zero octets (RFC 3079).
        assert_eq!(
            hex(&msk),
            "d5f0e9521e3ea9589645e86051c822268b7cdc149b993a1ba118cb153f56dccb\
             0000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
