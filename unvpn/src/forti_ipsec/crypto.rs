//! IKEv2 cryptography (RFC 7296 §2.13–2.17): the PRF and `prf+` key-derivation
//! ladder, the SK (Encrypted) payload's AES-CBC + HMAC protection, the AUTH
//! payload computation, and the CHILD SA key material. DH is reused from the
//! IKEv1 `ike::crypto` module (same Oakley MODP groups).
//!
//! Algorithm agility: the PRF, integrity and encryption transforms are chosen from
//! what the gateway accepted in IKE_SA_INIT. FortiGate's common proposal is
//! AES-CBC-256 / HMAC-SHA256 / PRF-SHA256 / MODP2048.

#![allow(dead_code)]

use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
    rand::rand_bytes,
};

use super::model::*;
use crate::ike::crypto::IkeCrypto;

fn e<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

/// The constant hashed with the PSK before it keys the AUTH PRF (RFC 7296 §2.15).
const KEY_PAD: &[u8] = b"Key Pad for IKEv2";

/// All keys derived for one IKE SA (RFC 7296 §2.14).
#[derive(Clone)]
pub struct SaKeys {
    pub sk_d: Vec<u8>,
    pub sk_ai: Vec<u8>,
    pub sk_ar: Vec<u8>,
    pub sk_ei: Vec<u8>,
    pub sk_er: Vec<u8>,
    pub sk_pi: Vec<u8>,
    pub sk_pr: Vec<u8>,
}

pub struct Ikev2Crypto {
    prf: MessageDigest,
    integ: MessageDigest,
    integ_icv_len: usize,
    cipher: Cipher,
    enc_key_len: usize,
}

impl Ikev2Crypto {
    pub fn new(prf_id: u16, integ_id: u16, encr_id: u16, encr_key_bits: usize) -> Result<Self, String> {
        let prf = match prf_id {
            PRF_HMAC_SHA1 => MessageDigest::sha1(),
            PRF_HMAC_SHA256 => MessageDigest::sha256(),
            PRF_HMAC_SHA384 => MessageDigest::sha384(),
            PRF_HMAC_SHA512 => MessageDigest::sha512(),
            o => return Err(format!("unsupported IKEv2 PRF {o}")),
        };
        let (integ, integ_icv_len) = match integ_id {
            INTEG_HMAC_SHA1_96 => (MessageDigest::sha1(), 12),
            INTEG_HMAC_SHA256_128 => (MessageDigest::sha256(), 16),
            INTEG_HMAC_SHA384_192 => (MessageDigest::sha384(), 24),
            INTEG_HMAC_SHA512_256 => (MessageDigest::sha512(), 32),
            o => return Err(format!("unsupported IKEv2 integrity alg {o}")),
        };
        let (cipher, enc_key_len) = match (encr_id, encr_key_bits) {
            (ENCR_AES_CBC, 128) => (Cipher::aes_128_cbc(), 16),
            (ENCR_AES_CBC, 192) => (Cipher::aes_192_cbc(), 24),
            (ENCR_AES_CBC, 256) => (Cipher::aes_256_cbc(), 32),
            (ENCR_3DES, _) => (Cipher::des_ede3_cbc(), 24),
            (a, k) => return Err(format!("unsupported IKEv2 cipher {a}/{k}")),
        };
        Ok(Ikev2Crypto { prf, integ, integ_icv_len, cipher, enc_key_len })
    }

    pub fn prf_len(&self) -> usize {
        self.prf.size()
    }
    pub fn integ_key_len(&self) -> usize {
        self.integ.size()
    }
    pub fn integ_icv_len(&self) -> usize {
        self.integ_icv_len
    }
    pub fn enc_key_len(&self) -> usize {
        self.enc_key_len
    }
    pub fn iv_len(&self) -> usize {
        self.cipher.iv_len().unwrap_or(self.cipher.block_size())
    }
    pub fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    /// `prf(key, data)` = HMAC-<prf> (RFC 7296 §2.13).
    pub fn prf(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let pkey = PKey::hmac(key).expect("hmac key");
        let mut s = Signer::new(self.prf, &pkey).expect("signer");
        s.update(data).expect("update");
        s.sign_to_vec().expect("sign")
    }

    /// `prf+(key, seed)` to `n` octets: T1=prf(key,seed|0x01), Ti=prf(key,Ti-1|seed|i).
    pub fn prf_plus(&self, key: &[u8], seed: &[u8], n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n + self.prf_len());
        let mut t: Vec<u8> = Vec::new();
        let mut counter = 1u8;
        while out.len() < n {
            let mut data = Vec::with_capacity(t.len() + seed.len() + 1);
            data.extend_from_slice(&t);
            data.extend_from_slice(seed);
            data.push(counter);
            t = self.prf(key, &data);
            out.extend_from_slice(&t);
            counter = counter.wrapping_add(1);
        }
        out.truncate(n);
        out
    }

    /// Derive the seven IKE SA keys (RFC 7296 §2.14):
    /// SKEYSEED = prf(Ni | Nr, g^ir); then prf+(SKEYSEED, Ni | Nr | SPIi | SPIr).
    pub fn derive_sa_keys(
        &self,
        shared_secret: &[u8],
        ni: &[u8],
        nr: &[u8],
        spi_i: [u8; 8],
        spi_r: [u8; 8],
    ) -> SaKeys {
        let mut nonces = Vec::with_capacity(ni.len() + nr.len());
        nonces.extend_from_slice(ni);
        nonces.extend_from_slice(nr);
        let skeyseed = self.prf(&nonces, shared_secret);

        let mut seed = Vec::new();
        seed.extend_from_slice(ni);
        seed.extend_from_slice(nr);
        seed.extend_from_slice(&spi_i);
        seed.extend_from_slice(&spi_r);

        let pk = self.prf_len();
        let ik = self.integ_key_len();
        let ek = self.enc_key_len;
        let total = pk + 2 * ik + 2 * ek + 2 * pk;
        let km = self.prf_plus(&skeyseed, &seed, total);

        let mut o = 0;
        let take = |n: usize, km: &[u8], o: &mut usize| {
            let s = km[*o..*o + n].to_vec();
            *o += n;
            s
        };
        SaKeys {
            sk_d: take(pk, &km, &mut o),
            sk_ai: take(ik, &km, &mut o),
            sk_ar: take(ik, &km, &mut o),
            sk_ei: take(ek, &km, &mut o),
            sk_er: take(ek, &km, &mut o),
            sk_pi: take(pk, &km, &mut o),
            sk_pr: take(pk, &km, &mut o),
        }
    }

    /// Encrypt the SK payload's plaintext (the inner payload chain): returns
    /// `IV | ciphertext` with RFC 7296 §3.14 padding (pad bytes + pad-length byte).
    /// The ICV is added separately over the whole message by [`integ_icv`].
    pub fn sk_encrypt(&self, sk_e: &[u8], plain: &[u8]) -> Result<Vec<u8>, String> {
        let block = self.cipher.block_size();
        let pad_len = (block - ((plain.len() + 1) % block)) % block;
        let mut padded = Vec::with_capacity(plain.len() + pad_len + 1);
        padded.extend_from_slice(plain);
        padded.extend(std::iter::repeat(0u8).take(pad_len));
        padded.push(pad_len as u8);

        let mut iv = vec![0u8; self.iv_len()];
        rand_bytes(&mut iv).map_err(e)?;
        let ct = self.cbc(Mode::Encrypt, sk_e, &iv, &padded)?;
        let mut out = iv;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt `IV | ciphertext` (ICV already verified and stripped) back to the
    /// inner payload chain.
    pub fn sk_decrypt(&self, sk_e: &[u8], iv_ct: &[u8]) -> Result<Vec<u8>, String> {
        let ivl = self.iv_len();
        if iv_ct.len() < ivl + self.cipher.block_size() {
            return Err("SK ciphertext too short".into());
        }
        let (iv, ct) = iv_ct.split_at(ivl);
        let padded = self.cbc(Mode::Decrypt, sk_e, iv, ct)?;
        if padded.is_empty() {
            return Err("empty SK plaintext".into());
        }
        let pad_len = padded[padded.len() - 1] as usize;
        if padded.len() < pad_len + 1 {
            return Err("bad SK pad length".into());
        }
        Ok(padded[..padded.len() - pad_len - 1].to_vec())
    }

    /// The truncated HMAC over `associated` (the whole message from the IKE header
    /// through the ciphertext, i.e. everything that precedes the ICV field).
    pub fn integ_icv(&self, sk_a: &[u8], associated: &[u8]) -> Vec<u8> {
        let pkey = PKey::hmac(sk_a).expect("hmac key");
        let mut s = Signer::new(self.integ, &pkey).expect("signer");
        s.update(associated).expect("update");
        let mut mac = s.sign_to_vec().expect("sign");
        mac.truncate(self.integ_icv_len);
        mac
    }

    fn cbc(&self, mode: Mode, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        let mut c = Crypter::new(self.cipher, mode, key, Some(iv)).map_err(e)?;
        c.pad(false);
        let mut out = vec![0u8; data.len() + self.cipher.block_size()];
        let n = c.update(data, &mut out).map_err(e)?;
        let r = c.finalize(&mut out[n..]).map_err(e)?;
        out.truncate(n + r);
        Ok(out)
    }

    /// PSK-based AUTH value (RFC 7296 §2.15):
    /// `prf(prf(PSK, "Key Pad for IKEv2"), signed_octets)`. Also used with the EAP
    /// MSK in place of the PSK when the EAP method establishes a shared key.
    pub fn psk_auth(&self, psk: &[u8], signed_octets: &[u8]) -> Vec<u8> {
        let inner = self.prf(psk, KEY_PAD);
        self.prf(&inner, signed_octets)
    }

    /// AUTH value keyed directly by SK_pi/SK_pr (RFC 7296 §2.16, for EAP methods
    /// that do not establish a shared key): `prf(SK_p, signed_octets)`.
    pub fn key_auth(&self, sk_p: &[u8], signed_octets: &[u8]) -> Vec<u8> {
        self.prf(sk_p, signed_octets)
    }

    /// Initiator's signed octets (RFC 7296 §2.15):
    /// `RealMessage1 | Nr | prf(SK_pi, IDi')` where IDi' is the IDi payload *body*
    /// (ID type + 3 reserved + ID data, without the generic payload header).
    pub fn initiator_signed_octets(
        &self,
        real_message1: &[u8],
        nr: &[u8],
        sk_pi: &[u8],
        idi_body: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(real_message1);
        out.extend_from_slice(nr);
        out.extend_from_slice(&self.prf(sk_pi, idi_body));
        out
    }

    /// Responder's signed octets, used to verify the gateway's AUTH:
    /// `RealMessage2 | Ni | prf(SK_pr, IDr')`.
    pub fn responder_signed_octets(
        &self,
        real_message2: &[u8],
        ni: &[u8],
        sk_pr: &[u8],
        idr_body: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(real_message2);
        out.extend_from_slice(ni);
        out.extend_from_slice(&self.prf(sk_pr, idr_body));
        out
    }

    /// CHILD SA key material (RFC 7296 §2.17, no PFS): KEYMAT = prf+(SK_d, Ni | Nr),
    /// split into the initiator→responder keys then responder→initiator keys, each
    /// `enc_key || integ_key` for the negotiated ESP transforms.
    pub fn child_keymat(&self, sk_d: &[u8], ni: &[u8], nr: &[u8], per_dir: usize) -> (Vec<u8>, Vec<u8>) {
        let mut seed = Vec::with_capacity(ni.len() + nr.len());
        seed.extend_from_slice(ni);
        seed.extend_from_slice(nr);
        let km = self.prf_plus(sk_d, &seed, 2 * per_dir);
        (km[..per_dir].to_vec(), km[per_dir..2 * per_dir].to_vec())
    }
}

/// DH for IKEv2, reusing the IKEv1 MODP implementation. Returns the keypair's
/// public value and a closure-free handle via [`IkeCrypto`].
pub fn dh_new(group: u16) -> Result<IkeCrypto, String> {
    // IkeCrypto bundles a digest+cipher we don't use here; pass SHA256/AES256 as
    // inert placeholders. Only public_key/shared_secret are called.
    IkeCrypto::new(group, IKE_HASH_SHA256_PLACEHOLDER, IKE_ENC_AES_CBC_PLACEHOLDER, 256)
}

// The numeric hash/enc ids IkeCrypto expects (from ike::model); duplicated as
// named placeholders so the intent (DH only) is clear at the call site.
const IKE_HASH_SHA256_PLACEHOLDER: u16 = 4;
const IKE_ENC_AES_CBC_PLACEHOLDER: u16 = 7;

#[cfg(test)]
mod tests {
    use super::*;

    fn c() -> Ikev2Crypto {
        Ikev2Crypto::new(PRF_HMAC_SHA256, INTEG_HMAC_SHA256_128, ENCR_AES_CBC, 256).unwrap()
    }

    #[test]
    fn prf_plus_length_and_determinism() {
        let c = c();
        let a = c.prf_plus(b"key-material", b"seed", 100);
        let b = c.prf_plus(b"key-material", b"seed", 100);
        assert_eq!(a.len(), 100);
        assert_eq!(a, b);
        // First block equals T1 = prf(key, seed | 0x01).
        let t1 = c.prf(b"key-material", b"seed\x01");
        assert_eq!(&a[..32], &t1[..]);
        // Second block equals T2 = prf(key, T1 | seed | 0x02).
        let mut d = t1.clone();
        d.extend_from_slice(b"seed");
        d.push(2);
        let t2 = c.prf(b"key-material", &d);
        assert_eq!(&a[32..64], &t2[..]);
    }

    #[test]
    fn sa_keys_have_right_lengths() {
        let c = c();
        let keys = c.derive_sa_keys(&[0x42; 256], &[1; 32], &[2; 32], [0xaa; 8], [0xbb; 8]);
        assert_eq!(keys.sk_d.len(), 32);
        assert_eq!(keys.sk_ai.len(), 32);
        assert_eq!(keys.sk_ei.len(), 32);
        assert_eq!(keys.sk_pr.len(), 32);
    }

    #[test]
    fn sk_encrypt_decrypt_roundtrip() {
        let c = c();
        let key = [0x11u8; 32];
        for len in [0usize, 1, 15, 16, 17, 200] {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let iv_ct = c.sk_encrypt(&key, &plain).unwrap();
            // IV + at least one cipher block.
            assert!(iv_ct.len() >= 16 + 16);
            let back = c.sk_decrypt(&key, &iv_ct).unwrap();
            assert_eq!(back, plain, "roundtrip len {len}");
        }
    }

    #[test]
    fn icv_is_truncated_hmac() {
        let c = c();
        let icv = c.integ_icv(&[0x22; 32], b"associated data");
        assert_eq!(icv.len(), 16); // HMAC-SHA256-128
    }

    #[test]
    fn psk_auth_matches_manual() {
        let c = c();
        let psk = b"s3cr3t";
        let octets = b"real-message-1|Nr|prf(SK_pi,IDi)";
        let inner = c.prf(psk, KEY_PAD);
        let expect = c.prf(&inner, octets);
        assert_eq!(c.psk_auth(psk, octets), expect);
    }

    #[test]
    fn child_keymat_splits_two_directions() {
        let c = c();
        let (i2r, r2i) = c.child_keymat(&[0x5a; 32], &[1; 32], &[2; 32], 36);
        assert_eq!(i2r.len(), 36);
        assert_eq!(r2i.len(), 36);
        assert_ne!(i2r, r2i);
    }

    #[test]
    fn dh_roundtrip_via_ike_crypto() {
        let a = dh_new(DH_MODP2048).unwrap();
        let b = dh_new(DH_MODP2048).unwrap();
        let sa = a.shared_secret(&b.public_key()).unwrap();
        let sb = b.shared_secret(&a.public_key()).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), 256);
    }
}
