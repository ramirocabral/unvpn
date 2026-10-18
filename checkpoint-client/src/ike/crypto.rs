//! IKEv1 / ESP cryptographic primitives, backed by OpenSSL.
//!
//! A single negotiated hash serves as PRF, integrity function and hash in
//! IKEv1 (RFC 2409). DH uses the Oakley MODP groups (prime embedded from the
//! RFC). Ported from the `isakmp` crate's `crypto.rs`.

use openssl::{
    bn::BigNum,
    dh::Dh,
    hash::{Hasher, MessageDigest},
    pkey::PKey,
    rand::rand_bytes,
    rsa::Padding,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
    x509::X509,
};

use super::model::*;

const G2_P: &[u8] = include_bytes!("../../testdata/g2_p.bin");
const G14_P: &[u8] = include_bytes!("../../testdata/g14_p.bin");

fn e<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

/// Cryptographically secure random bytes (nonces, cookies, SPIs, IVs).
pub fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rand_bytes(&mut b).expect("openssl rand");
    b
}

pub fn random_u32() -> u32 {
    u32::from_be_bytes(random(4).try_into().unwrap())
}

pub fn random_u64() -> u64 {
    u64::from_be_bytes(random(8).try_into().unwrap())
}

/// Left-pad to exactly `len` octets. IKE carries the KE payload and the shared
/// secret as fixed-width big-endian integers; BigNum drops leading zeroes.
fn left_pad(data: &[u8], len: usize) -> Vec<u8> {
    if data.len() >= len {
        data.to_vec()
    } else {
        let mut out = vec![0u8; len - data.len()];
        out.extend_from_slice(data);
        out
    }
}

/// IKEv1 crypto context for one negotiated Phase-1 suite.
pub struct IkeCrypto {
    dh: Dh<openssl::pkey::Private>,
    digest: MessageDigest,
    cipher: Cipher,
    pub_len: usize,
}

impl IkeCrypto {
    pub fn new(group: u16, hash_alg: u16, enc_alg: u16, key_len_bits: usize) -> Result<Self, String> {
        let (prime, pub_len) = match group {
            IKE_GROUP_MODP1024 => (G2_P, 128),
            IKE_GROUP_MODP2048 => (G14_P, 256),
            g => return Err(format!("unsupported DH group {g}")),
        };
        let p = BigNum::from_slice(prime).map_err(e)?;
        let g = BigNum::from_u32(2).map_err(e)?;
        let dh = Dh::from_pqg(p, None, g)
            .map_err(e)?
            .generate_key()
            .map_err(e)?;

        let digest = match hash_alg {
            IKE_HASH_MD5 => MessageDigest::md5(),
            IKE_HASH_SHA1 => MessageDigest::sha1(),
            IKE_HASH_SHA256 => MessageDigest::sha256(),
            IKE_HASH_SHA384 => MessageDigest::sha384(),
            IKE_HASH_SHA512 => MessageDigest::sha512(),
            h => return Err(format!("unsupported IKE hash {h}")),
        };
        let cipher = match (enc_alg, key_len_bits) {
            (IKE_ENC_AES_CBC, 128) => Cipher::aes_128_cbc(),
            (IKE_ENC_AES_CBC, 192) => Cipher::aes_192_cbc(),
            (IKE_ENC_AES_CBC, 256) => Cipher::aes_256_cbc(),
            (IKE_ENC_3DES, _) => Cipher::des_ede3_cbc(),
            (a, k) => return Err(format!("unsupported IKE cipher {a}/{k}")),
        };
        Ok(Self {
            dh,
            digest,
            cipher,
            pub_len,
        })
    }

    /// Our DH public value g^x, left-padded to the group width.
    pub fn public_key(&self) -> Vec<u8> {
        left_pad(&self.dh.public_key().to_vec(), self.pub_len)
    }

    /// The shared secret g^xy, left-padded to the group width.
    pub fn shared_secret(&self, peer: &[u8]) -> Result<Vec<u8>, String> {
        let peer = BigNum::from_slice(peer).map_err(e)?;
        let secret = self.dh.compute_key(&peer).map_err(e)?;
        Ok(left_pad(&secret, self.pub_len))
    }

    /// PRF = HMAC over the negotiated digest, concatenating the data chunks.
    pub fn prf(&self, key: &[u8], data: &[&[u8]]) -> Vec<u8> {
        let pkey = PKey::hmac(key).expect("hmac key");
        let mut signer = Signer::new(self.digest, &pkey).expect("signer");
        for d in data {
            signer.update(d).expect("hmac update");
        }
        signer.sign_to_vec().expect("hmac sign")
    }

    /// Plain digest over the concatenated chunks.
    pub fn hash(&self, data: &[&[u8]]) -> Vec<u8> {
        let mut h = Hasher::new(self.digest).expect("hasher");
        for d in data {
            h.update(d).expect("hash update");
        }
        h.finish().expect("hash finish").to_vec()
    }

    pub fn hash_len(&self) -> usize {
        self.digest.size()
    }

    pub fn block_size(&self) -> usize {
        self.cipher.block_size()
    }

    pub fn key_len(&self) -> usize {
        self.cipher.key_len()
    }

    fn crypt(&self, mode: Mode, key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
        let mut c = Crypter::new(self.cipher, mode, key, Some(iv)).map_err(e)?;
        c.pad(false);
        let mut out = vec![0u8; data.len() + self.cipher.block_size()];
        let n = c.update(data, &mut out).map_err(e)?;
        let r = c.finalize(&mut out[n..]).map_err(e)?;
        out.truncate(n + r);
        Ok(out)
    }

    pub fn encrypt(&self, key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
        self.crypt(Mode::Encrypt, key, data, iv)
    }

    pub fn decrypt(&self, key: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
        self.crypt(Mode::Decrypt, key, data, iv)
    }

    /// Verify the gateway's IKE signature: in IKEv1 SIG_R is the peer's private
    /// key applied to the already-computed HASH_R (PKCS#1 v1.5, no extra digest
    /// round). We RSA-public-decrypt and compare to the expected hash.
    pub fn verify_rsa_signature(&self, hash: &[u8], signature: &[u8], cert_der: &[u8]) -> Result<(), String> {
        let cert = X509::from_der(cert_der).map_err(e)?;
        let rsa = cert.public_key().map_err(e)?.rsa().map_err(e)?;
        let mut out = vec![0u8; rsa.size() as usize];
        let n = rsa
            .public_decrypt(signature, &mut out, Padding::PKCS1)
            .map_err(e)?;
        out.truncate(n);
        if out == hash {
            Ok(())
        } else {
            Err("IKE signature does not match HASH_R".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crypto() -> IkeCrypto {
        IkeCrypto::new(IKE_GROUP_MODP1024, IKE_HASH_SHA256, IKE_ENC_AES_CBC, 256).unwrap()
    }

    #[test]
    fn dh_group2_roundtrip() {
        let a = crypto();
        let b = crypto();
        let pa = a.public_key();
        let pb = b.public_key();
        assert_eq!(pa.len(), 128);
        assert_eq!(pb.len(), 128);
        let sa = a.shared_secret(&pb).unwrap();
        let sb = b.shared_secret(&pa).unwrap();
        assert_eq!(sa, sb, "DH shared secrets must agree");
        assert_eq!(sa.len(), 128);
    }

    #[test]
    fn prf_hmac_sha256_known_vector() {
        let c = crypto();
        // RFC-style known answer: HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog")
        let mac = c.prf(b"key", &[b"The quick brown fox jumps over the lazy dog"]);
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn aes256_cbc_roundtrip_no_pad() {
        let c = crypto();
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let pt = [0xabu8; 32]; // block-aligned
        let ct = c.encrypt(&key, &pt, &iv).unwrap();
        let back = c.decrypt(&key, &ct, &iv).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn sha256_hash_len() {
        assert_eq!(crypto().hash_len(), 32);
        assert_eq!(crypto().block_size(), 16);
        assert_eq!(crypto().key_len(), 32);
    }
}
