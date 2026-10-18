//! IKEv1 session key schedule (RFC 2409 §5) for the initiator role.
//!
//! Derives SKEYID / SKEYID_{d,a,e} from the DH shared secret and nonces, keeps
//! the CBC IV chain per message-id, and computes HASH_I / HASH_R and the ESP
//! KEYMAT. Ported from the `isakmp` crate's `ikev1/session.rs`.

use std::collections::HashMap;

use super::crypto::{random, random_u64, IkeCrypto};

pub struct Ikev1Session {
    crypto: Option<IkeCrypto>,
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub initiator_pubkey: Vec<u8>,
    pub responder_pubkey: Vec<u8>,
    pub initiator_nonce: Vec<u8>,
    pub responder_nonce: Vec<u8>,
    pub shared_secret: Vec<u8>,
    pub skeyid: Vec<u8>,
    pub skeyid_d: Vec<u8>,
    pub skeyid_a: Vec<u8>,
    pub skeyid_e: Vec<u8>,
    /// The SA payload *body* we sent in Main Mode msg 1 (SAi_b), hashed into
    /// HASH_I / HASH_R.
    pub sa_bytes: Vec<u8>,
    iv: HashMap<u32, Vec<u8>>,
}

impl Default for Ikev1Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Ikev1Session {
    pub fn new() -> Self {
        let mut spi = random_u64();
        if spi == 0 {
            spi = 1;
        }
        Ikev1Session {
            crypto: None,
            initiator_spi: spi,
            responder_spi: 0,
            initiator_pubkey: Vec::new(),
            responder_pubkey: Vec::new(),
            initiator_nonce: random(32),
            responder_nonce: Vec::new(),
            shared_secret: Vec::new(),
            skeyid: Vec::new(),
            skeyid_d: Vec::new(),
            skeyid_a: Vec::new(),
            skeyid_e: Vec::new(),
            sa_bytes: Vec::new(),
            iv: HashMap::new(),
        }
    }

    fn crypto(&self) -> &IkeCrypto {
        self.crypto.as_ref().expect("IKE crypto not initialised")
    }

    /// Set up the negotiated Phase-1 suite and generate our DH keypair.
    pub fn set_suite(&mut self, group: u16, hash: u16, enc: u16, key_bits: usize) -> Result<(), String> {
        let c = IkeCrypto::new(group, hash, enc, key_bits)?;
        self.initiator_pubkey = c.public_key();
        self.crypto = Some(c);
        Ok(())
    }

    pub fn set_sa_bytes(&mut self, sa: &[u8]) {
        self.sa_bytes = sa.to_vec();
    }

    pub fn block_size(&self) -> usize {
        self.crypto().block_size()
    }

    pub fn hash_len(&self) -> usize {
        self.crypto().hash_len()
    }

    /// Derive the full key schedule from the responder's KE + nonce.
    pub fn compute_keys(&mut self, responder_pubkey: &[u8], responder_nonce: &[u8]) -> Result<(), String> {
        self.responder_pubkey = responder_pubkey.to_vec();
        self.responder_nonce = responder_nonce.to_vec();

        let secret = self.crypto().shared_secret(responder_pubkey)?;
        self.shared_secret = secret;

        // SKEYID = prf(Ni_b | Nr_b, g^xy)  (signature / hybrid auth)
        let mut nonce_key = self.initiator_nonce.clone();
        nonce_key.extend_from_slice(&self.responder_nonce);
        self.skeyid = self.crypto().prf(&nonce_key, &[&self.shared_secret]);

        // SKEYID_{d,a,e}: seed_i = prf(SKEYID, seed_{i-1} | g^xy | CKY-I | CKY-R | i)
        let hlen = self.hash_len();
        let mut data = Vec::new();
        let mut seed: Vec<u8> = Vec::new();
        for i in 0..3u8 {
            seed = self.crypto().prf(
                &self.skeyid,
                &[
                    &seed,
                    &self.shared_secret,
                    &self.initiator_spi.to_be_bytes(),
                    &self.responder_spi.to_be_bytes(),
                    &[i],
                ],
            );
            data.extend_from_slice(&seed);
        }
        self.skeyid_d = data[0..hlen].to_vec();
        self.skeyid_a = data[hlen..hlen * 2].to_vec();

        // SKEYID_e, expanded if the cipher key is longer than the hash output.
        let key_len = self.crypto().key_len();
        let mut skeyid_e = data[hlen * 2..].to_vec();
        if skeyid_e.len() < key_len {
            let mut expanded = Vec::new();
            let mut s = vec![0u8];
            while expanded.len() < key_len {
                s = self.crypto().prf(&skeyid_e, &[&s]);
                expanded.extend_from_slice(&s);
            }
            expanded.truncate(key_len);
            skeyid_e = expanded;
        } else {
            skeyid_e.truncate(key_len);
        }
        self.skeyid_e = skeyid_e;

        // Initial IV = hash(g^xi | g^xr) truncated to the block size.
        let mut iv0 = self
            .crypto()
            .hash(&[&self.initiator_pubkey, &self.responder_pubkey]);
        iv0.truncate(self.block_size());
        self.iv.insert(0, iv0);

        Ok(())
    }

    fn retrieve_iv(&mut self, message_id: u32) -> Vec<u8> {
        let iv0 = self.iv.get(&0).expect("IV0 not initialised").clone();
        if let Some(iv) = self.iv.get(&message_id) {
            return iv.clone();
        }
        let mut h = self.crypto().hash(&[&iv0, &message_id.to_be_bytes()]);
        h.truncate(self.block_size());
        self.iv.insert(message_id, h.clone());
        h
    }

    /// Encrypt a payload chain for `message_id`, advancing the CBC IV chain.
    pub fn encrypt(&mut self, message_id: u32, data: &[u8]) -> Result<Vec<u8>, String> {
        let iv = self.retrieve_iv(message_id);
        let enc = self.crypto().encrypt(&self.skeyid_e, data, &iv)?;
        let bs = self.block_size();
        self.iv.insert(message_id, enc[enc.len() - bs..].to_vec());
        Ok(enc)
    }

    /// Decrypt a payload chain for `message_id`, advancing the CBC IV chain.
    pub fn decrypt(&mut self, message_id: u32, data: &[u8]) -> Result<Vec<u8>, String> {
        let iv = self.retrieve_iv(message_id);
        let dec = self.crypto().decrypt(&self.skeyid_e, data, &iv)?;
        let bs = self.block_size();
        self.iv.insert(message_id, data[data.len() - bs..].to_vec());
        Ok(dec)
    }

    /// HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)
    pub fn hash_id_i(&self, id_body: &[u8]) -> Vec<u8> {
        self.crypto().prf(
            &self.skeyid,
            &[
                &self.initiator_pubkey,
                &self.responder_pubkey,
                &self.initiator_spi.to_be_bytes(),
                &self.responder_spi.to_be_bytes(),
                &self.sa_bytes,
                id_body,
            ],
        )
    }

    /// HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b)
    pub fn hash_id_r(&self, id_body: &[u8]) -> Vec<u8> {
        self.crypto().prf(
            &self.skeyid,
            &[
                &self.responder_pubkey,
                &self.initiator_pubkey,
                &self.responder_spi.to_be_bytes(),
                &self.initiator_spi.to_be_bytes(),
                &self.sa_bytes,
                id_body,
            ],
        )
    }

    pub fn prf(&self, key: &[u8], data: &[&[u8]]) -> Vec<u8> {
        self.crypto().prf(key, data)
    }

    /// Plain digest with the negotiated hash (for NAT-D payloads).
    pub fn hash(&self, data: &[&[u8]]) -> Vec<u8> {
        self.crypto().hash(data)
    }

    pub fn verify_rsa_signature(&self, hash: &[u8], sig: &[u8], cert_der: &[u8]) -> Result<(), String> {
        self.crypto().verify_rsa_signature(hash, sig, cert_der)
    }

    /// ESP KEYMAT = prf(SKEYID_d, seed | [proto=ESP(3)] | SPI | Ni | Nr),
    /// expanded to `need` bytes (RFC 2409 §5.5).
    pub fn gen_esp_keymat(&self, spi: u32, nonce_i: &[u8], nonce_r: &[u8], need: usize) -> Vec<u8> {
        let mut data = Vec::new();
        let mut seed: Vec<u8> = Vec::new();
        while data.len() < need {
            seed = self.crypto().prf(
                &self.skeyid_d,
                &[&seed, &[3], &spi.to_be_bytes(), nonce_i, nonce_r],
            );
            data.extend_from_slice(&seed);
        }
        data.truncate(need);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::*;
    use super::*;

    /// Build an initiator session and derive keys against a second DH keypair
    /// standing in for the responder, exercising the full schedule.
    fn derived_session() -> Ikev1Session {
        let mut s = Ikev1Session::new();
        s.responder_spi = 0x0102030405060708;
        s.set_suite(IKE_GROUP_MODP1024, IKE_HASH_SHA256, IKE_ENC_AES_CBC, 256)
            .unwrap();
        s.set_sa_bytes(&[0xde, 0xad, 0xbe, 0xef]);
        // Stand-in responder keypair.
        let peer = IkeCrypto::new(IKE_GROUP_MODP1024, IKE_HASH_SHA256, IKE_ENC_AES_CBC, 256).unwrap();
        s.compute_keys(&peer.public_key(), &random(32)).unwrap();
        s
    }

    #[test]
    fn key_schedule_lengths() {
        let s = derived_session();
        assert_eq!(s.shared_secret.len(), 128);
        assert_eq!(s.skeyid.len(), 32); // SHA-256
        assert_eq!(s.skeyid_d.len(), 32);
        assert_eq!(s.skeyid_a.len(), 32);
        assert_eq!(s.skeyid_e.len(), 32); // AES-256 key
        assert_eq!(s.hash_id_i(b"id").len(), 32);
        assert_eq!(s.hash_id_r(b"id").len(), 32);
    }

    #[test]
    fn iv_chaining_and_cbc_roundtrip() {
        let mut enc_s = derived_session();
        // Clone the key material into a decrypt session with the same IV0.
        let mut dec_s = Ikev1Session::new();
        dec_s.responder_spi = enc_s.responder_spi;
        dec_s.set_suite(IKE_GROUP_MODP1024, IKE_HASH_SHA256, IKE_ENC_AES_CBC, 256)
            .unwrap();
        dec_s.skeyid_e = enc_s.skeyid_e.clone();
        dec_s.iv.insert(0, enc_s.iv.get(&0).unwrap().clone());

        let pt = [0x5au8; 48]; // 3 blocks
        let ct = enc_s.encrypt(0, &pt).unwrap();
        let back = dec_s.decrypt(0, &ct).unwrap();
        assert_eq!(back, pt);

        // After one block-cipher op the chained IV is the last ciphertext block.
        let bs = enc_s.block_size();
        assert_eq!(enc_s.iv.get(&0).unwrap(), &ct[ct.len() - bs..]);
    }

    #[test]
    fn esp_keymat_is_deterministic_and_sized() {
        let s = derived_session();
        let k1 = s.gen_esp_keymat(0x11223344, b"ni", b"nr", 36);
        let k2 = s.gen_esp_keymat(0x11223344, b"ni", b"nr", 36);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 36);
        // Different SPI → different keymat.
        assert_ne!(k1, s.gen_esp_keymat(0x55667788, b"ni", b"nr", 36));
    }
}
