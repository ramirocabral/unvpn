//! ESP data plane (RFC 4303, tunnel mode) over UDP-encap (NAT-T, port 4500).
//!
//! A raw ESP packet is `SPI(4) | Seq(4) | IV | ciphertext | ICV`; the SPI (never
//! zero) distinguishes it from an IKE message sharing the port. The ICV is
//! HMAC over `SPI | Seq | IV | ciphertext`, truncated. Inner payload is a whole
//! IPv4 packet (next_header = 4). Ported from the `isakmp` crate's `esp.rs`.

use std::sync::atomic::{AtomicU32, Ordering};

use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rand::rand_bytes,
    sign::Signer,
    symm::{Cipher, Crypter, Mode},
};

use super::model::*;

fn e<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

/// One bidirectional ESP security association.
pub struct EspSa {
    pub spi_in: u32,
    pub spi_out: u32,
    enc_in: Vec<u8>,
    auth_in: Vec<u8>,
    enc_out: Vec<u8>,
    auth_out: Vec<u8>,
    cipher: Cipher,
    digest: MessageDigest,
    iv_len: usize,
    icv_len: usize,
    seq: AtomicU32,
}

impl EspSa {
    /// Build from the negotiated transform + the two directional key materials
    /// (each `enc_key || auth_key`).
    pub fn new(
        transform_id: u8,
        auth_alg: u16,
        key_bits: usize,
        spi_in: u32,
        km_in: &[u8],
        spi_out: u32,
        km_out: &[u8],
    ) -> Result<Self, String> {
        let (cipher, enc_len, iv_len) = if transform_id == u8::from(TransformId::Esp3Des) {
            (Cipher::des_ede3_cbc(), 24usize, 8usize)
        } else if transform_id == u8::from(TransformId::EspAesCbc) {
            match key_bits {
                128 => (Cipher::aes_128_cbc(), 16, 16),
                192 => (Cipher::aes_192_cbc(), 24, 16),
                _ => (Cipher::aes_256_cbc(), 32, 16),
            }
        } else {
            return Err(format!("unsupported ESP transform id {transform_id}"));
        };

        let (digest, auth_len, icv_len) = match auth_alg {
            ESP_AUTH_HMAC_SHA96 => (MessageDigest::sha1(), 20usize, 12usize),
            ESP_AUTH_HMAC_SHA160 => (MessageDigest::sha1(), 20, 20),
            ESP_AUTH_HMAC_SHA256 | ESP_AUTH_HMAC_SHA256_V2 => (MessageDigest::sha256(), 32, 16),
            other => return Err(format!("unsupported ESP auth alg {other}")),
        };

        if km_in.len() < enc_len + auth_len || km_out.len() < enc_len + auth_len {
            return Err("ESP key material too short".into());
        }

        Ok(EspSa {
            spi_in,
            spi_out,
            enc_in: km_in[..enc_len].to_vec(),
            auth_in: km_in[enc_len..enc_len + auth_len].to_vec(),
            enc_out: km_out[..enc_len].to_vec(),
            auth_out: km_out[enc_len..enc_len + auth_len].to_vec(),
            cipher,
            digest,
            iv_len,
            icv_len,
            seq: AtomicU32::new(1),
        })
    }

    fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let pkey = PKey::hmac(key).expect("hmac key");
        let mut s = Signer::new(self.digest, &pkey).expect("signer");
        s.update(data).expect("update");
        let mut mac = s.sign_to_vec().expect("sign");
        mac.truncate(self.icv_len);
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

    /// Wrap an inner IPv4 packet into an outbound ESP packet.
    pub fn encode(&self, inner_ip: &[u8]) -> Result<Vec<u8>, String> {
        let block = self.cipher.block_size();
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);

        // RFC 4303 trailer: pad so (payload + padlen + nexthdr) aligns to block.
        let pad_len = (block - ((inner_ip.len() + 2) % block)) % block;
        let mut plain = Vec::with_capacity(inner_ip.len() + pad_len + 2);
        plain.extend_from_slice(inner_ip);
        for i in 1..=pad_len as u8 {
            plain.push(i);
        }
        plain.push(pad_len as u8);
        plain.push(4); // next header = IPv4 (tunnel mode)

        let mut iv = vec![0u8; self.iv_len];
        rand_bytes(&mut iv).map_err(e)?;
        let ct = self.cbc(Mode::Encrypt, &self.enc_out, &iv, &plain)?;

        let mut esp = Vec::with_capacity(8 + iv.len() + ct.len() + self.icv_len);
        esp.extend_from_slice(&self.spi_out.to_be_bytes());
        esp.extend_from_slice(&seq.to_be_bytes());
        esp.extend_from_slice(&iv);
        esp.extend_from_slice(&ct);
        let icv = self.hmac(&self.auth_out, &esp); // over SPI|Seq|IV|ct
        esp.extend_from_slice(&icv);
        Ok(esp)
    }

    /// Unwrap an inbound ESP packet into the inner IPv4 packet.
    pub fn decode(&self, esp: &[u8]) -> Result<Vec<u8>, String> {
        if esp.len() < 8 + self.iv_len + self.icv_len {
            return Err("ESP packet too short".into());
        }
        let spi = u32::from_be_bytes(esp[0..4].try_into().unwrap());
        if spi != self.spi_in {
            return Err(format!("ESP SPI {spi:#x} != ours {:#x}", self.spi_in));
        }
        let (signed, icv) = esp.split_at(esp.len() - self.icv_len);
        if self.hmac(&self.auth_in, signed) != icv {
            return Err("ESP ICV mismatch".into());
        }
        let iv = &signed[8..8 + self.iv_len];
        let ct = &signed[8 + self.iv_len..];
        let plain = self.cbc(Mode::Decrypt, &self.enc_in, iv, ct)?;
        if plain.len() < 2 {
            return Err("ESP plaintext too short".into());
        }
        let pad_len = plain[plain.len() - 2] as usize;
        if plain.len() < pad_len + 2 {
            return Err("ESP bad padding length".into());
        }
        Ok(plain[..plain.len() - pad_len - 2].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esp_3des_sha96_roundtrip() {
        // Loopback SA: same keys/SPI both directions.
        let km = vec![7u8; 44]; // 24 enc + 20 auth
        let sa = EspSa::new(
            u8::from(TransformId::Esp3Des),
            ESP_AUTH_HMAC_SHA96,
            0,
            0x11223344,
            &km,
            0x11223344,
            &km,
        )
        .unwrap();
        for len in [20usize, 21, 40, 1400] {
            let inner: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let esp = sa.encode(&inner).unwrap();
            assert!(esp.len() >= 8 + 8 + 12);
            let back = sa.decode(&esp).unwrap();
            assert_eq!(back, inner, "roundtrip len {len}");
        }
    }

    #[test]
    fn esp_aes256_sha256_roundtrip() {
        let km = vec![9u8; 64]; // 32 enc + 32 auth
        let sa = EspSa::new(
            u8::from(TransformId::EspAesCbc),
            ESP_AUTH_HMAC_SHA256,
            256,
            0xaabbccdd,
            &km,
            0xaabbccdd,
            &km,
        )
        .unwrap();
        let inner: Vec<u8> = (0..100).map(|i| (i * 3) as u8).collect();
        let esp = sa.encode(&inner).unwrap();
        assert_eq!(sa.decode(&esp).unwrap(), inner);
    }

    #[test]
    fn esp_rejects_tampered_icv() {
        let km = vec![3u8; 44];
        let sa = EspSa::new(u8::from(TransformId::Esp3Des), ESP_AUTH_HMAC_SHA96, 0, 1, &km, 1, &km).unwrap();
        let mut esp = sa.encode(&[1, 2, 3, 4]).unwrap();
        let n = esp.len();
        esp[n - 1] ^= 0xff; // corrupt ICV
        assert!(sa.decode(&esp).is_err());
    }
}
