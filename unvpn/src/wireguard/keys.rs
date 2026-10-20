//! WireGuard keys: X25519 (via OpenSSL) and their base64 text form.

use openssl::pkey::{Id, PKey};

/// Fresh X25519 key pair (private, public).
pub fn generate() -> Result<([u8; 32], [u8; 32]), String> {
    let k = PKey::generate_x25519().map_err(|e| format!("x25519 keygen: {e}"))?;
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&k.raw_private_key().map_err(|e| e.to_string())?);
    Ok((sk, public(&sk)?))
}

/// Public key of an X25519 private key.
pub fn public(private: &[u8; 32]) -> Result<[u8; 32], String> {
    let k = PKey::private_key_from_raw_bytes(private, Id::X25519).map_err(|e| format!("bad private key: {e}"))?;
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&k.raw_public_key().map_err(|e| e.to_string())?);
    Ok(pk)
}

pub fn from_b64(s: &str) -> Result<[u8; 32], String> {
    let v = openssl::base64::decode_block(s.trim()).map_err(|_| "not valid base64".to_string())?;
    v.try_into().map_err(|_| "a WireGuard key is 32 bytes (44 base64 characters)".to_string())
}

pub fn to_b64(k: &[u8; 32]) -> String {
    openssl::base64::encode_block(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn rfc7748_public_key() {
        // RFC 7748 §6.1, Alice.
        let a: [u8; 32] = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").try_into().unwrap();
        let p = public(&a).unwrap();
        assert_eq!(p.to_vec(), unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    }

    #[test]
    fn b64_roundtrip_and_generate() {
        let (sk, pk) = generate().unwrap();
        assert_eq!(from_b64(&to_b64(&sk)).unwrap(), sk);
        assert_eq!(public(&sk).unwrap(), pk);
        assert!(from_b64("AAAA").is_err());
    }
}
