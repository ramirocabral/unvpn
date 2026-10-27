//! Import connection settings from a FortiClient configuration file
//! (`<forticlient_configuration>` XML), including the obfuscated group pre-shared key.

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};

/// Obfuscation key for FortiClient `Enc` fields (constant across builds).
const ENC_KEY: &[u8] = b"fc_1A2Brown3Fox4Jumped5Over6A7Lazy8Dog";

const SALT_LEN: usize = 12;
const KEY_LEN: usize = 24;
const MAC_LEN: usize = 10;

/// IPsec connection settings parsed from a FortiClient config file.
#[derive(Debug, Clone, Default)]
pub struct FctProfile {
    pub name: String,
    pub server: String,
    pub udp_port: u16,
    pub localid: String,
    /// Group pre-shared key, de-obfuscated.
    pub psk: String,
    pub auth_method: String,
    pub eap_method: String,
    pub fctver: String,
    pub proposals: Vec<String>,
    pub dhgroup: String,
}

/// Parse the first IPsec connection from a `<forticlient_configuration>` XML.
pub fn parse(xml: &str) -> Result<FctProfile, String> {
    let ipsec = between(xml, "<ipsecvpn>", "</ipsecvpn>")
        .ok_or("no <ipsecvpn> section in the config")?;
    let conn = between(ipsec, "<connection>", "</connection>")
        .ok_or("no IPsec <connection> in the config")?;
    let ike = between(conn, "<ike_settings>", "</ike_settings>")
        .ok_or("no <ike_settings> in the IPsec connection")?;

    let mut p = FctProfile {
        name: tag(conn, "name").unwrap_or("").to_string(),
        server: tag(ike, "server").unwrap_or("").to_string(),
        udp_port: tag(ike, "udp_port").and_then(|s| s.parse().ok()).unwrap_or(500),
        localid: tag(ike, "localid").unwrap_or("").to_string(),
        auth_method: tag(ike, "authentication_method").unwrap_or("").to_string(),
        eap_method: tag(ike, "eap_method").unwrap_or("").to_string(),
        dhgroup: tag(ike, "dhgroup").unwrap_or("").to_string(),
        fctver: tag(xml, "forticlient_version").unwrap_or("").to_string(),
        proposals: Vec::new(),
        psk: String::new(),
    };

    if let Some(props) = between(ike, "<proposals>", "</proposals>") {
        let mut rest = props;
        while let Some(v) = tag(rest, "proposal") {
            p.proposals.push(v.to_string());
            match rest.find("</proposal>") {
                Some(i) => rest = &rest[i + "</proposal>".len()..],
                None => break,
            }
        }
    }

    if p.server.is_empty() {
        return Err("IPsec connection has no <server>".into());
    }

    if let Some(enc) = tag(ike, "preshared_key") {
        if !enc.trim().is_empty() {
            p.psk = decrypt_enc(enc)
                .map_err(|e| format!("decrypt preshared_key: {e}"))?;
        }
    }

    Ok(p)
}

/// De-obfuscate an `Enc <hex>` FortiClient field.
///
/// WinZip-AES-192: `salt(12) ‖ pwd_verify(2) ‖ ciphertext ‖ HMAC-SHA1_trunc10`, keys
/// from `PBKDF2-HMAC-SHA1(ENC_KEY, salt, 1000)` as `enc(24) ‖ mac(24) ‖ verify(2)`,
/// ciphertext in AES-192 counter mode with a little-endian counter from 1.
pub fn decrypt_enc(field: &str) -> Result<String, String> {
    let hex = field
        .trim()
        .split_once(' ')
        .map(|(_, h)| h.trim())
        .ok_or("not an 'Enc <hex>' field")?;
    let raw = hex_decode(hex)?;

    if raw.len() < SALT_LEN + 2 + MAC_LEN {
        return Err("Enc blob too short".into());
    }
    let salt = &raw[..SALT_LEN];
    let pwd_verify = &raw[SALT_LEN..SALT_LEN + 2];
    let ct = &raw[SALT_LEN + 2..raw.len() - MAC_LEN];
    let mac = &raw[raw.len() - MAC_LEN..];

    let mut dk = [0u8; KEY_LEN + KEY_LEN + 2];
    openssl::pkcs5::pbkdf2_hmac(ENC_KEY, salt, 1000, MessageDigest::sha1(), &mut dk)
        .map_err(|e| e.to_string())?;
    let enc_key = &dk[..KEY_LEN];
    let mac_key = &dk[KEY_LEN..2 * KEY_LEN];
    if &dk[2 * KEY_LEN..] != pwd_verify {
        return Err("password verifier mismatch (not an Enc field, or corrupt)".into());
    }

    let pkey = PKey::hmac(mac_key).map_err(|e| e.to_string())?;
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey).map_err(|e| e.to_string())?;
    signer.update(ct).map_err(|e| e.to_string())?;
    let tag = signer.sign_to_vec().map_err(|e| e.to_string())?;
    if tag.get(..MAC_LEN) != Some(mac) {
        return Err("authentication tag mismatch".into());
    }

    let plain = aes192_ctr(enc_key, ct)?;
    String::from_utf8(plain).map_err(|_| "decrypted PSK is not valid UTF-8".into())
}

/// AES-192 counter mode with a little-endian 128-bit counter from 1. The keystream
/// is generated block-by-block (OpenSSL's native CTR uses a big-endian counter).
fn aes192_ctr(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let e = |e: openssl::error::ErrorStack| e.to_string();
    let mut out = Vec::with_capacity(data.len());
    for (i, block) in data.chunks(16).enumerate() {
        let mut ctr = [0u8; 16];
        ctr[..8].copy_from_slice(&((i as u64) + 1).to_le_bytes());
        let mut c = Crypter::new(Cipher::aes_192_ecb(), Mode::Encrypt, key, None).map_err(e)?;
        c.pad(false);
        let mut ks = vec![0u8; 16 + Cipher::aes_192_ecb().block_size()];
        let n = c.update(&ctr, &mut ks).map_err(e)?;
        c.finalize(&mut ks[n..]).map_err(e)?;
        for (o, k) in block.iter().zip(&ks[..16]) {
            out.push(o ^ k);
        }
    }
    Ok(out)
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = s.find(open)? + open.len();
    let end = s[start..].find(close)? + start;
    Some(&s[start..end])
}

fn tag<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    between(s, &open, &close)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "bad hex digit".to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // "hello-unvpn-123!" encrypted with ENC_KEY and a fixed salt.
    const KAT_BLOB: &str = "Enc 000102030405060708090a0b1397109e333438abbb37e7196d70f7b9f570503266d32a549f1da19d";

    #[test]
    fn decrypt_known_answer() {
        assert_eq!(decrypt_enc(KAT_BLOB).unwrap(), "hello-unvpn-123!");
    }

    #[test]
    fn decrypt_rejects_wrong_blob() {
        let mut v: Vec<char> = KAT_BLOB.chars().collect();
        let i = "Enc ".len() + (12 + 2) * 2 + 2;
        v[i] = if v[i] == 'a' { 'b' } else { 'a' };
        let tampered: String = v.into_iter().collect();
        assert!(decrypt_enc(&tampered).is_err());
    }

    #[test]
    fn parse_minimal_ipsec_config() {
        let xml = format!(
            "<forticlient_configuration><forticlient_version>7.9.9.9999</forticlient_version>\
             <vpn><ipsecvpn><connections><connection><name>TEST_VPN</name>\
             <ike_settings><version>2</version>\
             <authentication_method>Preshared Key</authentication_method>\
             <eap_method>1</eap_method><server>vpn.example.com</server>\
             <localid>somegroup</localid><udp_port>500</udp_port><dhgroup>14</dhgroup>\
             <auth_data><preshared_key>{KAT_BLOB}</preshared_key></auth_data>\
             <proposals><proposal>AES128|SHA256</proposal><proposal>AES256|SHA256</proposal></proposals>\
             </ike_settings></connection></connections></ipsecvpn></vpn></forticlient_configuration>"
        );
        let p = parse(&xml).unwrap();
        assert_eq!(p.name, "TEST_VPN");
        assert_eq!(p.server, "vpn.example.com");
        assert_eq!(p.localid, "somegroup");
        assert_eq!(p.udp_port, 500);
        assert_eq!(p.eap_method, "1");
        assert_eq!(p.fctver, "7.9.9.9999");
        assert_eq!(p.psk, "hello-unvpn-123!");
        assert_eq!(p.proposals, vec!["AES128|SHA256", "AES256|SHA256"]);
    }
}
