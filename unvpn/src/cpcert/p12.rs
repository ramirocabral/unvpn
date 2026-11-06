//! PKCS#12 files holding the enrolled identity.

use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::{X509NameRef, X509};

pub struct Identity {
    pub key: PKey<Private>,
    pub cert: X509,
    /// Remaining certificates of the file (the internal CA).
    pub chain: Vec<X509>,
}

/// `O=…,OU=…,CN=…` style one-line DN.
pub fn dn_string(name: &X509NameRef) -> String {
    let parts: Vec<String> = name
        .entries()
        .map(|e| {
            let k = e.object().nid().short_name().unwrap_or("?").to_string();
            let v = String::from_utf8_lossy(e.data().as_slice()).into_owned();
            format!("{k}={v}")
        })
        .collect();
    parts.join(",")
}

/// Serialize key + certificate (+ CA) in the widely readable layout: 3DES-
/// shrouded key, plain certificate bags, SHA-1 MAC.
pub fn build(password: &str, key: &PKey<Private>, cert: &X509, ca: Option<&X509>) -> Result<Vec<u8>, String> {
    let mut b = Pkcs12::builder();
    b.name(&dn_string(cert.subject_name()))
        .pkey(key)
        .cert(cert)
        .key_algorithm(Nid::PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC)
        .cert_algorithm(Nid::from_raw(-1))
        .mac_md(MessageDigest::sha1());
    if let Some(ca) = ca {
        let mut st = Stack::new().map_err(|e| e.to_string())?;
        st.push(ca.clone()).map_err(|e| e.to_string())?;
        b.ca(st);
    }
    let p = b.build2(password).map_err(|e| format!("building PKCS#12: {e}"))?;
    p.to_der().map_err(|e| e.to_string())
}

pub fn parse(der: &[u8], password: &str) -> Result<Identity, String> {
    let p = Pkcs12::from_der(der).map_err(|e| format!("not a PKCS#12 file: {e}"))?;
    let parsed = p.parse2(password).map_err(|_| "cannot open the certificate file (wrong password?)".to_string())?;
    let key = parsed.pkey.ok_or("the certificate file has no private key")?;
    let mut chain: Vec<X509> = parsed.ca.map(|s| s.into_iter().collect()).unwrap_or_default();
    let cert = match parsed.cert {
        Some(c) => c,
        None => {
            let our = key.public_key_to_der().map_err(|e| e.to_string())?;
            let i = chain
                .iter()
                .position(|c| c.public_key().and_then(|k| k.public_key_to_der()).map(|k| k == our).unwrap_or(false))
                .ok_or("the certificate file has no certificate for its key")?;
            chain.remove(i)
        }
    };
    let ours = cert.public_key().and_then(|k| k.public_key_to_der()).map_err(|e| e.to_string())?;
    if ours != key.public_key_to_der().map_err(|e| e.to_string())? {
        return Err("the certificate in the file does not match its private key".into());
    }
    Ok(Identity { key, cert, chain })
}

pub fn load(path: &str, password: &str) -> Result<Identity, String> {
    let der = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    parse(&der, password)
}
