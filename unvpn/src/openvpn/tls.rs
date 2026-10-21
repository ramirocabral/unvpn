//! TLS for the control channel: OpenSSL driven over in-memory buffers (the TLS
//! records travel inside reliable P_CONTROL_V1 packets, not on a socket).
//!
//! Server verification matches OpenVPN's: chain to the configured CA, then at
//! depth 0 `verify-x509-name` (subject / CN / CN-prefix) and `remote-cert-tls
//! server` (EKU must include TLS Web Server Authentication). There is NO hostname
//! check and no SNI — OpenVPN doesn't do either.

use super::config::{Config, X509Name};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509NameRef, X509Ref, X509};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// A bidirectional in-memory byte pipe standing in for the socket under `SslStream`.
#[derive(Default)]
pub struct MemPipe {
    pub rx: Vec<u8>,
    pub tx: Vec<u8>,
}

impl Read for MemPipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.rx.is_empty() {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        let n = buf.len().min(self.rx.len());
        buf[..n].copy_from_slice(&self.rx[..n]);
        self.rx.drain(..n);
        Ok(n)
    }
}

impl Write for MemPipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// What the verify callback saw about the server certificate (for the log/errors).
#[derive(Default, Clone, Debug)]
pub struct PeerInfo {
    pub subject: String,
    pub issuer: String,
    pub error: Option<String>,
}

pub struct ClientId {
    pub cert: Option<X509>,
    pub chain: Vec<X509>,
    pub key: Option<PKey<Private>>,
    pub p12_ca: Vec<X509>,
}

/// For PKCS#12 the empty password is tried before `key_pass` (the common case).
pub fn load_client_id(cfg: &Config, key_pass: Option<&str>) -> Result<ClientId, String> {
    let mut id = ClientId { cert: None, chain: Vec::new(), key: None, p12_ca: Vec::new() };
    if let Some(der) = &cfg.pkcs12 {
        let p = Pkcs12::from_der(der).map_err(|e| format!("pkcs12: {e}"))?;
        let parsed = p
            .parse2("")
            .or_else(|e| match key_pass {
                Some(pw) => p.parse2(pw),
                None => Err(e),
            })
            .map_err(|_| NEEDS_PASS.to_string())?;
        id.cert = parsed.cert;
        id.key = parsed.pkey;
        if let Some(ca) = parsed.ca {
            id.p12_ca = ca.into_iter().collect();
        }
    }
    if let Some(pem) = &cfg.cert {
        let mut certs = X509::stack_from_pem(pem.as_bytes()).map_err(|e| format!("cert: {e}"))?;
        if certs.is_empty() {
            return Err("cert: no certificate in PEM".into());
        }
        id.cert = Some(certs.remove(0));
        id.chain = certs;
    }
    if let Some(pem) = &cfg.key {
        let encrypted = pem.contains("ENCRYPTED");
        id.key = Some(if encrypted {
            let pw = key_pass.ok_or_else(|| NEEDS_PASS.to_string())?;
            PKey::private_key_from_pem_passphrase(pem.as_bytes(), pw.as_bytes())
                .map_err(|_| WRONG_PASS.to_string())?
        } else {
            PKey::private_key_from_pem(pem.as_bytes()).map_err(|e| format!("private key: {e}"))?
        });
    }
    Ok(id)
}

/// Sentinel error: the key / PKCS#12 needs a passphrase we don't have yet.
pub const NEEDS_PASS: &str = "private key is encrypted — passphrase required";
/// Sentinel error: the passphrase given doesn't decrypt the PEM key.
pub const WRONG_PASS: &str = "private key: wrong passphrase";

pub fn key_is_encrypted(cfg: &Config) -> bool {
    cfg.key.as_deref().is_some_and(|k| k.contains("ENCRYPTED"))
}

/// `peer` collects what verification saw.
pub fn build_context(cfg: &Config, id: &ClientId, peer: Arc<Mutex<PeerInfo>>) -> Result<SslContext, String> {
    let mut b = SslContextBuilder::new(SslMethod::tls_client()).map_err(|e| e.to_string())?;
    // OpenVPN's default `tls-cert-profile legacy` = OpenSSL security level 1.
    b.set_security_level(1);
    let min = match cfg.tls_version_min.as_deref() {
        Some("1.3") => SslVersion::TLS1_3,
        Some("1.0") => SslVersion::TLS1,
        Some("1.1") => SslVersion::TLS1_1,
        _ => SslVersion::TLS1_2,
    };
    b.set_min_proto_version(Some(min)).map_err(|e| e.to_string())?;

    // CA store: <ca>, else the CA certs bundled in the PKCS#12.
    let mut store = X509StoreBuilder::new().map_err(|e| e.to_string())?;
    let mut n_ca = 0;
    if let Some(pem) = &cfg.ca {
        for c in X509::stack_from_pem(pem.as_bytes()).map_err(|e| format!("ca: {e}"))? {
            store.add_cert(c).map_err(|e| format!("ca: {e}"))?;
            n_ca += 1;
        }
    }
    if n_ca == 0 {
        for c in &id.p12_ca {
            store.add_cert(c.clone()).map_err(|e| format!("ca: {e}"))?;
            n_ca += 1;
        }
    }
    if n_ca == 0 {
        return Err("no CA certificate (<ca> or pkcs12 CA) — cannot verify the server".into());
    }
    b.set_verify_cert_store(store.build()).map_err(|e| e.to_string())?;

    if let Some(c) = &id.cert {
        b.set_certificate(c).map_err(|e| format!("client cert: {e}"))?;
        for extra in &id.chain {
            b.add_extra_chain_cert(extra.clone()).map_err(|e| e.to_string())?;
        }
    }
    if let Some(k) = &id.key {
        b.set_private_key(k).map_err(|e| format!("client key: {e}"))?;
        b.check_private_key().map_err(|e| format!("client key does not match cert: {e}"))?;
    }

    let want_name = cfg.verify_x509.clone();
    let want_server = cfg.remote_cert_tls_server;
    b.set_verify_callback(SslVerifyMode::PEER, move |ok, ctx| {
        let depth = ctx.error_depth();
        let mut p = peer.lock().unwrap();
        if let Some(cert) = ctx.current_cert() {
            if depth == 0 {
                p.subject = subject_string(cert.subject_name());
                p.issuer = subject_string(cert.issuer_name());
            }
        }
        if !ok {
            p.error = Some(format!("certificate verify failed at depth {depth}: {}", ctx.error().error_string()));
            return false;
        }
        if depth != 0 {
            return true;
        }
        let Some(cert) = ctx.current_cert() else { return false };
        if let Some(w) = &want_name {
            if let Err(e) = check_name(cert, w) {
                p.error = Some(e);
                return false;
            }
        }
        if want_server && !has_server_eku(cert) {
            p.error = Some("remote-cert-tls server: certificate lacks the TLS Web Server Authentication EKU".into());
            return false;
        }
        true
    });
    Ok(b.build())
}

/// OpenVPN's subject format: `C=AR, ST=…, O=…, emailAddress=…, CN=…` (cert order).
pub fn subject_string(n: &X509NameRef) -> String {
    n.entries()
        .map(|e| {
            let key = e.object().nid().short_name().unwrap_or("?");
            let val = e.data().to_string().unwrap_or_default();
            format!("{key}={val}")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn common_name(n: &X509NameRef) -> Option<String> {
    n.entries_by_nid(openssl::nid::Nid::COMMONNAME).next().and_then(|e| e.data().to_string().ok())
}

fn check_name(cert: &X509Ref, want: &X509Name) -> Result<(), String> {
    let subj = subject_string(cert.subject_name());
    let cn = common_name(cert.subject_name()).unwrap_or_default();
    let ok = match want {
        X509Name::Subject(s) => normalize_dn(&subj) == normalize_dn(s),
        X509Name::Name(s) => &cn == s,
        X509Name::NamePrefix(s) => cn.starts_with(s.as_str()),
    };
    if ok {
        Ok(())
    } else {
        Err(format!("verify-x509-name mismatch: server is \"{subj}\", expected {want:?}"))
    }
}

/// Compare DNs loosely on separators (`a=b,c=d` vs `a=b, c=d`).
fn normalize_dn(s: &str) -> String {
    s.split(',').map(str::trim).collect::<Vec<_>>().join(",")
}

fn has_server_eku(cert: &X509Ref) -> bool {
    // openssl-the-crate exposes no EKU accessor; the text dump is stable enough.
    let Ok(t) = cert.to_text() else { return false };
    let t = String::from_utf8_lossy(&t);
    let Some(i) = t.find("X509v3 Extended Key Usage") else { return false };
    t[i..].lines().nth(1).is_some_and(|l| l.contains("TLS Web Server Authentication"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dn_normalization() {
        assert_eq!(normalize_dn("C=AR, ST=Buenos Aires, CN=x"), normalize_dn("C=AR,ST=Buenos Aires,CN=x"));
    }

    #[test]
    fn mem_pipe() {
        let mut p = MemPipe::default();
        let mut b = [0u8; 4];
        assert_eq!(p.read(&mut b).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        p.rx.extend_from_slice(b"abcdef");
        assert_eq!(p.read(&mut b).unwrap(), 4);
        assert_eq!(&p.rx, b"ef");
        p.write_all(b"xy").unwrap();
        assert_eq!(&p.tx, b"xy");
    }
}
