//! `unvpn cp-enroll`: obtain a user certificate from the Check Point internal CA
//! with a one-time registration key.
//!
//! The registration key can be used once, so every step that cannot be redone is
//! made recoverable: the new key and the exact request are stored (key encrypted
//! with the chosen password) before anything is sent, and the CA's raw answer is
//! stored before it is interpreted. A failed run is continued with `--resume`
//! (re-reads the stored answer) or `--resend` (sends the identical request again).

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use openssl::x509::X509;

use super::cmc::{self, RegKey};
use super::{p12, rfc1751};
use crate::net::http::{self, Framing};

pub const ICA_PORT: u16 = 18264;
const MIN_PASSWORD_LEN: usize = 6;

/// The internal CA fingerprint as Check Point displays it.
pub fn ca_fingerprint(cert: &X509) -> String {
    let d = cert
        .digest(MessageDigest::sha1())
        .map(|d| d.to_vec())
        .unwrap_or_default();
    let mut k = [0u8; 16];
    k.copy_from_slice(&d[..16]);
    rfc1751::key_to_english(&k)
}

/// The enrollment HTTP request, headers exactly in this form (misspellings included).
pub fn http_request(host: &str, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "POST /registration HTTP/1.0\r\nConnection: Keep-Alive\r\nHost: {host}\r\nAccept: */*\r\n\
         Accpet-Language: en\r\nContent-Length: {}\r\nContent-Type: application/pkcs7-mime\r\n\
         Accpet-Charset: iso-8859-1,*,utf-8\r\n\r\n",
        body.len()
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

/// Split a raw HTTP response into (status code, body).
pub fn http_body(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let head_end = http::head_end(raw)
        .or_else(|| find(raw, b"\n\n").map(|i| i + 2))
        .ok_or("no HTTP header in the CA answer")?;
    let (code, headers) =
        http::parse_head(&raw[..head_end]).map_err(|e| format!("CA answer: {e}"))?;
    let rest = &raw[head_end..];
    let body = match http::body_framing(&headers) {
        Framing::Chunked => http::dechunk(rest).ok_or("truncated chunked body")?,
        Framing::Length(n) => rest
            .get(..n)
            .ok_or(format!(
                "CA answer truncated ({} of {n} body bytes)",
                rest.len()
            ))?
            .to_vec(),
        Framing::Close => rest.to_vec(),
    };
    Ok((code, body))
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Whether a raw HTTP response is complete (to stop reading on a kept-alive socket).
fn response_complete(raw: &[u8]) -> bool {
    let Some(i) = http::head_end(raw) else {
        return false;
    };
    let Ok((_, headers)) = http::parse_head(&raw[..i]) else {
        return false;
    };
    match http::body_framing(&headers) {
        Framing::Length(n) => raw.len() >= i + n,
        Framing::Chunked => http::dechunk(&raw[i..]).is_some(),
        Framing::Close => false,
    }
}

fn post(host: &str, port: u16, request: &[u8], raw_out: &Path) -> Result<Vec<u8>, String> {
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolving {host}: {e}"))?
        .next()
        .ok_or(format!("cannot resolve {host}"))?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(15))
        .map_err(|e| format!("cannot reach the internal CA at {addr}: {e}"))?;
    s.set_write_timeout(Some(Duration::from_secs(30))).ok();
    s.write_all(request)
        .map_err(|e| format!("sending the request: {e}"))?;
    println!(
        "# request sent ({} bytes); waiting for the CA...",
        request.len()
    );

    let start = Instant::now();
    let mut raw = Vec::new();
    let mut buf = [0u8; 16384];
    s.set_read_timeout(Some(Duration::from_secs(2))).ok();
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                write_private(raw_out, &raw)?;
                if response_complete(&raw) {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                let waited = start.elapsed();
                if !raw.is_empty()
                    && waited > Duration::from_secs(10)
                    && http::head_end(&raw).is_some()
                {
                    break;
                }
                if waited > Duration::from_secs(120) {
                    break;
                }
            }
            Err(e) => {
                if raw.is_empty() {
                    return Err(format!("reading the CA answer: {e}"));
                }
                break;
            }
        }
    }
    if raw.is_empty() {
        return Err("the internal CA closed the connection without answering".into());
    }
    Ok(raw)
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(data)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

struct Staging {
    dir: PathBuf,
}

impl Staging {
    fn new(out: &Path) -> Staging {
        let mut d = out.as_os_str().to_owned();
        d.push(".enroll");
        Staging {
            dir: PathBuf::from(d),
        }
    }
    fn key(&self) -> PathBuf {
        self.dir.join("key.pem")
    }
    fn request(&self) -> PathBuf {
        self.dir.join("request.der")
    }
    fn raw(&self) -> PathBuf {
        self.dir.join("response.http")
    }
    fn exists(&self) -> bool {
        self.key().exists()
    }
    fn create(&self) -> Result<(), String> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(|e| format!("{}: {e}", self.dir.display()))
    }
}

pub struct Options {
    pub gateway: String,
    pub port: u16,
    pub regkey: RegKey,
    pub out: PathBuf,
    pub password: String,
    pub key_bits: u32,
    pub resume: bool,
    pub resend: bool,
    pub trust_ca: bool,
    /// CA fingerprints the gateway advertises (RFC 1751 words).
    pub expected_ca: Vec<String>,
}

/// Run (or continue) an enrollment. Returns the issued certificate's subject.
pub fn run(o: &Options) -> Result<String, String> {
    let st = Staging::new(&o.out);
    if o.out.exists() && !st.exists() {
        return Err(format!(
            "{} already exists; choose another file name",
            o.out.display()
        ));
    }

    let (key, request) = if st.exists() {
        let pem = std::fs::read(st.key()).map_err(|e| format!("{}: {e}", st.key().display()))?;
        let key =
            PKey::private_key_from_pem_passphrase(&pem, o.password.as_bytes()).map_err(|_| {
                "cannot open the stored enrollment key (different password than the first attempt?)"
            })?;
        let request =
            std::fs::read(st.request()).map_err(|e| format!("{}: {e}", st.request().display()))?;
        println!("# continuing the enrollment stored in {}", st.dir.display());
        (key, request)
    } else {
        if o.resume || o.resend {
            return Err(format!(
                "nothing to continue: {} does not exist",
                st.dir.display()
            ));
        }
        let rsa = Rsa::generate(o.key_bits).map_err(|e| e.to_string())?;
        let key = PKey::from_rsa(rsa).map_err(|e| e.to_string())?;
        let request = cmc::build_request(&key, &o.regkey)?;
        st.create()?;
        let pem = key
            .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), o.password.as_bytes())
            .map_err(|e| e.to_string())?;
        write_private(&st.key(), &pem)?;
        write_private(&st.request(), &request)?;
        println!(
            "# new {}-bit key and request saved in {}",
            o.key_bits,
            st.dir.display()
        );
        (key, request)
    };

    let raw = if st.raw().exists() && !o.resend {
        std::fs::read(st.raw()).map_err(|e| e.to_string())?
    } else {
        if !o.resend && request_was_sent(&st) {
            return Err(format!(
                "a request was already sent from {} but no answer was stored. Re-run with --resend to send \
                 the same request again",
                st.dir.display()
            ));
        }
        mark_sent(&st)?;
        let req = http_request(&o.gateway, &request);
        println!("# POST http://{}:{}/registration", o.gateway, o.port);
        post(&o.gateway, o.port, &req, &st.raw())?
    };

    let (code, body) = http_body(&raw)?;
    if body.is_empty() {
        return Err(format!(
            "the internal CA answered HTTP {code} with no data (answer kept in {})",
            st.raw().display()
        ));
    }
    let spki = key.public_key_to_der().map_err(|e| e.to_string())?;
    let issued = cmc::parse_response(&body, &spki, &o.regkey).map_err(|e| {
        format!(
            "{e} (HTTP {code}; the answer is kept in {}, re-run with --resume once resolved)",
            st.raw().display()
        )
    })?;
    for n in &issued.notes {
        println!("# note: {n}");
    }

    let ca_fp = issued.ca.as_ref().map(ca_fingerprint);
    let fp_match = ca_fp
        .as_ref()
        .map(|f| o.expected_ca.iter().any(|e| e == f))
        .unwrap_or(false);
    if let Some(f) = &ca_fp {
        println!("# internal CA fingerprint: {f}");
    }
    match issued.ca_proof {
        Some(true) => println!("# the CA proved it knows the registration key"),
        Some(false) => println!("# WARNING: the CA's proof of the registration key does not match"),
        None => {}
    }
    if !o.expected_ca.is_empty() {
        if fp_match {
            println!("# the CA matches the one the gateway advertises");
        } else {
            println!(
                "# WARNING: the CA fingerprint differs from the gateway's: {}",
                o.expected_ca.join(" / ")
            );
        }
    }
    let authenticated = issued.ca_proof == Some(true) || fp_match;
    if !authenticated && !o.trust_ca {
        return Err(format!(
            "the issuing CA could not be authenticated (its registration-key proof is {} and its fingerprint does \
             not match the gateway's). If the fingerprint above is the one your administrator expects, re-run \
             with --resume --trust-ca (answer kept in {})",
            if issued.ca_proof.is_none() { "missing" } else { "wrong" },
            st.raw().display()
        ));
    }

    let der = p12::build(&o.password, &key, &issued.cert, issued.ca.as_ref())?;
    let check = p12::parse(&der, &o.password)?;
    if check.cert.to_der().ok() != issued.cert.to_der().ok() {
        return Err("internal error: the written certificate file does not read back".into());
    }
    write_private(&o.out, &der)?;
    let subject = p12::dn_string(issued.cert.subject_name());
    let _ = std::fs::remove_file(st.key());
    let _ = std::fs::remove_file(st.request());
    let _ = std::fs::remove_file(st.raw());
    let _ = std::fs::remove_file(st.dir.join("sent"));
    let _ = std::fs::remove_dir(&st.dir);
    Ok(subject)
}

fn request_was_sent(st: &Staging) -> bool {
    st.dir.join("sent").exists()
}

fn mark_sent(st: &Staging) -> Result<(), String> {
    write_private(&st.dir.join("sent"), b"1")
}

pub fn validate_password(p: &str) -> Result<(), String> {
    if p.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "the certificate password must have at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_answer_framings() {
        let len = b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabcdef";
        assert_eq!(http_body(len).unwrap(), (200, b"abc".to_vec()));
        assert!(response_complete(len));
        assert!(!response_complete(&len[..len.len() - 4]));
        assert!(http_body(&len[..len.len() - 4]).is_err());

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        assert_eq!(http_body(chunked).unwrap(), (200, b"abc".to_vec()));
        assert!(response_complete(chunked));
        assert!(!response_complete(&chunked[..chunked.len() - 5]));

        let bare_lf = b"HTTP/1.0 500 Error\nServer: x\n\nboom";
        assert_eq!(http_body(bare_lf).unwrap(), (500, b"boom".to_vec()));
        assert!(!response_complete(bare_lf));
        assert!(http_body(b"no header").is_err());
    }
}
