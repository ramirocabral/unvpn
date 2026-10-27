//! Encrypted export/import of connection profiles, to move them to another machine.
//!
//! An export is one file: `MAGIC | m_cost | t_cost | p_cost | salt | nonce |
//! ciphertext`. The key is Argon2id(passphrase, salt); the payload is
//! XChaCha20-Poly1305 over a TOML [`Bundle`], with the header as associated data.
//! A bundle carries each profile, its keyring secrets, and — for OpenVPN /
//! WireGuard — the profile file plus every file it references, rewritten to
//! sibling names so the set can be dropped into any directory.

use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use crate::profiles::{self, Backend, Profile};

const MAGIC: &[u8; 8] = b"UNVPNBK1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC.len() + 12 + SALT_LEN + NONCE_LEN;
const M_COST_KIB: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;
const MAX_M_COST_KIB: u32 = 1024 * 1024;
const MAX_T_COST: u32 = 64;

pub const FILE_EXT: &str = "unvpn";
pub const MIN_PASSPHRASE: usize = 8;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Serialize, Deserialize)]
pub struct Bundle {
    pub version: u32,
    #[serde(default, rename = "entry")]
    pub entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
pub struct Entry {
    /// For file-based back-ends `gateway` is the name of the main file in `files`.
    pub profile: Profile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_pass: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<EmbeddedFile>,
}

#[derive(Serialize, Deserialize)]
pub struct EmbeddedFile {
    pub name: String,
    /// Base64.
    pub data: String,
}

pub enum OpenError {
    NotABundle,
    WrongPassphrase,
    Corrupt(String),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::NotABundle => f.write_str("not an unvpn profile export"),
            OpenError::WrongPassphrase => f.write_str("wrong passphrase"),
            OpenError::Corrupt(e) => write!(f, "damaged export: {e}"),
        }
    }
}

pub fn is_bundle(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

/// Builds a bundle from the saved profiles, pulling their secrets from the keyring.
/// A profile whose files can't be read is left out and reported in the warnings.
pub fn collect(profs: &[Profile]) -> (Bundle, Vec<String>) {
    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    for p in profs {
        match collect_one(p, profiles::secret_get) {
            Ok(e) => entries.push(e),
            Err(e) => warnings.push(format!("{}: {e}", p.name)),
        }
    }
    (Bundle { version: 1, entries }, warnings)
}

fn collect_one(p: &Profile, secret: impl Fn(&str) -> Option<String>) -> Result<Entry, String> {
    let mut profile = p.clone();
    let mut files = Vec::new();
    if p.backend.uses_profile_file() {
        let path = Path::new(&p.gateway);
        let (main, refs) = if p.backend == Backend::OpenVpn {
            ovpn_files(path)?
        } else {
            let text = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
            (text, Vec::new())
        };
        let main_name = file_name(path, "profile.conf");
        files.push(EmbeddedFile { name: main_name.clone(), data: B64.encode(main) });
        files.extend(refs.into_iter().map(|(name, data)| EmbeddedFile { name, data: B64.encode(data) }));
        profile.gateway = main_name;
    }
    let password = if p.remember_password { secret(&p.name) } else { None };
    let key_pass = if p.remember_key_pass { secret(&profiles::keypass_account(&p.name)) } else { None };
    let psk = if p.backend == Backend::FortiIpsec { secret(&profiles::psk_account(&p.name)) } else { None };
    profile.remember_password = password.is_some();
    profile.remember_key_pass = key_pass.is_some();
    Ok(Entry { profile, password, key_pass, psk, files })
}

pub fn seal(bundle: &Bundle, passphrase: &str) -> Result<Vec<u8>, String> {
    let plain = toml::to_string(bundle).map_err(|e| e.to_string())?;
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| e.to_string())?;
    getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;

    let mut out = Vec::with_capacity(HEADER_LEN + plain.len() + 16);
    out.extend_from_slice(MAGIC);
    for v in [M_COST_KIB, T_COST, P_COST] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);

    let key = derive_key(passphrase, &salt, M_COST_KIB, T_COST, P_COST)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain.as_bytes(), aad: &out })
        .map_err(|_| "encryption failed".to_string())?;
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(data: &[u8], passphrase: &str) -> Result<Bundle, OpenError> {
    if !is_bundle(data) {
        return Err(OpenError::NotABundle);
    }
    if data.len() < HEADER_LEN + 16 {
        return Err(OpenError::Corrupt("truncated".into()));
    }
    let (header, ct) = data.split_at(HEADER_LEN);
    let u32_at = |i: usize| u32::from_le_bytes(header[i..i + 4].try_into().unwrap());
    let (m, t, p) = (u32_at(8), u32_at(12), u32_at(16));
    if m > MAX_M_COST_KIB || t > MAX_T_COST || p == 0 || p > 16 {
        return Err(OpenError::Corrupt("unsupported key-derivation parameters".into()));
    }
    let salt = &header[20..20 + SALT_LEN];
    let nonce = &header[20 + SALT_LEN..];
    let key = derive_key(passphrase, salt, m, t, p).map_err(OpenError::Corrupt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: header })
        .map_err(|_| OpenError::WrongPassphrase)?;
    let text = String::from_utf8(plain).map_err(|e| OpenError::Corrupt(e.to_string()))?;
    toml::from_str(&text).map_err(|e| OpenError::Corrupt(e.to_string()))
}

fn derive_key(passphrase: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; 32], String> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| e.to_string())?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

/// Writes the entry's files (if any) into a fresh directory under `root` and
/// returns its profile, renamed to `name`, with `gateway` pointing at them.
pub fn install_files(entry: &Entry, name: &str, root: &Path) -> Result<Profile, String> {
    let mut p = entry.profile.clone();
    p.name = name.to_string();
    if !p.backend.uses_profile_file() {
        return Ok(p);
    }
    if !entry.files.iter().any(|f| f.name == p.gateway) {
        return Err(format!("{name}: profile file missing from the export"));
    }
    let dir = fresh_dir(root, &slug(name));
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    restrict(&dir, 0o700);
    for f in &entry.files {
        if f.name.is_empty() || f.name.contains('/') || f.name.starts_with('.') {
            return Err(format!("{name}: bad file name in the export"));
        }
        let data = B64.decode(&f.data).map_err(|e| format!("{name}: {e}"))?;
        let path = dir.join(&f.name);
        write_private(&path, &data).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    p.gateway = dir.join(&p.gateway).to_string_lossy().into_owned();
    Ok(p)
}

/// Stores the entry's secrets in the keyring under `p`'s name, clearing the
/// "remember" flags of any that couldn't be stored. False if any failed.
pub fn install_secrets(entry: &Entry, p: &mut Profile) -> bool {
    let mut ok = true;
    let mut store = |account: String, secret: &Option<String>| match secret {
        Some(s) if profiles::secret_set(&account, s) => true,
        Some(_) => {
            ok = false;
            false
        }
        None => false,
    };
    p.remember_password = store(p.name.clone(), &entry.password);
    p.remember_key_pass = store(profiles::keypass_account(&p.name), &entry.key_pass);
    store(profiles::psk_account(&p.name), &entry.psk);
    ok
}

/// The main file (rewritten) and the files it references, as (name, contents).
fn ovpn_files(path: &Path) -> Result<(Vec<u8>, Vec<(String, Vec<u8>)>), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let main_name = file_name(path, "profile.conf");
    let mut refs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut out = String::with_capacity(text.len());
    let mut block: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(close) = &block {
            if t == close {
                block = None;
            }
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if let Some(tag) = t.strip_prefix('<').and_then(|l| l.strip_suffix('>')) {
            if !tag.starts_with('/') && tag != "connection" {
                block = Some(format!("</{tag}>"));
            }
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let w = split_words(t);
        let directive = w.first().map(|d| d.trim_start_matches("--"));
        let file_arg = matches!(
            directive,
            Some("ca" | "cert" | "key" | "pkcs12" | "tls-auth" | "tls-crypt" | "auth-user-pass")
        );
        let Some(f) = w.get(1).filter(|f| file_arg && f.as_str() != "[inline]") else {
            out.push_str(line);
            out.push('\n');
            continue;
        };
        let src = resolve(dir, f);
        let data = match std::fs::read(&src) {
            Ok(d) => d,
            Err(_) if directive == Some("auth-user-pass") => {
                out.push_str(line);
                out.push('\n');
                continue;
            }
            Err(e) => return Err(format!("read {}: {e}", src.display())),
        };
        let name = match refs.iter().find(|(_, d)| *d == data) {
            Some((n, _)) => n.clone(),
            None => {
                let base = file_name(&src, "file");
                let mut name = base.clone();
                let mut i = 2;
                while name == main_name || refs.iter().any(|(n, _)| *n == name) {
                    name = format!("{i}-{base}");
                    i += 1;
                }
                refs.push((name.clone(), data));
                name
            }
        };
        let mut words = vec![w[0].clone(), name];
        words.extend(w[2..].iter().map(|a| quote(a)));
        out.push_str(&words.join(" "));
        out.push('\n');
    }
    Ok((out.into_bytes(), refs))
}

fn resolve(dir: &Path, f: &str) -> PathBuf {
    let p = Path::new(f);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        dir.join(p)
    }
}

/// A file's name, made safe to use as a sibling file (no spaces, no leading dot).
fn file_name(path: &Path, fallback: &str) -> String {
    let raw = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let s: String = raw.chars().map(|c| if c.is_alphanumeric() || "-_.".contains(c) { c } else { '_' }).collect();
    let s = s.trim_start_matches('.').to_string();
    if s.is_empty() {
        fallback.to_string()
    } else {
        s
    }
}

fn slug(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    if s.is_empty() {
        "profile".to_string()
    } else {
        s
    }
}

fn fresh_dir(root: &Path, base: &str) -> PathBuf {
    let mut dir = root.join(base);
    let mut i = 2;
    while dir.exists() {
        dir = root.join(format!("{base}-{i}"));
        i += 1;
    }
    dir
}

fn quote(w: &str) -> String {
    if !w.is_empty() && !w.chars().any(|c| c.is_whitespace() || "\"'\\#;".contains(c)) {
        return w.to_string();
    }
    format!("\"{}\"", w.replace('\\', "\\\\").replace('"', "\\\""))
}

pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.write_all(data)
}

fn restrict(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

/// OpenVPN's word splitting: quotes, backslash escapes, trailing `#`/`;` comments.
fn split_words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == q => quote = None,
            Some('"') if c == '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            Some(_) => cur.push(c),
            None => match c {
                '"' | '\'' => {
                    quote = Some(c);
                    in_word = true;
                }
                '\\' => {
                    if let Some(n) = chars.next() {
                        cur.push(n);
                        in_word = true;
                    }
                }
                '#' | ';' if !in_word => break,
                c if c.is_whitespace() => {
                    if in_word {
                        out.push(std::mem::take(&mut cur));
                        in_word = false;
                    }
                }
                c => {
                    cur.push(c);
                    in_word = true;
                }
            },
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, backend: Backend, gateway: &str) -> Profile {
        toml::from_str(&format!("name = {name:?}\nbackend = {:?}\ngateway = {gateway:?}\n", backend_str(backend))).unwrap()
    }

    fn backend_str(b: Backend) -> &'static str {
        match b {
            Backend::OpenVpn => "openvpn",
            Backend::WireGuard => "wireguard",
            Backend::FortiIpsec => "fortiipsec",
            _ => "anyconnect",
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let mut p = profile("work", Backend::FortiIpsec, "vpn.example.com");
        p.remember_password = true;
        let e = collect_one(&p, |acct| Some(format!("secret-{acct}"))).unwrap();
        let sealed = seal(&Bundle { version: 1, entries: vec![e] }, "correct horse").unwrap();
        assert!(is_bundle(&sealed));
        let b = open(&sealed, "correct horse").ok().unwrap();
        let e = &b.entries[0];
        assert_eq!(e.profile.gateway, "vpn.example.com");
        assert_eq!(e.password.as_deref(), Some("secret-work"));
        assert_eq!(e.psk.as_deref(), Some("secret-work#psk"));
        assert!(e.key_pass.is_none());
        assert!(matches!(open(&sealed, "wrong horse"), Err(OpenError::WrongPassphrase)));
        let mut tampered = sealed.clone();
        tampered[9] ^= 1;
        assert!(open(&tampered, "correct horse").is_err());
        assert!(matches!(open(b"[profile]", "x"), Err(OpenError::NotABundle)));
    }

    #[test]
    fn ovpn_references_are_embedded_and_rewritten() {
        let src = tempfile::tempdir().unwrap();
        let keys = src.path().join("my keys");
        std::fs::create_dir(&keys).unwrap();
        std::fs::write(src.path().join("ca.crt"), "CA").unwrap();
        std::fs::write(keys.join("client.key"), "KEY").unwrap();
        std::fs::write(keys.join("ca.crt"), "OTHER CA").unwrap();
        std::fs::write(src.path().join("ta.key"), "TA").unwrap();
        let ovpn = src.path().join("office vpn.ovpn");
        std::fs::write(
            &ovpn,
            format!(
                "client\nremote vpn.example.com 1194\nca ca.crt\nkey \"my keys/client.key\"\n\
                 extra-certs {}\ntls-auth ta.key 1\nauth-user-pass missing.txt\n<cert>\nca inside-block\n</cert>\n",
                keys.join("ca.crt").display()
            ),
        )
        .unwrap();

        let e = collect_one(&profile("office", Backend::OpenVpn, ovpn.to_str().unwrap()), |_| None).unwrap();
        assert_eq!(e.profile.gateway, "office_vpn.ovpn");
        let names: Vec<_> = e.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["office_vpn.ovpn", "ca.crt", "client.key", "ta.key"]);
        let main = String::from_utf8(B64.decode(&e.files[0].data).unwrap()).unwrap();
        assert!(main.contains("\nca ca.crt\n"));
        assert!(main.contains("\nkey client.key\n"));
        assert!(main.contains("\ntls-auth ta.key 1\n"));
        assert!(main.contains("\nauth-user-pass missing.txt\n"));
        assert!(main.contains("\nca inside-block\n"));

        let dst = tempfile::tempdir().unwrap();
        let p = install_files(&e, "office", dst.path()).unwrap();
        let p2 = install_files(&e, "office", dst.path()).unwrap();
        assert_ne!(p.gateway, p2.gateway);
        let dir = Path::new(&p.gateway).parent().unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("client.key")).unwrap(), "KEY");
        assert_eq!(std::fs::read_to_string(dir.join("ca.crt")).unwrap(), "CA");
        assert_eq!(std::fs::read_to_string(&p.gateway).unwrap(), main);
    }

    #[test]
    fn duplicate_names_get_prefixed() {
        let src = tempfile::tempdir().unwrap();
        std::fs::create_dir(src.path().join("a")).unwrap();
        std::fs::write(src.path().join("a/key.pem"), "K1").unwrap();
        std::fs::write(src.path().join("key.pem"), "K2").unwrap();
        let ovpn = src.path().join("c.ovpn");
        std::fs::write(&ovpn, "remote h\ncert a/key.pem\nkey key.pem\n").unwrap();
        let (main, refs) = ovpn_files(&ovpn).unwrap();
        let names: Vec<_> = refs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["key.pem", "2-key.pem"]);
        assert!(String::from_utf8(main).unwrap().contains("key 2-key.pem"));
    }

    #[test]
    fn missing_required_file_fails() {
        let src = tempfile::tempdir().unwrap();
        let ovpn = src.path().join("c.ovpn");
        std::fs::write(&ovpn, "remote h\nca nope.crt\n").unwrap();
        assert!(ovpn_files(&ovpn).is_err());
    }

    #[test]
    fn rejects_path_traversal() {
        let e = Entry {
            profile: profile("x", Backend::WireGuard, "wg.conf"),
            password: None,
            key_pass: None,
            psk: None,
            files: vec![
                EmbeddedFile { name: "wg.conf".into(), data: B64.encode("x") },
                EmbeddedFile { name: "../evil".into(), data: B64.encode("x") },
            ],
        };
        let dst = tempfile::tempdir().unwrap();
        assert!(install_files(&e, "x", dst.path()).is_err());
    }
}
