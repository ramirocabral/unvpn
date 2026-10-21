//! Connection profiles: saved VPN connections the user can switch between.
//!
//! Non-secret fields live in `~/.config/unvpn/profiles.toml`. The password (or
//! SecurID PIN) is never written there — it goes to the system keyring (Secret
//! Service / libsecret) under service `unvpn`, keyed by the profile name; an
//! OpenVPN private-key passphrase likewise, under `<name>#keypass`. A 2FA token is
//! single-use and never stored.

use serde::{Deserialize, Serialize};

const KEYRING_SERVICE: &str = "unvpn";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    #[serde(rename = "checkpoint")]
    CheckPoint,
    Forti,
    F5,
    #[serde(rename = "anyconnect")]
    AnyConnect,
    #[serde(rename = "openvpn")]
    OpenVpn,
    #[serde(rename = "wireguard")]
    WireGuard,
}

impl Backend {
    pub fn label(self) -> &'static str {
        match self {
            Backend::CheckPoint => "Check Point",
            Backend::Forti => "FortiClient",
            Backend::F5 => "F5",
            Backend::AnyConnect => "AnyConnect (Cisco)",
            Backend::OpenVpn => "OpenVPN",
            Backend::WireGuard => "WireGuard",
        }
    }

    /// Position in the backend `ComboRow`; must match its model order.
    pub fn index(self) -> u32 {
        match self {
            Backend::CheckPoint => 0,
            Backend::Forti => 1,
            Backend::F5 => 2,
            Backend::AnyConnect => 3,
            Backend::OpenVpn => 4,
            Backend::WireGuard => 5,
        }
    }

    pub fn has_sso(self) -> bool {
        matches!(self, Backend::Forti | Backend::AnyConnect)
    }

    /// Back-ends configured by a profile file (`gateway` holds its path).
    pub fn uses_profile_file(self) -> bool {
        matches!(self, Backend::OpenVpn | Backend::WireGuard)
    }

    pub fn from_index(i: u32) -> Backend {
        match i {
            1 => Backend::Forti,
            2 => Backend::F5,
            3 => Backend::AnyConnect,
            4 => Backend::OpenVpn,
            5 => Backend::WireGuard,
            _ => Backend::CheckPoint,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub backend: Backend,
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub realm: String,
    /// AnyConnect tunnel group (pre-selects the gateway's group dropdown).
    #[serde(default)]
    pub group: String,
    #[serde(default, alias = "forti_saml")]
    pub sso: bool,
    #[serde(default)]
    pub remember_password: bool,
    #[serde(default)]
    pub remember_key_pass: bool,
}

impl Profile {
    pub fn subtitle(&self) -> String {
        let mut parts = vec![self.backend.label().to_string()];
        if self.backend.has_sso() && self.sso {
            parts.push("SSO".to_string());
        } else if !self.user.is_empty() {
            parts.push(self.user.clone());
        }
        if self.backend == Backend::AnyConnect && !self.group.is_empty() {
            parts.push(self.group.clone());
        }
        if self.backend.uses_profile_file() {
            // `gateway` holds the .ovpn/.conf path — the file name is what identifies it.
            let file = std::path::Path::new(&self.gateway).file_name().map(|f| f.to_string_lossy().into_owned());
            parts.extend(file);
        } else if !self.gateway.is_empty() {
            parts.push(self.gateway.clone());
        }
        parts.join("  ·  ")
    }
}

/// Whether an OpenVPN profile authenticates with a username/password
/// (`auth-user-pass` without an inline/file credential), i.e. the GUI must ask.
/// Unreadable file → false (the engine reports the real error).
pub fn ovpn_needs_userpass(path: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else { return false };
    let mut needs = false;
    for l in text.lines().map(str::trim) {
        if l.starts_with("<auth-user-pass>") {
            return false; // credentials inline
        }
        let mut w = l.split_whitespace();
        if w.next() == Some("auth-user-pass") {
            // `auth-user-pass <file>` with an existing file supplies them itself.
            let dir = std::path::Path::new(path).parent().unwrap_or(std::path::Path::new("."));
            needs = !w.next().is_some_and(|f| dir.join(f).is_file());
        }
    }
    needs
}

/// Whether an OpenVPN profile's client key may need a passphrase: an encrypted PEM
/// `<key>` (inline or file) or a PKCS#12 bundle (may or may not be protected).
/// Unreadable file → false.
pub fn ovpn_key_may_need_pass(path: &str) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else { return false };
    let dir = std::path::Path::new(path).parent().unwrap_or(std::path::Path::new("."));
    let mut in_key = false;
    for l in text.lines().map(str::trim) {
        match l {
            "<key>" => in_key = true,
            "</key>" => in_key = false,
            "<pkcs12>" => return true,
            _ if in_key => {
                if l.contains("ENCRYPTED") {
                    return true;
                }
            }
            _ => {
                let mut w = l.split_whitespace();
                match (w.next(), w.next()) {
                    (Some("pkcs12"), Some(_)) => return true,
                    (Some("key"), Some(f)) => {
                        if std::fs::read_to_string(dir.join(f)).is_ok_and(|k| k.contains("ENCRYPTED")) {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    false
}

#[derive(Default, Serialize, Deserialize)]
struct ProfileFile {
    #[serde(default, rename = "profile")]
    profiles: Vec<Profile>,
}

fn config_dir() -> std::path::PathBuf {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        std::path::PathBuf::from(x).join("unvpn")
    } else {
        let home = std::env::var_os("HOME").unwrap_or_default();
        std::path::PathBuf::from(home).join(".config/unvpn")
    }
}

fn profiles_path() -> std::path::PathBuf {
    config_dir().join("profiles.toml")
}

pub fn load() -> Vec<Profile> {
    let Ok(text) = std::fs::read_to_string(profiles_path()) else {
        return Vec::new();
    };
    match toml::from_str::<ProfileFile>(&text) {
        Ok(f) => f.profiles,
        Err(e) => {
            eprintln!("unvpn: ignoring unreadable profiles.toml: {e}");
            Vec::new()
        }
    }
}

pub fn save(profiles: &[Profile]) -> Result<(), String> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let file = ProfileFile { profiles: profiles.to_vec() };
    let text = toml::to_string_pretty(&file).map_err(|e| e.to_string())?;
    std::fs::write(profiles_path(), text).map_err(|e| e.to_string())
}

fn entry(name: &str) -> Option<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, name).ok()
}

pub fn secret_get(name: &str) -> Option<String> {
    entry(name)?.get_password().ok()
}

/// Returns false on failure (e.g. no Secret Service running).
pub fn secret_set(name: &str, secret: &str) -> bool {
    entry(name).map(|e| e.set_password(secret).is_ok()).unwrap_or(false)
}

pub fn secret_delete(name: &str) {
    if let Some(e) = entry(name) {
        let _ = e.delete_credential();
    }
}

pub fn keypass_account(name: &str) -> String {
    format!("{name}#keypass")
}
