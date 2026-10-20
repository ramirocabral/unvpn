//! Connection profiles: saved VPN connections the user can switch between.
//!
//! Non-secret fields live in `~/.config/cpvpn/profiles.toml`. The password (or
//! SecurID PIN) is never written there — it goes to the system keyring (Secret
//! Service / libsecret) under service `cpvpn`, keyed by the profile name. A 2FA
//! token is single-use and never stored.

use serde::{Deserialize, Serialize};

const KEYRING_SERVICE: &str = "cpvpn";

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    #[serde(rename = "checkpoint")]
    CheckPoint,
    Forti,
    F5,
    #[serde(rename = "anyconnect")]
    AnyConnect,
}

impl Backend {
    /// Human label shown in the backend selector.
    pub fn label(self) -> &'static str {
        match self {
            Backend::CheckPoint => "Check Point",
            Backend::Forti => "FortiClient",
            Backend::F5 => "F5",
            Backend::AnyConnect => "AnyConnect (Cisco)",
        }
    }

    /// Position in the backend `ComboRow` (Check Point, FortiClient, F5, AnyConnect).
    pub fn index(self) -> u32 {
        match self {
            Backend::CheckPoint => 0,
            Backend::Forti => 1,
            Backend::F5 => 2,
            Backend::AnyConnect => 3,
        }
    }

    /// Back-ends with a browser SSO/SAML login mode.
    pub fn has_sso(self) -> bool {
        matches!(self, Backend::Forti | Backend::AnyConnect)
    }

    pub fn from_index(i: u32) -> Backend {
        match i {
            1 => Backend::Forti,
            2 => Backend::F5,
            3 => Backend::AnyConnect,
            _ => Backend::CheckPoint,
        }
    }
}

/// One saved connection. `password` is never serialised (keyring only).
#[derive(Clone, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub backend: Backend,
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub user: String,
    /// Fortinet realm (optional).
    #[serde(default)]
    pub realm: String,
    /// AnyConnect tunnel group (optional; pre-selects the gateway's group dropdown).
    #[serde(default)]
    pub group: String,
    /// SSO/SAML (browser) instead of password auth — Fortinet or AnyConnect.
    /// (Older profiles saved it as `forti_saml`.)
    #[serde(default, alias = "forti_saml")]
    pub sso: bool,
    /// Whether a password/PIN is stored for this profile in the keyring.
    #[serde(default)]
    pub remember_password: bool,
}

impl Profile {
    /// The one-line subtitle shown under the profile name in the list.
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
        if !self.gateway.is_empty() {
            parts.push(self.gateway.clone());
        }
        parts.join("  ·  ")
    }
}

#[derive(Default, Serialize, Deserialize)]
struct ProfileFile {
    #[serde(default, rename = "profile")]
    profiles: Vec<Profile>,
}

fn config_dir() -> std::path::PathBuf {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        std::path::PathBuf::from(x).join("cpvpn")
    } else {
        let home = std::env::var_os("HOME").unwrap_or_default();
        std::path::PathBuf::from(home).join(".config/cpvpn")
    }
}

fn profiles_path() -> std::path::PathBuf {
    config_dir().join("profiles.toml")
}

/// Load the saved profiles (empty list if the file is missing or unreadable).
pub fn load() -> Vec<Profile> {
    let Ok(text) = std::fs::read_to_string(profiles_path()) else {
        return Vec::new();
    };
    match toml::from_str::<ProfileFile>(&text) {
        Ok(f) => f.profiles,
        Err(e) => {
            eprintln!("cpvpn: ignoring unreadable profiles.toml: {e}");
            Vec::new()
        }
    }
}

/// Persist the profiles. Returns an error string on failure.
pub fn save(profiles: &[Profile]) -> Result<(), String> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let file = ProfileFile { profiles: profiles.to_vec() };
    let text = toml::to_string_pretty(&file).map_err(|e| e.to_string())?;
    std::fs::write(profiles_path(), text).map_err(|e| e.to_string())
}

// ───────────────────────────── keyring (Secret Service) ────────────────────

fn entry(name: &str) -> Option<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, name).ok()
}

/// The stored password/PIN for a profile, if any (None if absent or no keyring).
pub fn secret_get(name: &str) -> Option<String> {
    entry(name)?.get_password().ok()
}

/// Store (or replace) the password/PIN for a profile. Returns false on failure
/// (e.g. no Secret Service running) — the caller treats it as "not remembered".
pub fn secret_set(name: &str, secret: &str) -> bool {
    entry(name).map(|e| e.set_password(secret).is_ok()).unwrap_or(false)
}

/// Remove a profile's stored password/PIN (ignored if absent).
pub fn secret_delete(name: &str) {
    if let Some(e) = entry(name) {
        let _ = e.delete_credential();
    }
}
