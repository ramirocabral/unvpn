//! Connection profiles: saved VPN connections, shared by the GUI and `unvpn connect`.
//!
//! Non-secret fields live in `~/.config/unvpn/profiles.toml`. The password (or
//! SecurID PIN) is never written there — it goes to the system keyring (Secret
//! Service / libsecret) under service `unvpn`, keyed by the profile name; an
//! OpenVPN private-key passphrase likewise, under `<name>#keypass`. A 2FA token is
//! single-use and never stored.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const KEYRING_SERVICE: &str = "unvpn";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    #[serde(rename = "checkpoint")]
    CheckPoint,
    Forti,
    F5,
    #[serde(rename = "anyconnect")]
    AnyConnect,
    #[serde(rename = "globalprotect")]
    GlobalProtect,
    #[serde(rename = "openvpn")]
    OpenVpn,
    #[serde(rename = "wireguard")]
    WireGuard,
    #[serde(rename = "fortiipsec", alias = "forti-ipsec")]
    FortiIpsec,
}

impl Backend {
    pub fn label(self) -> &'static str {
        match self {
            Backend::CheckPoint => "Check Point",
            Backend::Forti => "FortiClient (SSL-VPN)",
            Backend::F5 => "F5",
            Backend::AnyConnect => "AnyConnect (Cisco)",
            Backend::GlobalProtect => "GlobalProtect",
            Backend::OpenVpn => "OpenVPN",
            Backend::WireGuard => "WireGuard",
            Backend::FortiIpsec => "FortiClient (IPsec)",
        }
    }

    pub fn has_sso(self) -> bool {
        matches!(self, Backend::Forti | Backend::AnyConnect | Backend::GlobalProtect)
    }

    /// Back-ends whose `group` field is in use: AnyConnect's tunnel group,
    /// GlobalProtect's choice among the portal's gateways.
    pub fn uses_group(self) -> bool {
        matches!(self, Backend::AnyConnect | Backend::GlobalProtect)
    }

    /// Back-ends configured by a profile file (`gateway` holds its path).
    pub fn uses_profile_file(self) -> bool {
        matches!(self, Backend::OpenVpn | Backend::WireGuard)
    }

    /// Back-ends with an optional DTLS (UDP 443) data channel that `--no-dtls`
    /// turns off, forcing the data plane onto the TLS (TCP) tunnel. Use it when a
    /// network lets UDP out but drops the DTLS return path (tunnel connects but no
    /// traffic flows). The other back-ends have no DTLS to disable.
    pub fn uses_dtls(self) -> bool {
        matches!(self, Backend::AnyConnect | Backend::Forti | Backend::F5)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub name: String,
    pub backend: Backend,
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub realm: String,
    /// AnyConnect tunnel group (pre-selects the gateway's group dropdown), or the
    /// GlobalProtect gateway to pick from the portal's list.
    #[serde(default)]
    pub group: String,
    #[serde(default, alias = "forti_saml")]
    pub sso: bool,
    #[serde(default)]
    pub remember_password: bool,
    #[serde(default)]
    pub remember_key_pass: bool,
    /// Optional User-Agent for the embedded SSO sign-in window. Empty ⇒ default
    /// (WebKit's own, i.e. Linux). Set a Windows UA to pass an Entra/Azure
    /// Conditional Access "device platform" filter that blocks Linux. Only the
    /// SAML login is affected; the VPN data path is unchanged.
    #[serde(default)]
    pub sso_user_agent: String,
    /// FortiClient IPsec, EMS-managed gateways only: the endpoint's EMS serial
    /// (`FCTEMS…`), sent in the FORTICLIENT_CONNECT payload. Empty for a plain
    /// FortiGate IPsec dialup that is not EMS-managed.
    #[serde(default)]
    pub emssn: String,
    /// FortiClient IPsec: the FortiClient version to report (`FCTVER=`). Empty ⇒ the
    /// engine's built-in default. Only matters when a gateway pins a version.
    #[serde(default)]
    pub fctver: String,
    /// Fail-closed firewall: block every packet that isn't the tunnel, the gateway,
    /// the LAN or DHCP while connected, so a dropped tunnel can't leak traffic in
    /// clear. Off by default; not used by the WireGuard back-end.
    #[serde(default)]
    pub killswitch: bool,
    /// Force the data channel onto TLS (TCP) by not establishing DTLS (UDP 443).
    /// For networks that let UDP 443 out but drop its return path, where DTLS back-
    /// ends connect but pass no traffic. Only used by back-ends with DTLS
    /// ([`Backend::uses_dtls`]); ignored by the rest.
    #[serde(default)]
    pub no_dtls: bool,
    /// Check Point: log in with a certificate instead of a SecurID token. `realm`
    /// then holds the gateway login option to use (empty ⇒ the engine picks the
    /// first certificate one).
    #[serde(default)]
    pub cp_cert: bool,
    /// Check Point certificate login: the PKCS#12 file. Its password is the
    /// profile's keyring secret.
    #[serde(default)]
    pub cert_path: String,
}

impl Profile {
    /// A Check Point profile that logs in with a certificate.
    pub fn uses_cp_cert(&self) -> bool {
        self.backend == Backend::CheckPoint && self.cp_cert
    }

    /// Logs in through the browser (SAML) instead of a password.
    pub fn uses_sso(&self) -> bool {
        self.backend.has_sso() && self.sso
    }

    pub fn subtitle(&self) -> String {
        let mut parts = vec![self.backend.label().to_string()];
        if self.backend.has_sso() && self.sso {
            parts.push("SSO".to_string());
        } else if self.uses_cp_cert() {
            parts.push("certificate".to_string());
        } else if !self.user.is_empty() {
            parts.push(self.user.clone());
        }
        if self.backend.uses_group() && !self.group.is_empty() {
            parts.push(self.group.clone());
        }
        if self.backend.uses_profile_file() {
            // `gateway` holds the.ovpn/.conf path — the file name is what identifies it.
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

pub fn profiles_path() -> std::path::PathBuf {
    config_dir().join("profiles.toml")
}

/// Where imported OpenVPN / WireGuard profile files are kept, one directory per profile.
pub fn files_dir() -> std::path::PathBuf {
    config_dir().join("files")
}

/// The directory holding a profile's VPN file or certificate, if it is one of
/// ours (under [`files_dir`]) and so goes away with the profile.
pub fn owned_files(p: &Profile) -> Option<PathBuf> {
    let file = if p.backend.uses_profile_file() {
        &p.gateway
    } else if p.uses_cp_cert() {
        &p.cert_path
    } else {
        return None;
    };
    let dir = Path::new(file).parent()?;
    (dir.parent() == Some(files_dir().as_path())).then(|| dir.to_path_buf())
}

/// Removes a profile's file directory if it is one of ours (see [`owned_files`]).
pub fn remove_owned_files(p: &Profile) {
    if let Some(dir) = owned_files(p) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// The saved profiles. No file is an empty list; a file that can't be read or
/// parsed is an error, so it is never mistaken for an empty list and overwritten.
pub fn load() -> Result<Vec<Profile>, String> {
    load_from(&profiles_path())
}

pub fn load_from(path: &Path) -> Result<Vec<Profile>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    toml::from_str::<ProfileFile>(&text).map(|f| f.profiles).map_err(|e| format!("{}: {e}", path.display()))
}

/// Move an unreadable profiles file out of the way, to the first free
/// `<name>.bad`, `<name>.bad.1`, …, and return where it went.
pub fn set_aside(path: &Path) -> Result<PathBuf, String> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let bad = (0..1000)
        .map(|i| path.with_file_name(if i == 0 { format!("{name}.bad") } else { format!("{name}.bad.{i}") }))
        .find(|p| !p.exists())
        .ok_or("no free name for the unreadable profiles file")?;
    std::fs::rename(path, &bad).map_err(|e| format!("move {} aside: {e}", path.display()))?;
    Ok(bad)
}

pub fn save(profiles: &[Profile]) -> Result<(), String> {
    save_to(&profiles_path(), profiles)
}

/// Write `profiles` atomically (temporary file + rename, mode 0600). A file
/// already there that does not load is first moved aside with [`set_aside`].
pub fn save_to(path: &Path, profiles: &[Profile]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    }
    if path.exists() && load_from(path).is_err() {
        set_aside(path)?;
    }
    let file = ProfileFile { profiles: profiles.to_vec() };
    let text = toml::to_string_pretty(&file).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("toml.tmp");
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(text.as_bytes())?;
            f.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, path));
    written.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })
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

/// Keyring account for a profile's FortiClient IPsec group pre-shared key.
pub fn psk_account(name: &str) -> String {
    format!("{name}#psk")
}

/// The engine command line (sub-command and flags) that connects `p`. Secrets go
/// on the engine's stdin, never here; with `psk` a FortiClient IPsec engine expects
/// the group key as the first stdin line, ahead of the password. SSO logins get
/// `--no-browser`: the front-end, which runs as the user, opens the sign-in page
/// itself.
pub fn engine_args(p: &Profile, psk: bool) -> Vec<String> {
    let gw = p.gateway.trim();
    let user = p.user.trim();
    let realm = p.realm.trim();
    let group = p.group.trim();
    let mut a: Vec<&str> = Vec::new();
    match p.backend {
        Backend::CheckPoint if p.cp_cert => {
            a.extend(["ike", "-g", gw, "--cert", p.cert_path.trim()]);
            if !realm.is_empty() {
                a.extend(["--realm", realm]);
            }
        }
        Backend::CheckPoint => a.extend(["ike", "-g", gw, "-u", user]),
        Backend::Forti => {
            a.extend(["forti", "-g", gw]);
            if !realm.is_empty() {
                a.extend(["--realm", realm]);
            }
            if p.sso {
                a.extend(["--saml", "--no-browser"]);
            } else {
                a.extend(["-u", user]);
            }
        }
        Backend::F5 => a.extend(["f5", "-g", gw, "-u", user]),
        Backend::FortiIpsec => {
            // The dialup group (localid) selects the gateway's phase1.
            a.extend(["forti-ipsec", "-g", gw]);
            if !realm.is_empty() {
                a.extend(["--localid", realm]);
            }
            if psk {
                a.push("--psk-stdin");
            }
            if !p.emssn.trim().is_empty() {
                a.extend(["--emssn", p.emssn.trim()]);
            }
            if !p.fctver.trim().is_empty() {
                a.extend(["--fctver", p.fctver.trim()]);
            }
            a.extend(["-u", user]);
        }
        Backend::OpenVpn => {
            a.extend(["openvpn", "-c", gw]);
            if ovpn_needs_userpass(gw) {
                a.extend(["-u", user]);
            }
        }
        Backend::WireGuard => a.extend(["wireguard", "-c", gw]),
        Backend::AnyConnect => {
            a.extend(["anyconnect", "-g", gw]);
            if !group.is_empty() {
                a.extend(["--group", group]);
            }
            if p.sso {
                a.push("--sso");
            } else {
                a.extend(["-u", user]);
            }
        }
        Backend::GlobalProtect => {
            a.extend(["gp", "-g", gw]);
            if !group.is_empty() {
                a.extend(["--gw", group]);
            }
            if p.sso {
                a.push("--saml");
            } else {
                a.extend(["-u", user]);
            }
        }
    }
    a.push("--connect");
    if p.killswitch && p.backend != Backend::WireGuard {
        a.push("--killswitch");
    }
    if p.no_dtls && p.backend.uses_dtls() {
        a.push("--no-dtls");
    }
    a.into_iter().map(String::from).collect()
}

/// Whether connecting `p` reads a secret as the engine's first stdin line: the
/// password, the Check Point PIN (followed by the token code) or the password of
/// the Check Point certificate file.
pub fn takes_password(p: &Profile) -> bool {
    match p.backend {
        Backend::WireGuard => false,
        Backend::OpenVpn => ovpn_needs_userpass(&p.gateway),
        _ => !p.uses_sso(),
    }
}

/// The SSO entry point the engine prints for a Fortinet `gateway` (`host[:port]`,
/// default 443): the only URL a front-end should hand to the browser.
pub fn saml_entry(gateway: &str) -> String {
    let g = gateway.trim();
    let hostport = match g.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => format!("{h}:{p}"),
        _ => format!("{g}:443"),
    };
    format!("https://{hostport}/remote/saml/start?")
}

/// AnyConnect's SSO entry point for `gateway` (a URL, maybe with a group path):
/// the ASA/FTD `sso-v2-login` on the same host — `https://host[:port]/+CSCOE+/saml/`.
/// The gateway omits the default port, so `:443` is dropped here too.
pub fn anyconnect_saml_entry(gateway: &str) -> String {
    let g = gateway.trim();
    let g = g.strip_prefix("https://").or_else(|| g.strip_prefix("http://")).unwrap_or(g);
    let hostport = g.split(['/', '?', '#']).next().unwrap_or_default();
    let hostport = hostport.strip_suffix(":443").unwrap_or(hostport);
    format!("https://{hostport}/+CSCOE+/saml/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(toml_body: &str) -> Profile {
        let f: ProfileFile = toml::from_str(&format!("[[profile]]\nname = \"t\"\n{toml_body}")).unwrap();
        f.profiles.into_iter().next().unwrap()
    }

    fn args(toml_body: &str) -> String {
        engine_args(&profile(toml_body), false).join(" ")
    }

    #[test]
    fn a_broken_profiles_file_is_an_error_and_is_set_aside_on_save() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("unvpn-profiles-load-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("profiles.toml");
        assert_eq!(load_from(&path).unwrap().len(), 0);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "[[profile]]\nname = \"a\"\nbackend = 3\n").unwrap();
        assert!(load_from(&path).is_err());
        save_to(&path, &[profile("backend = \"f5\"\ngateway = \"vpn.example.com\"")]).unwrap();
        assert!(std::fs::read_to_string(dir.join("profiles.toml.bad")).unwrap().contains("backend = 3"));
        assert_eq!(load_from(&path).unwrap()[0].gateway, "vpn.example.com");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::write(&path, "not toml [").unwrap();
        save_to(&path, &[]).unwrap();
        assert!(dir.join("profiles.toml.bad.1").exists());
        assert!(!dir.join("profiles.toml.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn engine_args_per_backend() {
        assert_eq!(
            args("backend = \"checkpoint\"\ngateway = \"203.0.113.10\"\nuser = \"alice\"\nrealm = \"ignored\""),
            "ike -g 203.0.113.10 -u alice --connect"
        );
        assert_eq!(
            args("backend = \"checkpoint\"\ngateway = \"203.0.113.10\"\ncp_cert = true\ncert_path = \"/k/a.p12\"\nrealm = \"vpn_cert\""),
            "ike -g 203.0.113.10 --cert /k/a.p12 --realm vpn_cert --connect"
        );
        assert_eq!(
            args("backend = \"forti\"\ngateway = \"vpn.example.com:10443\"\nuser = \"alice\"\nrealm = \"staff\"\nkillswitch = true"),
            "forti -g vpn.example.com:10443 --realm staff -u alice --connect --killswitch"
        );
        assert_eq!(
            args("backend = \"forti\"\ngateway = \"vpn.example.com\"\nuser = \"alice\"\nsso = true\nno_dtls = true"),
            "forti -g vpn.example.com --saml --no-browser --connect --no-dtls"
        );
        assert_eq!(
            args("backend = \"anyconnect\"\ngateway = \"https://vpn.example.com\"\ngroup = \"EMPLOYEES\"\nsso = true"),
            "anyconnect -g https://vpn.example.com --group EMPLOYEES --sso --connect"
        );
        assert_eq!(
            args("backend = \"globalprotect\"\ngateway = \"vpn.example.com\"\nuser = \"alice\"\ngroup = \"gw-1\""),
            "gp -g vpn.example.com --gw gw-1 -u alice --connect"
        );
        assert_eq!(
            args("backend = \"f5\"\ngateway = \"vpn.example.com\"\nuser = \"alice\"\nno_dtls = true"),
            "f5 -g vpn.example.com -u alice --connect --no-dtls"
        );
        assert_eq!(
            args("backend = \"wireguard\"\ngateway = \"/x/wg0.conf\"\nkillswitch = true"),
            "wireguard -c /x/wg0.conf --connect"
        );
    }

    #[test]
    fn forti_ipsec_takes_the_group_key_and_endpoint_fields() {
        let p = profile(
            "backend = \"fortiipsec\"\ngateway = \"vpn.example.com\"\nuser = \"alice\"\nrealm = \"remote\"\nemssn = \"FCTEMS0000000000\"",
        );
        assert_eq!(
            engine_args(&p, true).join(" "),
            "forti-ipsec -g vpn.example.com --localid remote --psk-stdin --emssn FCTEMS0000000000 -u alice --connect"
        );
        assert_eq!(
            engine_args(&p, false).join(" "),
            "forti-ipsec -g vpn.example.com --localid remote --emssn FCTEMS0000000000 -u alice --connect"
        );
    }

    #[test]
    fn openvpn_asks_for_a_user_only_when_the_profile_needs_one() {
        let dir = std::env::temp_dir().join(format!("unvpn-profiles-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let with = dir.join("with.ovpn");
        let without = dir.join("without.ovpn");
        std::fs::write(&with, "client\nremote vpn.example.com 1194\nauth-user-pass\n").unwrap();
        std::fs::write(&without, "client\nremote vpn.example.com 1194\n").unwrap();
        let p = |f: &std::path::Path| profile(&format!("backend = \"openvpn\"\ngateway = \"{}\"\nuser = \"alice\"", f.display()));
        assert_eq!(engine_args(&p(&with), false).join(" "), format!("openvpn -c {} -u alice --connect", with.display()));
        assert_eq!(engine_args(&p(&without), false).join(" "), format!("openvpn -c {} --connect", without.display()));
        assert!(takes_password(&p(&with)));
        assert!(!takes_password(&p(&without)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn password_is_read_unless_sso_or_keys_in_the_profile() {
        assert!(takes_password(&profile("backend = \"checkpoint\"")));
        assert!(takes_password(&profile("backend = \"checkpoint\"\ncp_cert = true")));
        assert!(takes_password(&profile("backend = \"fortiipsec\"")));
        assert!(!takes_password(&profile("backend = \"forti\"\nsso = true")));
        assert!(!takes_password(&profile("backend = \"wireguard\"")));
        // A stale SSO flag on a back-end without SSO is ignored.
        assert!(takes_password(&profile("backend = \"f5\"\nsso = true")));
    }

    #[test]
    fn sso_entry_points() {
        assert_eq!(saml_entry("vpn.example.com"), "https://vpn.example.com:443/remote/saml/start?");
        assert_eq!(saml_entry("vpn.example.com:10443"), "https://vpn.example.com:10443/remote/saml/start?");
        assert_eq!(anyconnect_saml_entry("https://vpn.example.com/staff"), "https://vpn.example.com/+CSCOE+/saml/");
        assert_eq!(anyconnect_saml_entry("vpn.example.com:443"), "https://vpn.example.com/+CSCOE+/saml/");
        assert_eq!(anyconnect_saml_entry("vpn.example.com:8443"), "https://vpn.example.com:8443/+CSCOE+/saml/");
    }
}
