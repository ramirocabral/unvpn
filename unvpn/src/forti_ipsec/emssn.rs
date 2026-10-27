//! FortiClient endpoint-info payload carried in the first IKE_AUTH.
//!
//! A single Notify of type `0xF100` (FORTICLIENT_CONNECT) whose data is a
//! `\n`-separated `KEY=value` blob. EMS-managed gateways require it to accept the
//! session; a registered endpoint also sends its EMS serial. Unregistered endpoints
//! send `REG_STATUS=0` with empty serial and still connect.

#![allow(dead_code)]

use super::model::{FORTICLIENT_TVER, N_FORTINET_DEV_ID_NOTIFY, N_FORTINET_FORTICLIENT_CONNECT};
use super::wire::{Notify, Payload};

/// The EMS serial the gateway expects, if any.
#[derive(Debug, Clone)]
pub enum EmsSerial {
    Explicit(String),
    None,
}

impl EmsSerial {
    pub fn resolve(explicit: Option<&str>) -> EmsSerial {
        if let Some(s) = explicit.filter(|s| !s.is_empty()) {
            return EmsSerial::Explicit(s.to_string());
        }
        if let Ok(s) = std::env::var("UNVPN_EMSSN") {
            if !s.is_empty() {
                return EmsSerial::Explicit(s);
            }
        }
        if let Some(s) = read_local_forticlient_emssn() {
            return EmsSerial::Explicit(s);
        }
        EmsSerial::None
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            EmsSerial::Explicit(s) => Some(s),
            EmsSerial::None => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub fctver: String,
    pub uid: String,
    pub ip: String,
    pub host: String,
    pub osver: String,
    pub reg_status: String,
    pub emsid: String,
    pub user: String,
    pub emssn: String,
}

/// `UNVPN_FCT_<KEY>` override for an endpoint-info field, else `default`.
fn env_or(key: &str, default: String) -> String {
    std::env::var(format!("UNVPN_FCT_{key}")).unwrap_or(default)
}

impl ClientInfo {
    pub fn unregistered(user: &str, ip: &str, fctver: &str) -> Self {
        Self::build(user, ip, fctver, "", "0")
    }

    pub fn registered(user: &str, ip: &str, fctver: &str, emssn: &str) -> Self {
        Self::build(user, ip, fctver, emssn, "1")
    }

    /// Each informational field resolves as: explicit argument → `UNVPN_FCT_<KEY>`
    /// env override → host-derived default.
    fn build(user: &str, ip: &str, fctver: &str, emssn: &str, reg_default: &str) -> Self {
        let fctver = if fctver.is_empty() {
            env_or("FCTVER", FORTICLIENT_TVER.to_string())
        } else {
            fctver.to_string()
        };
        ClientInfo {
            fctver,
            uid: env_or("UID", machine_uid()),
            ip: env_or("IP", ip.to_string()),
            host: env_or("HOST", hostname()),
            osver: env_or("OSVER", os_version()),
            reg_status: env_or("REG_STATUS", reg_default.to_string()),
            emsid: env_or("EMSID", String::new()),
            user: user.to_string(),
            emssn: emssn.to_string(),
        }
    }

    /// `KEY=value\n` blob: `VER=1`, then
    /// `FCTVER UID IP HOST [USER] OSVER REG_STATUS [EMSSN] [EMSID]`. `USER`, `EMSSN`
    /// and `EMSID` are omitted when empty.
    pub fn blob(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_line(&mut out, "VER", "1");
        push_line(&mut out, "FCTVER", &self.fctver);
        push_line(&mut out, "UID", &self.uid);
        push_line(&mut out, "IP", &self.ip);
        push_line(&mut out, "HOST", &self.host);
        if !self.user.is_empty() {
            push_line(&mut out, "USER", &self.user);
        }
        push_line(&mut out, "OSVER", &self.osver);
        push_line(&mut out, "REG_STATUS", &self.reg_status);
        if !self.emssn.is_empty() {
            push_line(&mut out, "EMSSN", &self.emssn);
        }
        if !self.emsid.is_empty() {
            push_line(&mut out, "EMSID", &self.emsid);
        }
        out
    }
}

fn push_line(out: &mut Vec<u8>, key: &str, value: &str) {
    out.extend_from_slice(key.as_bytes());
    out.push(b'=');
    out.extend_from_slice(value.as_bytes());
    out.push(b'\n');
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    let r = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if r == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    } else {
        "localhost".to_string()
    }
}

/// Stable 32-hex-uppercase device id for `UID=`, from `/etc/machine-id` when it has
/// that shape, else a hostname-derived hash.
fn machine_uid() -> String {
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        let id = id.trim();
        if id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return id.to_ascii_uppercase();
        }
    }
    local_uid()
}

/// `OSVER=`, from `uname(2)`. Override via `UNVPN_FCT_OSVER` when a deployment
/// expects a specific string.
fn os_version() -> String {
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut u) == 0 {
            let field = |a: &[libc::c_char]| {
                let end = a.iter().position(|&c| c == 0).unwrap_or(a.len());
                let bytes: Vec<u8> = a[..end].iter().map(|&c| c as u8).collect();
                String::from_utf8_lossy(&bytes).into_owned()
            };
            return format!("{} {} {}", field(&u.sysname), field(&u.release), field(&u.machine));
        }
    }
    "Linux".to_string()
}

fn read_local_forticlient_emssn() -> Option<String> {
    None
}

pub fn auth_payloads(serial: &EmsSerial, user: &str, ip: &str, fctver: &str) -> Vec<Payload> {
    let info = match serial.as_str() {
        Some(sn) => ClientInfo::registered(user, ip, fctver, sn),
        None => ClientInfo::unregistered(user, ip, fctver),
    };
    let mut payloads = vec![Payload::Notify(Notify {
        protocol: 0,
        spi: vec![],
        ntype: N_FORTINET_FORTICLIENT_CONNECT,
        data: info.blob(),
    })];
    // A registered endpoint also sends the raw EMS serial in a separate Notify.
    if let Some(sn) = serial.as_str() {
        payloads.push(Payload::Notify(Notify {
            protocol: 0,
            spi: vec![],
            ntype: N_FORTINET_DEV_ID_NOTIFY,
            data: sn.as_bytes().to_vec(),
        }));
    }
    payloads
}

/// FNV-1a over the hostname, expanded to 128 bits, as a stable fallback UID.
fn local_uid() -> String {
    let host = hostname();
    let mut out = String::with_capacity(32);
    for salt in [0u8, 1, 2, 3] {
        let mut h: u64 = 0xcbf29ce484222325 ^ (salt as u64);
        for b in host.bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        out.push_str(&format!("{:08X}", (h ^ (h >> 32)) as u32));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_serial_sends_unregistered_payload() {
        let ps = auth_payloads(&EmsSerial::None, "user", "10.0.0.2", "");
        assert_eq!(ps.len(), 1);
        let Payload::Notify(n) = &ps[0] else { panic!("expected Notify") };
        let text = String::from_utf8(n.data.clone()).unwrap();
        assert!(text.starts_with("VER=1\nFCTVER="));
        assert!(text.contains("\nIP=10.0.0.2\n"));
        assert!(text.contains("\nREG_STATUS=0\n"));
        assert!(!text.contains("EMSSN="));
        assert!(!text.contains("EMSID="));
    }

    #[test]
    fn forticlient_connect_notify_type_and_blob() {
        let ps = auth_payloads(&EmsSerial::Explicit("FCTEMS0000123456".into()), "jdoe", "10.0.0.2", "");
        assert_eq!(ps.len(), 2);
        let Payload::Notify(n2) = &ps[1] else { panic!("expected a second Notify") };
        assert_eq!(n2.ntype, 0xF103);
        assert_eq!(n2.data, b"FCTEMS0000123456");
        let Payload::Notify(n) = &ps[0] else { panic!("expected Notify") };
        assert_eq!(n.ntype, 0xF100);
        assert_eq!(n.protocol, 0);
        assert!(n.spi.is_empty());
        let text = String::from_utf8(n.data.clone()).unwrap();
        assert!(text.starts_with("VER=1\nFCTVER=7.2.15.1309\n"));
        assert!(text.contains("\nUSER=jdoe\n"));
        assert!(text.contains("\nREG_STATUS=1\n"));
        assert!(text.ends_with("EMSSN=FCTEMS0000123456\n"));
        assert!(text.find("USER=").unwrap() < text.find("OSVER=").unwrap());
        assert!(text.find("REG_STATUS=").unwrap() < text.find("EMSSN=").unwrap());
    }

    #[test]
    fn blob_field_order_exact() {
        let info = ClientInfo::registered("u", "1.2.3.4", "", "S");
        let text = String::from_utf8(info.blob()).unwrap();
        let order: Vec<&str> = text.lines().map(|l| l.split('=').next().unwrap()).collect();
        assert_eq!(order, ["VER", "FCTVER", "UID", "IP", "HOST", "USER", "OSVER", "REG_STATUS", "EMSSN"]);
    }

    #[test]
    fn resolve_prefers_explicit_over_env() {
        assert_eq!(EmsSerial::resolve(Some("ABC")).as_str(), Some("ABC"));
    }
}
