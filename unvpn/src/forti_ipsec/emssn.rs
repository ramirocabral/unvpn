//! The FortiClient endpoint-info payload carried in IKE_AUTH, recovered from
//! `/opt/forticlient/iked` (7.4.3) by RE:
//!
//! - It is a **single Notify** of type **`0xF100` (FORTICLIENT_CONNECT)** — from
//!   iked's name/type table in `.rodata` (`FORTICLIENT_CONNECT`→`0xF100`, alongside
//!   `VPN_NETWORK_ID`→`0xF050`, `DEV_ID_NOTIFY`→`0xF103`, `CLIENT_RESUME`→`0xF118`;
//!   0xF118 also appears as a code immediate, confirming the table's wire values).
//! - Its data is a **`\n`-separated `KEY=value` text blob** built by the client
//!   (decompiled from the string-assembly at ~0x48d2xx): the fields, in order, are
//!   `TVER` `UID` `IP` `HOST` `OSVER` `REG_STATUS` `EMSID` `USER` `EMSSN`. `HOST`
//!   comes from `gethostname(2)`, `TVER` is the FortiClient version (`7.4.3.5411`),
//!   and **`EMSSN=<serial>`** is the EMS serial number the gateway validates
//!   (iked error: "IPsec VPN login failed due to mismatched pre-shared key, client
//!   certificate, or EMS serial number").
//!
//! The EMS serial is only issued by the gateway's EMS to a registered endpoint and
//! cannot be fabricated. This module presents a serial the operator already holds
//! (via `--emssn` / `UNVPN_EMSSN`, or — once implemented — read from a locally
//! EMS-registered FortiClient). The other fields are informational; the gateway
//! gates on `EMSSN`.

#![allow(dead_code)]

use super::model::{FORTICLIENT_TVER, N_FORTINET_FORTICLIENT_CONNECT};
use super::wire::{Notify, Payload};

/// Where to get the EMS serial the gateway expects.
#[derive(Debug, Clone)]
pub enum EmsSerial {
    Explicit(String),
    None,
}

impl EmsSerial {
    /// Resolve from an explicit value, else `UNVPN_EMSSN`, else the locally installed
    /// FortiClient's registered serial, else None.
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

/// The FortiClient endpoint-info fields. Only `EMSSN` is validated by the gateway;
/// the rest are filled best-effort (empty is accepted for the informational ones).
#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub tver: String,
    pub uid: String,
    pub ip: String,
    pub host: String,
    pub osver: String,
    pub reg_status: String,
    pub emsid: String,
    pub user: String,
    pub emssn: String,
}

impl ClientInfo {
    pub fn new(user: &str, emssn: &str) -> Self {
        ClientInfo {
            tver: FORTICLIENT_TVER.to_string(),
            uid: String::new(),
            ip: String::new(),
            host: hostname(),
            osver: String::new(),
            reg_status: "1".to_string(), // 1 = registered
            emsid: String::new(),
            user: user.to_string(),
            emssn: emssn.to_string(),
        }
    }

    /// The `\n`-separated `KEY=value` blob, in the field order iked emits.
    pub fn blob(&self) -> Vec<u8> {
        let fields = [
            ("TVER", &self.tver),
            ("UID", &self.uid),
            ("IP", &self.ip),
            ("HOST", &self.host),
            ("OSVER", &self.osver),
            ("REG_STATUS", &self.reg_status),
            ("EMSID", &self.emsid),
            ("USER", &self.user),
            ("EMSSN", &self.emssn),
        ];
        let mut out = Vec::new();
        for (k, v) in fields {
            out.extend_from_slice(k.as_bytes());
            out.push(b'=');
            out.extend_from_slice(v.as_bytes());
            out.push(b'\n');
        }
        out
    }
}

/// `gethostname(2)`, matching iked's HOST= source. Falls back to "localhost".
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

/// Best-effort read of the EMS serial from a locally installed, EMS-registered
/// FortiClient. STUB: the real source is iked's `fct_get_emssn` (shm /
/// `epctrl_ems_serial` in the config DB); not guessing a value that would fail the
/// gateway. Filled once the box is registered + the field is located.
fn read_local_forticlient_emssn() -> Option<String> {
    None
}

/// The FortiClient IKE_AUTH Notify payload(s) for the given serial and user. Empty
/// when there is no serial (a non-EMS-enforcing FortiGate ignores it).
pub fn auth_payloads(serial: &EmsSerial, user: &str) -> Vec<Payload> {
    let Some(sn) = serial.as_str() else {
        return Vec::new();
    };
    let info = ClientInfo::new(user, sn);
    vec![Payload::Notify(Notify {
        protocol: 0,
        spi: vec![],
        ntype: N_FORTINET_FORTICLIENT_CONNECT,
        data: info.blob(),
    })]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_serial_means_no_payloads() {
        assert!(auth_payloads(&EmsSerial::None, "user").is_empty());
    }

    #[test]
    fn forticlient_connect_notify_type_and_blob() {
        let ps = auth_payloads(&EmsSerial::Explicit("FCTEMS0000123456".into()), "jdoe");
        assert_eq!(ps.len(), 1);
        let Payload::Notify(n) = &ps[0] else { panic!("expected Notify") };
        assert_eq!(n.ntype, 0xF100);
        assert_eq!(n.protocol, 0);
        assert!(n.spi.is_empty());
        let text = String::from_utf8(n.data.clone()).unwrap();
        // Field order and separator match iked's assembly.
        assert!(text.starts_with("TVER=7.4.3.5411\n"));
        assert!(text.contains("\nUSER=jdoe\n"));
        assert!(text.contains("\nEMSSN=FCTEMS0000123456\n"));
        // TVER first, EMSSN last.
        assert!(text.find("TVER=").unwrap() < text.find("EMSSN=").unwrap());
        assert!(text.ends_with("EMSSN=FCTEMS0000123456\n"));
    }

    #[test]
    fn blob_field_order_exact() {
        let info = ClientInfo::new("u", "S");
        let text = String::from_utf8(info.blob()).unwrap();
        let order: Vec<&str> = text.lines().map(|l| l.split('=').next().unwrap()).collect();
        assert_eq!(order, ["TVER", "UID", "IP", "HOST", "OSVER", "REG_STATUS", "EMSID", "USER", "EMSSN"]);
    }

    #[test]
    fn resolve_prefers_explicit_over_env() {
        assert_eq!(EmsSerial::resolve(Some("ABC")).as_str(), Some("ABC"));
    }
}
