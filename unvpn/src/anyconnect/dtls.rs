//! Cisco AnyConnect DTLS data plane (UDP) — the fast path, via **GnuTLS**.
//!
//! AnyConnect's DTLS is a "resume of a session that never existed": client and
//! server already share a master secret (`X-DTLS-Master-Secret` sent in the CSTP
//! CONNECT) and a session id (`X-DTLS-Session-ID` returned), so the client injects
//! those into a DTLS session and completes an abbreviated handshake with no key
//! exchange. GnuTLS exposes exactly this via `gnutls_session_set_premaster`, and —
//! crucially — `GNUTLS_NO_DEFAULT_EXTENSIONS` lets it emit the *minimal* ClientHello
//! the ASA accepts (no `supported_groups`/`ec_point_formats`/`extended_master_secret`
//! that OpenSSL always adds for an ECDHE cipher and that make a modern ASA reject the
//! resume with an alert). This is why openconnect uses GnuTLS for AnyConnect DTLS,
//! and why we link it here just for the DTLS socket (OpenSSL stays for the TLS/CSTP
//! side). Parameters/priority strings mirror openconnect `gnutls-dtls.c`.
//!
//! Each datagram is `[type byte][payload]` (0 DATA, 3/4 DPD, 7 keepalive,
//! 5 disconnect) — the CSTP type codes with a 1-byte header instead of the STF one.
//! Best-effort: if the handshake doesn't complete, the caller stays on CSTP.
//!
//! **libgnutls is loaded at runtime with `dlopen`, never link-time.** That keeps the
//! engine a single distro-agnostic binary: it starts everywhere with no hard
//! dependency, uses the DTLS fast path where libgnutls is present (nearly all
//! distros), and silently stays on CSTP where it isn't. (A link-time dependency
//! would stop the binary even *starting* on a host without libgnutls.)

use crate::gnutls::{DtlsSession, Resume};
use std::ffi::c_int;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

// GnuTLS enums (gnutls.h) for the resume parameters.
const GNUTLS_DTLS1_0: c_int = 201;
const GNUTLS_DTLS1_2: c_int = 202;
const GNUTLS_CIPHER_3DES_CBC: c_int = 3;
const GNUTLS_CIPHER_AES_128_CBC: c_int = 4;
const GNUTLS_CIPHER_AES_256_CBC: c_int = 5;
const GNUTLS_CIPHER_AES_128_GCM: c_int = 10;
const GNUTLS_CIPHER_AES_256_GCM: c_int = 11;
const GNUTLS_KX_RSA: c_int = 1;
const GNUTLS_KX_DHE_RSA: c_int = 3;
const GNUTLS_KX_ECDHE_RSA: c_int = 12;
const GNUTLS_MAC_SHA1: c_int = 3;
const GNUTLS_MAC_AEAD: c_int = 200;

/// The cipher list to advertise in `X-DTLS12-CipherSuite` — openconnect's GnuTLS
/// order, ECDHE first. The ASA echoes back the chosen name, which [`resolve`] maps.
pub const DTLS12_CIPHERSUITES: &str =
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384";

/// DTLS parameters for one Cisco cipher name (mirrors openconnect `gnutls_dtls_ciphers`).
struct Params {
    version: c_int,
    kx: c_int,
    cipher: c_int,
    mac: c_int,
    prio: &'static str,
}

/// Resolve the gateway's cipher name to GnuTLS DTLS parameters. `dtls12` selects
/// the modern (DTLS 1.2) table vs the classic (DTLS 1.0) one.
fn resolve(name: &str, dtls12: bool) -> Option<Params> {
    let p = |version, kx, cipher, mac, prio| Params { version, kx, cipher, mac, prio };
    Some(if dtls12 {
        match name {
            "ECDHE-RSA-AES256-GCM-SHA384" => p(GNUTLS_DTLS1_2, GNUTLS_KX_ECDHE_RSA, GNUTLS_CIPHER_AES_256_GCM, GNUTLS_MAC_AEAD,
                "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-256-GCM:+AEAD:+ECDHE-RSA:+SIGN-ALL:%COMPAT"),
            "ECDHE-RSA-AES128-GCM-SHA256" => p(GNUTLS_DTLS1_2, GNUTLS_KX_ECDHE_RSA, GNUTLS_CIPHER_AES_128_GCM, GNUTLS_MAC_AEAD,
                "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-128-GCM:+AEAD:+ECDHE-RSA:+SIGN-ALL:%COMPAT"),
            "AES256-GCM-SHA384" => p(GNUTLS_DTLS1_2, GNUTLS_KX_RSA, GNUTLS_CIPHER_AES_256_GCM, GNUTLS_MAC_AEAD,
                "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-256-GCM:+AEAD:+RSA:+SIGN-ALL:%COMPAT"),
            "AES128-GCM-SHA256" => p(GNUTLS_DTLS1_2, GNUTLS_KX_RSA, GNUTLS_CIPHER_AES_128_GCM, GNUTLS_MAC_AEAD,
                "NONE:+VERS-DTLS1.2:+COMP-NULL:+AES-128-GCM:+AEAD:+RSA:+SIGN-ALL:%COMPAT"),
            _ => return None,
        }
    } else {
        match name {
            "AES256-SHA" => p(GNUTLS_DTLS1_0, GNUTLS_KX_RSA, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_MAC_SHA1,
                "NONE:+VERS-DTLS1.0:+COMP-NULL:+AES-256-CBC:+SHA1:+RSA:+SIGN-ALL:%COMPAT"),
            "AES128-SHA" => p(GNUTLS_DTLS1_0, GNUTLS_KX_RSA, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_MAC_SHA1,
                "NONE:+VERS-DTLS1.0:+COMP-NULL:+AES-128-CBC:+SHA1:+RSA:+SIGN-ALL:%COMPAT"),
            "DES-CBC3-SHA" => p(GNUTLS_DTLS1_0, GNUTLS_KX_RSA, GNUTLS_CIPHER_3DES_CBC, GNUTLS_MAC_SHA1,
                "NONE:+VERS-DTLS1.0:+COMP-NULL:+3DES-CBC:+SHA1:+RSA:+SIGN-ALL:%COMPAT"),
            "DHE-RSA-AES256-SHA" => p(GNUTLS_DTLS1_0, GNUTLS_KX_DHE_RSA, GNUTLS_CIPHER_AES_256_CBC, GNUTLS_MAC_SHA1,
                "NONE:+VERS-DTLS1.0:+COMP-NULL:+AES-256-CBC:+SHA1:+DHE-RSA:+SIGN-ALL:%COMPAT"),
            "DHE-RSA-AES128-SHA" => p(GNUTLS_DTLS1_0, GNUTLS_KX_DHE_RSA, GNUTLS_CIPHER_AES_128_CBC, GNUTLS_MAC_SHA1,
                "NONE:+VERS-DTLS1.0:+COMP-NULL:+AES-128-CBC:+SHA1:+DHE-RSA:+SIGN-ALL:%COMPAT"),
            _ => return None,
        }
    })
}

/// A live AnyConnect DTLS channel: `[type][payload]` records over a resumed session
/// (the shared GnuTLS layer is in `crate::gnutls`).
pub struct Dtls(DtlsSession);

impl Dtls {
    pub fn fd(&self) -> c_int {
        self.0.fd()
    }

    /// Send one `[type][payload]` datagram. UDP best-effort: `WouldBlock` is dropped.
    pub fn send(&self, ty: u8, payload: &[u8]) -> Result<(), String> {
        let mut pkt = Vec::with_capacity(1 + payload.len());
        pkt.push(ty);
        pkt.extend_from_slice(payload);
        self.0.send(&pkt).map(|_| ())
    }

    /// Receive one datagram as `(type, payload)`. `Ok(None)` when nothing is ready.
    pub fn recv(&self) -> Result<Option<(u8, Vec<u8>)>, String> {
        let mut buf = [0u8; 2048];
        Ok(match self.0.recv(&mut buf)? {
            Some(n) if n > 0 => Some((buf[0], buf[1..n].to_vec())),
            _ => None,
        })
    }
}

/// Bring up the DTLS channel by resuming the pre-shared session. `master_secret` is
/// the exact 48 bytes sent in `X-DTLS-Master-Secret`; `session_id` the decoded
/// `X-DTLS-Session-ID`; `cipher` the gateway's chosen `X-DTLS[12]-CipherSuite`.
pub fn connect(
    gw: Ipv4Addr,
    port: u16,
    session_id: &[u8],
    master_secret: &[u8],
    cipher: &str,
    dtls12: bool,
    timeout: Duration,
) -> Result<Dtls, String> {
    let p = resolve(cipher, dtls12).ok_or_else(|| format!("unsupported DTLS cipher {cipher:?}"))?;
    let r = Resume {
        session_id,
        master_secret,
        version: p.version,
        kx: p.kx,
        cipher: p.cipher,
        mac: p.mac,
        priority: p.prio,
    };
    DtlsSession::connect_resume(IpAddr::V4(gw), port, &r, timeout).map(Dtls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_modern_and_classic() {
        let m = resolve("ECDHE-RSA-AES256-GCM-SHA384", true).unwrap();
        assert_eq!(m.version, GNUTLS_DTLS1_2);
        assert_eq!(m.kx, GNUTLS_KX_ECDHE_RSA);
        assert_eq!(m.cipher, GNUTLS_CIPHER_AES_256_GCM);
        assert!(m.prio.contains("VERS-DTLS1.2") && m.prio.contains("ECDHE-RSA"));

        let c = resolve("AES256-SHA", false).unwrap();
        assert_eq!(c.version, GNUTLS_DTLS1_0);
        assert_eq!(c.cipher, GNUTLS_CIPHER_AES_256_CBC);
        assert_eq!(c.mac, GNUTLS_MAC_SHA1);
    }

    #[test]
    fn rejects_wrong_table_or_unknown() {
        assert!(resolve("ECDHE-RSA-AES256-GCM-SHA384", false).is_none());
        assert!(resolve("AES256-SHA", true).is_none());
        assert!(resolve("bogus", true).is_none());
    }

    #[test]
    fn offered_ciphersuites_are_ecdhe_first() {
        assert!(DTLS12_CIPHERSUITES.starts_with("ECDHE-RSA-AES256-GCM-SHA384"));
    }
}
