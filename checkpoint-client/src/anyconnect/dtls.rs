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

use std::ffi::{c_int, c_uint, c_void, CString};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::raw::c_char;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

// ───────────────────────────── GnuTLS FFI ──────────────────────────────────

type GnutlsSession = *mut c_void;

#[repr(C)]
struct GnutlsDatum {
    data: *const u8,
    size: c_uint,
}

#[link(name = "gnutls")]
extern "C" {
    fn gnutls_global_init() -> c_int;
    fn gnutls_init(session: *mut GnutlsSession, flags: c_uint) -> c_int;
    fn gnutls_deinit(session: GnutlsSession);
    fn gnutls_priority_set_direct(session: GnutlsSession, prio: *const c_char, err_pos: *mut *const c_char) -> c_int;
    fn gnutls_record_disable_padding(session: GnutlsSession);
    #[allow(clippy::too_many_arguments)]
    fn gnutls_session_set_premaster(
        session: GnutlsSession,
        entity: c_uint,
        version: c_int,
        kx: c_int,
        cipher: c_int,
        mac: c_int,
        comp: c_int,
        master: *const GnutlsDatum,
        session_id: *const GnutlsDatum,
    ) -> c_int;
    fn gnutls_transport_set_int2(session: GnutlsSession, r: c_int, s: c_int);
    fn gnutls_dtls_set_mtu(session: GnutlsSession, mtu: c_uint);
    fn gnutls_handshake(session: GnutlsSession) -> c_int;
    fn gnutls_record_get_direction(session: GnutlsSession) -> c_int;
    fn gnutls_record_recv(session: GnutlsSession, data: *mut c_void, len: usize) -> isize;
    fn gnutls_record_send(session: GnutlsSession, data: *const c_void, len: usize) -> isize;
    fn gnutls_bye(session: GnutlsSession, how: c_int) -> c_int;
    fn gnutls_error_is_fatal(err: c_int) -> c_int;
    fn gnutls_strerror(err: c_int) -> *const c_char;
}

// gnutls_init flags.
const GNUTLS_CLIENT: c_uint = 1 << 1;
const GNUTLS_DATAGRAM: c_uint = 1 << 2;
const GNUTLS_NONBLOCK: c_uint = 1 << 3;
const GNUTLS_NO_DEFAULT_EXTENSIONS: c_uint = 1 << 4;
// Protocols / algorithms (gnutls.h enums).
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
const GNUTLS_COMP_NULL: c_int = 1;
// Errors.
const GNUTLS_E_AGAIN: c_int = -28;
const GNUTLS_E_INTERRUPTED: c_int = -52;
const GNUTLS_E_REHANDSHAKE: c_int = -37;
const GNUTLS_SHUT_WR: c_int = 1;

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

/// A live DTLS channel. Owns the UDP socket (its fd backs the GnuTLS transport) and
/// the GnuTLS session, freed on drop.
pub struct Dtls {
    session: GnutlsSession,
    _sock: UdpSocket,
    fd: c_int,
}

// Touched only from the single data-loop thread that owns it.
unsafe impl Send for Dtls {}

impl Dtls {
    pub fn fd(&self) -> c_int {
        self.fd
    }

    /// Send one `[type][payload]` datagram. UDP best-effort: `WouldBlock` is dropped.
    pub fn send(&self, ty: u8, payload: &[u8]) -> Result<(), String> {
        let mut pkt = Vec::with_capacity(1 + payload.len());
        pkt.push(ty);
        pkt.extend_from_slice(payload);
        let n = unsafe { gnutls_record_send(self.session, pkt.as_ptr() as *const c_void, pkt.len()) };
        if n >= 0 {
            return Ok(());
        }
        let e = n as c_int;
        if e == GNUTLS_E_AGAIN || e == GNUTLS_E_INTERRUPTED {
            Ok(()) // drop, it's UDP
        } else {
            Err(format!("DTLS send: {}", gnutls_err(e)))
        }
    }

    /// Receive one datagram as `(type, payload)`. `Ok(None)` when nothing is ready.
    pub fn recv(&self) -> Result<Option<(u8, Vec<u8>)>, String> {
        let mut buf = [0u8; 2048];
        let n = unsafe { gnutls_record_recv(self.session, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n > 0 {
            let n = n as usize;
            return Ok(Some((buf[0], buf[1..n].to_vec())));
        }
        if n == 0 {
            return Err("DTLS closed by peer".into());
        }
        let e = n as c_int;
        if e == GNUTLS_E_AGAIN || e == GNUTLS_E_INTERRUPTED || e == GNUTLS_E_REHANDSHAKE {
            Ok(None)
        } else if unsafe { gnutls_error_is_fatal(e) } == 0 {
            Ok(None) // a non-fatal warning (e.g. a benign alert) — keep going
        } else {
            Err(format!("DTLS recv: {}", gnutls_err(e)))
        }
    }
}

impl Drop for Dtls {
    fn drop(&mut self) {
        unsafe {
            if !self.session.is_null() {
                let _ = gnutls_bye(self.session, GNUTLS_SHUT_WR);
                gnutls_deinit(self.session);
            }
        }
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
    let params = resolve(cipher, dtls12).ok_or_else(|| format!("unsupported DTLS cipher {cipher:?}"))?;
    if session_id.is_empty() || master_secret.len() != 48 {
        return Err("missing DTLS session id / master secret".into());
    }

    let sock = UdpSocket::bind(("0.0.0.0", 0)).map_err(|e| format!("DTLS udp bind: {e}"))?;
    sock.connect((gw, port)).map_err(|e| format!("DTLS udp connect {gw}:{port}: {e}"))?;
    sock.set_nonblocking(true).ok();
    let fd = sock.as_raw_fd();

    unsafe {
        gnutls_global_init(); // idempotent on modern GnuTLS

        let mut session: GnutlsSession = std::ptr::null_mut();
        let flags = GNUTLS_CLIENT | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK | GNUTLS_NO_DEFAULT_EXTENSIONS;
        let rc = gnutls_init(&mut session, flags);
        if rc != 0 || session.is_null() {
            return Err(format!("gnutls_init: {}", gnutls_err(rc)));
        }
        let guard = SessionGuard(session);

        gnutls_transport_set_int2(session, fd, fd);
        gnutls_dtls_set_mtu(session, 1500);

        let prio = CString::new(params.prio).unwrap();
        let rc = gnutls_priority_set_direct(session, prio.as_ptr(), std::ptr::null_mut());
        if rc != 0 {
            return Err(format!("DTLS priority {:?}: {}", params.prio, gnutls_err(rc)));
        }
        gnutls_record_disable_padding(session);

        let master = GnutlsDatum { data: master_secret.as_ptr(), size: master_secret.len() as c_uint };
        let sid = GnutlsDatum { data: session_id.as_ptr(), size: session_id.len() as c_uint };
        let rc = gnutls_session_set_premaster(
            session, GNUTLS_CLIENT, params.version, params.kx, params.cipher, params.mac, GNUTLS_COMP_NULL,
            &master, &sid,
        );
        if rc != 0 {
            return Err(format!("gnutls_session_set_premaster: {}", gnutls_err(rc)));
        }

        // Handshake (abbreviated/resumed). Non-blocking: poll the fd between tries.
        let deadline = Instant::now() + timeout;
        loop {
            let rc = gnutls_handshake(session);
            if rc == 0 {
                break;
            }
            if rc != GNUTLS_E_AGAIN && rc != GNUTLS_E_INTERRUPTED {
                return Err(format!("DTLS handshake: {}", gnutls_err(rc)));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("DTLS handshake timed out".into());
            }
            let want_send = gnutls_record_get_direction(session) == 1;
            let mut p = libc::pollfd {
                fd,
                events: if want_send { libc::POLLOUT } else { libc::POLLIN },
                revents: 0,
            };
            let ms = remaining.as_millis().min(1000) as c_int;
            libc::poll(&mut p, 1, ms);
        }

        guard.disarm();
        Ok(Dtls { session, _sock: sock, fd })
    }
}

fn gnutls_err(e: c_int) -> String {
    unsafe {
        let p = gnutls_strerror(e);
        if p.is_null() {
            format!("gnutls error {e}")
        } else {
            std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

/// Frees the GnuTLS session on an early error return; `disarm` once it's handed off.
struct SessionGuard(GnutlsSession);
impl SessionGuard {
    fn disarm(mut self) {
        self.0 = std::ptr::null_mut();
    }
}
impl Drop for SessionGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { gnutls_deinit(self.0) };
        }
    }
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
