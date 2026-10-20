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

use std::ffi::{c_int, c_uint, c_void, CString};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::raw::c_char;
use std::os::unix::io::AsRawFd;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// ───────────────────────── GnuTLS: runtime-loaded FFI ───────────────────────

type GnutlsSession = *mut c_void;

#[repr(C)]
struct GnutlsDatum {
    data: *const u8,
    size: c_uint,
}

/// The gnutls entry points we use, resolved from the shared object at runtime.
#[allow(clippy::type_complexity)]
struct Gnutls {
    global_init: unsafe extern "C" fn() -> c_int,
    init: unsafe extern "C" fn(*mut GnutlsSession, c_uint) -> c_int,
    deinit: unsafe extern "C" fn(GnutlsSession),
    priority_set_direct: unsafe extern "C" fn(GnutlsSession, *const c_char, *mut *const c_char) -> c_int,
    record_disable_padding: unsafe extern "C" fn(GnutlsSession),
    session_set_premaster: unsafe extern "C" fn(
        GnutlsSession, c_uint, c_int, c_int, c_int, c_int, c_int, *const GnutlsDatum, *const GnutlsDatum,
    ) -> c_int,
    transport_set_int2: unsafe extern "C" fn(GnutlsSession, c_int, c_int),
    dtls_set_mtu: unsafe extern "C" fn(GnutlsSession, c_uint),
    handshake: unsafe extern "C" fn(GnutlsSession) -> c_int,
    record_get_direction: unsafe extern "C" fn(GnutlsSession) -> c_int,
    record_recv: unsafe extern "C" fn(GnutlsSession, *mut c_void, usize) -> isize,
    record_send: unsafe extern "C" fn(GnutlsSession, *const c_void, usize) -> isize,
    bye: unsafe extern "C" fn(GnutlsSession, c_int) -> c_int,
    error_is_fatal: unsafe extern "C" fn(c_int) -> c_int,
    strerror: unsafe extern "C" fn(c_int) -> *const c_char,
}

// Only ever read (immutable fn pointers into a library we never unload).
unsafe impl Send for Gnutls {}
unsafe impl Sync for Gnutls {}

static GNUTLS: OnceLock<Option<Gnutls>> = OnceLock::new();

/// The loaded gnutls, or `None` if libgnutls isn't installed / is too old.
fn gnutls() -> Option<&'static Gnutls> {
    GNUTLS.get_or_init(load_gnutls).as_ref()
}

/// `dlopen` libgnutls and resolve the symbols. Returns `None` (not an error) when the
/// library is absent — the caller then stays on CSTP.
fn load_gnutls() -> Option<Gnutls> {
    unsafe {
        // The current soname first, then the dev symlink as a fallback.
        let handle = ["libgnutls.so.30\0", "libgnutls.so\0"].iter().find_map(|name| {
            let h = libc::dlopen(name.as_ptr() as *const c_char, libc::RTLD_NOW | libc::RTLD_GLOBAL);
            if h.is_null() {
                None
            } else {
                Some(h)
            }
        })?;

        // Resolve a symbol or bail (whole feature off) if any is missing. The handle
        // is intentionally never dlclose'd — gnutls stays mapped for the process.
        macro_rules! sym {
            ($name:literal) => {{
                let p = libc::dlsym(handle, concat!($name, "\0").as_ptr() as *const c_char);
                if p.is_null() {
                    return None;
                }
                std::mem::transmute(p)
            }};
        }
        Some(Gnutls {
            global_init: sym!("gnutls_global_init"),
            init: sym!("gnutls_init"),
            deinit: sym!("gnutls_deinit"),
            priority_set_direct: sym!("gnutls_priority_set_direct"),
            record_disable_padding: sym!("gnutls_record_disable_padding"),
            session_set_premaster: sym!("gnutls_session_set_premaster"),
            transport_set_int2: sym!("gnutls_transport_set_int2"),
            dtls_set_mtu: sym!("gnutls_dtls_set_mtu"),
            handshake: sym!("gnutls_handshake"),
            record_get_direction: sym!("gnutls_record_get_direction"),
            record_recv: sym!("gnutls_record_recv"),
            record_send: sym!("gnutls_record_send"),
            bye: sym!("gnutls_bye"),
            error_is_fatal: sym!("gnutls_error_is_fatal"),
            strerror: sym!("gnutls_strerror"),
        })
    }
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
    g: &'static Gnutls,
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
        let n = unsafe { (self.g.record_send)(self.session, pkt.as_ptr() as *const c_void, pkt.len()) };
        if n >= 0 {
            return Ok(());
        }
        let e = n as c_int;
        if e == GNUTLS_E_AGAIN || e == GNUTLS_E_INTERRUPTED {
            Ok(()) // drop, it's UDP
        } else {
            Err(format!("DTLS send: {}", gnutls_err(self.g, e)))
        }
    }

    /// Receive one datagram as `(type, payload)`. `Ok(None)` when nothing is ready.
    pub fn recv(&self) -> Result<Option<(u8, Vec<u8>)>, String> {
        let mut buf = [0u8; 2048];
        let n = unsafe { (self.g.record_recv)(self.session, buf.as_mut_ptr() as *mut c_void, buf.len()) };
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
        } else if unsafe { (self.g.error_is_fatal)(e) } == 0 {
            Ok(None) // a non-fatal warning (e.g. a benign alert) — keep going
        } else {
            Err(format!("DTLS recv: {}", gnutls_err(self.g, e)))
        }
    }
}

impl Drop for Dtls {
    fn drop(&mut self) {
        unsafe {
            if !self.session.is_null() {
                let _ = (self.g.bye)(self.session, GNUTLS_SHUT_WR);
                (self.g.deinit)(self.session);
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
    let g = gnutls().ok_or("libgnutls not available on this host (DTLS off; using CSTP)")?;

    let sock = UdpSocket::bind(("0.0.0.0", 0)).map_err(|e| format!("DTLS udp bind: {e}"))?;
    sock.connect((gw, port)).map_err(|e| format!("DTLS udp connect {gw}:{port}: {e}"))?;
    sock.set_nonblocking(true).ok();
    let fd = sock.as_raw_fd();

    unsafe {
        (g.global_init)(); // idempotent on modern GnuTLS

        let mut session: GnutlsSession = std::ptr::null_mut();
        let flags = GNUTLS_CLIENT | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK | GNUTLS_NO_DEFAULT_EXTENSIONS;
        let rc = (g.init)(&mut session, flags);
        if rc != 0 || session.is_null() {
            return Err(format!("gnutls_init: {}", gnutls_err(g, rc)));
        }
        let guard = SessionGuard(session, g);

        (g.transport_set_int2)(session, fd, fd);
        (g.dtls_set_mtu)(session, 1500);

        let prio = CString::new(params.prio).unwrap();
        let rc = (g.priority_set_direct)(session, prio.as_ptr(), std::ptr::null_mut());
        if rc != 0 {
            return Err(format!("DTLS priority {:?}: {}", params.prio, gnutls_err(g, rc)));
        }
        (g.record_disable_padding)(session);

        let master = GnutlsDatum { data: master_secret.as_ptr(), size: master_secret.len() as c_uint };
        let sid = GnutlsDatum { data: session_id.as_ptr(), size: session_id.len() as c_uint };
        let rc = (g.session_set_premaster)(
            session, GNUTLS_CLIENT, params.version, params.kx, params.cipher, params.mac, GNUTLS_COMP_NULL,
            &master, &sid,
        );
        if rc != 0 {
            return Err(format!("gnutls_session_set_premaster: {}", gnutls_err(g, rc)));
        }

        // Handshake (abbreviated/resumed). Non-blocking: poll the fd between tries.
        let deadline = Instant::now() + timeout;
        loop {
            let rc = (g.handshake)(session);
            if rc == 0 {
                break;
            }
            if rc != GNUTLS_E_AGAIN && rc != GNUTLS_E_INTERRUPTED {
                return Err(format!("DTLS handshake: {}", gnutls_err(g, rc)));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("DTLS handshake timed out".into());
            }
            let want_send = (g.record_get_direction)(session) == 1;
            let mut p = libc::pollfd {
                fd,
                events: if want_send { libc::POLLOUT } else { libc::POLLIN },
                revents: 0,
            };
            let ms = remaining.as_millis().min(1000) as c_int;
            libc::poll(&mut p, 1, ms);
        }

        guard.disarm();
        Ok(Dtls { session, g, _sock: sock, fd })
    }
}

fn gnutls_err(g: &Gnutls, e: c_int) -> String {
    unsafe {
        let p = (g.strerror)(e);
        if p.is_null() {
            format!("gnutls error {e}")
        } else {
            std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

/// Frees the GnuTLS session on an early error return; `disarm` once it's handed off.
struct SessionGuard(GnutlsSession, &'static Gnutls);
impl SessionGuard {
    fn disarm(mut self) {
        self.0 = std::ptr::null_mut();
    }
}
impl Drop for SessionGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { (self.1.deinit)(self.0) };
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
