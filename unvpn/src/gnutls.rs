//! DTLS over UDP via **GnuTLS**, shared by every back-end's UDP fast path.
//!
//! Two ways to bring a DTLS session up:
//! * [`DtlsSession::connect_resume`] — Cisco AnyConnect's "resume of a session that
//!   never existed" (pre-shared master secret + session id, abbreviated handshake).
//! * [`DtlsSession::connect_cert`] — an ordinary certificate-based DTLS handshake,
//!   used by the PPP protocols (Fortinet, F5): the gateway authenticates the tunnel
//!   afterwards with a vendor "hello" sent as the first application record.
//!
//! [`DtlsStream`] wraps a session as `Read + Write` (one record per call) so the
//! PPP back-ends run their unchanged framing/negotiation code over UDP.
//!
//! **libgnutls is loaded at runtime with `dlopen`, never link-time.** That keeps the
//! engine a single distro-agnostic binary: it starts everywhere with no hard
//! dependency, uses the DTLS fast path where libgnutls is present (nearly all
//! distros), and silently stays on TLS/TCP where it isn't.

use std::ffi::{c_int, c_uint, c_void, CString};
use std::io;
use std::net::{IpAddr, UdpSocket};
use std::os::raw::c_char;
use std::os::unix::io::AsRawFd;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

type GnutlsSession = *mut c_void;
type GnutlsCertCred = *mut c_void;

#[repr(C)]
struct GnutlsDatum {
    data: *const u8,
    size: c_uint,
}

#[allow(clippy::type_complexity)]
struct Gnutls {
    global_init: unsafe extern "C" fn() -> c_int,
    init: unsafe extern "C" fn(*mut GnutlsSession, c_uint) -> c_int,
    deinit: unsafe extern "C" fn(GnutlsSession),
    priority_set_direct: unsafe extern "C" fn(GnutlsSession, *const c_char, *mut *const c_char) -> c_int,
    record_disable_padding: unsafe extern "C" fn(GnutlsSession),
    session_set_premaster: unsafe extern "C" fn(
        GnutlsSession,
        c_uint,
        c_int,
        c_int,
        c_int,
        c_int,
        c_int,
        *const GnutlsDatum,
        *const GnutlsDatum,
    ) -> c_int,
    certificate_allocate_credentials: unsafe extern "C" fn(*mut GnutlsCertCred) -> c_int,
    certificate_free_credentials: unsafe extern "C" fn(GnutlsCertCred),
    credentials_set: unsafe extern "C" fn(GnutlsSession, c_int, *mut c_void) -> c_int,
    transport_set_int2: unsafe extern "C" fn(GnutlsSession, c_int, c_int),
    dtls_set_mtu: unsafe extern "C" fn(GnutlsSession, c_uint),
    dtls_get_data_mtu: unsafe extern "C" fn(GnutlsSession) -> c_uint,
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

pub fn available() -> bool {
    gnutls().is_some()
}

/// `dlopen` libgnutls and resolve the symbols. Returns `None` (not an error) when the
/// library is absent — the caller then stays on TLS/TCP.
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
        let g = Gnutls {
            global_init: sym!("gnutls_global_init"),
            init: sym!("gnutls_init"),
            deinit: sym!("gnutls_deinit"),
            priority_set_direct: sym!("gnutls_priority_set_direct"),
            record_disable_padding: sym!("gnutls_record_disable_padding"),
            session_set_premaster: sym!("gnutls_session_set_premaster"),
            certificate_allocate_credentials: sym!("gnutls_certificate_allocate_credentials"),
            certificate_free_credentials: sym!("gnutls_certificate_free_credentials"),
            credentials_set: sym!("gnutls_credentials_set"),
            transport_set_int2: sym!("gnutls_transport_set_int2"),
            dtls_set_mtu: sym!("gnutls_dtls_set_mtu"),
            dtls_get_data_mtu: sym!("gnutls_dtls_get_data_mtu"),
            handshake: sym!("gnutls_handshake"),
            record_get_direction: sym!("gnutls_record_get_direction"),
            record_recv: sym!("gnutls_record_recv"),
            record_send: sym!("gnutls_record_send"),
            bye: sym!("gnutls_bye"),
            error_is_fatal: sym!("gnutls_error_is_fatal"),
            strerror: sym!("gnutls_strerror"),
        };
        (g.global_init)(); // idempotent on modern GnuTLS
        Some(g)
    }
}

const GNUTLS_CLIENT: c_uint = 1 << 1;
const GNUTLS_DATAGRAM: c_uint = 1 << 2;
const GNUTLS_NONBLOCK: c_uint = 1 << 3;
const GNUTLS_NO_DEFAULT_EXTENSIONS: c_uint = 1 << 4;
const GNUTLS_CRD_CERTIFICATE: c_int = 1;
const GNUTLS_COMP_NULL: c_int = 1;
const GNUTLS_E_AGAIN: c_int = -28;
const GNUTLS_E_INTERRUPTED: c_int = -52;
const GNUTLS_E_REHANDSHAKE: c_int = -37;
const GNUTLS_E_LARGE_PACKET: c_int = -7;
const GNUTLS_SHUT_WR: c_int = 1;

/// Path MTU handed to GnuTLS (UDP payload over a 1500-byte IPv4 link). The record
/// layer then reports how much application data fits ([`DtlsSession::data_mtu`]).
const UDP_PAYLOAD_MTU: c_uint = 1500 - 20 - 8;

/// Priority for the certificate handshake: `NORMAL` minus the
/// broken bits, plus CBC-SHA256 for old servers).
const CERT_PRIORITY: &str = "NORMAL:-VERS-SSL3.0:+SHA256:%COMPAT:-3DES-CBC:-ARCFOUR-128";

/// The pre-shared parameters of an AnyConnect resumed session.
pub struct Resume<'a> {
    pub session_id: &'a [u8],
    pub master_secret: &'a [u8],
    pub version: c_int,
    pub kx: c_int,
    pub cipher: c_int,
    pub mac: c_int,
    pub priority: &'a str,
}

pub struct DtlsSession {
    session: GnutlsSession,
    cred: GnutlsCertCred,
    g: &'static Gnutls,
    _sock: UdpSocket,
    fd: c_int,
}

// Touched only from the single data-loop thread that owns it.
unsafe impl Send for DtlsSession {}

impl DtlsSession {
    /// AnyConnect: resume the session the gateway pre-agreed over CSTP. The flags
    /// (`NO_DEFAULT_EXTENSIONS`) give the minimal ClientHello a modern ASA accepts.
    pub fn connect_resume(gw: IpAddr, port: u16, r: &Resume, timeout: Duration) -> Result<Self, String> {
        if r.session_id.is_empty() || r.master_secret.len() != 48 {
            return Err("missing DTLS session id / master secret".into());
        }
        let mut s = Self::new_raw(gw, port)?;
        let g = s.g;
        unsafe {
            s.set_priority(r.priority)?;
            (g.record_disable_padding)(s.session);
            let master = GnutlsDatum {
                data: r.master_secret.as_ptr(),
                size: r.master_secret.len() as c_uint,
            };
            let sid = GnutlsDatum {
                data: r.session_id.as_ptr(),
                size: r.session_id.len() as c_uint,
            };
            let rc = (g.session_set_premaster)(
                s.session,
                GNUTLS_CLIENT,
                r.version,
                r.kx,
                r.cipher,
                r.mac,
                GNUTLS_COMP_NULL,
                &master,
                &sid,
            );
            if rc != 0 {
                return Err(format!("gnutls_session_set_premaster: {}", err_str(g, rc)));
            }
        }
        s.handshake(timeout)?;
        Ok(s)
    }

    /// Fortinet / F5: an ordinary certificate-based handshake. The server certificate
    /// is not verified — consistent with the TLS side, which accepts the gateway's
    /// (typically self-signed) certificate; the tunnel itself is authenticated by the
    /// vendor hello carrying the session cookie. `dtls12 = false` caps at DTLS 1.0
    /// (old BIG-IPs choke on even being offered 1.2).
    pub fn connect_cert(gw: IpAddr, port: u16, dtls12: bool, timeout: Duration) -> Result<Self, String> {
        let mut s = Self::new_raw(gw, port)?;
        let g = s.g;
        unsafe {
            let rc = (g.certificate_allocate_credentials)(&mut s.cred);
            if rc != 0 || s.cred.is_null() {
                s.cred = std::ptr::null_mut();
                return Err(format!("gnutls credentials: {}", err_str(g, rc)));
            }
            let rc = (g.credentials_set)(s.session, GNUTLS_CRD_CERTIFICATE, s.cred);
            if rc != 0 {
                return Err(format!("gnutls_credentials_set: {}", err_str(g, rc)));
            }
        }
        let prio = if dtls12 {
            CERT_PRIORITY.to_string()
        } else {
            format!("{CERT_PRIORITY}:-VERS-DTLS1.2:+VERS-DTLS1.0")
        };
        s.set_priority(&prio)?;
        s.handshake(timeout)?;
        Ok(s)
    }

    fn new_raw(gw: IpAddr, port: u16) -> Result<Self, String> {
        let g = gnutls().ok_or("libgnutls not available on this host (DTLS off)")?;
        let bind = if gw.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let sock = UdpSocket::bind(bind).map_err(|e| format!("DTLS udp bind: {e}"))?;
        sock.connect((gw, port))
            .map_err(|e| format!("DTLS udp connect {gw}:{port}: {e}"))?;
        sock.set_nonblocking(true).ok();
        let fd = sock.as_raw_fd();
        let mut session: GnutlsSession = std::ptr::null_mut();
        let flags = GNUTLS_CLIENT | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK | GNUTLS_NO_DEFAULT_EXTENSIONS;
        let rc = unsafe { (g.init)(&mut session, flags) };
        if rc != 0 || session.is_null() {
            return Err(format!("gnutls_init: {}", err_str(g, rc)));
        }
        unsafe {
            (g.transport_set_int2)(session, fd, fd);
            (g.dtls_set_mtu)(session, UDP_PAYLOAD_MTU);
        }
        Ok(DtlsSession {
            session,
            cred: std::ptr::null_mut(),
            g,
            _sock: sock,
            fd,
        })
    }

    fn set_priority(&mut self, prio: &str) -> Result<(), String> {
        let c = CString::new(prio).unwrap();
        let rc = unsafe { (self.g.priority_set_direct)(self.session, c.as_ptr(), std::ptr::null_mut()) };
        if rc != 0 {
            return Err(format!("DTLS priority {prio:?}: {}", err_str(self.g, rc)));
        }
        Ok(())
    }

    fn handshake(&mut self, timeout: Duration) -> Result<(), String> {
        let g = self.g;
        let deadline = Instant::now() + timeout;
        loop {
            let rc = unsafe { (g.handshake)(self.session) };
            if rc == 0 {
                return Ok(());
            }
            if rc != GNUTLS_E_AGAIN && rc != GNUTLS_E_INTERRUPTED {
                return Err(format!("DTLS handshake: {}", err_str(g, rc)));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("DTLS handshake timed out".into());
            }
            let want_send = unsafe { (g.record_get_direction)(self.session) } == 1;
            let events = if want_send { libc::POLLOUT } else { libc::POLLIN };
            poll_fd(self.fd, events, remaining.min(Duration::from_secs(1)));
        }
    }

    pub fn fd(&self) -> c_int {
        self.fd
    }

    /// Largest application payload one record can carry over this path.
    pub fn data_mtu(&self) -> usize {
        unsafe { (self.g.dtls_get_data_mtu)(self.session) as usize }
    }

    /// Send one record that may exceed the path MTU (the IP layer fragments the
    /// datagram) — for the vendor hellos, whose session cookie alone can be ~2 KB
    /// (FortiClient sends a 2 KB hello datagram). Data records stay within the MTU.
    pub fn send_oversized(&self, data: &[u8]) -> Result<bool, String> {
        unsafe { (self.g.dtls_set_mtu)(self.session, (data.len() as c_uint + 256).max(UDP_PAYLOAD_MTU)) };
        let n = unsafe { (self.g.record_send)(self.session, data.as_ptr() as *const c_void, data.len()) };
        unsafe { (self.g.dtls_set_mtu)(self.session, UDP_PAYLOAD_MTU) };
        match n {
            n if n >= 0 => Ok(true),
            n if n as c_int == GNUTLS_E_AGAIN || n as c_int == GNUTLS_E_INTERRUPTED => Ok(false),
            n => Err(format!("DTLS send: {}", err_str(self.g, n as c_int))),
        }
    }

    /// Send one record. `Ok(false)` = would block (UDP: the caller may drop it). An
    /// over-MTU record is dropped (`Ok(true)`) rather than killing the tunnel.
    pub fn send(&self, data: &[u8]) -> Result<bool, String> {
        let n = unsafe { (self.g.record_send)(self.session, data.as_ptr() as *const c_void, data.len()) };
        if n >= 0 {
            return Ok(true);
        }
        match n as c_int {
            GNUTLS_E_AGAIN | GNUTLS_E_INTERRUPTED => Ok(false),
            GNUTLS_E_LARGE_PACKET => Ok(true),
            e => Err(format!("DTLS send: {}", err_str(self.g, e))),
        }
    }

    /// Receive one record into `buf`. `Ok(None)` when nothing is ready (incl. a
    /// non-fatal alert or a discarded bad record); `Err` when closed or fatal.
    pub fn recv(&self, buf: &mut [u8]) -> Result<Option<usize>, String> {
        let n = unsafe { (self.g.record_recv)(self.session, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n > 0 {
            return Ok(Some(n as usize));
        }
        if n == 0 {
            return Err("DTLS closed by peer".into());
        }
        let e = n as c_int;
        if e == GNUTLS_E_AGAIN || e == GNUTLS_E_INTERRUPTED || e == GNUTLS_E_REHANDSHAKE {
            Ok(None)
        } else if unsafe { (self.g.error_is_fatal)(e) } == 0 {
            Ok(None)
        } else {
            Err(format!("DTLS recv: {}", err_str(self.g, e)))
        }
    }
}

impl Drop for DtlsSession {
    fn drop(&mut self) {
        unsafe {
            let _ = (self.g.bye)(self.session, GNUTLS_SHUT_WR);
            (self.g.deinit)(self.session);
            if !self.cred.is_null() {
                (self.g.certificate_free_credentials)(self.cred);
            }
        }
    }
}

/// A DTLS session as a `Read + Write` byte "stream" where every `write` is one
/// record (one datagram) and every `read` returns one record — so a record-oriented
/// framing (one PPP frame per record) maps 1:1. Non-blocking by default; with a
/// read timeout set, `read` waits up to it before reporting `WouldBlock`.
pub struct DtlsStream {
    pub session: DtlsSession,
    read_timeout: Option<Duration>,
}

impl DtlsStream {
    pub fn new(session: DtlsSession) -> Self {
        DtlsStream {
            session,
            read_timeout: None,
        }
    }

    pub fn set_read_timeout(&mut self, t: Option<Duration>) {
        self.read_timeout = t;
    }

    pub fn fd(&self) -> c_int {
        self.session.fd()
    }
}

impl io::Read for DtlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let deadline = self.read_timeout.map(|t| Instant::now() + t);
        loop {
            match self.session.recv(buf) {
                Ok(Some(n)) => return Ok(n),
                Ok(None) => {}
                Err(e) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, e)),
            }
            let Some(deadline) = deadline else {
                return Err(io::ErrorKind::WouldBlock.into());
            };
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            poll_fd(self.session.fd(), libc::POLLIN, left);
        }
    }
}

impl io::Write for DtlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.session.send(buf) {
            Ok(true) => Ok(buf.len()),
            Ok(false) => Err(io::ErrorKind::WouldBlock.into()),
            Err(e) => Err(io::Error::new(io::ErrorKind::ConnectionAborted, e)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn poll_fd(fd: c_int, events: libc::c_short, t: Duration) {
    let mut p = libc::pollfd { fd, events, revents: 0 };
    unsafe { libc::poll(&mut p, 1, t.as_millis().min(i32::MAX as u128) as c_int) };
}

fn err_str(g: &Gnutls, e: c_int) -> String {
    unsafe {
        let p = (g.strerror)(e);
        if p.is_null() {
            format!("gnutls error {e}")
        } else {
            std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// Live check of the certificate handshake + record I/O against a local DTLS echo
    /// server: `gnutls-serv --udp --echo -p 4433 …` then
    /// `UNVPN_DTLS_ECHO_PORT=4433 cargo test dtls_cert_echo -- --ignored`.
    #[test]
    #[ignore]
    fn dtls_cert_echo() {
        let port: u16 = std::env::var("UNVPN_DTLS_ECHO_PORT").unwrap().parse().unwrap();
        let s = DtlsSession::connect_cert("127.0.0.1".parse().unwrap(), port, true, Duration::from_secs(5)).unwrap();
        let mtu = s.data_mtu();
        assert!(mtu > 1300 && mtu < 1472, "data mtu {mtu}");
        let mut st = DtlsStream::new(s);
        st.set_read_timeout(Some(Duration::from_secs(3)));
        st.write_all(b"hello over dtls").unwrap();
        let mut buf = [0u8; 2048];
        let n = st.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello over dtls");
        // A ~2 KB vendor hello (big session cookie) goes out as one fragmented datagram.
        let big = vec![b'x'; 2000];
        assert!(st.session.send_oversized(&big).unwrap());
        let mut big_back = vec![0u8; 4096];
        // (gnutls-serv echoes it back in pieces; receiving any proves it arrived.)
        assert!(st.read(&mut big_back).unwrap() > 0);
        eprintln!("data_mtu={mtu}");
    }
}
