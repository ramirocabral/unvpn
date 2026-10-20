//! Cisco AnyConnect DTLS data plane (UDP) — the fast path.
//!
//! AnyConnect's DTLS is not a normal DTLS handshake: the client and server already
//! share a master secret (the `X-DTLS-Master-Secret` the client sent in the CSTP
//! CONNECT, plus the `X-DTLS-Session-ID` the server returned), so the client
//! *resumes* a session that was never really established. We hand OpenSSL a
//! hand-built `SSL_SESSION` (ASN.1, via `d2i_SSL_SESSION`) carrying that id +
//! secret + the negotiated cipher, set `SSL_OP_CISCO_ANYCONNECT`, and `SSL_connect`
//! over a datagram BIO — the server "resumes" and the tunnel is up with no key
//! exchange. This is exactly openconnect's `openssl-dtls.c` path for the classic
//! (`AES256-SHA`, `DTLS1_BAD_VER`) ciphers an ASA offers; native-tls can't express
//! it, so we drop to raw `openssl-sys` FFI here.
//!
//! Once connected, each datagram is `[type byte][payload]` (type 0 = DATA raw IPv4,
//! 3 = DPD request, 4 = DPD reply, 7 = keepalive, 5 = disconnect) — the same type
//! codes as CSTP but with a 1-byte header instead of the 8-byte STF one.
//!
//! Best-effort: if the handshake doesn't complete (loss, an ASA that only wants
//! DTLS1.2/PSK, a firewall blocking UDP), the caller stays on CSTP — no harm.

use openssl_sys as ssl;
use std::ffi::c_void;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::raw::{c_char, c_int, c_long, c_uchar};
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

// Constants not exported by openssl-sys (values from the OpenSSL headers).
const BIO_C_SET_FD: c_int = 104;
const BIO_CTRL_DGRAM_SET_CONNECTED: c_int = 32;
const BIO_NOCLOSE: c_long = 0x00;
const DTLS1_BAD_VER: u16 = 0x0100;
const DTLS1_2_VERSION: c_long = 0xFEFD;
const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
/// `SSL_OP_NO_EXTENDED_MASTER_SECRET` = `SSL_OP_BIT(0)`. A resumed session must not
/// advertise EMS or the ASA rejects it (RFC 7627 forces a full handshake, which it
/// won't do) — openconnect's ClientHello omits it too.
const SSL_OP_NO_EXTENDED_MASTER_SECRET: u64 = 0x0000_0001;
/// `SSL_OP_NO_ENCRYPT_THEN_MAC` = `SSL_OP_BIT(19)`; Cisco DTLS never did EtM, and a
/// resumed CBC session must have it off or the MAC placement won't match.
const SSL_OP_NO_ENCRYPT_THEN_MAC: u64 = 0x0008_0000;

/// A live DTLS channel. Holds the UDP socket (so its fd stays valid for the BIO,
/// which we create with BIO_NOCLOSE) and the OpenSSL objects, freed on drop.
pub struct Dtls {
    ssl: *mut ssl::SSL,
    ctx: *mut ssl::SSL_CTX,
    _sock: UdpSocket,
    fd: c_int,
}

// The raw pointers are only touched from the single data-loop thread that owns the
// Dtls; nothing else aliases them.
unsafe impl Send for Dtls {}

impl Dtls {
    /// The UDP socket fd, for the data loop's `poll`.
    pub fn fd(&self) -> c_int {
        self.fd
    }

    /// Send one `[type][payload]` datagram. UDP + best-effort: a WouldBlock is
    /// dropped (the tunnel tolerates loss; DPD covers real death).
    pub fn send(&self, ty: u8, payload: &[u8]) -> Result<(), String> {
        let mut pkt = Vec::with_capacity(1 + payload.len());
        pkt.push(ty);
        pkt.extend_from_slice(payload);
        let n = unsafe { ssl::SSL_write(self.ssl, pkt.as_ptr() as *const c_void, pkt.len() as c_int) };
        if n > 0 {
            return Ok(());
        }
        match unsafe { ssl::SSL_get_error(self.ssl, n) } {
            ssl::SSL_ERROR_WANT_READ | ssl::SSL_ERROR_WANT_WRITE => Ok(()), // drop, it's UDP
            e => Err(format!("DTLS write failed (SSL error {e})")),
        }
    }

    /// Receive one datagram as `(type, payload)`. `Ok(None)` when nothing is ready.
    pub fn recv(&self) -> Result<Option<(u8, Vec<u8>)>, String> {
        let mut buf = [0u8; 2048];
        let n = unsafe { ssl::SSL_read(self.ssl, buf.as_mut_ptr() as *mut c_void, buf.len() as c_int) };
        if n > 0 {
            let n = n as usize;
            return Ok(Some((buf[0], buf[1..n].to_vec())));
        }
        match unsafe { ssl::SSL_get_error(self.ssl, n) } {
            ssl::SSL_ERROR_WANT_READ | ssl::SSL_ERROR_WANT_WRITE => Ok(None),
            ssl::SSL_ERROR_ZERO_RETURN => Err("DTLS closed by peer".into()),
            e => Err(format!("DTLS read failed (SSL error {e})")),
        }
    }
}

impl Drop for Dtls {
    fn drop(&mut self) {
        unsafe {
            if !self.ssl.is_null() {
                ssl::SSL_free(self.ssl); // also frees the BIO we attached
            }
            if !self.ctx.is_null() {
                ssl::SSL_CTX_free(self.ctx);
            }
        }
    }
}

/// Bring up the DTLS channel by resuming the pre-shared session. `master_secret` is
/// the exact 48 bytes sent in `X-DTLS-Master-Secret`; `session_id` is the decoded
/// `X-DTLS-Session-ID`; `cipher` is the gateway's `X-DTLS-CipherSuite`.
pub fn connect(
    gw: Ipv4Addr,
    port: u16,
    session_id: &[u8],
    master_secret: &[u8],
    cipher: &str,
    dtls12: bool,
    timeout: Duration,
) -> Result<Dtls, String> {
    let (cipher_id, ossl_name) =
        resolve_cipher(cipher, dtls12).ok_or_else(|| format!("unsupported DTLS cipher {cipher:?}"))?;
    let version = if dtls12 { DTLS1_2_VERSION as u16 } else { DTLS1_BAD_VER };
    if session_id.is_empty() || master_secret.len() != 48 {
        return Err("missing DTLS session id / master secret".into());
    }

    // 1) Connected UDP socket with a receive timeout for the blocking handshake.
    let sock = UdpSocket::bind(("0.0.0.0", 0)).map_err(|e| format!("DTLS udp bind: {e}"))?;
    sock.connect((gw, port)).map_err(|e| format!("DTLS udp connect {gw}:{port}: {e}"))?;
    set_rcv_timeout(&sock, Duration::from_secs(3));
    let fd = sock.as_raw_fd();

    unsafe {
        // 2) A DTLS client context that tolerates the ancient Cisco resume: low
        //    security level (AES256-SHA/DTLS1_BAD_VER is below OpenSSL 3's default),
        //    Cisco-anyconnect quirk, no EtM, legacy renegotiation.
        let ctx = ssl::SSL_CTX_new(ssl::DTLS_client_method());
        if ctx.is_null() {
            return Err("SSL_CTX_new(DTLS) failed".into());
        }
        let guard = CtxGuard(ctx);
        ssl::SSL_CTX_set_security_level(ctx, 0);
        // Both paths must omit encrypt-then-mac and extended-master-secret from the
        // ClientHello — Cisco's resume predates them and the ASA rejects a resume
        // that advertises them (confirmed by capturing openconnect's ClientHello).
        let mut options = ssl::SSL_OP_LEGACY_SERVER_CONNECT | SSL_OP_NO_ENCRYPT_THEN_MAC | SSL_OP_NO_EXTENDED_MASTER_SECRET;
        if dtls12 {
            // Modern ASA: pin DTLS 1.2 and resume at it (no Cisco BAD_VER quirk).
            ssl::SSL_CTX_set_options(ctx, options);
            ssl::SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, DTLS1_2_VERSION, std::ptr::null_mut());
            ssl::SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, DTLS1_2_VERSION, std::ptr::null_mut());
        } else {
            // Classic ASA: the ancient Cisco DTLS1_BAD_VER resume.
            options |= ssl::SSL_OP_CISCO_ANYCONNECT;
            ssl::SSL_CTX_set_options(ctx, options);
        }
        let clist = std::ffi::CString::new(format!("{ossl_name}@SECLEVEL=0")).unwrap();
        if ssl::SSL_CTX_set_cipher_list(ctx, clist.as_ptr() as *const c_char) != 1 {
            return Err(format!("no DTLS cipher {cipher} available in OpenSSL ({})", err_stack()));
        }

        let sslp = ssl::SSL_new(ctx);
        if sslp.is_null() {
            return Err("SSL_new(DTLS) failed".into());
        }
        let sslg = SslGuard(sslp);
        ssl::SSL_set_connect_state(sslp);

        // 3) Datagram BIO over the connected UDP fd.
        let bio = ssl::BIO_new(ssl::BIO_s_datagram());
        if bio.is_null() {
            return Err("BIO_new(dgram) failed".into());
        }
        let mut fd_c: c_int = fd;
        ssl::BIO_ctrl(bio, BIO_C_SET_FD, BIO_NOCLOSE, &mut fd_c as *mut c_int as *mut c_void);
        let mut peer = sockaddr_in(gw, port);
        ssl::BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &mut peer as *mut _ as *mut c_void);
        ssl::SSL_set_bio(sslp, bio, bio); // SSL takes ownership of the BIO

        // 4) Hand-built resume session (id + secret + cipher).
        let asn1 = encode_session(version, cipher_id, session_id, master_secret);
        let mut p: *const c_uchar = asn1.as_ptr();
        let sess = ssl::d2i_SSL_SESSION(std::ptr::null_mut(), &mut p, asn1.len() as c_long);
        if sess.is_null() {
            return Err("d2i_SSL_SESSION failed (bad resume blob)".into());
        }
        let set_ok = ssl::SSL_set_session(sslp, sess) == 1;
        ssl::SSL_SESSION_free(sess); // SSL keeps its own ref
        if !set_ok {
            return Err("SSL_set_session failed".into());
        }

        // 5) Handshake (best-effort within the deadline).
        let deadline = Instant::now() + timeout;
        loop {
            let ret = ssl::SSL_connect(sslp);
            if ret == 1 {
                break;
            }
            let err = ssl::SSL_get_error(sslp, ret);
            let retryable = err == ssl::SSL_ERROR_WANT_READ || err == ssl::SSL_ERROR_WANT_WRITE;
            if !retryable || Instant::now() >= deadline {
                return Err(format!("DTLS handshake failed (SSL error {err}): {}", err_stack()));
            }
        }

        // 6) Non-blocking for the data loop; hand the live objects to the caller.
        sock.set_nonblocking(true).ok();
        guard.disarm();
        sslg.disarm();
        Ok(Dtls { ssl: sslp, ctx, _sock: sock, fd })
    }
}

/// Map a Cisco DTLS cipher name to `(tls_cipher_id, openssl_cipher_name)` for the
/// resume session. On the DTLS 1.2 path the ASA's shorthand (`AES256-GCM-SHA384`)
/// means the **ECDHE-RSA** suite (0xC030), not the RSA one (0x009D) — confirmed by
/// capturing openconnect's ClientHello; using the RSA id gets a handshake_failure.
fn resolve_cipher(name: &str, dtls12: bool) -> Option<(u16, &'static str)> {
    Some(if dtls12 {
        match name {
            "AES256-GCM-SHA384" => (0xC030, "ECDHE-RSA-AES256-GCM-SHA384"),
            "AES128-GCM-SHA256" => (0xC02F, "ECDHE-RSA-AES128-GCM-SHA256"),
            _ => return None,
        }
    } else {
        match name {
            "AES256-SHA" => (0x0035, "AES256-SHA"),
            "AES128-SHA" => (0x002F, "AES128-SHA"),
            "DES-CBC3-SHA" => (0x000A, "DES-CBC3-SHA"),
            "DHE-RSA-AES256-SHA" => (0x0039, "DHE-RSA-AES256-SHA"),
            "DHE-RSA-AES128-SHA" => (0x0033, "DHE-RSA-AES128-SHA"),
            _ => return None,
        }
    })
}

/// Build the DER `SSL_SESSION` for `d2i_SSL_SESSION` (OpenSSL ≥1.1 layout, from
/// openconnect `generate_dtls_session`): a SEQUENCE of
/// `INTEGER 1` (ASN1 version), `INTEGER dtlsver`, `OCTET_STRING cipher_id(2B BE)`,
/// `OCTET_STRING session_id`, `OCTET_STRING master_key`.
fn encode_session(dtlsver: u16, cipher_id: u16, session_id: &[u8], master_key: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    push_integer(&mut body, 1);
    push_integer(&mut body, dtlsver as u32);
    push_octet_string(&mut body, &cipher_id.to_be_bytes());
    push_octet_string(&mut body, session_id);
    push_octet_string(&mut body, master_key);

    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(0x30); // SEQUENCE
    if body.len() < 0x80 {
        out.push(body.len() as u8);
        out.extend_from_slice(&body);
    } else {
        // Long form length (one length byte suffices for our ~95-byte body, but be safe).
        out.push(0x81);
        out.push(body.len() as u8);
        out.extend_from_slice(&body);
    }
    out
}

fn push_integer(buf: &mut Vec<u8>, v: u32) {
    let l = if v < 0x80 {
        1
    } else if v < 0x8000 {
        2
    } else if v < 0x0080_0000 {
        3
    } else {
        4
    };
    buf.push(0x02);
    buf.push(l as u8);
    for i in (0..l).rev() {
        buf.push((v >> (i * 8)) as u8);
    }
}

fn push_octet_string(buf: &mut Vec<u8>, data: &[u8]) {
    debug_assert!(data.len() < 0x80);
    buf.push(0x04);
    buf.push(data.len() as u8);
    buf.extend_from_slice(data);
}

/// Drain OpenSSL's thread error queue into a one-line string (via the high-level
/// crate, which formats lib/reason nicely). Empty when the queue is empty.
fn err_stack() -> String {
    let s = openssl::error::ErrorStack::get().to_string();
    if s.is_empty() {
        "no OpenSSL error detail".to_string()
    } else {
        s.replace('\n', "; ")
    }
}

fn sockaddr_in(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(ip.octets()) },
        sin_zero: [0; 8],
    }
}

fn set_rcv_timeout(sock: &UdpSocket, d: Duration) {
    let tv = libc::timeval { tv_sec: d.as_secs() as libc::time_t, tv_usec: 0 };
    unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
}

/// Frees an SSL_CTX on an early error return; `disarm` once ownership transfers.
struct CtxGuard(*mut ssl::SSL_CTX);
impl CtxGuard {
    fn disarm(mut self) {
        self.0 = std::ptr::null_mut();
    }
}
impl Drop for CtxGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { ssl::SSL_CTX_free(self.0) };
        }
    }
}

struct SslGuard(*mut ssl::SSL);
impl SslGuard {
    fn disarm(mut self) {
        self.0 = std::ptr::null_mut();
    }
}
impl Drop for SslGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { ssl::SSL_free(self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_encoding() {
        let mut b = Vec::new();
        push_integer(&mut b, 1);
        assert_eq!(b, vec![0x02, 0x01, 0x01]);
        let mut b = Vec::new();
        push_integer(&mut b, 0x0100);
        assert_eq!(b, vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn octet_string_encoding() {
        let mut b = Vec::new();
        push_octet_string(&mut b, &[0x00, 0x35]);
        assert_eq!(b, vec![0x04, 0x02, 0x00, 0x35]);
    }

    #[test]
    fn session_blob_shape() {
        // 32-byte id, 48-byte secret, AES256-SHA (0x0035), DTLS1_BAD_VER.
        let id = [0xabu8; 32];
        let secret = [0xcdu8; 48];
        let blob = encode_session(DTLS1_BAD_VER, 0x0035, &id, &secret);
        // SEQUENCE, short-form length (content is 95 bytes < 128).
        assert_eq!(blob[0], 0x30);
        assert_eq!(blob[1] as usize, blob.len() - 2);
        assert_eq!(blob.len(), 97);
        // First element: INTEGER 1.
        assert_eq!(&blob[2..5], &[0x02, 0x01, 0x01]);
        // Then INTEGER 0x0100 (version).
        assert_eq!(&blob[5..9], &[0x02, 0x02, 0x01, 0x00]);
        // Then OCTET_STRING cipher id.
        assert_eq!(&blob[9..13], &[0x04, 0x02, 0x00, 0x35]);
        // The 48-byte master key must appear verbatim at the tail.
        assert!(blob.windows(48).any(|w| w == secret));
    }

    #[test]
    fn cipher_ids() {
        assert_eq!(resolve_cipher("AES256-SHA", false), Some((0x0035, "AES256-SHA")));
        // The DTLS 1.2 shorthand resolves to the ECDHE-RSA suite, not the RSA one.
        assert_eq!(resolve_cipher("AES256-GCM-SHA384", true), Some((0xC030, "ECDHE-RSA-AES256-GCM-SHA384")));
        assert_eq!(resolve_cipher("AES128-GCM-SHA256", true), Some((0xC02F, "ECDHE-RSA-AES128-GCM-SHA256")));
        assert_eq!(resolve_cipher("bogus", true), None);
        // A classic name is not offered on the dtls12 path and vice-versa.
        assert_eq!(resolve_cipher("AES256-GCM-SHA384", false), None);
    }
}
