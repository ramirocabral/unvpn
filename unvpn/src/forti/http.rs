//! Minimal HTTPS/1.1 client for the Fortinet SSL-VPN control channel.
//!
//! Two modes, both over `native-tls` (same stack as the Check Point side):
//!  - [`request`]: one-shot `Connection: close` request with a shared cookie jar —
//!    used for the whole auth dance (`/remote/logincheck`, `fortisslvpn_xml`, …).
//!    FortiGate keeps auth state in the `SVPNCOOKIE`, so a fresh connection per
//!    request is correct and keeps the code simple/robust.
//!  - [`connect_tls`] + [`read_response`]: a live TLS stream the tunnel layer
//!    keeps open — after `GET /remote/sslvpn-tunnel` the same stream carries PPP.
//!
//! The gateway cert is accepted (corporate CAs are often not in the system store).

use native_tls::{TlsConnector, TlsStream};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 SV1";

/// Attributes (Path/Domain/Expires) are ignored — one gateway, one session.
#[derive(Default, Clone)]
pub struct Cookies(pub BTreeMap<String, String>);

impl Cookies {
    pub fn new() -> Self {
        Cookies(BTreeMap::new())
    }
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(|s| s.as_str())
    }
    pub fn header(&self) -> Option<String> {
        if self.0.is_empty() {
            return None;
        }
        Some(self.0.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; "))
    }
    fn absorb(&mut self, set_cookie: &str) {
        let pair = set_cookie.split(';').next().unwrap_or("").trim();
        if let Some((k, v)) = pair.split_once('=') {
            let (k, v) = (k.trim(), v.trim());
            if !k.is_empty() {
                // An empty value (SVPNCOOKIE=;) is the server clearing it — honor that.
                self.0.insert(k.to_string(), v.to_string());
            }
        }
    }
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    pub fn body_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }
}

pub fn connect_tls(host: &str, port: u16, timeout: Duration) -> Result<TlsStream<TcpStream>, String> {
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|e| format!("tls builder: {e}"))?;
    let tcp = connect_tcp(host, port, timeout)?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();
    tcp.set_nodelay(true).ok();
    connector.connect(host, tcp).map_err(|e| format!("TLS to {host}: {e}"))
}

/// TCP connect with a timeout per address (a plain `connect` to a dead gateway
/// hangs ~2 min), trying each resolved address in turn like `TcpStream::connect`.
fn connect_tcp(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
    use std::net::ToSocketAddrs;
    let addrs = (host, port).to_socket_addrs().map_err(|e| format!("resolve {host}: {e}"))?;
    let mut last = format!("connect {host}:{port}: no address");
    for a in addrs {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = format!("connect {host}:{port} ({a}): {e}"),
        }
    }
    Err(last)
}

/// `extra` holds additional header lines ("Name: value"); `body` is already encoded.
pub fn build_request(
    method: &str,
    host: &str,
    path: &str,
    cookies: &Cookies,
    extra: &[String],
    body: &[u8],
    keep_alive: bool,
) -> Vec<u8> {
    let mut req = format!("{method} {path} HTTP/1.1\r\n");
    req.push_str(&format!("Host: {host}\r\n"));
    req.push_str(&format!("User-Agent: {DEFAULT_USER_AGENT}\r\n"));
    req.push_str("Accept: */*\r\n");
    if let Some(c) = cookies.header() {
        req.push_str(&format!("Cookie: {c}\r\n"));
    }
    let mut has_connection = false;
    for h in extra {
        if h.to_ascii_lowercase().starts_with("connection:") {
            has_connection = true;
        }
        req.push_str(h);
        req.push_str("\r\n");
    }
    if method == "POST" {
        req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
    }
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    if !has_connection {
        req.push_str(if keep_alive { "Connection: keep-alive\r\n" } else { "Connection: close\r\n" });
    }
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    out.extend_from_slice(body);
    out
}

/// One-shot `Connection: close` request that updates the cookie jar. The body is
/// read by `Content-Length` or chunked encoding and only falls back to
/// read-until-close when neither is present — so a gateway that ignores our
/// `Connection: close` and keeps the socket open doesn't hang us to a timeout.
pub fn request(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    cookies: &mut Cookies,
    extra: &[String],
    body: &[u8],
    timeout: Duration,
) -> Result<Response, String> {
    let tls = connect_tls(host, port, timeout)?;
    exchange(tls, host, method, path, cookies, extra, body)
}

/// Lets another thread abort an in-flight [`request_cancellable`]. Sticky: a
/// cancel that lands before the request has connected still stops it.
#[derive(Clone, Default)]
pub struct Cancel(Arc<Mutex<CancelState>>);

#[derive(Default)]
struct CancelState {
    cancelled: bool,
    sock: Option<TcpStream>,
}

impl Cancel {
    /// Abort the request: shut its socket down (its blocked read fails at once),
    /// or make it give up before sending if it hasn't connected yet.
    pub fn cancel(&self) {
        let mut st = self.0.lock().unwrap_or_else(|e| e.into_inner());
        st.cancelled = true;
        if let Some(s) = st.sock.take() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

/// [`request`], abortable through `cancel` — for a request the gateway holds open
/// (a FortiToken push waits for the user to approve on the phone).
#[allow(clippy::too_many_arguments)]
pub fn request_cancellable(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    cookies: &mut Cookies,
    body: &[u8],
    timeout: Duration,
    cancel: &Cancel,
) -> Result<Response, String> {
    if cancel.0.lock().unwrap_or_else(|e| e.into_inner()).cancelled {
        return Err("cancelled".into());
    }
    let tls = connect_tls(host, port, timeout)?;
    {
        // Register under the same lock that cancel takes, so a cancel between
        // the check above and here is not lost.
        let mut st = cancel.0.lock().unwrap_or_else(|e| e.into_inner());
        if st.cancelled {
            let _ = tls.get_ref().shutdown(Shutdown::Both);
            return Err("cancelled".into());
        }
        st.sock = tls.get_ref().try_clone().ok();
    }
    exchange(tls, host, method, path, cookies, &[], body)
}

fn exchange(
    mut tls: TlsStream<TcpStream>,
    host: &str,
    method: &str,
    path: &str,
    cookies: &mut Cookies,
    extra: &[String],
    body: &[u8],
) -> Result<Response, String> {
    let req = build_request(method, host, path, cookies, extra, body, false);
    tls.write_all(&req).map_err(|e| format!("write request: {e}"))?;
    tls.flush().ok();

    let mut tmp = [0u8; 4096];
    let mut raw = Vec::new();
    let header_end = loop {
        if let Some(e) = find_header_end(&raw) {
            break e;
        }
        match tls.read(&mut tmp) {
            Ok(0) => return Err("connection closed before response headers".into()),
            Ok(n) => raw.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(format!("read headers: {e}")),
        }
        if raw.len() > 1 << 20 {
            return Err("response headers too large".into());
        }
    };
    let (status, headers) = parse_status_and_headers(&raw[..header_end])?;
    let mut body = raw[header_end..].to_vec();

    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"));
    let clen = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok());

    if chunked {
        loop {
            if let Some(d) = try_dechunk_complete(&body) {
                body = d;
                break;
            }
            match tls.read(&mut tmp) {
                Ok(0) => {
                    body = dechunk_buffer(&body);
                    break;
                }
                Ok(n) => body.extend_from_slice(&tmp[..n]),
                Err(e) => return Err(format!("read chunked body: {e}")),
            }
        }
    } else if let Some(len) = clen {
        while body.len() < len {
            match tls.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
                Err(_) => break,
            }
        }
        body.truncate(len);
    } else {
        loop {
            match tls.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
                Err(_) => break, // timeout: return what we have (headers are enough)
            }
        }
    }

    for (k, v) in &headers {
        if k.eq_ignore_ascii_case("set-cookie") {
            cookies.absorb(v);
        }
    }
    Ok(Response { status, headers, body })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_status_and_headers(head: &[u8]) -> Result<(u16, Vec<(String, String)>), String> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or("empty response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("bad status line: {status_line:?}"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, headers))
}

/// De-chunk a complete buffer; returns None if the terminating 0-chunk isn't present
/// yet. Checked arithmetic throughout: a chunk whose trailing CRLF hasn't arrived,
/// or a bogus huge size, just means "not complete" — never a panic.
fn try_dechunk_complete(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let rest = raw.get(i..)?;
        let line_end = rest.windows(2).position(|w| w == b"\r\n")? + i;
        let size_str = std::str::from_utf8(&raw[i..line_end]).ok()?;
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16).ok()?;
        i = line_end + 2;
        if size == 0 {
            return Some(out);
        }
        let end = i.checked_add(size)?;
        if end.checked_add(2)? > raw.len() {
            return None;
        }
        out.extend_from_slice(&raw[i..end]);
        i = end + 2;
    }
}

fn dechunk_buffer(raw: &[u8]) -> Vec<u8> {
    try_dechunk_complete(raw).unwrap_or_else(|| raw.to_vec())
}

/// Decode `%XX` escapes only (like JS `decodeURIComponent`: `+` stays `+`, which
/// matters for an email `tokeninfo` such as `user+vpn@example.com`).
pub fn percent_decode(s: &str) -> String {
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dechunk_complete_and_partial() {
        let full = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(try_dechunk_complete(full).as_deref(), Some(&b"hello world"[..]));
        // Every prefix is "not complete yet" — never a panic (a TLS record may end
        // right after a chunk's data, before its CRLF).
        for cut in 0..full.len() - 4 {
            assert_eq!(try_dechunk_complete(&full[..cut]), None, "cut at {cut}");
        }
        // A bogus huge size must not overflow.
        assert_eq!(try_dechunk_complete(b"ffffffffffffffff\r\nab\r\n"), None);
    }

    #[test]
    fn percent_decode_keeps_plus_and_bad_escapes() {
        assert_eq!(percent_decode("ana%2Bvpn%40example.com"), "ana+vpn@example.com");
        assert_eq!(percent_decode("a+b%zz%4"), "a+b%zz%4");
        assert_eq!(percent_decode("%C3%A9%"), "é%");
    }

    #[test]
    fn cancel_before_connect_sends_nothing() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let cancel = Cancel::default();
        cancel.cancel();
        let mut jar = Cookies::new();
        let r = request_cancellable("127.0.0.1", port, "POST", "/x", &mut jar, b"", Duration::from_secs(2), &cancel);
        assert_eq!(r.err().as_deref(), Some("cancelled"));
        assert!(listener.accept().is_err(), "a cancelled request must not even connect");
    }
}
