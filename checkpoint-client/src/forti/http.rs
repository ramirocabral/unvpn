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
//! Certificates: like the Check Point probe and openfortivpn's default, we accept
//! the gateway cert (corporate CAs are often not in the system store). Pinning via
//! a `--trusted-cert <sha256>` is a later hardening step.

use native_tls::{TlsConnector, TlsStream};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 SV1";

/// A trivial cookie jar: name → value. Enough for `SVPNCOOKIE` and friends; we
/// ignore attributes (Path/Domain/Expires) — one gateway, one session.
#[derive(Default, Clone)]
pub struct Cookies(pub BTreeMap<String, String>);

impl Cookies {
    pub fn new() -> Self {
        Cookies(BTreeMap::new())
    }
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(|s| s.as_str())
    }
    /// Render the `Cookie:` header value (`a=1; b=2`), or `None` if empty.
    pub fn header(&self) -> Option<String> {
        if self.0.is_empty() {
            return None;
        }
        Some(self.0.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; "))
    }
    /// Absorb a `Set-Cookie` header value.
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

/// A parsed HTTP response.
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
    /// `Location:` header (for 3xx redirects, e.g. SAML → IdP).
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }
}

/// Open a TLS stream to the gateway. Blocking, with read/write timeouts.
pub fn connect_tls(host: &str, port: u16, timeout: Duration) -> Result<TlsStream<TcpStream>, String> {
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|e| format!("tls builder: {e}"))?;
    let tcp = TcpStream::connect((host, port)).map_err(|e| format!("connect {host}:{port}: {e}"))?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();
    tcp.set_nodelay(true).ok();
    connector.connect(host, tcp).map_err(|e| format!("TLS to {host}: {e}"))
}

/// Build a raw HTTP/1.1 request. `extra` holds additional header lines
/// ("Name: value"); `body` is the already-encoded body (empty for GET).
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
    // Don't emit a second Connection header if the caller already set one.
    if !has_connection {
        req.push_str(if keep_alive { "Connection: keep-alive\r\n" } else { "Connection: close\r\n" });
    }
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    out.extend_from_slice(body);
    out
}

/// One-shot request: connect, send (`Connection: close`), parse the response, and
/// update the cookie jar from any `Set-Cookie`. The body is read by
/// `Content-Length` or `Transfer-Encoding: chunked` and only falls back to
/// read-until-close when neither is present — so a gateway that ignores our
/// `Connection: close` and keeps the socket open doesn't hang us to a timeout.
/// The robust path used for the entire authentication/config sequence.
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
    let mut tls = connect_tls(host, port, timeout)?;
    let req = build_request(method, host, path, cookies, extra, body, false);
    tls.write_all(&req).map_err(|e| format!("write request: {e}"))?;
    tls.flush().ok();

    let mut tmp = [0u8; 4096];
    // Read until the end of the header block.
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
        // No length and not chunked: the server must close to signal the end.
        loop {
            match tls.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
                Err(_) => break, // timeout/close → return what we have (headers are enough)
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

// ───────────────────────────── parsing helpers ──────────────────────────────

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_status_and_headers(head: &[u8]) -> Result<(u16, Vec<(String, String)>), String> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or("empty response")?;
    // "HTTP/1.1 200 OK"
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

/// De-chunk a complete buffer; returns None if the terminating 0-chunk isn't present yet.
fn try_dechunk_complete(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let line_end = raw[i..].windows(2).position(|w| w == b"\r\n")? + i;
        let size_str = std::str::from_utf8(&raw[i..line_end]).ok()?;
        let size = usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16).ok()?;
        i = line_end + 2;
        if size == 0 {
            return Some(out); // terminating chunk
        }
        if i + size > raw.len() {
            return None; // incomplete
        }
        out.extend_from_slice(&raw[i..i + size]);
        i += size + 2; // skip data + CRLF
    }
}

/// Best-effort de-chunk of whatever we have (used when the connection closed).
fn dechunk_buffer(raw: &[u8]) -> Vec<u8> {
    try_dechunk_complete(raw).unwrap_or_else(|| raw.to_vec())
}

/// URL-encode a value for `application/x-www-form-urlencoded` bodies.
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
