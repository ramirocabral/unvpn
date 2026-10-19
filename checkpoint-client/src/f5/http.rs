//! Minimal HTTPS/1.1 client for the F5 BIG-IP APM SSL-VPN control channel.
//!
//! Same shape as the Fortinet back-end's `http` (native-tls + a trivial cookie
//! jar), with one addition F5 needs: [`request_follow`], which chases 3xx
//! redirects — the APM logon flow is a chain of `GET /` → `302 /my.policy` →
//! form POST → `302 …` steps, and the session is only established once both the
//! `MRHSession` and `F5_ST` cookies are set.
//!
//!  - [`request`] / [`request_follow`]: one-shot `Connection: close` requests with
//!    a shared cookie jar — the whole auth + profile/options dance.
//!  - [`connect_tls`] + [`build_request`]: a live TLS stream the tunnel layer keeps
//!    open — after `GET /myvpn?…` the same stream carries PPP.
//!
//! Certificates: like the Check Point / Fortinet probes and openconnect's default,
//! we accept the gateway cert (corporate CAs are often not in the system store).
//! Pinning via `--trusted-cert <sha256>` is a later hardening step.

use native_tls::{TlsConnector, TlsStream};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// The exact User-Agent the official F5 client sends — recovered from the shipped
/// `f5vpn.exe` (APM clients 7.2.5.x; string verified in the binary). Some APM access
/// policies branch on "F5 Networks Client" in the UA, so we mimic it for maximum
/// interop (openconnect uses its own UA and also works, but this is the safe choice).
pub const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0; F5 Networks Client)";

/// A trivial cookie jar: name → value. Enough for `MRHSession` / `F5_ST`; we ignore
/// attributes (Path/Domain/Expires) — one gateway, one session.
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
                // An empty value (NAME=;) / "deleted" is the server clearing it — honor that.
                if v.is_empty() || v == "deleted" {
                    self.0.remove(k);
                } else {
                    self.0.insert(k.to_string(), v.to_string());
                }
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
    if !has_connection {
        req.push_str(if keep_alive { "Connection: keep-alive\r\n" } else { "Connection: close\r\n" });
    }
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    out.extend_from_slice(body);
    out
}

/// One-shot request: connect, send (`Connection: close`), parse the response, and
/// update the cookie jar from any `Set-Cookie`. Body read by `Content-Length` or
/// `Transfer-Encoding: chunked`, falling back to read-until-close.
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
                Err(_) => break,
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

/// Like [`request`], but follow up to `max_redirects` same-host 3xx redirects,
/// turning the method into GET after the first hop (`HTTP_REDIRECT_TO_GET`), and
/// carrying the cookie jar across hops. Cross-host redirects are returned as-is
/// (the caller decides — e.g. an external IdP for SAML, out of scope here).
pub fn request_follow(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    cookies: &mut Cookies,
    extra: &[String],
    body: &[u8],
    timeout: Duration,
    max_redirects: u32,
) -> Result<Response, String> {
    let mut cur_method = method.to_string();
    let mut cur_path = path.to_string();
    let mut cur_body = body.to_vec();
    for _ in 0..=max_redirects {
        let resp = request(host, port, &cur_method, &cur_path, cookies, extra, &cur_body, timeout)?;
        if !(300..400).contains(&resp.status) {
            return Ok(resp);
        }
        let Some(loc) = resp.location() else {
            return Ok(resp); // 3xx without Location — give it back
        };
        let Some(next) = same_host_path(host, port, loc) else {
            return Ok(resp); // cross-host (e.g. IdP) — hand back to caller
        };
        cur_path = next;
        cur_method = "GET".to_string();
        cur_body = Vec::new();
    }
    Err("too many redirects".into())
}

/// Resolve a `Location` to a path on the same host, or `None` if it points
/// elsewhere. Accepts absolute (`https://host[:port]/p`) and relative (`/p`, `p`).
fn same_host_path(host: &str, port: u16, loc: &str) -> Option<String> {
    let loc = loc.trim();
    if let Some(rest) = loc.strip_prefix("https://").or_else(|| loc.strip_prefix("http://")) {
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let a_host = authority.split('@').next_back().unwrap_or(authority);
        let a_host = a_host.rsplit_once(':').map(|(h, _)| h).unwrap_or(a_host);
        let _ = port;
        if a_host.eq_ignore_ascii_case(host) {
            return Some(path.to_string());
        }
        None
    } else if loc.starts_with('/') {
        Some(loc.to_string())
    } else {
        Some(format!("/{loc}"))
    }
}

// ───────────────────────────── parsing helpers ──────────────────────────────

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
            return Some(out); // terminating chunk
        }
        let end = i.checked_add(size)?;
        if end.checked_add(2)? > raw.len() {
            return None; // data or its CRLF still incomplete
        }
        out.extend_from_slice(&raw[i..end]);
        i = end + 2; // skip data + CRLF
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_jar_set_and_clear() {
        let mut c = Cookies::new();
        c.absorb("MRHSession=abc123; path=/; secure");
        c.absorb("F5_ST=1z1z0z1700000000z86400; path=/");
        assert_eq!(c.get("MRHSession"), Some("abc123"));
        assert_eq!(c.get("F5_ST"), Some("1z1z0z1700000000z86400"));
        c.absorb("MRHSession=deleted; path=/");
        assert_eq!(c.get("MRHSession"), None);
        assert_eq!(c.get("F5_ST"), Some("1z1z0z1700000000z86400"));
    }

    #[test]
    fn same_host_variants() {
        assert_eq!(same_host_path("gw.example.com", 443, "/my.policy").as_deref(), Some("/my.policy"));
        assert_eq!(
            same_host_path("gw.example.com", 443, "https://gw.example.com/vdesk/").as_deref(),
            Some("/vdesk/")
        );
        assert_eq!(
            same_host_path("gw.example.com", 443, "https://gw.example.com:443/x?y=1").as_deref(),
            Some("/x?y=1")
        );
        // cross-host → None (hand back to caller)
        assert_eq!(same_host_path("gw.example.com", 443, "https://idp.okta.com/sso"), None);
    }
}
