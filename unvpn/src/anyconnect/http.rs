//! Minimal HTTPS/1.1 client for the Cisco AnyConnect control channel.
//!
//! Every request carries the aggregate-auth headers (`X-Transcend-Version`,
//! `X-Aggregate-Auth`). Redirects are handed back to the caller: the auth layer
//! decides whether a `Location` is a load-balancer hop to another gateway
//! (follow) or something XML-POST can't handle (fail), as openconnect does.
//!
//! Certificates: like the other back-ends and openconnect's default, the gateway
//! certificate is accepted (corporate CAs are often not in the system store); the
//! session is bound by the `webvpn` cookie, not by the certificate.

use native_tls::{TlsConnector, TlsStream};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Default, Clone, Debug)]
pub struct Cookies(pub BTreeMap<String, String>);

impl Cookies {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(|s| s.as_str())
    }
    pub fn set(&mut self, name: &str, value: &str) {
        self.0.insert(name.to_string(), value.to_string());
    }
    pub fn header(&self) -> Option<String> {
        if self.0.is_empty() {
            return None;
        }
        Some(self.0.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; "))
    }
    pub fn absorb(&mut self, set_cookie: &str) {
        let pair = set_cookie.split(';').next().unwrap_or("").trim();
        if let Some((k, v)) = pair.split_once('=') {
            let (k, v) = (k.trim(), v.trim());
            if k.is_empty() {
                return;
            }
            if v.is_empty() || v == "deleted" {
                self.0.remove(k);
            } else {
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
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    pub fn body_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
}

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub user_agent: String,
    pub timeout: Duration,
}

impl Endpoint {
    /// Port only when not 443, as the real client does.
    pub fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
    pub fn base_url(&self) -> String {
        format!("https://{}", self.host_header())
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

/// TCP connect with a per-address timeout (a plain `connect` to a dead gateway
/// hangs ~2 min), trying each resolved address in turn.
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

/// The headers every AnyConnect control request carries (openconnect
/// `cstp_common_headers`): identity, cookies and the aggregate-auth markers.
pub fn common_headers(ep: &Endpoint, cookies: &Cookies) -> String {
    let mut h = format!("Host: {}\r\nUser-Agent: {}\r\n", ep.host_header(), ep.user_agent);
    if let Some(c) = cookies.header() {
        h.push_str(&format!("Cookie: {c}\r\n"));
    }
    h.push_str("Accept: */*\r\nAccept-Encoding: identity\r\nX-Transcend-Version: 1\r\nX-Aggregate-Auth: 1\r\n");
    h
}

/// One-shot request (`Connection: close`). Updates the cookie jar from any
/// `Set-Cookie`. Redirects are NOT followed.
pub fn request(
    ep: &Endpoint,
    method: &str,
    path: &str,
    cookies: &mut Cookies,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<Response, String> {
    let mut tls = connect_tls(&ep.host, ep.port, ep.timeout)?;
    let mut req = format!("{method} {path} HTTP/1.1\r\n");
    req.push_str(&common_headers(ep, cookies));
    if let Some(ct) = content_type {
        req.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    if method == "POST" || !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("Connection: close\r\n\r\n");
    let mut raw = req.into_bytes();
    raw.extend_from_slice(body);
    tls.write_all(&raw).map_err(|e| format!("write request: {e}"))?;
    tls.flush().ok();

    let resp = read_response(&mut tls, true)?;
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("set-cookie") {
            cookies.absorb(v);
        }
    }
    Ok(resp)
}

/// Read one HTTP response from `s`. With `with_body`, the body is read by
/// `Transfer-Encoding: chunked`, `Content-Length`, or until close.
pub fn read_response<S: Read>(s: &mut S, with_body: bool) -> Result<Response, String> {
    let mut tmp = [0u8; 4096];
    let mut raw = Vec::new();
    let header_end = loop {
        if let Some(e) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break e + 4;
        }
        match s.read(&mut tmp) {
            Ok(0) => return Err("connection closed before response headers".into()),
            Ok(n) => raw.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(format!("read headers: {e}")),
        }
        if raw.len() > 1 << 20 {
            return Err("response headers too large".into());
        }
    };
    let (status, headers) = parse_head(&raw[..header_end])?;
    let mut body = raw[header_end..].to_vec();
    if !with_body {
        return Ok(Response { status, headers, body });
    }

    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"));
    let clen = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok());

    if chunked {
        loop {
            if let Some(d) = dechunk(&body) {
                body = d;
                break;
            }
            match s.read(&mut tmp) {
                Ok(0) => break, // truncated: keep what we have
                Ok(n) => body.extend_from_slice(&tmp[..n]),
                Err(e) => return Err(format!("read chunked body: {e}")),
            }
        }
    } else if let Some(len) = clen {
        while body.len() < len {
            match s.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
            }
        }
        body.truncate(len);
    } else {
        loop {
            match s.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
            }
        }
    }
    Ok(Response { status, headers, body })
}

pub fn parse_head(head: &[u8]) -> Result<(u16, Vec<(String, String)>), String> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or("empty response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("bad status line: {status_line:?}"))?;
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Ok((status, headers))
}

/// De-chunk a complete buffer; `None` until the terminating 0-chunk has arrived.
/// Checked arithmetic: a short or bogus chunk means "not complete", never a panic.
fn dechunk(raw: &[u8]) -> Option<Vec<u8>> {
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

/// Split an `https://host[:port]/path` URL (or bare `host[:port][/path]`) into
/// `(host, port, path)`. The path keeps its query and defaults to `/`.
pub fn split_url(url: &str) -> Result<(String, u16, String), String> {
    let u = url.trim();
    let rest = u
        .strip_prefix("https://")
        .or_else(|| u.strip_prefix("HTTPS://"))
        .unwrap_or(u);
    if rest.starts_with("http://") {
        return Err("plain http:// gateways are not supported".into());
    }
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_string()),
    };
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.is_empty() {
        return Err(format!("no host in {url:?}"));
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, tail) = v6.split_once(']').ok_or("bad [IPv6] host")?;
        let port = tail.strip_prefix(':').map(|p| p.parse::<u16>().map_err(|_| "bad port")).transpose()?;
        (h.to_string(), port.unwrap_or(443))
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().map_err(|_| format!("bad port in {url:?}"))?)
    } else {
        (authority.to_string(), 443)
    };
    Ok((host, port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_forms() {
        assert_eq!(split_url("203.0.113.20").unwrap(), ("203.0.113.20".into(), 443, "/".into()));
        assert_eq!(
            split_url("https://vpn-sso.example.com/SSOGROUP").unwrap(),
            ("vpn-sso.example.com".into(), 443, "/SSOGROUP".into())
        );
        assert_eq!(split_url("gw.example:8443/grp").unwrap(), ("gw.example".into(), 8443, "/grp".into()));
        assert_eq!(split_url("https://gw/?a=1").unwrap(), ("gw".into(), 443, "/?a=1".into()));
        assert_eq!(split_url("[2001:db8::1]:444/x").unwrap(), ("2001:db8::1".into(), 444, "/x".into()));
        assert!(split_url("http://gw").is_err());
        assert!(split_url("https://").is_err());
    }

    #[test]
    fn response_chunked_and_cookies() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: webvpn=abc; path=/; secure\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut cur = std::io::Cursor::new(wire.to_vec());
        let r = read_response(&mut cur, true).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello world");
        let mut c = Cookies::default();
        c.absorb(r.header("set-cookie").unwrap());
        assert_eq!(c.get("webvpn"), Some("abc"));
        c.absorb("webvpn=; expires=Thu, 01 Jan 1970 22:00:00 GMT; path=/");
        assert_eq!(c.get("webvpn"), None);
    }

    #[test]
    fn host_header_omits_default_port() {
        let ep = Endpoint { host: "gw".into(), port: 443, user_agent: "AnyConnect".into(), timeout: Duration::from_secs(1) };
        assert_eq!(ep.host_header(), "gw");
        let ep2 = Endpoint { port: 8443, ..ep };
        assert_eq!(ep2.base_url(), "https://gw:8443");
    }
}
