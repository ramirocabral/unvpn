//! HTTP/1.1 over TLS for the gateways' control channels.
//!
//! Each request opens its own connection (`Connection: close`); the session lives
//! in the cookie jar. Tunnel set-up requests are written on a stream the caller
//! keeps ([`Request::encode`] + [`read_response`] without body).

pub use crate::net::tls::{connect as connect_tls, TlsStream};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const FORM: &str = "application/x-www-form-urlencoded";

const MAX_HEAD: usize = 1 << 20;

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub user_agent: String,
    pub timeout: Duration,
    /// Header lines ("Name: value") sent with every request.
    pub headers: Vec<String>,
}

impl Endpoint {
    pub fn new(host: &str, port: u16, user_agent: &str, timeout: Duration) -> Self {
        Endpoint {
            host: host.to_string(),
            port,
            user_agent: user_agent.to_string(),
            timeout,
            headers: Vec::new(),
        }
    }

    /// Port only when not 443.
    pub fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn base_url(&self) -> String {
        format!("https://{}", self.host_header())
    }

    pub fn connect(&self) -> Result<TlsStream, String> {
        connect_tls(&self.host, self.port, self.timeout)
    }
}

/// Name → value; attributes (Path/Domain/Expires) are ignored: one gateway, one
/// session.
#[derive(Default, Clone, Debug)]
pub struct Cookies(pub BTreeMap<String, String>);

impl Cookies {
    pub fn new() -> Self {
        Cookies(BTreeMap::new())
    }

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
        Some(
            self.0
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// Apply one `Set-Cookie` value. An empty value, `deleted` or `Max-Age=0` is
    /// the server clearing the cookie.
    pub fn absorb(&mut self, set_cookie: &str) {
        let mut parts = set_cookie.split(';');
        let Some((k, v)) = parts.next().unwrap_or("").trim().split_once('=') else {
            return;
        };
        let (k, v) = (k.trim(), v.trim());
        if k.is_empty() {
            return;
        }
        let expired = parts.any(|a| {
            a.trim()
                .split_once('=')
                .is_some_and(|(n, v)| n.trim().eq_ignore_ascii_case("max-age") && v.trim() == "0")
        });
        if v.is_empty() || v == "deleted" || expired {
            self.0.remove(k);
        } else {
            self.0.insert(k.to_string(), v.to_string());
        }
    }

    pub fn absorb_response(&mut self, resp: &Response) {
        for (k, v) in &resp.headers {
            if k.eq_ignore_ascii_case("set-cookie") {
                self.absorb(v);
            }
        }
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// The body; for a response read without body, the bytes already received
    /// past the headers.
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

    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.status)
    }

    /// The value of a cookie this response sets.
    pub fn set_cookie(&self, name: &str) -> Option<String> {
        let mut jar = Cookies::new();
        jar.absorb_response(self);
        jar.get(name).map(str::to_string)
    }

    /// Status line and headers, for diagnostics.
    pub fn head_text(&self) -> String {
        let mut s = format!("HTTP {}", self.status);
        for (k, v) in &self.headers {
            s.push_str(&format!("\n{k}: {v}"));
        }
        s
    }
}

#[derive(Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub content_type: Option<&'a str>,
    pub body: &'a [u8],
    /// Extra header lines ("Name: value"); one named like a default replaces it.
    pub headers: &'a [String],
    /// Host header instead of the endpoint's.
    pub host: Option<&'a str>,
    pub cookies: bool,
}

impl<'a> Request<'a> {
    pub fn new(method: &'a str, path: &'a str) -> Self {
        Request {
            method,
            path,
            content_type: None,
            body: b"",
            headers: &[],
            host: None,
            cookies: true,
        }
    }

    pub fn get(path: &'a str) -> Self {
        Self::new("GET", path)
    }

    pub fn post(path: &'a str, content_type: Option<&'a str>, body: &'a [u8]) -> Self {
        Request {
            content_type,
            body,
            ..Self::new("POST", path)
        }
    }

    /// POST of an URL-encoded form.
    pub fn form(path: &'a str, body: &'a str) -> Self {
        Self::post(path, Some(FORM), body.as_bytes())
    }

    pub fn headers(self, headers: &'a [String]) -> Self {
        Request { headers, ..self }
    }

    pub fn host(self, host: &'a str) -> Self {
        Request {
            host: Some(host),
            ..self
        }
    }

    pub fn without_cookies(self) -> Self {
        Request {
            cookies: false,
            ..self
        }
    }

    pub fn encode(&self, ep: &Endpoint, cookies: &Cookies, keep_alive: bool) -> Vec<u8> {
        let given = |name: &str| {
            ep.headers.iter().chain(self.headers).any(|h| {
                h.split_once(':')
                    .is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(name))
            })
        };
        let mut req = format!("{} {} HTTP/1.1\r\n", self.method, self.path);
        let host = self
            .host
            .map(str::to_string)
            .unwrap_or_else(|| ep.host_header());
        req.push_str(&format!("Host: {host}\r\n"));
        req.push_str(&format!("User-Agent: {}\r\n", ep.user_agent));
        if !given("accept") {
            req.push_str("Accept: */*\r\n");
        }
        if !given("accept-encoding") {
            req.push_str("Accept-Encoding: identity\r\n");
        }
        if let Some(c) = cookies.header().filter(|_| self.cookies) {
            req.push_str(&format!("Cookie: {c}\r\n"));
        }
        for h in ep.headers.iter().chain(self.headers) {
            req.push_str(h);
            req.push_str("\r\n");
        }
        if let Some(ct) = self.content_type {
            req.push_str(&format!("Content-Type: {ct}\r\n"));
        }
        if self.method == "POST" || !self.body.is_empty() {
            req.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        if !given("connection") {
            req.push_str(if keep_alive {
                "Connection: keep-alive\r\n"
            } else {
                "Connection: close\r\n"
            });
        }
        req.push_str("\r\n");
        let mut out = req.into_bytes();
        out.extend_from_slice(self.body);
        out
    }
}

/// One request on a fresh connection; the jar absorbs any `Set-Cookie`.
/// Redirects are returned, not followed.
pub fn send(ep: &Endpoint, req: Request, cookies: &mut Cookies) -> Result<Response, String> {
    exchange(ep.connect()?, ep, req, cookies)
}

/// [`send`], following same-host redirects as GETs. A redirect to another host
/// (an external IdP) is returned.
pub fn send_following(
    ep: &Endpoint,
    req: Request,
    cookies: &mut Cookies,
    max_redirects: u32,
) -> Result<Response, String> {
    let mut next: Option<String> = None;
    for _ in 0..=max_redirects {
        let resp = match &next {
            None => send(ep, req, cookies)?,
            Some(path) => send(ep, Request::get(path).headers(req.headers), cookies)?,
        };
        if !resp.is_redirect() {
            return Ok(resp);
        }
        match resp.location().and_then(|l| same_host_path(&ep.host, l)) {
            Some(p) => next = Some(p),
            None => return Ok(resp),
        }
    }
    Err("too many redirects".into())
}

/// Lets another thread abort an in-flight [`send_cancellable`]. Sticky: a cancel
/// that lands before the request has connected still stops it.
#[derive(Clone, Default)]
pub struct Cancel(Arc<Mutex<CancelState>>);

#[derive(Default)]
struct CancelState {
    cancelled: bool,
    sock: Option<TcpStream>,
}

impl Cancel {
    /// Shut the request's socket down, or stop it before it sends.
    pub fn cancel(&self) {
        let mut st = self.0.lock().unwrap_or_else(|e| e.into_inner());
        st.cancelled = true;
        if let Some(s) = st.sock.take() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

/// [`send`], abortable through `cancel` (for a request the gateway holds open).
pub fn send_cancellable(
    ep: &Endpoint,
    req: Request,
    cookies: &mut Cookies,
    cancel: &Cancel,
) -> Result<Response, String> {
    if cancel.0.lock().unwrap_or_else(|e| e.into_inner()).cancelled {
        return Err("cancelled".into());
    }
    let tls = ep.connect()?;
    {
        // Registered under the lock cancel takes, so a cancel in between isn't lost.
        let mut st = cancel.0.lock().unwrap_or_else(|e| e.into_inner());
        if st.cancelled {
            let _ = tls.get_ref().shutdown(Shutdown::Both);
            return Err("cancelled".into());
        }
        st.sock = tls.get_ref().try_clone().ok();
    }
    exchange(tls, ep, req, cookies)
}

fn exchange(
    mut tls: TlsStream,
    ep: &Endpoint,
    req: Request,
    cookies: &mut Cookies,
) -> Result<Response, String> {
    tls.write_all(&req.encode(ep, cookies, false))
        .map_err(|e| format!("write request: {e}"))?;
    tls.flush().ok();
    let resp = read_response(&mut tls, true)?;
    cookies.absorb_response(&resp);
    Ok(resp)
}

/// Read one response. With `with_body`, the body is read by chunked encoding or
/// `Content-Length`, and only without either until close (so a server that keeps
/// the socket open despite `Connection: close` doesn't stall us to a timeout).
pub fn read_response<S: Read>(s: &mut S, with_body: bool) -> Result<Response, String> {
    let mut tmp = [0u8; 4096];
    let mut raw = Vec::new();
    let header_end = loop {
        if let Some(e) = head_end(&raw) {
            break e;
        }
        match s.read(&mut tmp) {
            Ok(0) => return Err("connection closed before response headers".into()),
            Ok(n) => raw.extend_from_slice(&tmp[..n]),
            Err(e) => return Err(format!("read headers: {e}")),
        }
        if raw.len() > MAX_HEAD {
            return Err("response headers too large".into());
        }
    };
    let (status, headers) = parse_head(&raw[..header_end])?;
    let mut body = raw.split_off(header_end);
    if !with_body {
        return Ok(Response {
            status,
            headers,
            body,
        });
    }
    match body_framing(&headers) {
        Framing::Chunked => loop {
            if let Some(d) = dechunk(&body) {
                body = d;
                break;
            }
            match s.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
                Err(e) => return Err(format!("read chunked body: {e}")),
            }
        },
        Framing::Length(len) => {
            while body.len() < len {
                match s.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&tmp[..n]),
                }
            }
            body.truncate(len);
        }
        Framing::Close => loop {
            match s.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
            }
        },
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}

pub enum Framing {
    Chunked,
    Length(usize),
    Close,
}

pub fn body_framing(headers: &[(String, String)]) -> Framing {
    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });
    if chunked {
        return Framing::Chunked;
    }
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .map_or(Framing::Close, Framing::Length)
}

/// Offset just past the blank line that ends the headers.
pub fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

pub fn parse_head(head: &[u8]) -> Result<(u16, Vec<(String, String)>), String> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.lines();
    let status_line = lines.next().ok_or("empty response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("bad status line: {status_line:?}"))?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Ok((status, headers))
}

/// A complete chunked body, decoded; `None` until the terminating 0-chunk has
/// arrived. A short or bogus chunk means "not complete", never a panic.
pub fn dechunk(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let rest = raw.get(i..)?;
        let line_end = rest.windows(2).position(|w| w == b"\r\n")? + i;
        let size_str = std::str::from_utf8(&raw[i..line_end]).ok()?;
        let size =
            usize::from_str_radix(size_str.split(';').next().unwrap_or("").trim(), 16).ok()?;
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

/// The path of a `Location` on `host`, `None` when it points elsewhere.
pub fn same_host_path(host: &str, loc: &str) -> Option<String> {
    let loc = loc.trim();
    if let Some(rest) = loc
        .strip_prefix("https://")
        .or_else(|| loc.strip_prefix("http://"))
    {
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let a_host = authority.rsplit('@').next().unwrap_or(authority);
        let a_host = match a_host.strip_prefix('[') {
            Some(v6) => v6.split(']').next().unwrap_or(v6),
            None => a_host.rsplit_once(':').map_or(a_host, |(h, _)| h),
        };
        a_host.eq_ignore_ascii_case(host).then(|| path.to_string())
    } else if loc.starts_with('/') {
        Some(loc.to_string())
    } else {
        Some(format!("/{loc}"))
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
        let port = tail
            .strip_prefix(':')
            .map(|p| p.parse::<u16>().map_err(|_| "bad port"))
            .transpose()?;
        (h.to_string(), port.unwrap_or(443))
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| format!("bad port in {url:?}"))?,
        )
    } else {
        (authority.to_string(), 443)
    };
    Ok((host, port, path))
}

/// Decode `%XX` escapes only, like JS `decodeURIComponent` (`+` stays `+`).
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

/// Decode a form/query value: `+` is a space.
pub fn form_decode(s: &str) -> String {
    percent_decode(&s.replace('+', " "))
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// A `key=value&…` form body, values URL-encoded in insertion order.
#[derive(Default, Clone)]
pub struct Form(Vec<(String, String)>);

impl Form {
    pub fn new() -> Self {
        Form::default()
    }

    pub fn add(&mut self, k: &str, v: &str) -> &mut Self {
        self.0.push((k.to_string(), v.to_string()));
        self
    }

    /// Append a pre-encoded `a=b&c=d` fragment.
    pub fn extend_encoded(&mut self, query: &str) -> &mut Self {
        for kv in query.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            self.0.push((percent_decode(k), percent_decode(v)));
        }
        self
    }

    pub fn encode(&self) -> String {
        self.0
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(port: u16) -> Endpoint {
        Endpoint::new("gw.example.com", port, "ua/1", Duration::from_secs(1))
    }

    #[test]
    fn request_bytes() {
        let mut jar = Cookies::new();
        jar.set("a", "1");
        let r = Request::form("/login", "u=x").encode(&ep(443), &jar, false);
        assert_eq!(
            String::from_utf8(r).unwrap(),
            "POST /login HTTP/1.1\r\nHost: gw.example.com\r\nUser-Agent: ua/1\r\n\
             Accept: */*\r\nAccept-Encoding: identity\r\nCookie: a=1\r\n\
             Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\
             Connection: close\r\n\r\nu=x"
        );
        let up = ["Connection: Upgrade".to_string()];
        let r = Request::get("/t")
            .headers(&up)
            .host("sslvpn")
            .without_cookies()
            .encode(&ep(8443), &jar, true);
        assert_eq!(
            String::from_utf8(r).unwrap(),
            "GET /t HTTP/1.1\r\nHost: sslvpn\r\nUser-Agent: ua/1\r\nAccept: */*\r\n\
             Accept-Encoding: identity\r\nConnection: Upgrade\r\n\r\n"
        );
        let mut e = ep(8443);
        e.headers = vec!["X-Aggregate-Auth: 1".into(), "Accept: text/xml".into()];
        let r = String::from_utf8(Request::get("/").encode(&e, &Cookies::new(), true)).unwrap();
        assert!(r.starts_with("GET / HTTP/1.1\r\nHost: gw.example.com:8443\r\n"));
        assert!(r.contains("\r\nAccept: text/xml\r\n") && !r.contains("*/*"));
        assert!(r.ends_with(
            "X-Aggregate-Auth: 1\r\nAccept: text/xml\r\nConnection: keep-alive\r\n\r\n"
        ));
    }

    #[test]
    fn host_header_omits_default_port() {
        assert_eq!(ep(443).host_header(), "gw.example.com");
        assert_eq!(ep(8443).base_url(), "https://gw.example.com:8443");
        let v6 = Endpoint::new("2001:db8::1", 444, "", Duration::ZERO);
        assert_eq!(v6.host_header(), "[2001:db8::1]:444");
    }

    #[test]
    fn cookie_jar_set_and_clear() {
        let mut c = Cookies::new();
        c.absorb("MRHSession=abc123; path=/; secure");
        c.absorb("F5_ST=1z1z0z1700000000z86400; path=/");
        assert_eq!(c.get("MRHSession"), Some("abc123"));
        c.absorb("MRHSession=deleted; path=/");
        assert_eq!(c.get("MRHSession"), None);
        c.absorb("SVPNCOOKIE=; path=/; expires=Thu, 01 Jan 1970 22:00:00 GMT");
        assert_eq!(c.get("SVPNCOOKIE"), None);
        c.absorb("F5_ST=x; Max-Age=0");
        assert_eq!(c.get("F5_ST"), None);
        c.absorb("=x");
        c.absorb("junk");
        assert!(c.header().is_none());
    }

    #[test]
    fn response_chunked_and_cookies() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: webvpn=abc; path=/; secure\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let r = read_response(&mut std::io::Cursor::new(wire.to_vec()), true).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello world");
        assert_eq!(r.set_cookie("webvpn").as_deref(), Some("abc"));
    }

    #[test]
    fn response_length_and_leftover() {
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA";
        let r = read_response(&mut std::io::Cursor::new(wire.to_vec()), true).unwrap();
        assert_eq!(r.body, b"ok");
        let r = read_response(&mut std::io::Cursor::new(wire.to_vec()), false).unwrap();
        assert_eq!(r.body, b"okEXTRA");
        assert!(read_response(&mut std::io::Cursor::new(b"HTTP/1.1 200".to_vec()), true).is_err());
        assert!(
            read_response(&mut std::io::Cursor::new(b"garbage\r\n\r\n".to_vec()), true).is_err()
        );
    }

    #[test]
    fn dechunk_complete_and_partial() {
        let full = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(dechunk(full).as_deref(), Some(&b"hello world"[..]));
        for cut in 0..full.len() - 4 {
            assert_eq!(dechunk(&full[..cut]), None, "cut at {cut}");
        }
        assert_eq!(dechunk(b"ffffffffffffffff\r\nab\r\n"), None);
    }

    #[test]
    fn same_host_variants() {
        let h = "gw.example.com";
        assert_eq!(
            same_host_path(h, "/my.policy").as_deref(),
            Some("/my.policy")
        );
        assert_eq!(
            same_host_path(h, "https://gw.example.com/vdesk/").as_deref(),
            Some("/vdesk/")
        );
        assert_eq!(
            same_host_path(h, "https://gw.example.com:443/x?y=1").as_deref(),
            Some("/x?y=1")
        );
        assert_eq!(same_host_path(h, "https://idp.example.net/sso"), None);
        assert_eq!(
            same_host_path("2001:db8::1", "https://[2001:db8::1]:443/a").as_deref(),
            Some("/a")
        );
    }

    #[test]
    fn url_forms() {
        assert_eq!(
            split_url("203.0.113.20").unwrap(),
            ("203.0.113.20".into(), 443, "/".into())
        );
        assert_eq!(
            split_url("https://vpn-sso.example.com/SSOGROUP").unwrap(),
            ("vpn-sso.example.com".into(), 443, "/SSOGROUP".into())
        );
        assert_eq!(
            split_url("gw.example:8443/grp").unwrap(),
            ("gw.example".into(), 8443, "/grp".into())
        );
        assert_eq!(
            split_url("https://gw/?a=1").unwrap(),
            ("gw".into(), 443, "/?a=1".into())
        );
        assert_eq!(
            split_url("[2001:db8::1]:444/x").unwrap(),
            ("2001:db8::1".into(), 444, "/x".into())
        );
        assert!(split_url("http://gw").is_err());
        assert!(split_url("https://").is_err());
    }

    #[test]
    fn percent_and_form_decoding() {
        assert_eq!(
            percent_decode("ana%2Bvpn%40example.com"),
            "ana+vpn@example.com"
        );
        assert_eq!(percent_decode("a+b%zz%4"), "a+b%zz%4");
        assert_eq!(percent_decode("%C3%A9%"), "é%");
        assert_eq!(
            form_decode("%2FCommon%2FNetwork_Access"),
            "/Common/Network_Access"
        );
        assert_eq!(form_decode("a+b%2B"), "a b+");
        assert_eq!(urlencode("a b&c=é"), "a%20b%26c%3D%C3%A9");
    }

    #[test]
    fn form_encodes_in_order() {
        let mut f = Form::new();
        f.add("user", "alice@example.com")
            .add("passwd", "p&ss w=rd")
            .add("ok", "Login");
        assert_eq!(
            f.encode(),
            "user=alice%40example.com&passwd=p%26ss%20w%3Drd&ok=Login"
        );
        let mut f = Form::new();
        f.extend_encoded("authcookie=abc&domain=%28empty_domain%29&user=alice");
        assert_eq!(
            f.encode(),
            "authcookie=abc&domain=%28empty_domain%29&user=alice"
        );
    }

    #[test]
    fn cancel_before_connect_sends_nothing() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let cancel = Cancel::default();
        cancel.cancel();
        let ep = Endpoint::new("127.0.0.1", port, "t", Duration::from_secs(2));
        let r = send_cancellable(&ep, Request::form("/x", ""), &mut Cookies::new(), &cancel);
        assert_eq!(r.err().as_deref(), Some("cancelled"));
        assert!(
            listener.accept().is_err(),
            "a cancelled request must not even connect"
        );
    }
}
