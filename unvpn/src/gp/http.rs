//! HTTPS for the GlobalProtect control channel.
//!
//! Every GP control call is a form POST (`application/x-www-form-urlencoded`) to
//! a `*.esp` page on the portal or gateway, answered with XML (sometimes a
//! JavaScript or HTML-wrapped challenge). The transport is the generic
//! HTTP/1.1-over-TLS client the AnyConnect back-end already has; only the headers
//! differ. The gateway certificate is accepted as-is (the session is bound by the
//! authcookie).

pub use crate::anyconnect::http::{connect_tls, read_response, split_url, Cookies, Endpoint, Response};
pub use crate::forti::http::{percent_decode, urlencode};
use std::io::Write;

/// The User-Agent the gateway expects from its own client; some older PAN-OS
/// releases reject anything else.
pub const USER_AGENT: &str = "PAN GlobalProtect";

/// POST `body` to `path` (a fresh `Connection: close` request). Cookies set by
/// the server are absorbed; redirects are returned, not followed.
pub fn post_form(ep: &Endpoint, path: &str, cookies: &mut Cookies, body: &str) -> Result<Response, String> {
    let mut tls = connect_tls(&ep.host, ep.port, ep.timeout)?;
    let mut req = format!("POST {path} HTTP/1.1\r\n");
    req.push_str(&format!("Host: {}\r\nUser-Agent: {}\r\n", ep.host_header(), ep.user_agent));
    if let Some(c) = cookies.header() {
        req.push_str(&format!("Cookie: {c}\r\n"));
    }
    req.push_str("Accept: */*\r\nAccept-Encoding: identity\r\n");
    req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
    req.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
    req.push_str(body);
    tls.write_all(req.as_bytes()).map_err(|e| format!("write request: {e}"))?;
    tls.flush().ok();
    let resp = read_response(&mut tls, true)?;
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("set-cookie") {
            cookies.absorb(v);
        }
    }
    Ok(resp)
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
    /// Append a pre-encoded `a=b&c=d` fragment (the session cookie string).
    pub fn extend_encoded(&mut self, query: &str) -> &mut Self {
        for kv in query.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            self.0.push((percent_decode(k), percent_decode(v)));
        }
        self
    }
    pub fn encode(&self) -> String {
        self.0.iter().map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v))).collect::<Vec<_>>().join("&")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_encodes_in_order() {
        let mut f = Form::new();
        f.add("user", "alice@example.com").add("passwd", "p&ss w=rd").add("ok", "Login");
        assert_eq!(f.encode(), "user=alice%40example.com&passwd=p%26ss%20w%3Drd&ok=Login");
    }

    #[test]
    fn encoded_fragment_roundtrips() {
        let mut f = Form::new();
        f.extend_encoded("authcookie=abc&domain=%28empty_domain%29&user=alice");
        assert_eq!(f.encode(), "authcookie=abc&domain=%28empty_domain%29&user=alice");
    }
}
