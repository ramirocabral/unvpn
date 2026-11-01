//! HTTPS for the Ivanti Connect Secure (Pulse) control channel.
//!
//! Web login is a GET of the realm's `welcome.cgi` followed by a form POST to
//! `login.cgi`; success is signalled by a `DSID` session cookie in `Set-Cookie`.
//! The transport is the shared HTTP/1.1-over-TLS client; the gateway
//! certificate is accepted as-is (the session is bound by the cookie).

pub use crate::anyconnect::http::{connect_tls, read_response, split_url, Cookies, Endpoint, Response};
pub use crate::forti::http::{percent_decode, urlencode};
pub use crate::gp::http::Form;
use std::io::Write;

/// User-Agent presented by the native client.
pub const USER_AGENT: &str = "Pulse-Secure/9.1 (Linux) unvpn";

/// Base path of the web-auth endpoints.
pub const AUTH_BASE: &str = "/dana-na/auth";

/// GET `path`, absorbing any cookies the server sets. Redirects are returned,
/// not followed.
pub fn get(ep: &Endpoint, path: &str, cookies: &mut Cookies) -> Result<Response, String> {
    let mut tls = connect_tls(&ep.host, ep.port, ep.timeout)?;
    let mut req = format!("GET {path} HTTP/1.1\r\n");
    req.push_str(&format!("Host: {}\r\nUser-Agent: {}\r\n", ep.host_header(), ep.user_agent));
    if let Some(c) = cookies.header() {
        req.push_str(&format!("Cookie: {c}\r\n"));
    }
    req.push_str("Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).map_err(|e| format!("write request: {e}"))?;
    tls.flush().ok();
    let resp = read_response(&mut tls, true)?;
    absorb(&resp, cookies);
    Ok(resp)
}

/// POST a URL-encoded form to `path`, absorbing any cookies the server sets.
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
    absorb(&resp, cookies);
    Ok(resp)
}

fn absorb(resp: &Response, cookies: &mut Cookies) {
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("set-cookie") {
            cookies.absorb(v);
        }
    }
}
