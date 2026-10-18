//! SAML / SSO login for FortiGate SSL-VPN.
//!
//! Flow (openfortivpn `--saml-login` compatible; matches FortiClient's
//! `listenSamlLoginRequest` and the `/remote/saml/auth_id?id=` string in the
//! `vpn` binary):
//!   1. Start a loopback HTTP listener (default 127.0.0.1:8020).
//!   2. User opens `https://<gw>/remote/saml/start?redirect=1[&realm=..]` and
//!      completes SSO in their browser.
//!   3. The gateway redirects the browser to `http://127.0.0.1:8020/?id=<id>`.
//!   4. We exchange that id: `GET /remote/saml/auth_id?id=<id>` →
//!      `Set-Cookie: SVPNCOOKIE=<value>`.
//!
//! The engine prints a `# SAML-URL: <url>` line so the GUI (running as the user)
//! can open it in the real browser; the engine also tries `xdg-open` for CLI use.

use super::auth::Session;
use super::http;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

const DEFAULT_SAML_PORT: u16 = 8020;
const AUTH_ID_PATH: &str = "/remote/saml/auth_id?id=";

/// Perform the SAML browser login and return an authenticated session.
pub fn login(host: &str, port: u16, realm: &str, saml_port: Option<u16>, open_browser: bool) -> Result<Session, String> {
    let lport = saml_port.unwrap_or(DEFAULT_SAML_PORT);
    let listener = TcpListener::bind(("127.0.0.1", lport))
        .map_err(|e| format!("cannot bind SAML listener on 127.0.0.1:{lport}: {e} (try --saml-port)"))?;

    let mut start = format!("https://{host}:{port}/remote/saml/start?redirect=1");
    if !realm.is_empty() {
        start.push_str(&format!("&realm={}", http::urlencode(realm)));
    }
    // The GUI parses this exact marker to open the user's browser.
    println!("# SAML-URL: {start}");
    println!("# Open this URL in your browser to sign in:\n#   {start}");
    if open_browser {
        let _ = std::process::Command::new("xdg-open").arg(&start).spawn();
    }
    println!("# waiting for SSO redirect on http://127.0.0.1:{lport}/ …");

    let id = wait_for_redirect(&listener, Duration::from_secs(180))?;
    println!("# SAML redirect received (id {} chars) — fetching session cookie …", id.len());

    let mut s = Session::new(host.to_string(), port, realm.to_string(), String::new(), Duration::from_secs(20));
    let path = format!("{AUTH_ID_PATH}{}", http::urlencode(&id));
    let resp = http::request(host, port, "GET", &path, &mut s.cookies, &[], b"", Duration::from_secs(20))?;
    if s.svpncookie().is_none() {
        return Err(format!("SAML auth_id did not yield SVPNCOOKIE (HTTP {})", resp.status));
    }
    Ok(s)
}

/// Accept connections until one carries `?id=<..>`, reply with a friendly page,
/// and return the id. Times out after `timeout`.
fn wait_for_redirect(listener: &TcpListener, timeout: Duration) -> Result<String, String> {
    listener.set_nonblocking(true).ok();
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::time::Instant::now() >= deadline {
            return Err("timed out waiting for SAML redirect".into());
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("");
                if let Some(id) = query_param(path, "id") {
                    let body = "<html><body style='font-family:sans-serif'>\
                        <h3>Signed in \u{2713}</h3><p>You can close this window and return to cpvpn.</p>\
                        </body></html>";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    return Ok(id);
                }
                // Not the redirect we want (e.g. a favicon probe) — answer and keep waiting.
                let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return Err(format!("SAML listener accept: {e}")),
        }
    }
}

/// Extract a query parameter value from a request path like `/?id=abc&x=1`.
fn query_param(path: &str, key: &str) -> Option<String> {
    let q = path.split_once('?')?.1;
    for kv in q.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == key && !v.is_empty() {
                return Some(url_decode(v));
            }
        }
    }
    None
}

/// Minimal percent-decoding for the redirect query value.
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                if let Ok(n) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(n);
                    i += 3;
                    continue;
                }
                out.push(b[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
