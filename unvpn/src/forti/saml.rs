//! SAML / SSO login for FortiGate SSL-VPN ("external browser" mode).
//!
//! The engine exchanges the SSO result at `/remote/saml/auth_id?id=`:
//!   1. `GET /remote/info` → `<api … remoteauthtimeout='240' sso_port='8020'/>`.
//!      `sso_port` (FortiOS `saml-redirect-port`, default 8020) is where the gateway
//!      sends the browser back; `remoteauthtimeout` bounds the wait. FortiClient
//!      only offers the external-browser flow when `sso_port` is present.
//!   2. Listen on `127.0.0.1:<sso_port>` and open the user's browser on
//!      `https://<gw>/remote/saml/start?[realm=<r>&]redirect=1`. The gateway
//!      answers with a JS `window.location='…'` (or a 302) to the IdP, where the
//!      user signs in — MFA included, that's the IdP's business.
//!   3. The IdP POSTs the SAMLResponse to the gateway ACS (`/remote/saml/login`);
//!      because the flow started with `redirect=1` the gateway then sends the
//!      browser to `http://127.0.0.1:<sso_port>/?id=<auth_id>`.
//!   4. `GET /remote/saml/auth_id?id=<auth_id>` → `Set-Cookie: SVPNCOOKIE=…`;
//!      from here on it's identical to password auth.
//!
//! The engine usually runs as root (sudo/pkexec), so the browser is opened in the
//! invoking user's desktop session, never as root. The GUI opens it itself from the
//! `# SAML-URL:` marker and passes `--no-browser`. If the browser can't reach the
//! loopback listener (e.g. it runs on another machine), the user can paste the
//! final `http://127.0.0.1:…/?id=…` URL — or just the id — on stdin.

use super::auth::Session;
use super::http;
use crate::sysnet::{self, StdinEvent};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const INFO_PATH: &str = "/remote/info";
const AUTH_ID_PATH: &str = "/remote/saml/auth_id?id=";
/// FortiClient's `SAML_DEFAULT_SSO_PORT` / `SAML_LOGIN_DEFAULT_TIMEOUT`.
const DEFAULT_SSO_PORT: u16 = 8020;
const DEFAULT_AUTH_TIMEOUT: u64 = 300;

#[derive(Debug, Default, PartialEq)]
pub struct RemoteInfo {
    pub sso_port: Option<u16>,
    pub auth_timeout: Option<u64>,
}

pub struct SamlOpts {
    /// Override the listener port (default: the gateway's `sso_port`).
    pub port: Option<u16>,
    /// Open the browser ourselves (CLI). The GUI opens it and sets this false.
    pub open_browser: bool,
}

pub fn remote_info(host: &str, port: u16) -> Result<RemoteInfo, String> {
    let mut cookies = http::Cookies::new();
    let resp = http::request(host, port, "GET", INFO_PATH, &mut cookies, &[], b"", Duration::from_secs(20))?;
    if resp.status != 200 {
        return Err(format!("GET {INFO_PATH} → HTTP {}", resp.status));
    }
    Ok(parse_remote_info(&resp.body_str()))
}

/// `<info><api encmethod='0' salt='…' remoteauthtimeout='240' sso_port='8020' f='3cdf' /></info>`
pub fn parse_remote_info(xml: &str) -> RemoteInfo {
    RemoteInfo {
        sso_port: xml_attr(xml, "sso_port").and_then(|v| v.parse().ok()).filter(|p| *p != 0),
        auth_timeout: xml_attr(xml, "remoteauthtimeout").and_then(|v| v.parse().ok()).filter(|t| *t != 0),
    }
}

/// Value of `name='…'` / `name="…"` anywhere in `s`.
fn xml_attr<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(i) = s[from..].find(name) {
        let at = from + i;
        from = at + name.len();
        // Must be a whole attribute name: preceded by whitespace/`<`.
        if at > 0 && !matches!(s.as_bytes()[at - 1], b' ' | b'\t' | b'\n' | b'\r' | b'<') {
            continue;
        }
        let rest = s[from..].trim_start();
        let Some(rest) = rest.strip_prefix('=') else { continue };
        let rest = rest.trim_start();
        let q = rest.chars().next()?;
        if q != '\'' && q != '"' {
            continue;
        }
        let end = rest[1..].find(q)?;
        return Some(&rest[1..1 + end]);
    }
    None
}

pub fn start_url(host: &str, port: u16, realm: &str) -> String {
    if realm.is_empty() {
        format!("https://{host}:{port}/remote/saml/start?redirect=1")
    } else {
        format!("https://{host}:{port}/remote/saml/start?realm={}&redirect=1", http::urlencode(realm))
    }
}

/// Where `/remote/saml/start` sends the browser: a 3xx `Location`, or — as FortiOS
/// 7.x does — a 200 page whose script does `window.location='<idp url>'`.
pub fn idp_redirect(resp: &http::Response) -> Option<String> {
    if (300..400).contains(&resp.status) {
        return resp.location().map(str::to_string);
    }
    if resp.status == 200 {
        return js_redirect(&resp.body_str());
    }
    None
}

fn js_redirect(body: &str) -> Option<String> {
    for key in ["window.location.href", "window.location", "location.href"] {
        let Some(i) = body.find(key) else { continue };
        let rest = body[i + key.len()..].trim_start().strip_prefix('=')?.trim_start();
        let q = rest.chars().next()?;
        if q != '\'' && q != '"' {
            continue;
        }
        let end = rest[1..].find(q)?;
        return Some(rest[1..1 + end].to_string());
    }
    None
}

pub fn login(host: &str, port: u16, realm: &str, opts: &SamlOpts) -> Result<Session, String> {
    let info = remote_info(host, port).unwrap_or_else(|e| {
        println!("# /remote/info unavailable ({e}) — assuming defaults");
        RemoteInfo::default()
    });
    if info.sso_port.is_none() && opts.port.is_none() {
        println!(
            "# gateway advertises no sso_port (external-browser SAML off?) — trying {DEFAULT_SSO_PORT} anyway"
        );
    }
    let lport = opts.port.or(info.sso_port).unwrap_or(DEFAULT_SSO_PORT);
    let wait = Duration::from_secs(info.auth_timeout.unwrap_or(DEFAULT_AUTH_TIMEOUT));
    let listeners = bind_listeners(lport)?;

    let start = start_url(host, port, realm);
    // The GUI parses this exact marker to open the user's browser.
    println!("# SAML-URL: {start}");
    println!("# Sign in with your browser:\n#   {start}");
    if opts.open_browser {
        open_browser(&start);
    }
    println!(
        "# waiting up to {}s for the SSO redirect on http://127.0.0.1:{lport}/ …\n\
         #   (or paste the final http://127.0.0.1:{lport}/?id=… URL here + Enter)",
        wait.as_secs()
    );

    let id = wait_for_auth_id(&listeners, wait)?;
    drop(listeners);
    println!("# SAML redirect received (auth id {} chars) — exchanging for SVPNCOOKIE …", id.len());

    let mut s = Session::new(host.to_string(), port, realm.to_string(), String::new(), Duration::from_secs(20));
    let path = format!("{AUTH_ID_PATH}{}", http::urlencode(&id));
    let resp = http::request(host, port, "GET", &path, &mut s.cookies, &[], b"", Duration::from_secs(20))?;
    if s.svpncookie().is_none() {
        // One sanitized line: this is gateway text and ends up in the GUI's parser.
        let snippet: String = super::auth::one_line(&resp.body_str()).chars().take(200).collect();
        return Err(format!("SAML auth_id did not yield SVPNCOOKIE (HTTP {}): {snippet}", resp.status));
    }
    Ok(s)
}

/// Bind the loopback redirect listener: IPv4 is required (the gateway redirects to
/// `127.0.0.1`); `[::1]` is best-effort, for browsers that resolve `localhost` to it.
fn bind_listeners(port: u16) -> Result<Vec<TcpListener>, String> {
    let v4 = TcpListener::bind(("127.0.0.1", port)).map_err(|e| {
        format!("cannot listen on 127.0.0.1:{port}: {e} (FortiClient running? close it or use --saml-port)")
    })?;
    let mut all = vec![v4];
    if let Ok(v6) = TcpListener::bind(("::1", port)) {
        all.push(v6);
    }
    for l in &all {
        l.set_nonblocking(true).map_err(|e| format!("listener nonblocking: {e}"))?;
    }
    Ok(all)
}

/// Wait until the browser hits a listener with `?id=<..>` (answering it with a
/// friendly page), or the user pastes the URL/id on stdin, or `timeout` elapses.
/// `disconnect`/EOF on stdin (the GUI's cancel) aborts.
fn wait_for_auth_id(listeners: &[TcpListener], timeout: Duration) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err("timed out waiting for the SAML redirect".into());
        }
        for l in listeners {
            match l.accept() {
                Ok((stream, _)) => {
                    if let Some(id) = serve_redirect(stream) {
                        return Ok(id);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("SAML listener accept: {e}")),
            }
        }
        match sysnet::stdin_next(Some(Duration::from_millis(150))) {
            StdinEvent::Line(l) if sysnet::is_disconnect(&l) => return Err("SAML login cancelled".into()),
            StdinEvent::Line(l) => match id_from_pasted(&l) {
                Some(id) => return Ok(id),
                None if l.trim().is_empty() => {}
                None => println!("# that doesn't look like the redirect URL or an auth id — still waiting"),
            },
            StdinEvent::Eof => return Err("SAML login cancelled (stdin closed)".into()),
            StdinEvent::Timeout => {}
        }
    }
}

/// Handle one connection on the loopback listener. Returns the auth id if this was
/// the gateway's redirect; anything else (favicon, preconnect) gets a 204.
fn serve_redirect(mut stream: std::net::TcpStream) -> Option<String> {
    stream.set_nonblocking(false).ok();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("");
    match query_param(path, "id") {
        Some(id) => {
            let body = "<!doctype html><html><head><meta charset='utf-8'><title>unvpn</title></head>\
                <body style='font-family:sans-serif;max-width:32em;margin:4em auto'>\
                <h2>Signed in \u{2713}</h2><p>unvpn is bringing up the VPN. You can close this tab.</p>\
                </body></html>";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
                 Cache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            Some(id)
        }
        None => {
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
            None
        }
    }
}

/// Accept a pasted redirect URL (`http://127.0.0.1:8020/?id=…`), a bare `?id=…`,
/// or the raw id itself.
fn id_from_pasted(line: &str) -> Option<String> {
    let l = line.trim();
    if l.contains("id=") {
        let q = if l.contains('?') { l.to_string() } else { format!("?{l}") };
        return query_param(&q, "id");
    }
    let token_like = l.len() >= 8 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.%".contains(&b));
    token_like.then(|| url_decode(l))
}

/// Open `url` in the desktop user's browser. As root (sudo/pkexec) that means
/// dropping to the invoking user with their session environment rebuilt — a root
/// browser would be the wrong profile at best and refuse to start at worst.
pub fn open_browser(url: &str) {
    let mut cmd = if unsafe { libc::geteuid() } == 0 {
        let Some(u) = invoking_user() else {
            println!("# (root without SUDO_UID/PKEXEC_UID — open the URL above yourself)");
            return;
        };
        let rt = format!("/run/user/{}", u.uid);
        let mut env = vec![
            format!("HOME={}", u.home),
            format!("USER={}", u.name),
            format!("LOGNAME={}", u.name),
            "PATH=/usr/local/bin:/usr/bin:/bin".to_string(),
            format!("XDG_RUNTIME_DIR={rt}"),
            format!("DBUS_SESSION_BUS_ADDRESS=unix:path={rt}/bus"),
        ];
        let wayland = std::env::var("WAYLAND_DISPLAY").ok().or_else(|| wayland_socket(&rt));
        if let Some(w) = wayland {
            env.push(format!("WAYLAND_DISPLAY={w}"));
        }
        let display = std::env::var("DISPLAY")
            .ok()
            .or_else(|| std::path::Path::new("/tmp/.X11-unix/X0").exists().then(|| ":0".to_string()));
        if let Some(d) = display {
            env.push(format!("DISPLAY={d}"));
        }
        for k in ["XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE"] {
            if let Ok(v) = std::env::var(k) {
                env.push(format!("{k}={v}"));
            }
        }
        let mut c = Command::new("runuser");
        c.args(["-u", &u.name, "--", "env", "-i"]).args(env).arg("xdg-open").arg(url);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    match cmd.spawn() {
        Ok(mut child) => {
            std::thread::spawn(move || child.wait()); // reap it
            println!("# opened your browser");
        }
        Err(e) => println!("# could not open a browser ({e}) — open the URL above yourself"),
    }
}

struct DesktopUser {
    name: String,
    uid: u32,
    home: String,
}

/// The real user behind sudo (`SUDO_UID`) or pkexec (`PKEXEC_UID`).
fn invoking_user() -> Option<DesktopUser> {
    let uid: u32 = std::env::var("SUDO_UID")
        .or_else(|_| std::env::var("PKEXEC_UID"))
        .ok()?
        .parse()
        .ok()?;
    if uid == 0 {
        return None;
    }
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() {
        return None;
    }
    let cstr = |p: *const libc::c_char| unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned();
    Some(DesktopUser { name: cstr(pw.pw_name), uid, home: cstr(pw.pw_dir) })
}

fn wayland_socket(runtime_dir: &str) -> Option<String> {
    let mut names: Vec<String> = std::fs::read_dir(runtime_dir)
        .ok()?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.starts_with("wayland-") && !n.ends_with(".lock"))
        .collect();
    names.sort();
    names.into_iter().next()
}

fn query_param(path: &str, key: &str) -> Option<String> {
    let q = path.split_once('?')?.1;
    let q = q.split('#').next().unwrap_or(q);
    for kv in q.split('&') {
        if let Some((k, v)) = kv.split_once('=') {
            if k == key && !v.is_empty() {
                return Some(url_decode(v));
            }
        }
    }
    None
}

/// Form-style percent-decoding (`+` = space) for the redirect query value. Works
/// on bytes: the request line comes from any local client and may hold anything
/// (slicing the `str` there would panic on a non-ASCII byte after a `%`).
fn url_decode(s: &str) -> String {
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_id_from_redirect() {
        assert_eq!(query_param("/?id=abc123&x=1", "id").as_deref(), Some("abc123"));
        assert_eq!(query_param("/callback?foo=1&id=XYZ", "id").as_deref(), Some("XYZ"));
        assert_eq!(query_param("/?id=abc#frag", "id").as_deref(), Some("abc"));
        assert_eq!(query_param("/?x=1", "id"), None);
        assert_eq!(query_param("/nothing", "id"), None);
    }

    #[test]
    fn url_decode_basic() {
        assert_eq!(url_decode("a%2Fb+c%21"), "a/b c!");
        // Hostile request lines must not panic (non-ASCII right after '%').
        assert_eq!(url_decode("%\u{fffd}x"), "%\u{fffd}x");
        assert_eq!(url_decode("%é1"), "%é1");
        assert_eq!(url_decode("%4"), "%4");
    }

    #[test]
    fn remote_info_real_gateway() {
        // Verbatim from a FortiGate with external-browser SAML (203.0.113.30:10443).
        let xml = "<?xml version='1.0' encoding='utf-8'?><info><api encmethod='0' salt='00612a8b' \
                   remoteauthtimeout='240' sso_port='8020' f='3cdf' /></info>";
        assert_eq!(parse_remote_info(xml), RemoteInfo { sso_port: Some(8020), auth_timeout: Some(240) });
        assert_eq!(parse_remote_info("<info><api encmethod='0' /></info>"), RemoteInfo::default());
    }

    #[test]
    fn xml_attr_whole_name_only() {
        assert_eq!(xml_attr("<api xsso_port='1' sso_port=\"2\"/>", "sso_port"), Some("2"));
    }

    #[test]
    fn js_redirect_to_idp() {
        let body = "<html><body><script>window.location='https://203.0.113.31:19000/application/saml/x/sso/\
                    binding/redirect/?SAMLRequest=jZLB&RelayState=magic%3D2-c4e5';</script></body></html>";
        let url = js_redirect(body).unwrap();
        assert!(url.starts_with("https://203.0.113.31:19000/application/saml/"));
        assert!(url.ends_with("RelayState=magic%3D2-c4e5"));
        assert_eq!(js_redirect("<html>nothing</html>"), None);
    }

    #[test]
    fn start_url_with_realm() {
        assert_eq!(start_url("gw", 10443, ""), "https://gw:10443/remote/saml/start?redirect=1");
        assert_eq!(start_url("gw", 443, "corp vpn"), "https://gw:443/remote/saml/start?realm=corp%20vpn&redirect=1");
    }

    #[test]
    fn pasted_redirects() {
        assert_eq!(id_from_pasted("http://127.0.0.1:8020/?id=AbC123xyz").as_deref(), Some("AbC123xyz"));
        assert_eq!(id_from_pasted("  ?id=Zz9_8-7 ").as_deref(), Some("Zz9_8-7"));
        assert_eq!(id_from_pasted("id=QWERTYUI").as_deref(), Some("QWERTYUI"));
        assert_eq!(id_from_pasted("0123456789abcdef").as_deref(), Some("0123456789abcdef"));
        assert_eq!(id_from_pasted("hello"), None);
        assert_eq!(id_from_pasted("not an id at all"), None);
    }
}
