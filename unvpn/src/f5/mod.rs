//! F5 BIG-IP APM "Network Access" SSL-VPN back-end.

pub mod auth;
pub mod config;
pub mod http;
pub mod ppp;
pub mod tunnel;

use auth::{Outcome, Session};
use std::time::Duration;

struct Args {
    host: String,
    port: u16,
    user: String,
    password: Option<String>,
    code: Option<String>,
    action: Action,
    no_dtls: bool,
    /// Bring the tunnel up but install no routes and no DNS — a data-plane test
    /// that cannot disturb the host's networking.
    no_routes: bool,
    /// The `f5-vpn://…` URL from the webtop "Start" handoff.
    launch_url: Option<String>,
    /// `--launch` run by a front-end that owns stdin (the app): `disconnect` or EOF
    /// there stops the tunnel, as on the other paths.
    watch_stdin: bool,
}

#[derive(PartialEq)]
enum Action {
    Probe,
    Login,
    Connect,
    /// `f5-vpn://` launch URL: the Linux equivalent of the webtop "Start" button
    /// (which on Windows launches the native client via this URL scheme).
    Launch,
}

pub fn cmd_f5(args: &[String]) {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            usage();
            std::process::exit(2);
        }
    };
    let r = match parsed.action {
        Action::Probe => probe(&parsed),
        Action::Login => do_login(&parsed).map(|_| ()),
        Action::Connect => connect(&parsed),
        Action::Launch => launch(&parsed),
    };
    if let Err(e) = r {
        crate::report::fail("f5", &e);
    }
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut host: Option<String> = None;
    let mut port = 443u16;
    let mut user = String::new();
    let mut password = None;
    let mut code = None;
    let mut action = Action::Login;
    let mut no_dtls = false;
    let mut no_routes = false;
    let mut launch_url: Option<String> = None;
    let mut watch_stdin = false;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" => {
                let v = it.next().ok_or("--gateway needs a value")?;
                if let Some((h, p)) = v.rsplit_once(':') {
                    if let Ok(pn) = p.parse::<u16>() {
                        host = Some(h.to_string());
                        port = pn;
                    } else {
                        host = Some(v.clone());
                    }
                } else {
                    host = Some(v.clone());
                }
            }
            "--port" => port = it.next().and_then(|s| s.parse().ok()).ok_or("--port needs a number")?,
            "--user" | "-u" => user = it.next().cloned().ok_or("--user needs a value")?,
            "--password" | "-p" => password = it.next().cloned(),
            "--code" | "--otp" => code = it.next().cloned(),
            "--probe" => action = Action::Probe,
            "--login" => action = Action::Login,
            "--connect" => action = Action::Connect,
            "--no-dtls" => no_dtls = true,
            "--no-routes" => no_routes = true,
            "--watch-stdin" => watch_stdin = true,
            "--launch" => {
                action = Action::Launch;
                launch_url = Some(it.next().cloned().ok_or("--launch needs an f5-vpn:// URL")?);
            }
            // The scheme handler passes the URL as a bare argument.
            other if other.starts_with("f5-vpn:") => {
                action = Action::Launch;
                launch_url = Some(other.to_string());
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if action == Action::Launch {
        // host/user come from the URL.
        let host = host.unwrap_or_default();
        return Ok(Args { host, port, user, password, code, action, no_dtls, no_routes, launch_url, watch_stdin });
    }
    let host = host.ok_or("f5 requires --gateway <host[:port]>")?;
    if action != Action::Probe && user.is_empty() {
        return Err("f5 requires --user <user>".into());
    }
    Ok(Args { host, port, user, password, code, action, no_dtls, no_routes, launch_url, watch_stdin })
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  unvpn f5 -g <host[:port]> --probe");
    eprintln!("  unvpn f5 -g <host[:port]> -u <user> [--password p] [--code otp] --login");
    eprintln!("  unvpn f5 -g <host[:port]> -u <user> [...] --connect     # brings up the tunnel (sudo)");
    eprintln!("      [--no-routes]  tunnel up but install no routes/DNS (safe data-plane test;");
    eprintln!("                     verify with: ping -I f5vpn0 <internal-host>)");
    eprintln!("  unvpn f5 --launch \"f5-vpn://…\"   # webtop 'Start' handoff (SSO token → tunnel, sudo)");
    eprintln!("      --watch-stdin  stop on a `disconnect` line or EOF on stdin (when a front-end runs it)");
    eprintln!("  password/OTP are read from stdin (no echo) when not given with --password/--code");
}

fn timeout() -> Duration {
    Duration::from_secs(20)
}

/// Non-destructive probe: sends no credentials.
fn probe(a: &Args) -> Result<(), String> {
    let mut cookies = http::Cookies::new();
    println!("# probing {}:{} …", a.host, a.port);
    let resp = http::request_follow(&a.host, a.port, "GET", "/", &mut cookies, &[], b"", timeout(), 5)?;
    let server = resp.header("server").unwrap_or("(no Server header)");
    println!("# GET / → HTTP {} · Server: {server}", resp.status);

    let body = resp.body_str();
    let bl = body.to_ascii_lowercase();
    let looks_f5 = cookies.get("MRHSession").is_some()
        || bl.contains("my.policy")
        || bl.contains("auth_form")
        || bl.contains("f5 networks")
        || server.to_ascii_lowercase().contains("big");
    if looks_f5 {
        println!("# looks like an F5 BIG-IP APM logon portal");
    } else {
        println!("# does not obviously look like F5 APM (no MRHSession / my.policy / auth_form)");
    }

    match auth::try_parse_form(&body) {
        Some(f) => {
            let t = f.text_fields().len();
            let p = f.password_fields().len();
            println!("# logon form found: action={:?}, {t} text field(s), {p} password field(s)", f.action);
            if !f.banner.is_empty() {
                println!("#   banner: {}", f.banner);
            }
            println!("#   (use: unvpn f5 -g {}:{} -u <user> --connect)", a.host, a.port);
        }
        None => println!("# no static logon form (JavaScript-built form; username+password fallback will be used)"),
    }
    Ok(())
}

/// Authenticate with password (+ optional OTP), walking the APM form chain.
fn do_login(a: &Args) -> Result<Session, String> {
    let mut s = Session::new(a.host.clone(), a.port, timeout());
    println!("# authenticating {} @ {}:{} …", a.user, a.host, a.port);

    let mut form = s.start()?;
    let mut password_sent = false;

    for round in 1..=6u32 {
        let has_user = form_has_username(&form);

        // If we're bounced back to a username form after already sending the
        // password, the gateway rejected our credentials — don't resubmit them.
        if round > 1 && has_user && password_sent {
            return Err("login rejected (gateway returned the logon form again)".into());
        }
        if !form.banner.is_empty() {
            println!("# gateway prompt: {}", form.banner);
        }

        let mut answers: Vec<(String, String)> = Vec::new();

        if let Some(uname_field) = username_field(&form) {
            answers.push((uname_field, a.user.clone()));
        }

        // Password on the first round, OTP afterwards.
        let pw_fields = form.password_fields();
        if !pw_fields.is_empty() {
            let secret = if !password_sent {
                let p = match &a.password {
                    Some(p) => p.clone(),
                    None => crate::anyconnect::read_secret("Password: ").ok_or("no password provided")?,
                };
                password_sent = true;
                p
            } else {
                match &a.code {
                    Some(c) => c.clone(),
                    None => {
                        // The code is often emailed/SMS and doesn't exist until the password is in.
                        let msg = if form.banner.is_empty() { "One-time passcode" } else { form.banner.as_str() };
                        crate::report::prompt("code", msg);
                        crate::anyconnect::read_secret("Token code (OTP): ").ok_or("OTP required but none provided")?
                    }
                }
            };
            for idx in pw_fields {
                answers.push((form.fields[idx].name.clone(), secret.clone()));
            }
        } else if round > 1 {
            // Non-password follow-up form (e.g. group confirmation): submit defaults.
            println!("# submitting intermediate form (no secret field) …");
        }

        match s.submit(&form, &answers)? {
            Outcome::Authenticated => {
                println!("# authenticated — MRHSession + F5_ST acquired.");
                return Ok(s);
            }
            Outcome::Failed(msg) => return Err(msg),
            Outcome::NextForm(next) => {
                form = next;
                let _ = round;
            }
        }
    }
    Err("authentication did not complete after 6 form steps".into())
}

/// Needs root.
fn connect(a: &Args) -> Result<(), String> {
    let mut session = do_login(a)?;
    tunnel::run(
        &mut session,
        tunnel::RunOpts { no_dtls: a.no_dtls, no_routes: a.no_routes, watch_stdin: true },
    )
}

/// Webtop "Start" handoff: the browser already authenticated and minted a one-time
/// token, so no password is needed. Stdin is watched only with `--watch-stdin`
/// (the scheme handler launches this detached); otherwise stop with SIGTERM.
fn launch(a: &Args) -> Result<(), String> {
    let url = a.launch_url.as_deref().ok_or("launch requires an f5-vpn:// URL")?;
    let p = parse_launch_url(url)?;
    println!("# f5-vpn launch: server={}:{} resource={:?}", p.host, p.port, p.resource);
    println!("# exchanging one-time token for a session (get_sessid_for_token.php3) …");
    let mut session = auth::Session::from_handoff(p.host, p.port, timeout(), &p.token)?;
    println!("# session acquired via handoff (MRHSession set)");
    tunnel::run(
        &mut session,
        tunnel::RunOpts { no_dtls: a.no_dtls, no_routes: a.no_routes, watch_stdin: a.watch_stdin },
    )
}

/// `f5-vpn://host/path?server=&port=&otc=&token=…`
struct LaunchUrl {
    host: String,
    port: u16,
    token: String,
    resource: Option<String>,
}

/// The gateway is the `server` query parameter (not the URL authority); the handoff
/// credential is `otc` (falling back to `token`).
fn parse_launch_url(url: &str) -> Result<LaunchUrl, String> {
    let rest = url
        .strip_prefix("f5-vpn://")
        .or_else(|| url.strip_prefix("f5-vpn:"))
        .ok_or("not an f5-vpn:// URL")?;
    let query = rest.splitn(2, '?').nth(1).unwrap_or("");
    let mut server = None;
    let mut port: u16 = 443;
    let mut otc = None;
    let mut token = None;
    let mut resource = None;
    for kv in query.split('&') {
        let (k, v) = match kv.split_once('=') {
            Some(p) => p,
            None => continue,
        };
        let v = percent_decode(v);
        match k {
            "server" => server = Some(v),
            "port" => port = v.parse().unwrap_or(443),
            "otc" => otc = Some(v),
            "token" => token = Some(v),
            "resourcename" => resource = Some(v),
            _ => {}
        }
    }
    let host = server.filter(|s| !s.is_empty()).ok_or("launch URL has no server= parameter")?;
    // `otc` is sent as X-ACCESS-Session-Token; fall back to `token`.
    let token = otc
        .filter(|s| !s.is_empty())
        .or(token)
        .filter(|s| !s.is_empty())
        .ok_or("launch URL has no otc=/token= parameter")?;
    Ok(LaunchUrl { host, port, token, resource })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = |c: u8| match c {
                    b'0'..=b'9' => Some(c - b'0'),
                    b'a'..=b'f' => Some(c - b'a' + 10),
                    b'A'..=b'F' => Some(c - b'A' + 10),
                    _ => None,
                };
                match (hex(b[i + 1]), hex(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
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

fn form_has_username(form: &auth::LoginForm) -> bool {
    username_field(form).is_some()
}

/// A text field whose name looks like a user field, else the sole text field.
fn username_field(form: &auth::LoginForm) -> Option<String> {
    let texts = form.text_fields();
    for &i in &texts {
        let n = form.fields[i].name.to_ascii_lowercase();
        if n.contains("user") || n.contains("logon") || n.contains("email") || n.contains("uname") {
            return Some(form.fields[i].name.clone());
        }
    }
    if texts.len() == 1 {
        return Some(form.fields[texts[0]].name.clone());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_basics() {
        assert_eq!(percent_decode("abc"), "abc");
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        assert_eq!(percent_decode("%2FCommon%2FNetwork_Access"), "/Common/Network_Access");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn launch_url_parsed() {
        let url = "f5-vpn://./?server=vpn-f5.example.com&resourcename=%2FCommon%2FNetwork_Access\
                   &resourcetype=network_access&cmd=connect&protocol=https&port=443\
                   &sid=AAAA&token=BBBB&otc=CCCC";
        let p = parse_launch_url(url).unwrap();
        assert_eq!(p.host, "vpn-f5.example.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.resource.as_deref(), Some("/Common/Network_Access"));
        // otc takes precedence over token.
        assert_eq!(p.token, "CCCC");
    }

    #[test]
    fn launch_url_falls_back_to_token() {
        let p = parse_launch_url("f5-vpn://x/?server=gw.example&token=TOK").unwrap();
        assert_eq!(p.host, "gw.example");
        assert_eq!(p.token, "TOK");
    }

    #[test]
    fn launch_url_requires_server_and_token() {
        assert!(parse_launch_url("f5-vpn://x/?otc=CCCC").is_err());
        assert!(parse_launch_url("f5-vpn://x/?server=gw").is_err());
        assert!(parse_launch_url("https://x/?server=gw&otc=c").is_err());
    }
}
