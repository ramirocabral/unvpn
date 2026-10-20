//! Cisco AnyConnect (SSL / CSTP) back-end for cpvpn.
//!
//! Native, from-scratch client for Cisco's AnyConnect SSL-VPN protocol — the one
//! the Secure Client / AnyConnect speaks to an ASA or Secure Firewall, and the one
//! openconnect's default (`anyconnect`) backend interoperates with. Reverse-
//! engineered from the AnyConnect Windows installer plus openconnect prior art.
//! See docs/anyconnect-protocol-notes.md.
//!
//! Subcommand: `cpvpn anyconnect -g <url> -u <user> [...]`
//!   --probe      non-destructive aggregate-auth handshake (no creds): shows the
//!                login form / groups / SSO the gateway offers
//!   --login      authenticate and show the result (no tunnel)
//!   --connect    authenticate, then bring up the CSTP tunnel (needs root)
//!
//! `-g` takes the full gateway URL, including the group path if any
//! (`https://vpn.example.com/GROUPNAME`), exactly as it appears in the browser or
//! the NetworkManager `gateway` field.

pub mod auth;
pub mod config;
pub mod cstp;
pub mod dtls;
pub mod http;
pub mod xml;

use auth::{Creds, Prompter, Session, Sso};
use http::Endpoint;
use std::io::Write;
use std::time::Duration;

/// Version string reported to the gateway (`<version who="vpn">`). Some policies
/// branch on a plausible AnyConnect version; this mirrors a recent client.
const CLIENT_VERSION: &str = "4.10.07073";
/// Default User-Agent. The real client sends `AnyConnect <version> <platform>`;
/// openconnect appends its own. Kept close to the genuine one for policy interop.
const DEFAULT_UA: &str = "AnyConnect Linux_64 4.10.07073";

struct Args {
    url: String,
    user: String,
    password: Option<String>,
    code: Option<String>,
    group: Option<String>,
    sso_token: Option<String>,
    /// SSO login without a username: the token comes from the browser (stdin).
    sso: bool,
    user_agent: String,
    action: Action,
    no_routes: bool,
    no_dtls: bool,
}

#[derive(PartialEq)]
enum Action {
    Probe,
    Login,
    Connect,
}

pub fn cmd_anyconnect(args: &[String]) {
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
    };
    if let Err(e) = r {
        eprintln!("anyconnect failed: {e}");
        std::process::exit(1);
    }
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut url = None;
    let mut user = String::new();
    let mut password = None;
    let mut code = None;
    let mut group = None;
    let mut sso_token = None;
    let mut sso = false;
    let mut user_agent = DEFAULT_UA.to_string();
    let mut action = Action::Login;
    let mut no_routes = false;
    let mut no_dtls = false;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" => url = it.next().cloned(),
            "--user" | "-u" => user = it.next().cloned().ok_or("--user needs a value")?,
            "--password" | "-p" => password = it.next().cloned(),
            "--code" | "--otp" => code = it.next().cloned(),
            "--group" => group = it.next().cloned(),
            "--sso-token" => sso_token = it.next().cloned(),
            "--sso" => sso = true,
            "--user-agent" => user_agent = it.next().cloned().ok_or("--user-agent needs a value")?,
            "--probe" => action = Action::Probe,
            "--login" => action = Action::Login,
            "--connect" => action = Action::Connect,
            "--no-routes" => no_routes = true,
            "--no-dtls" => no_dtls = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let url = url.ok_or("anyconnect requires --gateway <url>")?;
    if action != Action::Probe && user.is_empty() && sso_token.is_none() && !sso {
        return Err("anyconnect requires --user <user> (or --sso / --sso-token for SSO)".into());
    }
    Ok(Args { url, user, password, code, group, sso_token, sso, user_agent, action, no_routes, no_dtls })
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  cpvpn anyconnect -g <url> --probe");
    eprintln!("  cpvpn anyconnect -g <url> -u <user> [--password p] [--code otp] [--group G] --login");
    eprintln!("  cpvpn anyconnect -g <url> -u <user> [...] --connect     # brings up the tunnel (sudo)");
    eprintln!("      [--group G]    pre-select a tunnel group (else the gateway's default)");
    eprintln!("  cpvpn anyconnect -g <url> --sso [--group G] --connect   # SAML: browser login, paste the token");
    eprintln!("      [--sso-token T] supply a SAML sso-v2 token instead of password auth");
    eprintln!("      [--no-routes]  tunnel up but install no routes/DNS (safe data-plane test)");
    eprintln!("  -g is the full gateway URL incl. any group path, e.g. https://vpn.example.com/GROUP");
    eprintln!("  password/OTP are read from stdin (no echo) when not given with --password/--code");
}

fn timeout() -> Duration {
    Duration::from_secs(20)
}

fn make_session(a: &Args) -> Result<Session, String> {
    let (host, port, path) = http::split_url(&a.url)?;
    let ep = Endpoint { host, port, user_agent: a.user_agent.clone(), timeout: timeout() };
    Ok(Session::new(ep, path, CLIENT_VERSION.to_string()))
}

/// Non-destructive probe: run the init exchange with no credentials and report
/// what the gateway offers (form fields, groups, SSO).
fn probe(a: &Args) -> Result<(), String> {
    let mut s = make_session(a)?;
    println!("# probing {} …", s.ep.base_url());
    let mut path = s.path.clone();
    let body = auth::build_init(CLIENT_VERSION, &s.group_access(&path), a.group.as_deref(), false);
    let reply = s.post_xml(&mut path, &body)?;
    println!("# gateway answered config-auth type={:?}", reply.kind);
    if let Some(op) = &reply.opaque {
        if let Some(tg) = xml::parse(op).ok().and_then(|e| e.child_text("tunnel-group")) {
            println!("#   tunnel-group: {tg}");
        }
    }
    match reply.form {
        Some(f) => {
            if let Some(t) = &f.title {
                println!("#   title: {}", auth::one_line(t));
            }
            if let Some(m) = &f.message {
                println!("#   message: {}", auth::one_line(m));
            }
            if let Some(sso) = &f.sso {
                println!("#   SSO (sso-v2) login: {}", sso.login);
                println!("#   → SSO login: cpvpn anyconnect -g {} --sso --connect", a.url);
            }
            for fld in &f.fields {
                println!("#   input: {} ({:?}) — {}", fld.name, fld.kind, auth::one_line(&fld.label));
            }
            for sel in &f.selects {
                let opts: Vec<_> = sel.choices.iter().map(|c| c.label.as_str()).collect();
                println!("#   {} ({:?}): {}", sel.label.trim_end_matches(':'), sel.name, opts.join(", "));
            }
            if f.sso.is_none() {
                println!("#   (use: cpvpn anyconnect -g {} -u <user> --connect)", a.url);
            }
        }
        None => println!("# no <auth> form (already authorised? or cert-only)"),
    }
    Ok(())
}

/// Authenticate; returns the session with its `webvpn` cookie. Shared by
/// `--login` and `--connect`.
fn do_login(a: &Args) -> Result<Session, String> {
    let mut s = make_session(a)?;
    println!("# authenticating {} @ {} …", if a.user.is_empty() { "<SSO>" } else { &a.user }, s.ep.base_url());
    let creds = Creds { user: a.user.clone(), password: a.password.clone(), group: a.group.clone() };
    let mut p = CliPrompter { code: a.code.clone(), sso_token: a.sso_token.clone(), sso_only: a.sso };
    s.login(&creds, &mut p)?;
    println!("# ✅ authenticated — webvpn session acquired.");
    if let Some(g) = &s.group {
        println!("# tunnel group: {g}");
    }
    Ok(s)
}

/// Authenticate and bring up the tunnel. Needs root.
fn connect(a: &Args) -> Result<(), String> {
    let mut s = do_login(a)?;
    cstp::run(&mut s, cstp::RunOpts { no_routes: a.no_routes, watch_stdin: true, no_dtls: a.no_dtls })
}

/// The CLI/GUI prompter: reads secrets from stdin (no echo on a TTY) and emits the
/// `# AUTH-PROMPT:`/`# SAML-URL:` markers the GUI understands.
struct CliPrompter {
    code: Option<String>,
    sso_token: Option<String>,
    /// `--sso`: no password was supplied, so a password form is a mismatch.
    sso_only: bool,
}

impl Prompter for CliPrompter {
    fn password(&mut self) -> Result<String, String> {
        if self.sso_only {
            return Err("the gateway asked for a password, not SSO — use password auth (-u <user>)".into());
        }
        read_secret("Password: ").ok_or("no password provided".into())
    }

    fn ask(&mut self, kind: &str, message: &str) -> Result<String, String> {
        // A pre-supplied OTP answers the first `code` prompt.
        if kind == "code" {
            if let Some(c) = self.code.take() {
                return Ok(c);
            }
        }
        // The marker drives the GUI's prompt card; harmless on a TTY (read_secret
        // prints its own label). Gateway text is flattened to one line.
        println!("# AUTH-PROMPT: {kind}: {}", auth::one_line(message));
        let _ = std::io::stdout().flush();
        read_secret(&format!("{message}: ")).ok_or_else(|| format!("{kind} required but none provided"))
    }

    fn sso_token(&mut self, sso: &Sso) -> Result<String, String> {
        if let Some(t) = self.sso_token.take() {
            return clean_sso_token(&t, &sso.token_cookie).ok_or("empty --sso-token".into());
        }
        // The engine runs as root and can't reach the user's browser session; emit
        // the login URL for the front-end to open, then wait for the token the user
        // pastes (the `<token_cookie>` value after completing the IdP login).
        let cookie = if sso.token_cookie.is_empty() { "acSamlv2Token" } else { &sso.token_cookie };
        println!("# SAML-URL: {}", sso.login);
        let msg = format!(
            "Sign in in the browser tab, then paste the {cookie} cookie of {} (DevTools → Application/Storage → Cookies)",
            http::split_url(&sso.login).map(|(h, _, _)| h).unwrap_or_default()
        );
        println!("# AUTH-PROMPT: sso: {}", auth::one_line(&msg));
        let _ = std::io::stdout().flush();
        let raw = read_secret("SSO token: ").ok_or("SSO token required but none provided")?;
        clean_sso_token(&raw, cookie).ok_or("SSO token required but none provided".into())
    }

    fn info(&mut self, line: &str) {
        println!("# {line}");
    }
}

/// Normalize a pasted SSO token: accept the bare value or a `name=value[; …]`
/// copied from DevTools / a Cookie header, with stray quotes/whitespace.
fn clean_sso_token(raw: &str, cookie: &str) -> Option<String> {
    let mut t = raw.trim();
    // `acSamlv2Token=VALUE; other=…` → VALUE (the cookie may sit anywhere in a header).
    if !cookie.is_empty() {
        if let Some(v) = t.split(';').map(str::trim).find_map(|kv| kv.strip_prefix(cookie)?.strip_prefix('=')) {
            t = v;
        }
    }
    let t = t.trim().trim_matches('"').trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Read one line from stdin, with echo off on a TTY (restored after). The GUI
/// pipes answers here; a TTY user types them.
fn read_secret(prompt: &str) -> Option<String> {
    let fd = libc::STDIN_FILENO;
    let is_tty = unsafe { libc::isatty(fd) == 1 };
    if is_tty {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
    }
    let _echo = if is_tty { Some(crate::sysnet::EchoOff::new()) } else { None };
    match crate::sysnet::stdin_next(None) {
        crate::sysnet::StdinEvent::Line(l) => {
            let t = l.trim_end_matches(['\n', '\r']).to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_connect() {
        let a = parse_args(&[
            "-g".into(),
            "https://vpn.example.com/GRP".into(),
            "-u".into(),
            "alice".into(),
            "--group".into(),
            "Employees".into(),
            "--connect".into(),
        ])
        .unwrap();
        assert_eq!(a.url, "https://vpn.example.com/GRP");
        assert_eq!(a.user, "alice");
        assert_eq!(a.group.as_deref(), Some("Employees"));
        assert!(a.action == Action::Connect);
    }

    #[test]
    fn probe_needs_no_user() {
        assert!(parse_args(&["-g".into(), "https://gw".into(), "--probe".into()]).is_ok());
    }

    #[test]
    fn login_requires_user_or_sso() {
        assert!(parse_args(&["-g".into(), "https://gw".into(), "--login".into()]).is_err());
        assert!(parse_args(&["-g".into(), "https://gw".into(), "--sso-token".into(), "T".into()]).is_ok());
    }

    #[test]
    fn sso_needs_no_user() {
        let a = parse_args(&["-g".into(), "https://gw/G".into(), "--sso".into(), "--connect".into()]).unwrap();
        assert!(a.sso && a.user.is_empty() && a.action == Action::Connect);
    }

    #[test]
    fn sso_token_paste_is_normalized() {
        let c = "acSamlv2Token";
        assert_eq!(clean_sso_token("  ABC123 \n", c).as_deref(), Some("ABC123"));
        assert_eq!(clean_sso_token("acSamlv2Token=ABC123", c).as_deref(), Some("ABC123"));
        assert_eq!(clean_sso_token("webvpn=x; acSamlv2Token=ABC123; path=/", c).as_deref(), Some("ABC123"));
        assert_eq!(clean_sso_token("\"ABC123\"", c).as_deref(), Some("ABC123"));
        assert_eq!(clean_sso_token("   ", c), None);
    }

    #[test]
    fn gateway_required() {
        assert!(parse_args(&["-u".into(), "bob".into()]).is_err());
    }
}
