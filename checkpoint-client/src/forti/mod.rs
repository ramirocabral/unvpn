//! Fortinet FortiGate SSL-VPN back-end for cpvpn.
//!
//! Native, from-scratch client for the FortiGate SSL-VPN protocol (the one
//! openfortivpn / openconnect speak), reverse-engineered from FortiClient
//! 7.4.3 for Linux. See docs/forti-protocol-notes.md.
//!
//! Subcommand: `cpvpn forti -g <gw> -u <user> [...]`
//!   --probe      non-destructive reachability + auth-method detection (no creds)
//!   --login      authenticate (password + optional 2FA) and show the result
//!   --connect    authenticate, then bring up the PPP tunnel (needs sudo)       [F4]
//!   --saml       SSO/SAML login via the browser                                 [F3]

pub mod auth;
pub mod config;
pub mod http;
pub mod ppp;
pub mod saml;
pub mod tunnel;

use auth::{AuthOutcome, Session};
use std::io::Write;
use std::time::Duration;

const INFO_PATH: &str = "/remote/info";
const SAML_START: &str = "/remote/saml/start?redirect=1";

/// Parsed `cpvpn forti` arguments.
struct Args {
    host: String,
    port: u16,
    user: String,
    realm: String,
    password: Option<String>,
    code: Option<String>,
    action: Action,
    push: bool,
    no_dtls: bool,
    saml: bool,
    saml_port: Option<u16>,
}

#[derive(PartialEq)]
enum Action {
    Probe,
    Login,
    Connect,
}

pub fn cmd_forti(args: &[String]) {
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
        Action::Login => authenticate(&parsed).map(|_| ()),
        Action::Connect => connect(&parsed),
    };
    if let Err(e) = r {
        eprintln!("forti failed: {e}");
        std::process::exit(1);
    }
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut host: Option<String> = None;
    let mut port = 443u16;
    let mut user = String::new();
    let mut realm = String::new();
    let mut password = None;
    let mut code = None;
    let mut action = Action::Login;
    let mut push = false;
    let mut no_dtls = false;
    let mut saml = false;
    let mut saml_port = None;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" => {
                let v = it.next().ok_or("--gateway needs a value")?;
                // host[:port]
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
            "--realm" | "-r" => realm = it.next().cloned().unwrap_or_default(),
            "--password" | "-p" => password = it.next().cloned(),
            "--code" | "--otp" => code = it.next().cloned(),
            "--probe" => action = Action::Probe,
            "--login" => action = Action::Login,
            "--connect" => action = Action::Connect,
            "--saml" => saml = true,
            "--saml-port" => saml_port = it.next().and_then(|s| s.parse().ok()),
            "--push" => push = true,
            "--no-dtls" => no_dtls = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let host = host.ok_or("forti requires --gateway <host[:port]>")?;
    if action != Action::Probe && !saml && user.is_empty() {
        return Err("forti requires --user <user> (password auth) or --saml".into());
    }
    Ok(Args { host, port, user, realm, password, code, action, push, no_dtls, saml, saml_port })
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  cpvpn forti -g <host[:port]> --probe");
    eprintln!("  cpvpn forti -g <host[:port]> -u <user> [--realm r] [--password p] [--code otp] --login");
    eprintln!("  cpvpn forti -g <host[:port]> -u <user> [...] --connect     # brings up the tunnel (sudo)");
    eprintln!("  cpvpn forti -g <host[:port]> --saml --connect              # SSO/SAML via browser");
}

fn timeout() -> Duration {
    Duration::from_secs(20)
}

/// Non-destructive probe: confirm it's a FortiGate SSL-VPN and detect whether
/// SAML SSO is configured. Sends no credentials.
fn probe(a: &Args) -> Result<(), String> {
    let mut cookies = http::Cookies::new();
    println!("# probing {}:{} …", a.host, a.port);
    let resp = http::request(&a.host, a.port, "GET", INFO_PATH, &mut cookies, &[], b"", timeout())?;
    let server = resp.header("server").unwrap_or("(no Server header)");
    println!("# GET {INFO_PATH} → HTTP {} · Server: {server}", resp.status);
    let body = resp.body_str();
    if body.contains("fgt_lang") || body.contains("sslvpn") || server.to_ascii_lowercase().contains("forti") {
        println!("# looks like a FortiGate SSL-VPN portal ✓");
    }

    // SAML detection: a 3xx with a Location to an IdP means SSO is configured.
    let mut c2 = http::Cookies::new();
    match http::request(&a.host, a.port, "GET", SAML_START, &mut c2, &[], b"", timeout()) {
        Ok(r) if (300..400).contains(&r.status) => {
            if let Some(loc) = r.location() {
                let idp = loc.split('/').nth(2).unwrap_or(loc);
                println!("# SAML/SSO is ENABLED → IdP redirect to {idp}");
                println!("#   (use: cpvpn forti -g {}:{} --saml --connect)", a.host, a.port);
            } else {
                println!("# SAML endpoint redirected (SSO likely enabled)");
            }
        }
        Ok(r) => println!("# SAML endpoint → HTTP {} (password/token auth path)", r.status),
        Err(e) => println!("# SAML probe inconclusive: {e}"),
    }
    Ok(())
}

/// Read one line from stdin (the GUI pipes secrets here; a TTY user types them).
fn read_stdin_line(prompt: &str) -> Option<String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => {
            let t = line.trim_end_matches(['\n', '\r']).to_string();
            if t.is_empty() { None } else { Some(t) }
        }
        Err(_) => None,
    }
}

/// Authenticate with password (+ 2FA). Returns the authenticated session.
/// Shared by `--login` and `--connect`.
fn do_login(a: &Args) -> Result<Session, String> {
    let mut s = Session::new(a.host.clone(), a.port, a.realm.clone(), a.user.clone(), timeout());

    let password = match &a.password {
        Some(p) => p.clone(),
        None => read_stdin_line("Password: ").ok_or("no password provided")?,
    };
    println!("# authenticating {} @ {}:{} (realm {:?}) …", a.user, a.host, a.port, a.realm);

    let mut outcome = s.login(&password, a.push)?;
    // 2FA loop: answer challenges until authenticated or failed.
    loop {
        match outcome {
            AuthOutcome::Authenticated => {
                println!("# ✅ authenticated — SVPNCOOKIE acquired ({} bytes).", s.svpncookie().map(|c| c.len()).unwrap_or(0));
                return Ok(s);
            }
            AuthOutcome::Failed(msg) => return Err(msg),
            AuthOutcome::Challenge(ch) => {
                if !ch.message.is_empty() {
                    println!("# gateway 2FA prompt: {}", ch.message);
                }
                if !ch.tokeninfo.is_empty() {
                    println!("# gateway token info: {}", ch.tokeninfo);
                }
                if ch.ftm_push && a.push {
                    println!("# FortiToken push sent — approve it in the app …");
                    outcome = poll_push_until(&mut s, &ch)?;
                    continue;
                }
                let code = match a.code.clone() {
                    Some(c) => c,
                    None => read_stdin_line("Token code: ").ok_or("2FA required but no code provided")?,
                };
                outcome = s.answer_challenge(&ch, &code, "")?;
            }
        }
    }
}

/// Poll a FortiToken Mobile push up to ~60s. Re-posts the 2FA form with an empty
/// code; the gateway keeps returning `ret=2` until the user approves, then sets
/// the cookie.
fn poll_push_until(s: &mut Session, ch: &auth::Challenge) -> Result<AuthOutcome, String> {
    for _ in 0..30 {
        std::thread::sleep(Duration::from_secs(2));
        match s.answer_challenge(ch, "", "")? {
            AuthOutcome::Challenge(_) => continue, // still pending
            other => return Ok(other),
        }
    }
    Err("FortiToken push not approved in time".into())
}

/// Authenticate by the selected method (SAML/SSO or password+2FA).
fn authenticate(a: &Args) -> Result<Session, String> {
    if a.saml {
        let s = saml::login(&a.host, a.port, &a.realm, a.saml_port, true)?;
        println!("# ✅ SAML authenticated — SVPNCOOKIE acquired.");
        Ok(s)
    } else {
        do_login(a)
    }
}

/// Authenticate and bring up the PPP tunnel. Needs root.
fn connect(a: &Args) -> Result<(), String> {
    let mut session = authenticate(a)?;
    tunnel::run(&mut session, a.no_dtls)
}
