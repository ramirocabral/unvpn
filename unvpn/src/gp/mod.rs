//! Palo Alto Networks GlobalProtect back-end for unvpn.
//!
//! Native client for the GlobalProtect SSL-VPN as spoken by PAN-OS firewalls and
//! Prisma Access: portal/gateway login over HTTPS form posts, then the data plane
//! over ESP-in-UDP (keys delivered in the config, no IKE) with the SSL tunnel as
//! fallback, plus the HIP posture report. Interoperable with openconnect's `gp`
//! protocol (`auth-globalprotect.c`, `gpst.c`), which documents the wire format.

pub mod auth;
pub mod config;
pub mod hip;
pub mod http;
pub mod tunnel;

use auth::{Creds, GpError, Prompter, Role, Saml, SamlResult, Session};
use http::Endpoint;
use std::io::Write;
use std::time::Duration;

/// `app-version` when the portal didn't tell us its own (openconnect's default).
pub const DEFAULT_APP_VERSION: &str = "6.3.0-33";
const CLIENT_OS: &str = "Linux";
const OS_VERSION: &str = "linux-64";

struct Args {
    host: String,
    user: String,
    password: Option<String>,
    code: Option<String>,
    gw: Option<String>,
    role: Role,
    saml: bool,
    saml_cookie: Option<String>,
    user_agent: String,
    action: Action,
    no_routes: bool,
    no_esp: bool,
    no_hip: bool,
}

#[derive(PartialEq)]
enum Action {
    Probe,
    Login,
    Connect,
}

pub fn cmd_gp(args: &[String]) {
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
        eprintln!("globalprotect failed: {e}");
        std::process::exit(1);
    }
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut host = None;
    let mut user = String::new();
    let mut password = None;
    let mut code = None;
    let mut gw = None;
    let mut role = None;
    let mut saml = false;
    let mut saml_cookie = None;
    let mut user_agent = http::USER_AGENT.to_string();
    let mut action = Action::Login;
    let (mut no_routes, mut no_esp, mut no_hip) = (false, false, false);

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" | "--portal" => host = it.next().cloned(),
            "--user" | "-u" => user = it.next().cloned().ok_or("--user needs a value")?,
            "--password" | "-p" => password = it.next().cloned(),
            "--code" | "--otp" => code = it.next().cloned(),
            "--gw" | "--select" => gw = it.next().cloned(),
            "--as-portal" => role = Some(Role::Portal),
            "--as-gateway" => role = Some(Role::Gateway),
            "--saml" | "--sso" => saml = true,
            "--saml-cookie" => saml_cookie = it.next().cloned(),
            "--user-agent" => user_agent = it.next().cloned().ok_or("--user-agent needs a value")?,
            "--probe" => action = Action::Probe,
            "--login" => action = Action::Login,
            "--connect" => action = Action::Connect,
            "--no-routes" => no_routes = true,
            "--no-esp" | "--no-udp" => no_esp = true,
            "--no-hip" => no_hip = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let host = host.ok_or("gp requires --gateway <portal-or-gateway>")?;
    let (_, _, path) = http::split_url(&host)?;
    // openconnect-style hint in the URL path: /global-protect = portal, /ssl-vpn = gateway.
    let role = role.unwrap_or(if path.starts_with("/global-protect") || path == "/portal" {
        Role::Portal
    } else if path.starts_with("/ssl-vpn") || path == "/gateway" {
        Role::Gateway
    } else {
        Role::Auto
    });
    if action != Action::Probe && user.is_empty() && !saml && saml_cookie.is_none() {
        return Err("gp requires --user <user> (or --saml for SAML/SSO)".into());
    }
    Ok(Args { host, user, password, code, gw, role, saml, saml_cookie, user_agent, action, no_routes, no_esp, no_hip })
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  unvpn gp -g <portal-or-gateway> --probe");
    eprintln!("  unvpn gp -g <host> -u <user> [--password p] [--code otp] [--gw <gateway>] --login");
    eprintln!("  unvpn gp -g <host> -u <user> [...] --connect     # brings up the tunnel (sudo)");
    eprintln!("      [--gw G]          pick the portal's gateway by host or label (default: preferred)");
    eprintln!("      [--as-portal | --as-gateway]  skip role detection");
    eprintln!("  unvpn gp -g <host> --saml --connect             # SAML: browser login, paste the result");
    eprintln!("      [--saml-cookie C] supply the prelogin-cookie / globalprotectcallback: URL");
    eprintln!("      [--no-esp]        SSL tunnel only (no UDP/ESP)");
    eprintln!("      [--no-hip]        don't answer the HIP posture check");
    eprintln!("      [--no-routes]     tunnel up but install no routes/DNS (safe data-plane test)");
    eprintln!("  password/OTP are read from stdin (no echo) when not given with --password/--code");
}

fn make_session(a: &Args) -> Result<Session, String> {
    let (host, port, _) = http::split_url(&a.host)?;
    let ep = Endpoint { host, port, user_agent: a.user_agent.clone(), timeout: Duration::from_secs(20) };
    Ok(Session::new(ep, CLIENT_OS, OS_VERSION, &local_hostname()))
}

/// Unauthenticated: is the host a portal or a gateway, and how does it log in?
fn probe(a: &Args) -> Result<(), String> {
    let mut s = make_session(a)?;
    println!("# probing {} …", s.portal_ep.base_url());
    for (portal, role) in [(true, "portal"), (false, "gateway")] {
        if (portal && a.role == Role::Gateway) || (!portal && a.role == Role::Portal) {
            continue;
        }
        match s.prelogin(portal) {
            Ok(pre) => {
                println!("# {} is a GlobalProtect {role}", s.portal_ep.host_header());
                if !pre.message.is_empty() {
                    println!("#   message: {}", one_line(&pre.message));
                }
                if let Some(r) = &pre.region {
                    println!("#   region: {r}");
                }
                match &pre.saml {
                    Some(saml) => {
                        println!("#   SAML ({}) login", saml.method);
                        println!("#   → unvpn gp -g {} --saml --connect", a.host);
                    }
                    None => {
                        println!("#   fields: {} / {}", or(&pre.user_label, "Username"), or(&pre.pass_label, "Password"));
                        println!("#   → unvpn gp -g {} -u <user> --connect", a.host);
                    }
                }
                return Ok(());
            }
            Err(GpError::NotHere(m)) => println!("#   not a {role} ({m})"),
            Err(e) => return Err(format!("{role} prelogin: {e}")),
        }
    }
    Err("the host is neither a GlobalProtect portal nor a gateway".into())
}

fn or<'a>(s: &'a str, d: &'a str) -> &'a str {
    if s.is_empty() {
        d
    } else {
        s
    }
}

fn do_login(a: &Args) -> Result<Session, String> {
    let mut s = make_session(a)?;
    let who = if a.user.is_empty() { "<SAML>" } else { &a.user };
    println!("# authenticating {who} @ {} …", s.portal_ep.base_url());
    let creds = Creds { user: a.user.clone(), password: a.password.clone() };
    let mut p = CliPrompter { code: a.code.clone(), saml_cookie: a.saml_cookie.clone(), saml_only: a.saml, password_asked: false };
    s.login(&creds, a.role, a.gw.as_deref(), &mut p)?;
    let auth = s.auth.as_ref().ok_or("login returned no session")?;
    println!("# authenticated — GlobalProtect session for {} on {}", auth.user, s.ep.host_header());
    if !auth.portal.is_empty() {
        println!("# gateway config: {}", auth.portal);
    }
    Ok(s)
}

/// Needs root.
fn connect(a: &Args) -> Result<(), String> {
    let mut s = do_login(a)?;
    tunnel::run(&mut s, tunnel::RunOpts { no_routes: a.no_routes, watch_stdin: true, no_esp: a.no_esp, no_hip: a.no_hip })
}

/// Reads secrets from stdin (no echo on a TTY) and emits the `# AUTH-PROMPT:` /
/// `# SAML-URL:` markers the GUI understands.
struct CliPrompter {
    code: Option<String>,
    saml_cookie: Option<String>,
    /// `--saml` without a password: a password form is a mismatch.
    saml_only: bool,
    /// The first password comes queued on stdin (GUI) or typed at the TTY; a later
    /// one (after a rejection) needs a prompt the GUI can show.
    password_asked: bool,
}

impl Prompter for CliPrompter {
    fn username(&mut self, label: &str) -> Result<String, String> {
        println!("# AUTH-PROMPT: username: {}", one_line(label));
        let _ = std::io::stdout().flush();
        crate::anyconnect::read_secret(&format!("{label}: ")).ok_or_else(|| "username required".into())
    }

    fn password(&mut self, label: &str, _message: &str) -> Result<String, String> {
        if self.saml_only {
            return Err("the server asked for a password, not SAML — use password auth (-u <user>)".into());
        }
        if std::mem::replace(&mut self.password_asked, true) {
            println!("# AUTH-PROMPT: answer: {} (the previous one was rejected)", one_line(label));
            let _ = std::io::stdout().flush();
        }
        crate::anyconnect::read_secret(&format!("{label}: ")).ok_or_else(|| "no password provided".into())
    }

    fn challenge(&mut self, message: &str) -> Result<String, String> {
        if let Some(c) = self.code.take() {
            return Ok(c);
        }
        let msg = if message.trim().is_empty() { "Enter the verification code" } else { message };
        println!("# AUTH-PROMPT: code: {}", one_line(msg));
        let _ = std::io::stdout().flush();
        crate::anyconnect::read_secret("Code: ").ok_or_else(|| "verification code required but none provided".into())
    }

    fn saml(&mut self, saml: &Saml) -> Result<SamlResult, String> {
        if let Some(c) = self.saml_cookie.take() {
            return auth::parse_saml_result(&c).ok_or_else(|| "empty --saml-cookie".into());
        }
        // For a front-end with an embedded browser: the login result arrives as
        // response headers of the final page, not as a cookie.
        println!("# SAML-HEADERS: saml-username prelogin-cookie portal-userauthcookie");
        println!("# SAML-URL: {}", saml.url);
        println!(
            "# AUTH-PROMPT: sso: Sign in in the browser, then paste the globalprotectcallback: link it tries to open (or the prelogin-cookie)"
        );
        let _ = std::io::stdout().flush();
        let raw = crate::anyconnect::read_secret("SAML result: ").ok_or("SAML result required but none provided")?;
        auth::parse_saml_result(&raw).ok_or_else(|| "could not read a SAML result from the input".into())
    }

    fn info(&mut self, line: &str) {
        println!("# {line}");
    }
}

/// Gateway text flattened to one line (markers and logs are line-based).
pub fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn local_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Result<Args, String> {
        parse_args(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn connect_args() {
        let a = args(&["-g", "vpn.example.com", "-u", "alice", "--gw", "gw-b", "--no-esp", "--connect"]).unwrap();
        assert_eq!((a.host.as_str(), a.user.as_str(), a.gw.as_deref()), ("vpn.example.com", "alice", Some("gw-b")));
        assert!(a.no_esp && a.action == Action::Connect && a.role == Role::Auto);
    }

    #[test]
    fn role_from_path_hint() {
        assert_eq!(args(&["-g", "https://vpn.example.com/global-protect", "--probe"]).unwrap().role, Role::Portal);
        assert_eq!(args(&["-g", "vpn.example.com/ssl-vpn", "--probe"]).unwrap().role, Role::Gateway);
        assert_eq!(args(&["-g", "vpn.example.com", "--as-gateway", "--probe"]).unwrap().role, Role::Gateway);
    }

    #[test]
    fn user_or_saml_required() {
        assert!(args(&["-g", "gw", "--connect"]).is_err());
        assert!(args(&["-g", "gw", "--saml", "--connect"]).is_ok());
        assert!(args(&["-g", "gw", "--probe"]).is_ok());
        assert!(args(&["-u", "bob"]).is_err());
    }
}
