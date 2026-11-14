//! Ivanti Connect Secure (Pulse) back-end for unvpn.
//!
//! Native client for the SSL-VPN of Ivanti Connect Secure gateways (formerly
//! Pulse Connect Secure): EAP authentication inside IF-T/TLS on the sign-in URL,
//! which yields the `DSID` session cookie, then the tunnel on that same
//! connection, with ESP over UDP as the fast path.

pub mod auth;
pub mod config;
pub mod ift;
pub mod tunnel;

use crate::net::http::{self, Endpoint};
use auth::{Creds, Prompter, Session};
use ift::IftConn;
use std::time::Duration;

const USER_AGENT: &str = "Pulse-Secure/22.2.1.1295 (Linux) unvpn";

struct Args {
    host: String,
    user: String,
    password: Option<String>,
    code: Option<String>,
    realm: Option<String>,
    saml: bool,
    saml_cookie: Option<String>,
    user_agent: String,
    action: Action,
    no_routes: bool,
    no_esp: bool,
}

#[derive(PartialEq)]
enum Action {
    Probe,
    Login,
    Connect,
}

pub fn cmd_ivanti(args: &[String]) {
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
        crate::report::fail("ivanti", &e);
    }
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut host = None;
    let mut user = String::new();
    let mut password = None;
    let mut code = None;
    let mut realm = None;
    let mut saml = false;
    let mut saml_cookie = None;
    let mut user_agent = USER_AGENT.to_string();
    let mut action = Action::Login;
    let (mut no_routes, mut no_esp) = (false, false);

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" | "--host" => host = it.next().cloned(),
            "--user" | "-u" => user = it.next().cloned().ok_or("--user needs a value")?,
            "--password" | "-p" => password = it.next().cloned(),
            "--code" | "--otp" => code = it.next().cloned(),
            "--realm" | "-r" => realm = it.next().cloned().filter(|r| !r.trim().is_empty()),
            "--saml" | "--sso" => saml = true,
            "--saml-cookie" | "--dsid" => {
                saml_cookie = Some(it.next().cloned().ok_or("--saml-cookie needs a value")?);
                saml = true;
            }
            "--user-agent" => {
                user_agent = it.next().cloned().ok_or("--user-agent needs a value")?
            }
            "--probe" => action = Action::Probe,
            "--login" => action = Action::Login,
            "--connect" => action = Action::Connect,
            "--no-routes" => no_routes = true,
            "--no-esp" | "--no-udp" => no_esp = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let host = host.ok_or("ivanti requires --gateway <host or sign-in URL>")?;
    if action != Action::Probe && user.is_empty() && !saml {
        return Err("ivanti requires --user <user> (or --saml for SAML/SSO)".into());
    }
    Ok(Args {
        host,
        user,
        password,
        code,
        realm,
        saml,
        saml_cookie,
        user_agent,
        action,
        no_routes,
        no_esp,
    })
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  unvpn ivanti -g <host[/sign-in-path]> --probe       # what does the gateway ask?");
    eprintln!("  unvpn ivanti -g <host> -u <user> [--realm R] --login");
    eprintln!(
        "  unvpn ivanti -g <host> -u <user> [...] --connect     # brings up the tunnel (sudo)"
    );
    eprintln!("      [--password p] [--code otp] [--realm R]");
    eprintln!("  unvpn ivanti -g <host> --saml --connect              # SAML: browser login, paste the DSID cookie");
    eprintln!("      [--saml-cookie DSID]  supply the DSID cookie of a finished browser login");
    eprintln!("      [--no-esp]            IF-T/TLS data path only (no UDP/ESP)");
    eprintln!(
        "      [--no-routes]         tunnel up but install no routes/DNS (safe data-plane test)"
    );
    eprintln!("  password/OTP are read from stdin (no echo) when not given on the command line");
}

fn make_session(a: &Args) -> Result<Session, String> {
    let (host, port, path) = http::split_url(&a.host)?;
    let ep = Endpoint::new(&host, port, &a.user_agent, Duration::from_secs(20));
    Ok(Session::new(ep, &path))
}

/// Unauthenticated: is this an Ivanti gateway, and what does it ask first?
fn probe(a: &Args) -> Result<(), String> {
    let mut s = make_session(a)?;
    println!("# probing {}{} …", s.ep.base_url(), s.path);
    let pre = s.probe()?;
    println!(
        "# {} is an Ivanti Connect Secure gateway (IF-T/TLS v{})",
        s.ep.host_header(),
        pre.version
    );
    if let Some(b) = &pre.banner {
        println!("#   notice: {}", crate::sysnet::one_line(b));
    }
    if !pre.realms.is_empty() {
        println!("#   realms: {}", pre.realms.join(", "));
    }
    println!("#   asks for: {}", pre.asks);
    if pre.realms.len() > 1 {
        println!(
            "#   → unvpn ivanti -g {} -u <user> --realm <realm> --connect",
            a.host
        );
    } else {
        println!("#   → unvpn ivanti -g {} -u <user> --connect", a.host);
    }
    Ok(())
}

fn do_login(a: &Args) -> Result<(Session, IftConn), String> {
    let mut s = make_session(a)?;
    let conn = if a.saml {
        let dsid = match &a.saml_cookie {
            Some(c) => clean_dsid(c),
            None => saml_browser_login(&s)?,
        }
        .ok_or("no DSID cookie given")?;
        println!("# resuming the browser session @ {} …", s.ep.base_url());
        s.dsid = Some(dsid);
        s.resume().map_err(|e| match e.to_string() {
            m if m.contains(auth::COOKIE_REJECTED) => {
                "the gateway did not accept the DSID cookie — sign in again in the browser".into()
            }
            m => m,
        })?
    } else {
        println!(
            "# authenticating {} @ {}{} …",
            a.user,
            s.ep.base_url(),
            s.path
        );
        let creds = Creds {
            user: a.user.clone(),
            password: a.password.clone(),
            realm: a.realm.clone(),
        };
        let mut p = CliPrompter {
            code: a.code.clone(),
        };
        s.login(creds, &mut p)?
    };
    println!(
        "# authenticated — Ivanti session established on {}",
        s.ep.host_header()
    );
    Ok((s, conn))
}

/// Needs root.
fn connect(a: &Args) -> Result<(), String> {
    let (mut s, conn) = do_login(a)?;
    tunnel::run(
        &mut s,
        conn,
        tunnel::RunOpts {
            no_routes: a.no_routes,
            no_esp: a.no_esp,
            watch_stdin: true,
        },
    )
}

/// The engine runs as root without the user's browser: announce the sign-in URL
/// (and, for an embedded browser, where the flow ends and which cookie to read),
/// then wait for the DSID cookie.
fn saml_browser_login(s: &Session) -> Result<Option<String>, String> {
    let base = s.ep.base_url();
    crate::report::saml_final(&format!("{base}/dana/"));
    crate::report::saml_cookie("DSID");
    crate::report::saml_url(&format!("{base}{}", s.path));
    crate::report::prompt(
        "sso",
        &format!(
            "Sign in in the browser, then paste the DSID cookie of {} (DevTools → Application/Storage → Cookies)",
            s.ep.host_header()
        ),
    );
    let raw =
        crate::anyconnect::read_secret("DSID: ").ok_or("DSID cookie required but none provided")?;
    Ok(clean_dsid(&raw))
}

/// The bare value, from `DSID=…; other=…` or the value itself.
fn clean_dsid(raw: &str) -> Option<String> {
    let t = raw.trim();
    let v = t
        .split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix("DSID="))
        .unwrap_or(t)
        .trim_matches(|c: char| c == '"' || c.is_whitespace());
    (!v.is_empty()).then(|| v.to_string())
}

/// Reads secrets from stdin (no echo on a TTY) and emits the `# AUTH-PROMPT:`
/// markers the GUI understands.
struct CliPrompter {
    code: Option<String>,
}

impl Prompter for CliPrompter {
    fn password(&mut self, label: &str, retry: bool) -> Result<String, String> {
        // The first password comes queued on stdin (GUI) or typed at the TTY; a
        // later one needs a prompt the GUI can show.
        if retry {
            crate::report::prompt(
                "answer",
                &format!(
                    "{} (the previous one was rejected)",
                    crate::sysnet::one_line(label)
                ),
            );
        }
        crate::anyconnect::read_secret(&format!("{}: ", label.trim_end_matches(':')))
            .ok_or_else(|| "no password provided".into())
    }

    fn challenge(&mut self, message: &str) -> Result<String, String> {
        if let Some(c) = self.code.take() {
            return Ok(c);
        }
        let msg = if message.trim().is_empty() {
            "Enter the verification code"
        } else {
            message
        };
        crate::report::prompt("code", &crate::sysnet::one_line(msg));
        crate::anyconnect::read_secret("Code: ")
            .ok_or_else(|| "verification code required but none provided".into())
    }

    fn new_password(&mut self, message: &str) -> Result<String, String> {
        crate::report::prompt("newpass", message);
        crate::anyconnect::read_secret("New password: ")
            .ok_or_else(|| "a new password is required".into())
    }

    fn info(&mut self, line: &str) {
        crate::report::note(line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Result<Args, String> {
        parse_args(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn connect_args() {
        let a = args(&[
            "-g",
            "https://vpn.example.com/users",
            "-u",
            "alice",
            "--realm",
            "Users",
            "--no-esp",
            "--connect",
        ])
        .unwrap();
        assert_eq!(
            (a.host.as_str(), a.user.as_str(), a.realm.as_deref()),
            ("https://vpn.example.com/users", "alice", Some("Users"))
        );
        assert!(a.no_esp && a.action == Action::Connect && !a.saml);
        let s = make_session(&a).unwrap();
        assert_eq!(
            (s.ep.host.as_str(), s.path.as_str()),
            ("vpn.example.com", "/users")
        );
    }

    #[test]
    fn user_or_saml_required() {
        assert!(args(&["-g", "vpn.example.com", "--connect"]).is_err());
        assert!(args(&["-g", "vpn.example.com", "--saml", "--connect"]).is_ok());
        assert!(
            args(&["-g", "vpn.example.com", "--saml-cookie", "x", "--connect"])
                .unwrap()
                .saml
        );
        assert!(args(&["-g", "vpn.example.com", "--probe"]).is_ok());
        assert!(args(&["-u", "alice"]).is_err());
    }

    #[test]
    fn dsid_is_cleaned() {
        assert_eq!(clean_dsid(" abc123 ").as_deref(), Some("abc123"));
        assert_eq!(
            clean_dsid("DSSignInURL=/; DSID=abc123; path=/").as_deref(),
            Some("abc123")
        );
        assert_eq!(clean_dsid("  "), None);
    }
}
