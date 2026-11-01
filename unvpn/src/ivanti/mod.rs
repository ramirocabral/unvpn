//! Ivanti Connect Secure (Pulse) back-end for unvpn.
//!
//! Native client for the SSL-VPN spoken by Ivanti Connect Secure gateways
//! (formerly Pulse Connect Secure): web login over HTTPS that yields a `DSID`
//! session cookie, then the IF-T/TLS data plane with ESP-over-UDP as the fast
//! path. Login works; the data-plane handshake is still a skeleton (see
//! [`tunnel`]).

pub mod auth;
pub mod config;
pub mod http;
pub mod ift;
pub mod tunnel;

use auth::{Creds, IvantiError, Prompter, Session};
use http::Endpoint;
use std::io::Write;
use std::time::Duration;

/// Default sign-in policy URL segment.
const DEFAULT_URL: &str = "url_default";

struct Args {
    host: String,
    url: String,
    user: String,
    password: Option<String>,
    code: Option<String>,
    realm: Option<String>,
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
        eprintln!("ivanti failed: {e}");
        std::process::exit(1);
    }
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut host = None;
    let mut url = DEFAULT_URL.to_string();
    let mut user = String::new();
    let mut password = None;
    let mut code = None;
    let mut realm = None;
    let mut user_agent = http::USER_AGENT.to_string();
    let mut action = Action::Login;
    let (mut no_routes, mut no_esp) = (false, false);

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" | "--host" => host = it.next().cloned(),
            "--url" | "--sign-in" => url = it.next().cloned().ok_or("--url needs a value")?,
            "--user" | "-u" => user = it.next().cloned().ok_or("--user needs a value")?,
            "--password" | "-p" => password = it.next().cloned(),
            "--code" | "--otp" => code = it.next().cloned(),
            "--realm" | "-r" => realm = it.next().cloned(),
            "--user-agent" => user_agent = it.next().cloned().ok_or("--user-agent needs a value")?,
            "--probe" => action = Action::Probe,
            "--login" => action = Action::Login,
            "--connect" => action = Action::Connect,
            "--no-routes" => no_routes = true,
            "--no-esp" | "--no-udp" => no_esp = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let host = host.ok_or("ivanti requires --gateway <host>")?;
    if action != Action::Probe && user.is_empty() {
        return Err("ivanti requires --user <user>".into());
    }
    Ok(Args { host, url, user, password, code, realm, user_agent, action, no_routes, no_esp })
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  unvpn ivanti -g <host> --probe                       # is this an Ivanti/Pulse gateway?");
    eprintln!("  unvpn ivanti -g <host> -u <user> [--realm R] --login # authenticate, get a DSID");
    eprintln!("  unvpn ivanti -g <host> -u <user> [...] --connect     # bring up the tunnel (sudo)");
    eprintln!("      [--url url_<policy>]  sign-in policy URL segment (default: url_default)");
    eprintln!("      [--password p] [--code otp] [--realm R]");
    eprintln!("      [--no-esp]            IF-T/TLS data path only (no UDP/ESP)");
    eprintln!("      [--no-routes]         tunnel up but install no routes/DNS");
    eprintln!("  password/OTP are read from stdin (no echo) when not given on the command line");
}

fn make_session(a: &Args) -> Result<Session, String> {
    let (host, port, _) = http::split_url(&a.host)?;
    let ep = Endpoint { host, port, user_agent: a.user_agent.clone(), timeout: Duration::from_secs(20) };
    Ok(Session::new(ep, &a.url))
}

/// Unauthenticated: does the host look like an Ivanti/Pulse gateway?
fn probe(a: &Args) -> Result<(), String> {
    let mut s = make_session(a)?;
    println!("# probing {} …", s.ep.base_url());
    let pre = s.prelogin().map_err(|e| e.to_string())?;
    println!("# {} is an Ivanti Connect Secure (Pulse) sign-in page", s.ep.host_header());
    println!("#   fields: {} / {}", pre.user_label, pre.pass_label);
    if pre.realms.is_empty() {
        println!("#   → unvpn ivanti -g {} -u <user> --connect", a.host);
    } else {
        println!("#   realms: {}", pre.realms.join(", "));
        println!("#   → unvpn ivanti -g {} -u <user> --realm <realm> --connect", a.host);
    }
    Ok(())
}

fn do_login(a: &Args) -> Result<Session, String> {
    let mut s = make_session(a)?;
    println!("# authenticating {} @ {} …", a.user, s.ep.base_url());
    let creds = Creds { user: a.user.clone(), password: a.password.clone() };
    let mut p = CliPrompter { code: a.code.clone() };
    s.login(&creds, a.realm.as_deref(), &mut p).map_err(|e: IvantiError| e.to_string())?;
    let dsid = s.dsid.clone().ok_or("login returned no DSID")?;
    println!("# authenticated — DSID session established on {}", s.ep.host_header());
    println!("# DSID={}…", &dsid[..dsid.len().min(8)]);
    Ok(s)
}

/// Needs root.
fn connect(a: &Args) -> Result<(), String> {
    let mut s = do_login(a)?;
    tunnel::run(&mut s, tunnel::RunOpts { no_routes: a.no_routes, no_esp: a.no_esp, watch_stdin: true })
}

struct CliPrompter {
    code: Option<String>,
}

impl Prompter for CliPrompter {
    fn password(&mut self, label: &str) -> Result<String, String> {
        println!("# AUTH-PROMPT: answer: {label}");
        let _ = std::io::stdout().flush();
        crate::anyconnect::read_secret(&format!("{label}: ")).ok_or_else(|| "no password provided".into())
    }

    fn challenge(&mut self, message: &str) -> Result<String, String> {
        if let Some(c) = self.code.take() {
            return Ok(c);
        }
        let msg = if message.trim().is_empty() { "Enter the verification code" } else { message };
        println!("# AUTH-PROMPT: code: {msg}");
        let _ = std::io::stdout().flush();
        crate::anyconnect::read_secret("Code: ").ok_or_else(|| "verification code required but none provided".into())
    }

    fn info(&mut self, line: &str) {
        println!("# {line}");
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
        let a = args(&["-g", "vpn.example.com", "-u", "alice", "--realm", "Users", "--no-esp", "--connect"]).unwrap();
        assert_eq!((a.host.as_str(), a.user.as_str(), a.realm.as_deref()), ("vpn.example.com", "alice", Some("Users")));
        assert!(a.no_esp && a.action == Action::Connect && a.url == DEFAULT_URL);
    }

    #[test]
    fn custom_sign_in_url() {
        let a = args(&["-g", "vpn.example.com", "-u", "bob", "--url", "url_corp", "--login"]).unwrap();
        assert_eq!(a.url, "url_corp");
    }

    #[test]
    fn user_required_unless_probe() {
        assert!(args(&["-g", "vpn.example.com", "--connect"]).is_err());
        assert!(args(&["-g", "vpn.example.com", "--probe"]).is_ok());
        assert!(args(&["-u", "alice"]).is_err());
    }
}
