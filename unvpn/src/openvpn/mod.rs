//! OpenVPN (2.x protocol) back-end for unvpn.
//!
//! A from-scratch, native client for the OpenVPN protocol — no `openvpn` binary,
//! no plugin: control channel (reliability layer + TLS + key-method 2, with
//! `tls-auth`/`tls-crypt` wrapping), data channel (AES-GCM / ChaCha20-Poly1305
//! AEAD with P_DATA_V2, or legacy AES-CBC + HMAC), PUSH_REPLY configuration,
//! renegotiation and reconnection (OpenVPN 2.x protocol).
//!
//! Subcommand: `unvpn openvpn -c <profile.ovpn> [...]`
//!   --probe      reset + TLS handshake only (no credentials): checks reachability,
//!                the tls-auth/tls-crypt key and the server certificate
//!   --login      authenticate and print the pushed configuration (no tunnel)
//!   --connect    authenticate, then bring up the tunnel (needs root)

pub mod config;
pub mod crypto;
pub mod link;
pub mod packet;
pub mod push;
pub mod session;
pub mod tls;
pub mod tunnel;

use session::Creds;
use tunnel::Prompter as _;
use std::io::Write;
use std::path::PathBuf;

struct Args {
    config: PathBuf,
    user: Option<String>,
    password: Option<String>,
    code: Option<String>,
    key_pass: Option<String>,
    action: Action,
    no_routes: bool,
}

#[derive(PartialEq)]
enum Action {
    Probe,
    Login,
    Connect,
}

pub fn cmd_openvpn(args: &[String]) {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            usage();
            std::process::exit(2);
        }
    };
    if let Err(e) = run(&parsed) {
        eprintln!("openvpn failed: {e}");
        std::process::exit(1);
    }
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut a = Args { config: PathBuf::new(), user: None, password: None, code: None, key_pass: None, action: Action::Login, no_routes: false };
    let mut config = None;
    let mut it = args.iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "--config" | "-c" => config = it.next().cloned(),
            "--user" | "-u" => a.user = Some(it.next().cloned().ok_or("--user needs a value")?),
            "--password" | "-p" => a.password = it.next().cloned(),
            "--code" | "--otp" => a.code = it.next().cloned(),
            "--key-pass" => a.key_pass = it.next().cloned(),
            "--probe" => a.action = Action::Probe,
            "--login" => a.action = Action::Login,
            "--connect" => a.action = Action::Connect,
            "--no-routes" => a.no_routes = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    a.config = PathBuf::from(config.ok_or("openvpn requires --config <profile.ovpn>")?);
    Ok(a)
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  unvpn openvpn -c <profile.ovpn> --probe                 # reachability + TLS + server cert, no login");
    eprintln!("  unvpn openvpn -c <profile.ovpn> [-u user] --login       # authenticate, show the pushed config");
    eprintln!("  unvpn openvpn -c <profile.ovpn> [-u user] --connect     # bring up the tunnel (sudo)");
    eprintln!("      [--password p]  password (else read from stdin, no echo)");
    eprintln!("      [--code c]      static-challenge / OTP answer (else prompted)");
    eprintln!("      [--key-pass k]  passphrase of an encrypted private key / PKCS#12");
    eprintln!("      [--no-routes]   tunnel up but install no routes/DNS (safe data-plane test)");
}

fn run(a: &Args) -> Result<(), String> {
    let cfg = config::load(&a.config)?;
    let mut prompter = CliPrompter { code: a.code.clone() };

    let creds = if cfg.auth_user_pass && a.action != Action::Probe {
        let user = a.user.clone().or_else(|| cfg.auth_user.clone()).ok_or("this profile uses auth-user-pass: give --user <name>")?;
        let mut pass = match a.password.clone().or_else(|| cfg.auth_pass.clone()) {
            Some(p) => p,
            None => read_secret("Password: ").ok_or("no password provided")?,
        };
        if let Some((text, echo)) = &cfg.static_challenge {
            let resp = prompter.ask("code", text, *echo)?;
            pass = format!("SCRV1:{}:{}", b64(&pass), b64(&resp));
        }
        Some(Creds { user, pass })
    } else {
        None
    };

    // `keypass` prompts may be answered by the GUI from the keyring.
    let mut key_pass = a.key_pass.clone();
    if key_pass.is_none() && tls::key_is_encrypted(&cfg) {
        key_pass = Some(prompter.ask("keypass", "Private key passphrase", false)?);
    }
    let mut retries = 0;
    let prepared = loop {
        match tunnel::prepare(cfg.clone(), creds.clone(), key_pass.as_deref()) {
            Err(e) if (e == tls::NEEDS_PASS || e == tls::WRONG_PASS) && retries < 3 => {
                retries += 1;
                let msg = if key_pass.is_some() { "Wrong passphrase, try again" } else { "PKCS#12 / private key passphrase" };
                key_pass = Some(prompter.ask("keypass", msg, false).map_err(|_| e.clone())?);
            }
            r => break r?,
        }
    };

    match a.action {
        Action::Probe => tunnel::probe(&prepared),
        Action::Login => tunnel::run(prepared, &mut prompter, tunnel::RunOpts { no_routes: true, watch_stdin: false, login_only: true }),
        Action::Connect => tunnel::run(prepared, &mut prompter, tunnel::RunOpts { no_routes: a.no_routes, watch_stdin: true, login_only: false }),
    }
}

fn b64(s: &str) -> String {
    openssl::base64::encode_block(s.as_bytes())
}

/// CLI/GUI prompter: `# AUTH-PROMPT:` markers for the GUI, then a stdin line.
struct CliPrompter {
    code: Option<String>,
}

impl tunnel::Prompter for CliPrompter {
    fn ask(&mut self, kind: &str, message: &str, _echo: bool) -> Result<String, String> {
        if kind == "code" {
            if let Some(c) = self.code.take() {
                return Ok(c);
            }
        }
        let msg: String = message.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
        println!("# AUTH-PROMPT: {kind}: {msg}");
        let _ = std::io::stdout().flush();
        read_secret(&format!("{msg}: ")).ok_or_else(|| format!("{kind} required but none provided"))
    }

    fn open_url(&mut self, url: &str) {
        println!("# SAML-URL: {url}");
        let _ = std::io::stdout().flush();
    }
}

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
            (!t.is_empty()).then_some(t)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args() {
        let a = parse_args(&["-c".into(), "x.ovpn".into(), "-u".into(), "bob".into(), "--connect".into()]).unwrap();
        assert!(a.action == Action::Connect && a.user.as_deref() == Some("bob"));
        assert!(parse_args(&["--probe".into()]).is_err());
    }
}
