//! Fortinet FortiGate SSL-VPN back-end for unvpn.
//!
//! Native, from-scratch client for the FortiGate SSL-VPN protocol (the one
//! openfortivpn / openconnect speak), reverse-engineered from FortiClient
//! 7.4.3 for Linux. See docs/forti-protocol-notes.md.
//!
//! Subcommand: `unvpn forti -g <gw> -u <user> [...]`
//!   --probe      non-destructive reachability + auth-method detection (no creds)
//!   --login      authenticate (password + any 2FA step) and show the result
//!   --connect    authenticate, then bring up the PPP tunnel (needs sudo)       [F4]
//!   --saml       SSO/SAML login via the browser (auto-detected when no --user)   [F3]

pub mod auth;
pub mod config;
pub mod http;
pub mod ppp;
pub mod saml;
pub mod tunnel;

use crate::sysnet::{self, StdinEvent};
use auth::{AuthOutcome, Challenge, ChallengeKind, Session};
use std::io::{IsTerminal, Write};
use std::sync::mpsc;
use std::time::Duration;

const INFO_PATH: &str = "/remote/info";
const SAML_START: &str = "/remote/saml/start?redirect=1";

/// Parsed `unvpn forti` arguments.
struct Args {
    host: String,
    port: u16,
    user: String,
    realm: String,
    password: Option<String>,
    code: Option<String>,
    action: Action,
    /// Never trigger a FortiToken Mobile push; ask for the code instead.
    no_push: bool,
    no_dtls: bool,
    saml: bool,
    saml_port: Option<u16>,
    /// Don't open the browser (the GUI opens it from the `# SAML-URL:` marker).
    no_browser: bool,
    /// Tunnel up but no routes/DNS (safe data-plane test).
    no_routes: bool,
    /// Reuse the SVPNCOOKIE stored in this file instead of authenticating
    /// (like `openconnect --cookie`; a file, not argv, so `ps` can't see it).
    cookie_file: Option<String>,
    /// After authenticating, store the SVPNCOOKIE in this file (mode 0600).
    save_cookie: Option<String>,
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
    let mut no_push = false;
    let mut no_dtls = false;
    let mut saml = false;
    let mut saml_port = None;
    let mut no_browser = false;
    let mut no_routes = false;
    let mut cookie_file = None;
    let mut save_cookie = None;

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
            "--no-push" => no_push = true,
            "--no-dtls" => no_dtls = true,
            "--no-browser" => no_browser = true,
            "--no-routes" => no_routes = true,
            "--cookie-file" => cookie_file = Some(it.next().cloned().ok_or("--cookie-file needs a path")?),
            "--save-cookie" => save_cookie = Some(it.next().cloned().ok_or("--save-cookie needs a path")?),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    let host = host.ok_or("forti requires --gateway <host[:port]>")?;
    Ok(Args {
        host, port, user, realm, password, code, action, no_push, no_dtls, saml, saml_port, no_browser, no_routes,
        cookie_file, save_cookie,
    })
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  unvpn forti -g <host[:port]> --probe");
    eprintln!("  unvpn forti -g <host[:port]> -u <user> [--realm r] [--password p] [--code otp] [--no-push] --login");
    eprintln!("  unvpn forti -g <host[:port]> -u <user> [...] --connect     # brings up the tunnel (sudo)");
    eprintln!("  unvpn forti -g <host[:port]> [--saml] --connect            # SSO/SAML via browser");
    eprintln!("      [--realm r] [--saml-port n] [--no-browser]  (SAML is auto-detected without -u)");
    eprintln!("      [--no-routes]  tunnel up but install no routes/DNS (safe data-plane test)");
    eprintln!("      [--no-dtls]    stay on TLS even if the gateway offers DTLS (UDP)");
    eprintln!("      [--save-cookie f] store the SVPNCOOKIE (0600)   [--cookie-file f] reuse it, no login");
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
    if body.contains("fgt_lang") || body.contains("<api ") || server.to_ascii_lowercase().contains("forti") {
        println!("# looks like a FortiGate SSL-VPN portal");
    }
    let info = saml::parse_remote_info(&body);
    if info != saml::RemoteInfo::default() {
        println!(
            "# remote info: sso_port={} remoteauthtimeout={}",
            info.sso_port.map(|p| p.to_string()).unwrap_or("-".into()),
            info.auth_timeout.map(|t| format!("{t}s")).unwrap_or("-".into())
        );
    }

    match saml_idp(a) {
        Ok(Some(url)) => {
            let idp = url.split('/').nth(2).unwrap_or(&url);
            println!("# SAML/SSO is ENABLED → IdP {idp}");
            if info.sso_port.is_some() {
                println!("#   external-browser SSO supported (redirect back to 127.0.0.1:{})", info.sso_port.unwrap());
            }
            println!("#   (use: unvpn forti -g {}:{} --connect)", a.host, a.port);
        }
        Ok(None) => println!("# no SAML redirect (password/token auth path)"),
        Err(e) => println!("# SAML probe inconclusive: {e}"),
    }
    Ok(())
}

/// `Some(idp_url)` if `/remote/saml/start` sends the browser to an IdP.
fn saml_idp(a: &Args) -> Result<Option<String>, String> {
    let mut c = http::Cookies::new();
    let r = http::request(&a.host, a.port, "GET", SAML_START, &mut c, &[], b"", timeout())?;
    Ok(saml::idp_redirect(&r))
}

/// Most second-factor rounds one login may take (token → drift, challenge → renew, …).
const MAX_AUTH_ROUNDS: usize = 8;

/// Read the password: the GUI pipes it as the first stdin line; a TTY user types it
/// (echo off). Only a TTY gets the label: on the GUI's pipe it would glue itself to
/// the next stderr line and hide the "forti failed: …" the GUI looks for.
fn read_password() -> Option<String> {
    if std::io::stdin().is_terminal() {
        eprint!("Password: ");
        let _ = std::io::stderr().flush();
    }
    let _quiet = sysnet::EchoOff::new();
    match sysnet::stdin_next(None) {
        StdinEvent::Line(l) if !l.is_empty() && !sysnet::is_disconnect(&l) => Some(l),
        _ => None,
    }
}

/// Announce a mid-login question so the GUI can show a card for it:
/// `# AUTH-PROMPT: <kind>: <message>` (kinds: code, code2, answer, newpass, renew,
/// push). One stdin line answers it.
fn announce(kind: &str, msg: &str) {
    println!("# AUTH-PROMPT: {kind}: {}", auth::one_line(msg));
    let _ = std::io::stdout().flush();
}

/// One stdin line as the answer to a prompt: `disconnect`/EOF cancel, `deadline`
/// (the gateway's `to=`) times out.
fn answer_line(deadline: Option<Duration>) -> Result<String, String> {
    match sysnet::stdin_next(deadline) {
        StdinEvent::Line(l) if sysnet::is_disconnect(&l) => Err("authentication cancelled".into()),
        StdinEvent::Line(l) => Ok(l),
        StdinEvent::Eof => Err("authentication cancelled (stdin closed)".into()),
        StdinEvent::Timeout => Err(format!(
            "2FA timed out — the gateway allowed {}s; log in again",
            deadline.map(|d| d.as_secs().saturating_sub(5)).unwrap_or(0)
        )),
    }
}

/// Ask one question and wait for its answer line. Secrets come back verbatim (a
/// password may end in a space); codes are trimmed.
fn ask(kind: &str, msg: &str, deadline: Option<Duration>, secret: bool) -> Result<String, String> {
    announce(kind, msg);
    let tty = std::io::stdin().is_terminal();
    if tty {
        let label = match kind {
            "code2" => "Next code",
            "answer" => "Answer",
            "newpass" => "New password",
            "renew" => "New password (empty = keep the current one)",
            _ => "Code",
        };
        eprint!("{label}: ");
        let _ = std::io::stderr().flush();
    }
    let _quiet = (secret && tty).then(sysnet::EchoOff::new);
    let line = answer_line(deadline)?;
    Ok(if secret { line } else { line.trim().to_string() })
}

/// On a TTY, type the new password a second time before anything is sent (the GUI
/// card has its own confirm field, and the gateway can't catch a typo for us).
fn confirm_on_tty(new: &str, deadline: Option<Duration>) -> Result<(), String> {
    if !std::io::stdin().is_terminal() {
        return Ok(());
    }
    eprint!("Confirm new password: ");
    let _ = std::io::stderr().flush();
    let _quiet = sysnet::EchoOff::new();
    if answer_line(deadline)? == new {
        Ok(())
    } else {
        Err("the new passwords don't match — nothing was sent".into())
    }
}

/// The gateway's `to=` (seconds to answer) as a prompt deadline, with a little slack.
fn deadline(ch: &Challenge) -> Option<Duration> {
    ch.timeout.map(|t| Duration::from_secs(t + 5))
}

/// Authenticate with password + whatever second factor the gateway asks for:
/// FortiToken (code or push), email/SMS code, clock-drift next code, RADIUS
/// challenge, expired password. Shared by `--login` and `--connect`.
fn do_login(a: &Args) -> Result<Session, String> {
    let mut s = Session::new(a.host.clone(), a.port, a.realm.clone(), a.user.clone(), timeout());

    let password = match &a.password {
        Some(p) => p.clone(),
        None => read_password().ok_or("no password provided")?,
    };
    println!("# authenticating {} @ {}:{} (realm {:?}) …", a.user, a.host, a.port, a.realm);

    let mut outcome = s.login(&password)?;
    let mut preset = a.code.clone(); // --code answers the first code question only
    let mut last_code = String::new(); // the code a drift (ret=5) round must repeat
    let mut push_allowed = !a.no_push;
    // One extra pass only to look at the reply to the last answer we may send.
    for round in 0..=MAX_AUTH_ROUNDS {
        let ch = match outcome {
            AuthOutcome::Authenticated => {
                println!("# authenticated — SVPNCOOKIE acquired ({} bytes).", s.svpncookie().map(|c| c.len()).unwrap_or(0));
                return Ok(s);
            }
            AuthOutcome::Failed(msg) => return Err(msg),
            AuthOutcome::Challenge(ch) => ch,
        };
        if round == MAX_AUTH_ROUNDS {
            break;
        }
        if sysnet::stop_requested() {
            return Err("authentication cancelled".into());
        }
        let pushing = ch.kind == ChallengeKind::Token && ch.ftm_push && preset.is_none() && push_allowed;
        let msg = ch.prompt_text(pushing);
        println!("# gateway asks for {:?} (auth timeout {}s)", ch.kind, s.auth_budget.as_secs());
        outcome = match ch.kind {
            ChallengeKind::Token if pushing => match push_or_code(&mut s, &ch, &msg)? {
                PushEnd::Done(o, typed) => {
                    if let Some(c) = typed {
                        last_code = c;
                    }
                    o
                }
                PushEnd::Refused(why) => {
                    // Some gateways offer ftm_push and then refuse the push request
                    // (HTTP 405 — openfortivpn #947/#1019), which may also drop the
                    // pending login. Start over and ask for the code instead, which is
                    // what openfortivpn's --no-ftm-push workaround does.
                    println!("# FortiToken push refused ({why}) — logging in again to ask for the code");
                    push_allowed = false;
                    s.login(&password)?
                }
            },
            ChallengeKind::Token | ChallengeKind::Email | ChallengeKind::Sms => {
                let code = match preset.take() {
                    Some(c) => c,
                    None => ask("code", &msg, deadline(&ch), false)?,
                };
                if code.is_empty() {
                    return Err("2FA code required but none entered".into());
                }
                last_code = code.clone();
                s.answer_code(&ch, &code, "")?
            }
            ChallengeKind::Drift => {
                let next = ask("code2", &msg, deadline(&ch), false)?;
                if next.is_empty() {
                    return Err("the gateway needs the next token code (clock drift) but none was entered".into());
                }
                // The portal's order (login.js): code = the code already sent, code2 =
                // the next one. FortiClient's engine sends them the other way round;
                // the portal is the gateway's own form, so it is certainly accepted.
                let o = s.answer_code(&ch, &last_code, &next)?;
                last_code = next;
                o
            }
            ChallengeKind::Answer | ChallengeKind::HtmlAnswer => {
                // An OTP asked as a RADIUS challenge (ret=6 "please enter otp:") or on the
                // legacy SMS/RSA token page is still the first code question.
                let answer = match preset.take() {
                    Some(c) => c,
                    None => ask("answer", &msg, deadline(&ch), true)?,
                };
                last_code = answer.clone();
                s.answer(&ch, &answer)?
            }
            ChallengeKind::NewPassword | ChallengeKind::HtmlNewPassword => {
                let kind = if ch.allow_cancel { "renew" } else { "newpass" };
                let new = ask(kind, &msg, deadline(&ch), true)?;
                match (new.is_empty(), ch.allow_cancel) {
                    (true, true) => {
                        println!("# keeping the current password (skip)");
                        s.skip_renew(&ch)?
                    }
                    (true, false) => return Err("the password expired and no new one was entered".into()),
                    (false, _) => {
                        confirm_on_tty(&new, deadline(&ch))?;
                        s.answer(&ch, &new)?
                    }
                }
            }
        };
    }
    Err(format!("gave up after {MAX_AUTH_ROUNDS} authentication rounds"))
}

/// How a FortiToken Mobile push round ended.
enum PushEnd {
    /// The push (or a code typed meanwhile) produced this reply; the code, if typed.
    Done(AuthOutcome, Option<String>),
    /// The gateway refused the push itself — fall back to asking for the code.
    Refused(String),
}

/// FortiToken Mobile, the way the portal does it: fire the push right away (one
/// request the gateway holds open until the user approves on the phone) and
/// meanwhile accept a typed code — whichever comes first wins, and a typed code
/// aborts the in-flight push.
fn push_or_code(s: &mut Session, ch: &Challenge, msg: &str) -> Result<PushEnd, String> {
    announce("push", msg);
    println!("# FortiToken Mobile push sent — approve it on your phone (or type the code)");
    let cancel = http::Cancel::default();
    let (tx, rx) = mpsc::channel();
    {
        let (mut ps, ch, cancel) = (s.clone(), ch.clone(), cancel.clone());
        std::thread::spawn(move || {
            let r = ps.push(&ch, &cancel);
            let _ = tx.send((r, ps.cookies));
        });
    }
    loop {
        match rx.try_recv() {
            Ok((r, cookies)) => {
                s.cookies = cookies;
                return match r {
                    Ok(AuthOutcome::Failed(why)) => Ok(PushEnd::Refused(why)),
                    Ok(o) => Ok(PushEnd::Done(o, None)),
                    // Our own timeout: the user never approved. Not a refusal.
                    Err(e) if e.starts_with("FortiToken push not approved") => Err(e),
                    Err(e) => Ok(PushEnd::Refused(e)),
                };
            }
            // The push thread died without answering (it panicked): nothing will come.
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err("FortiToken push failed (internal error) — log in again, or use --no-push".into());
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        match sysnet::stdin_next(Some(Duration::from_millis(200))) {
            StdinEvent::Line(l) if sysnet::is_disconnect(&l) => {
                cancel.cancel();
                return Err("authentication cancelled".into());
            }
            StdinEvent::Line(l) if l.trim().is_empty() => {} // nothing typed — keep waiting
            StdinEvent::Line(code) => {
                cancel.cancel();
                // The push may have been approved while we read this line: it already
                // used up this login's reqid, so keep its session instead of the code.
                if let Ok((Ok(AuthOutcome::Authenticated), cookies)) = rx.recv_timeout(Duration::from_secs(2)) {
                    s.cookies = cookies;
                    return Ok(PushEnd::Done(AuthOutcome::Authenticated, None));
                }
                println!("# code entered — dropping the push");
                let code = code.trim().to_string();
                let o = s.answer_code(ch, &code, "")?;
                return Ok(PushEnd::Done(o, Some(code)));
            }
            StdinEvent::Eof => {
                cancel.cancel();
                return Err("authentication cancelled (stdin closed)".into());
            }
            StdinEvent::Timeout => {}
        }
    }
}

/// Authenticate by the selected method (SAML/SSO or password+2FA). Without
/// `--user` or `--saml`, ask the gateway: SSO if it redirects to an IdP.
fn authenticate(a: &Args) -> Result<Session, String> {
    if let Some(path) = &a.cookie_file {
        let v = std::fs::read_to_string(path).map_err(|e| format!("--cookie-file {path}: {e}"))?;
        let v = v.trim().trim_start_matches("SVPNCOOKIE=");
        if v.is_empty() {
            return Err(format!("--cookie-file {path} is empty"));
        }
        let mut s = Session::new(a.host.clone(), a.port, a.realm.clone(), a.user.clone(), timeout());
        s.cookies.0.insert("SVPNCOOKIE".into(), v.to_string());
        println!("# reusing SVPNCOOKIE from {path} ({} bytes) — no login", v.len());
        return Ok(s);
    }
    let s = authenticate_fresh(a)?;
    if let (Some(path), Some(c)) = (&a.save_cookie, s.svpncookie()) {
        use std::os::unix::fs::OpenOptionsExt;
        let w = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, c.as_bytes()));
        match w {
            Ok(()) => println!("# SVPNCOOKIE saved to {path}"),
            Err(e) => println!("# could not save SVPNCOOKIE to {path}: {e}"),
        }
    }
    Ok(s)
}

fn authenticate_fresh(a: &Args) -> Result<Session, String> {
    let use_saml = a.saml
        || (a.user.is_empty() && {
            match saml_idp(a) {
                Ok(Some(url)) => {
                    println!("# gateway uses SAML/SSO (IdP {}) — signing in with the browser", url.split('/').nth(2).unwrap_or(""));
                    true
                }
                Ok(None) => return Err("no --user given and the gateway has no SAML/SSO — pass -u <user>".into()),
                Err(e) => return Err(format!("no --user given and SAML detection failed: {e}")),
            }
        });
    if use_saml {
        let opts = saml::SamlOpts { port: a.saml_port, open_browser: !a.no_browser };
        let s = saml::login(&a.host, a.port, &a.realm, &opts)?;
        println!("# SAML authenticated — SVPNCOOKIE acquired ({} bytes).", s.svpncookie().map(|c| c.len()).unwrap_or(0));
        Ok(s)
    } else {
        do_login(a)
    }
}

/// Authenticate and bring up the PPP tunnel. Needs root.
fn connect(a: &Args) -> Result<(), String> {
    let mut session = authenticate(a)?;
    if sysnet::stop_requested() {
        return Err("disconnect requested — not bringing the tunnel up".into());
    }
    tunnel::run(&mut session, a.no_dtls, a.no_routes)
}
