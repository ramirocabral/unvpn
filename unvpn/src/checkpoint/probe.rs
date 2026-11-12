//! Diagnostics against a gateway: the CCC hello, a CCC login and the
//! deobfuscation of the secrets it prints.

use super::*;
use crate::anyconnect;

/// Debug helper: deobfuscate hex secrets the gateway prints (prompt, error_*).
pub fn cmd_deob(args: &[String]) {
    for h in args {
        match ccc::deobfuscate(h) {
            Ok(b) => println!(
                "{h}\n  -> text: {:?}\n  -> hex : {}",
                String::from_utf8_lossy(&b),
                b.iter().map(|x| format!("{x:02x}")).collect::<String>()
            ),
            Err(e) => println!("{h}\n  -> error: {e}"),
        }
    }
}

pub fn cmd_hello(args: &[String]) {
    let mut gateway: Option<String> = None;
    let mut send = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" => gateway = it.next().cloned(),
            "--send" => send = true,
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let pkt = ccc::client_hello(new_request_id());
    let body = pkt.serialize();

    println!("# CCC ClientHello (body, {} bytes):", body.len());
    println!("{body}\n");

    let host = match gateway {
        Some(h) => h,
        None => {
            println!("(no --gateway given; not sending. Pass --gateway <host> --send to probe.)");
            return;
        }
    };

    let request = http::Request::form(CCC_PATH, &body).encode(
        &ccc_endpoint(&host),
        &http::Cookies::new(),
        false,
    );
    println!("# HTTP request that would be sent to {host}:443 :");
    println!("{}", preview(&String::from_utf8_lossy(&request)));

    if !send {
        println!("(dry run; add --send to actually POST to the gateway)");
        return;
    }

    match ccc_post(&host, &body) {
        Ok(resp) => {
            let parsed_body = resp.body_str();
            println!("\n# raw response ({} bytes of body):", parsed_body.len());
            println!("{}\n", preview(&parsed_body));
            match ccc::parse(&parsed_body) {
                Ok(p) => {
                    println!("# parsed CCCserverResponse:");
                    println!("{} {}", p.name, p.body.pretty(0));
                }
                Err(e) => println!("(could not parse body as CCC: {e})"),
            }
        }
        Err(e) => {
            eprintln!("send failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Authenticate over CCC. UserPass (empty password) → challenge loop
/// (SecurID passcode via MultiChallange) → session. The initial UserPass
/// carries no passcode, so `--probe` validates the format and shows the real
/// gateway challenge WITHOUT consuming a one-time passcode. `--verbose` dumps
/// the full raw HTTP response at each step.
pub fn cmd_login(args: &[String]) {
    let mut gateway: Option<String> = None;
    let mut user = String::new();
    let mut realm = "vpn".to_string();
    let mut passcode: Option<String> = None;
    let mut probe = false;
    let mut verbose = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" => gateway = it.next().cloned(),
            "--user" | "-u" => user = it.next().cloned().unwrap_or(user),
            "--realm" | "-r" => realm = it.next().cloned().unwrap_or(realm),
            "--passcode" | "-p" => passcode = it.next().cloned(),
            "--probe" => probe = true,
            "--verbose" | "-v" => verbose = true,
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let host = match gateway {
        Some(h) => h,
        None => {
            eprintln!("login requires --gateway <host>");
            std::process::exit(2);
        }
    };
    if user.is_empty() {
        eprintln!("login requires --user <user>");
        std::process::exit(2);
    }

    let req = ccc::auth_userpass(new_request_id(), &user, &realm);
    println!("# UserPass request (user={user}, realm={realm}):");
    println!("{}\n", req.serialize());
    let (mut raw, mut resp) = post_ccc(&host, &req, verbose);

    loop {
        let rc = resp
            .path(&["ResponseHeader", "return_code"])
            .and_then(|v| v.text())
            .unwrap_or_default();
        let status = resp
            .path(&["ResponseData", "authn_status"])
            .and_then(|v| v.text())
            .unwrap_or_default();
        println!("# response: return_code={rc} authn_status={status}");
        if let Some(c) = raw.set_cookie("CPCVPN_SESSION_ID") {
            println!("# Set-Cookie CPCVPN_SESSION_ID = {c}");
        }

        match status.as_str() {
            "done" => {
                if verbose {
                    println!("\n# ---- full 'done' response headers ----");
                    println!("{}", raw.head_text());
                    println!("\n# ---- full 'done' response body (parsed) ----");
                    println!("{}\n", resp.body.pretty(0));
                }
                let authed = resp
                    .path(&["ResponseData", "is_authenticated"])
                    .and_then(|v| v.text())
                    .unwrap_or_default();
                let sid = resp
                    .path(&["ResponseData", "session_id"])
                    .and_then(|v| v.text())
                    .unwrap_or_default();
                let cookie = raw.set_cookie("CPCVPN_SESSION_ID");

                if authed == "true" {
                    println!("\nAUTH OK (is_authenticated=true).");
                    if !sid.is_empty() {
                        println!("   session_id : {sid}");
                    }
                    if let Some(c) = &cookie {
                        println!("   CPCVPN_SESSION_ID cookie: {c}");
                    }
                    if let Some(k) = resp
                        .path(&["ResponseData", "active_key"])
                        .and_then(|v| v.text())
                    {
                        let key = ccc::deobfuscate(&k).unwrap_or_default();
                        println!("   active_key : {} bytes (deobfuscated)", key.len());
                    }
                } else {
                    let err = resp
                        .path(&["ResponseData", "error_message"])
                        .and_then(|v| v.text())
                        .filter(|h| !h.is_empty())
                        .and_then(|h| ccc::deobfuscate(&h).ok())
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                        .unwrap_or_default();
                    let ecode = resp
                        .path(&["ResponseData", "error_code"])
                        .and_then(|v| v.text())
                        .unwrap_or_default();
                    println!("\nAUTH FAILED (is_authenticated=false, error_code={ecode}).");
                    if !err.is_empty() {
                        println!("   gateway says: \"{err}\"");
                    }
                    println!("   → passcode not accepted; re-run with a fresh passcode.");
                }
                return;
            }
            "continue" => {
                let sid = resp
                    .path(&["ResponseData", "session_id"])
                    .and_then(|v| v.text())
                    .unwrap_or_default();
                let prompt = resp
                    .path(&["ResponseData", "prompt"])
                    .and_then(|v| v.text())
                    .map(|h| {
                        ccc::deobfuscate(&h)
                            .map(|b| String::from_utf8_lossy(&b).into_owned())
                            .unwrap_or(h)
                    })
                    .unwrap_or_default();
                println!("\n# gateway challenge: \"{prompt}\"");
                println!("# auth session_id: {sid}");

                let input = if let Some(pc) = passcode.take() {
                    pc
                } else if probe {
                    println!(
                        "\n(--probe set: stopping before sending any passcode — UserPass format validated)"
                    );
                    return;
                } else {
                    match anyconnect::read_secret("Passcode: ") {
                        Some(l) if !l.trim().is_empty() => l.trim().to_string(),
                        _ => {
                            println!("(no passcode entered; stopping)");
                            return;
                        }
                    }
                };

                let chr = ccc::multi_challenge(new_request_id(), &sid, &input);
                let (r, p) = post_ccc(&host, &chr, verbose);
                raw = r;
                resp = p;
            }
            other => {
                println!("\n# ---- full response body (parsed) ----");
                println!("{}\n", resp.body.pretty(0));
                let err = resp
                    .path(&["ResponseData", "error_message"])
                    .and_then(|v| v.text())
                    .and_then(|h| ccc::deobfuscate(&h).ok())
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .unwrap_or_default();
                println!("auth not completed (authn_status={other}). {err}");
                return;
            }
        }
    }
}

/// POST a CCC packet; return the HTTP response and its parsed body. Exits on
/// transport/parse failure.
pub(super) fn post_ccc(
    host: &str,
    pkt: &ccc::Packet,
    verbose: bool,
) -> (http::Response, ccc::Packet) {
    let resp = ccc_post(host, &pkt.serialize()).unwrap_or_else(|e| {
        eprintln!("send failed: {e}");
        std::process::exit(1);
    });
    let body = resp.body_str().into_owned();
    if verbose {
        println!(
            "# ---- raw HTTP response ----\n{}\n\n{body}\n# ----",
            resp.head_text()
        );
    }
    let parsed = ccc::parse(&body).unwrap_or_else(|e| {
        eprintln!("parse failed: {e}\n--- raw body ---\n{body}");
        std::process::exit(1);
    });
    (resp, parsed)
}

pub(super) fn preview(s: &str) -> String {
    const MAX: usize = 1600;
    if s.len() <= MAX {
        s.to_string()
    } else {
        format!("{}\n... [{} more bytes]", &s[..MAX], s.len() - MAX)
    }
}
