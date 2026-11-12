//! `unvpn tunnel`: the SSL data-plane handshake, to read the Office Mode
//! address and routes of an existing session.

use super::*;
use crate::net;
use std::io::{Read, Write};

/// Open the SSL data-plane tunnel and perform the `client_hello` /
/// `hello_reply` handshake to obtain the Office Mode IP + routes. Uses the
/// `active_key` (obfuscated hex) from a prior `login` as the session cookie, so
/// it can run against an existing 9h session without a fresh passcode.
/// Framing = "Slim": [u32 be len][u32 be type][payload]; type 1 = CONTROL
/// (S-expression + NUL), type 2 = DATA (raw IP packet).
pub fn cmd_tunnel(args: &[String]) {
    let mut gateway: Option<String> = None;
    let mut active_key: Option<String> = None;
    let mut om_ip = "0.0.0.0".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--gateway" | "-g" => gateway = it.next().cloned(),
            "--active-key" | "-k" => active_key = it.next().cloned(),
            "--om-ip" => om_ip = it.next().cloned().unwrap_or(om_ip),
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let host = gateway.unwrap_or_else(|| {
        eprintln!("tunnel requires --gateway <host>");
        std::process::exit(2);
    });
    let akey = active_key.unwrap_or_else(|| {
        eprintln!("tunnel requires --active-key <obfuscated-hex>");
        std::process::exit(2);
    });

    // cookie = the DEOBFUSCATED active_key (a 64-char hex session key).
    let cookie = match ccc::deobfuscate(&akey) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(e) => {
            eprintln!("bad --active-key: {e}");
            std::process::exit(1);
        }
    };

    let mut tls = net::tls::connect(&host, 443, Duration::from_secs(20)).unwrap_or_else(|e| {
        eprintln!("TLS failed: {e}");
        std::process::exit(1);
    });
    println!("# SSL tunnel: TLS connected to {host}:443");

    let hello = ccc::tunnel_client_hello(&cookie, &om_ip);
    let payload = hello.serialize();
    println!("# tunnel client_hello (cookie elided):");
    println!("{}\n", payload.replace(&cookie, "<SESSION_KEY>"));
    if let Err(e) = send_control(&mut tls, &payload) {
        eprintln!("send failed: {e}");
        std::process::exit(1);
    }

    match read_frame(&mut tls) {
        Ok((1, data)) => {
            let s = strip_nul(&data);
            match ccc::parse(&s) {
                Ok(p) => {
                    println!("# {} reply:\n{}\n", p.name, p.body.pretty(0));
                    if p.name == "hello_reply" {
                        let ip = p
                            .path(&["OM", "ipaddr"])
                            .and_then(|v| v.text())
                            .unwrap_or_default();
                        let subnet = p
                            .path(&["optional", "subnet"])
                            .and_then(|v| v.text())
                            .unwrap_or_default();
                        println!("SSL TUNNEL UP — Office Mode IP: {ip}  subnet: {subnet}");
                    } else if p.name == "disconnect" {
                        println!("gateway sent disconnect (session invalid/expired?)");
                    }
                }
                Err(e) => println!("(could not parse control reply: {e})\n{s}"),
            }
        }
        Ok((2, data)) => println!(
            "# unexpected DATA packet ({} bytes) during handshake",
            data.len()
        ),
        Ok((t, _)) => println!("# unexpected packet type {t}"),
        Err(e) => {
            eprintln!("read failed: {e}");
            std::process::exit(1);
        }
    }
}

pub(super) fn send_control(tls: &mut impl Write, payload: &str) -> std::io::Result<()> {
    let mut body = payload.as_bytes().to_vec();
    body.push(0);
    let mut frame = Vec::with_capacity(8 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes()); // PKT_CONTROL
    frame.extend_from_slice(&body);
    tls.write_all(&frame)
}

pub(super) fn read_frame(tls: &mut impl Read) -> std::io::Result<(u32, Vec<u8>)> {
    let mut hdr = [0u8; 8];
    tls.read_exact(&mut hdr)?;
    let len = u32::from_be_bytes(hdr[0..4].try_into().unwrap()) as usize;
    let ptype = u32::from_be_bytes(hdr[4..8].try_into().unwrap());
    let mut payload = vec![0u8; len];
    tls.read_exact(&mut payload)?;
    Ok((ptype, payload))
}

pub(super) fn strip_nul(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}
