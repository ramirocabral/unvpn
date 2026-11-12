//! Which gateway certificates to trust when no system CA vouches for them: one
//! pinned with `--pin [<host>:<port>=]sha256:<hex>`, one already trusted for the
//! same host in this run, or one the user accepts when asked. An endpoint whose
//! pin doesn't match is refused, never asked about.
//!
//! Endpoints are `host:port` for TLS and `host:ike` for an IKE certificate.

use crate::sysnet::{self, StdinEvent};
use openssl::x509::X509Ref;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{IsTerminal, Write};
use std::sync::{Mutex, MutexGuard};

struct Policy {
    insecure: bool,
    /// Endpoint → the fingerprints pinned for it.
    pinned: BTreeMap<String, Vec<String>>,
    /// Pins given without an endpoint, valid for any.
    anywhere: Vec<String>,
    /// Host → the fingerprints trusted for it in this run.
    trusted: BTreeMap<String, BTreeSet<String>>,
    /// `<endpoint> <fingerprint>` the user turned down in this run: not asked again.
    refused: BTreeSet<String>,
}

static POLICY: Mutex<Policy> = Mutex::new(Policy {
    insecure: false,
    pinned: BTreeMap::new(),
    anywhere: Vec::new(),
    trusted: BTreeMap::new(),
    refused: BTreeSet::new(),
});

fn policy() -> MutexGuard<'static, Policy> {
    POLICY.lock().unwrap_or_else(|e| e.into_inner())
}

/// The command line's `--pin`s and `--insecure`, before anything connects.
pub fn configure(pins: &[String], insecure: bool) -> Result<(), String> {
    let mut p = policy();
    p.insecure = insecure;
    for s in pins {
        match parse_pin(s)? {
            (Some(endpoint), fp) => p.pinned.entry(endpoint).or_default().push(fp),
            (None, fp) => p.anywhere.push(fp),
        }
    }
    Ok(())
}

/// `[<host>:<port>=]sha256:<hex>` → (endpoint, `sha256:<lowercase hex>`). The hex
/// may be in either case and colon-separated.
pub fn parse_pin(s: &str) -> Result<(Option<String>, String), String> {
    let bad = || format!("bad --pin {s:?}: expected [<host>:<port>=]sha256:<64 hex digits>");
    let (endpoint, fp) = match s.rsplit_once('=') {
        Some((e, f)) => {
            let e = e.trim().to_ascii_lowercase();
            match e.rsplit_once(':') {
                Some((h, p))
                    if !h.is_empty() && !p.is_empty() && !e.contains(char::is_whitespace) => {}
                _ => return Err(bad()),
            }
            (Some(e), f)
        }
        None => (None, s),
    };
    let fp = fp.trim().to_ascii_lowercase();
    let hex = fp.strip_prefix("sha256:").ok_or_else(bad)?.replace(':', "");
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    Ok((endpoint, format!("sha256:{hex}")))
}

/// `sha256:<hex>` of a DER certificate.
pub fn fingerprint(der: &[u8]) -> String {
    let d = openssl::sha::sha256(der);
    format!(
        "sha256:{}",
        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

fn host_of(endpoint: &str) -> &str {
    endpoint
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(endpoint)
}

/// A certificate the system's CAs vouched for on `endpoint`: the host's other
/// channels (DTLS, IKE) may present it too.
pub fn note_verified(endpoint: &str, der: &[u8]) {
    let endpoint = endpoint.to_ascii_lowercase();
    policy()
        .trusted
        .entry(host_of(&endpoint).to_string())
        .or_default()
        .insert(fingerprint(der));
}

enum Decision {
    Trust,
    Refuse(String),
    Ask,
}

fn not_trusted(endpoint: &str, fp: &str, why: &str) -> String {
    format!("the certificate of {endpoint} is not trusted ({why}); to trust it, pass --pin {endpoint}={fp}")
}

fn decide(p: &Policy, endpoint: &str, fp: &str, why: &str) -> Decision {
    if p.refused.contains(&format!("{endpoint} {fp}")) {
        return Decision::Refuse(not_trusted(endpoint, fp, why));
    }
    let host_trusts = p
        .trusted
        .get(host_of(endpoint))
        .is_some_and(|s| s.contains(fp));
    if p.insecure || (host_trusts && !p.pinned.contains_key(endpoint)) {
        return Decision::Trust;
    }
    let pins = p.pinned.get(endpoint).unwrap_or(&p.anywhere);
    if pins.is_empty() {
        Decision::Ask
    } else if pins.iter().any(|x| x == fp) {
        Decision::Trust
    } else {
        Decision::Refuse(format!(
            "the certificate of {endpoint} changed: it is {fp}, the trusted one is {} — possible interception, \
             not connecting. If the gateway really got a new certificate, forget the trusted one and connect again",
            pins.join(" or ")
        ))
    }
}

/// Decide on `cert`, presented by `endpoint`, that no system CA vouches for
/// (`why`). Asks the user when nothing settles it.
pub fn accept(endpoint: &str, cert: &X509Ref, why: &str) -> Result<(), String> {
    let endpoint = sysnet::one_word(&endpoint.to_ascii_lowercase());
    let der = cert
        .to_der()
        .map_err(|e| format!("certificate of {endpoint}: {e}"))?;
    let fp = fingerprint(&der);
    let decision = decide(&policy(), &endpoint, &fp, why);
    match decision {
        Decision::Trust => {}
        Decision::Refuse(e) => return Err(e),
        Decision::Ask => {
            let answer = ask(&endpoint, &fp, cert, why);
            if answer != Ok(true) {
                policy().refused.insert(format!("{endpoint} {fp}"));
                return Err(answer
                    .err()
                    .unwrap_or_else(|| not_trusted(&endpoint, &fp, why)));
            }
            out!("# trusting {fp} for {endpoint}");
        }
    }
    policy()
        .trusted
        .entry(host_of(&endpoint).to_string())
        .or_default()
        .insert(fp);
    Ok(())
}

/// Another channel to `host` (DTLS) must present a certificate already trusted
/// for it in this run.
pub fn require_known(host: &str, der: &[u8]) -> Result<(), String> {
    let fp = fingerprint(der);
    if known(&policy(), host, &fp) {
        Ok(())
    } else {
        Err(format!(
            "its certificate ({fp}) is not the one trusted for {host}"
        ))
    }
}

fn known(p: &Policy, host: &str, fp: &str) -> bool {
    p.insecure
        || p.trusted
            .get(&host.to_ascii_lowercase())
            .is_some_and(|s| s.contains(fp))
}

/// Show the certificate and ask whether to trust it: on a terminal, y/N; for a
/// front-end, `# AUTH-PROMPT: trust: <endpoint> <fingerprint> <details>`, answered
/// with `<fingerprint> yes|no`.
fn ask(endpoint: &str, fp: &str, cert: &X509Ref, why: &str) -> Result<bool, String> {
    let subject = sysnet::one_line(&crate::checkpoint::cert::p12::dn_string(
        cert.subject_name(),
    ));
    let issuer = sysnet::one_line(&crate::checkpoint::cert::p12::dn_string(cert.issuer_name()));
    out!("# no trusted CA vouches for the certificate of {endpoint}: {why}");
    out!("#   subject {subject}");
    out!("#   issuer  {issuer}");
    out!("#   valid until {}", cert.not_after());
    out!("#   {fp}");
    if std::io::stdin().is_terminal() {
        eprint!("Trust this certificate? [y/N] ");
        let _ = std::io::stderr().flush();
        return Ok(matches!(
            sysnet::stdin_next(None),
            StdinEvent::Line(l) if matches!(l.trim().to_ascii_lowercase().as_str(), "y" | "yes")
        ));
    }
    let _watch = sysnet::StdinWatchPause::new();
    let details = sysnet::one_line(&format!("{why}; subject {subject}; issuer {issuer}"));
    let announce = || crate::report::prompt("trust", &format!("{endpoint} {fp} {details}"));
    sysnet::stdin_ask(announce, None, |l| answer_for(fp, l)).ok_or_else(|| {
        format!("cancelled while asking whether to trust the certificate of {endpoint}")
    })
}

/// `<fingerprint> yes|no`, a front-end's answer to the trust question.
fn answer_for(fp: &str, line: &str) -> Option<bool> {
    let (f, a) = line.trim().split_once(' ')?;
    if !f.eq_ignore_ascii_case(fp) {
        return None;
    }
    match a.trim() {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const FP2: &str = "sha256:ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    fn policy_with(pins: &[&str]) -> Policy {
        let mut p = Policy {
            insecure: false,
            pinned: BTreeMap::new(),
            anywhere: Vec::new(),
            trusted: BTreeMap::new(),
            refused: BTreeSet::new(),
        };
        for s in pins {
            match parse_pin(s).unwrap() {
                (Some(e), fp) => p.pinned.entry(e).or_default().push(fp),
                (None, fp) => p.anywhere.push(fp),
            }
        }
        p
    }

    #[test]
    fn pins_parse_in_any_spelling() {
        assert_eq!(parse_pin(FP).unwrap(), (None, FP.to_string()));
        let colons = "SHA256:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF";
        assert_eq!(parse_pin(colons).unwrap(), (None, FP.to_string()));
        let scoped = format!("VPN.example.com:443={FP}");
        assert_eq!(
            parse_pin(&scoped).unwrap(),
            (Some("vpn.example.com:443".into()), FP.to_string())
        );
        assert_eq!(
            parse_pin(&format!("203.0.113.5:ike={FP}"))
                .unwrap()
                .0
                .as_deref(),
            Some("203.0.113.5:ike")
        );
        for bad in [
            "sha1:0011",
            "00112233",
            &format!("vpn.example.com={FP}"),
            &format!(":443={FP}"),
            "sha256:zz",
        ] {
            assert!(parse_pin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_pin_decides_for_its_endpoint_only() {
        let p = policy_with(&[&format!("vpn.example.com:443={FP}")]);
        assert!(matches!(
            decide(&p, "vpn.example.com:443", FP, "self-signed certificate"),
            Decision::Trust
        ));
        assert!(matches!(
            decide(&p, "vpn.example.com:443", FP2, "self-signed certificate"),
            Decision::Refuse(_)
        ));
        assert!(matches!(
            decide(&p, "vpn.example.com:10443", FP2, "self-signed certificate"),
            Decision::Ask
        ));
        assert!(matches!(
            decide(&p, "other.example.com:443", FP, "self-signed certificate"),
            Decision::Ask
        ));
    }

    #[test]
    fn an_unscoped_pin_covers_every_endpoint() {
        let p = policy_with(&[FP]);
        assert!(matches!(
            decide(&p, "vpn.example.com:443", FP, "self-signed certificate"),
            Decision::Trust
        ));
        match decide(&p, "other.example.com:8443", FP2, "self-signed certificate") {
            Decision::Refuse(e) => assert!(e.contains(FP) && e.contains(FP2), "{e}"),
            _ => panic!("expected a refusal"),
        }
    }

    #[test]
    fn a_certificate_trusted_for_the_host_covers_its_other_channels() {
        let mut p = policy_with(&[]);
        p.trusted
            .entry("vpn.example.com".into())
            .or_default()
            .insert(FP.into());
        assert!(matches!(
            decide(&p, "vpn.example.com:ike", FP, "self-signed certificate"),
            Decision::Trust
        ));
        assert!(matches!(
            decide(&p, "vpn.example.com:ike", FP2, "self-signed certificate"),
            Decision::Ask
        ));
        // A pin on the endpoint still wins over what the host trusted.
        let mut p = policy_with(&[&format!("vpn.example.com:ike={FP2}")]);
        p.trusted
            .entry("vpn.example.com".into())
            .or_default()
            .insert(FP.into());
        assert!(matches!(
            decide(&p, "vpn.example.com:ike", FP, "self-signed certificate"),
            Decision::Refuse(_)
        ));
    }

    #[test]
    fn a_refused_certificate_is_not_asked_about_again() {
        let mut p = policy_with(&[]);
        p.refused.insert(format!("vpn.example.com:443 {FP}"));
        assert!(matches!(
            decide(&p, "vpn.example.com:443", FP, "self-signed certificate"),
            Decision::Refuse(_)
        ));
        assert!(matches!(
            decide(&p, "vpn.example.com:443", FP2, "self-signed certificate"),
            Decision::Ask
        ));
    }

    #[test]
    fn a_second_channel_needs_the_certificate_already_trusted() {
        let mut p = policy_with(&[]);
        assert!(!known(&p, "vpn.example.com", FP));
        p.trusted
            .entry("vpn.example.com".into())
            .or_default()
            .insert(FP.into());
        assert!(known(&p, "VPN.example.com", FP));
        assert!(!known(&p, "vpn.example.com", FP2));
        assert!(!known(&p, "other.example.com", FP));
        p.insecure = true;
        assert!(known(&p, "other.example.com", FP2));
    }

    #[test]
    fn insecure_trusts_anything() {
        let mut p = policy_with(&[&format!("vpn.example.com:443={FP}")]);
        p.insecure = true;
        assert!(matches!(
            decide(&p, "vpn.example.com:443", FP2, "self-signed certificate"),
            Decision::Trust
        ));
    }

    #[test]
    fn only_a_tagged_line_answers() {
        assert_eq!(answer_for(FP, &format!("{FP} yes")), Some(true));
        assert_eq!(
            answer_for(FP, &format!("{} no\n", FP.to_uppercase())),
            Some(false)
        );
        assert_eq!(answer_for(FP, "yes"), None);
        assert_eq!(answer_for(FP, &format!("{FP2} yes")), None);
        assert_eq!(answer_for(FP, "hunter2"), None);
        assert_eq!(answer_for(FP, &format!("{FP} maybe")), None);
    }
}
