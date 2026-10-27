//! Host Information Profile (HIP): the gateway's posture check.
//!
//! After `getconfig.esp` the client asks `POST /ssl-vpn/hipreportcheck.esp`
//! whether a report is needed for an md5 that identifies this host+session; if
//! so it submits an XML report to `/ssl-vpn/hipreport.esp`. The md5 only has to be
//! stable and match between check and report (we hash the session cookie minus its
//! volatile fields).
//!
//! The report is generated natively and is truthful: the real OS, hostname and
//! tunnel address, and empty product lists — no invented antivirus or disk
//! encryption. A gateway whose HIP policy demands specific products will
//! classify this host accordingly; that's the administrator's call, not ours to
//! spoof.

use super::auth::{classify, Reply, Session};
use super::http::Form;
use std::net::Ipv4Addr;

/// The md5 the check and the report must agree on.
pub fn md5_token(session: &Session) -> Result<String, String> {
    let auth = session.auth.as_ref().ok_or("not authenticated")?;
    let stable = auth.query_filtered(&["authcookie", "preferred-ip"]);
    let d = openssl::hash::hash(openssl::hash::MessageDigest::md5(), stable.as_bytes()).map_err(|e| e.to_string())?;
    Ok(d.iter().map(|b| format!("{b:02x}")).collect())
}

/// `Ok(true)` when the gateway wants a report.
pub fn report_needed(session: &mut Session, ip: Ipv4Addr) -> Result<bool, String> {
    let mut f = Form::new();
    f.add("client-role", "global-protect-full");
    f.extend_encoded(&session.cookie_query()?);
    f.add("client-ip", &ip.to_string());
    f.add("md5", &md5_token(session)?);
    let resp = session.post(false, "/ssl-vpn/hipreportcheck.esp", &f.encode())?;
    if resp.status != 200 {
        return Err(format!("hipreportcheck: HTTP {}", resp.status));
    }
    match classify(&resp.body_str()).map_err(|e| e.to_string())? {
        Reply::Xml(root) => match root.child_text("hip-report-needed").as_deref() {
            Some("no") => Ok(false),
            Some("yes") => Ok(true),
            other => Err(format!("hipreportcheck: unexpected hip-report-needed {other:?}")),
        },
        Reply::Challenge { .. } => Err("hipreportcheck: unexpected challenge".into()),
    }
}

pub fn submit(session: &mut Session, ip: Ipv4Addr) -> Result<(), String> {
    let report = build_report(session, ip, &now_stamp())?;
    let mut f = Form::new();
    f.add("client-role", "global-protect-full");
    f.extend_encoded(&session.cookie_query()?);
    f.add("client-ip", &ip.to_string());
    f.add("report", &report);
    let resp = session.post(false, "/ssl-vpn/hipreport.esp", &f.encode())?;
    if resp.status != 200 {
        return Err(format!("hipreport: HTTP {}", resp.status));
    }
    classify(&resp.body_str()).map(|_| ()).map_err(|e| format!("hipreport: {e}"))
}

/// Check, and submit if asked. Returns a one-line outcome for the log.
pub fn check_and_submit(session: &mut Session, ip: Ipv4Addr) -> Result<&'static str, String> {
    if !report_needed(session, ip)? {
        return Ok("gateway needs no HIP report");
    }
    submit(session, ip)?;
    Ok("HIP report submitted")
}

pub fn build_report(session: &Session, ip: Ipv4Addr, stamp: &str) -> Result<String, String> {
    let auth = session.auth.as_ref().ok_or("not authenticated")?;
    let esc = crate::anyconnect::xml::escape;
    let host = esc(&session.computer);
    let domain = esc(&auth.domain);
    let host_id = host_id();
    let os = esc(&os_pretty_name());
    let version = esc(session.app_version.as_deref().unwrap_or(super::DEFAULT_APP_VERSION));
    let empty = |name: &str| format!("\t\t<entry name=\"{name}\">\n\t\t\t<list/>\n\t\t</entry>\n");
    let mut r = String::new();
    r.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<hip-report name=\"hip-report\">\n");
    r.push_str(&format!("\t<md5-sum>{}</md5-sum>\n", md5_token(session)?));
    r.push_str(&format!("\t<user-name>{}</user-name>\n", esc(&auth.user)));
    r.push_str(&format!("\t<domain>{domain}</domain>\n\t<host-name>{host}</host-name>\n\t<host-id>{host_id}</host-id>\n"));
    r.push_str(&format!("\t<ip-address>{ip}</ip-address>\n\t<ipv6-address></ipv6-address>\n"));
    r.push_str(&format!("\t<generate-time>{stamp}</generate-time>\n\t<hip-report-version>4</hip-report-version>\n"));
    r.push_str("\t<categories>\n\t\t<entry name=\"host-info\">\n");
    r.push_str(&format!("\t\t\t<client-version>{version}</client-version>\n\t\t\t<os>{os}</os>\n\t\t\t<os-vendor>Linux</os-vendor>\n"));
    r.push_str(&format!("\t\t\t<domain>{domain}</domain>\n\t\t\t<host-name>{host}</host-name>\n\t\t\t<host-id>{host_id}</host-id>\n"));
    r.push_str(&format!(
        "\t\t\t<network-interface>\n\t\t\t\t<entry name=\"{tun}\">\n\t\t\t\t\t<description>{tun}</description>\n\t\t\t\t\t<ip-address>\n\t\t\t\t\t\t<entry name=\"{ip}\"/>\n\t\t\t\t\t</ip-address>\n\t\t\t\t</entry>\n\t\t\t</network-interface>\n",
        tun = super::tunnel::TUN_NAME
    ));
    r.push_str("\t\t</entry>\n");
    for cat in ["anti-malware", "disk-backup", "disk-encryption", "firewall"] {
        r.push_str(&empty(cat));
    }
    r.push_str("\t\t<entry name=\"patch-management\">\n\t\t\t<list/>\n\t\t\t<missing-patches/>\n\t\t</entry>\n");
    r.push_str(&empty("data-loss-prevention"));
    r.push_str("\t</categories>\n</hip-report>\n");
    Ok(r)
}

/// `Linux <PRETTY_NAME>` from os-release.
fn os_pretty_name() -> String {
    let rel = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let name = rel
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "Linux".into());
    if name.starts_with("Linux") {
        name
    } else {
        format!("Linux {name}")
    }
}

/// A stable per-host UUID — derived from (not equal to) the machine-id.
fn host_id() -> String {
    let mid = std::fs::read_to_string("/etc/machine-id").unwrap_or_else(|_| super::local_hostname());
    let d = openssl::hash::hash(openssl::hash::MessageDigest::md5(), format!("unvpn-gp:{}", mid.trim()).as_bytes())
        .map(|d| d.to_vec())
        .unwrap_or_else(|_| vec![0; 16]);
    let h: String = d.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// Local time as `MM/DD/YYYY HH:MM:SS` (the format the gateway expects).
fn now_stamp() -> String {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        format!(
            "{:02}/{:02}/{:04} {:02}:{:02}:{:02}",
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_year + 1900,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::auth::AuthCookie;
    use super::super::http::Endpoint;
    use super::*;
    use std::time::Duration;

    fn session() -> Session {
        let ep = Endpoint { host: "gw.example.com".into(), port: 443, user_agent: "PAN GlobalProtect".into(), timeout: Duration::from_secs(1) };
        let mut s = Session::new(ep, "Linux", "linux-64", "myhost");
        s.auth = Some(AuthCookie {
            authcookie: "secret".into(),
            portal: "GP-Gateway".into(),
            user: "alice".into(),
            domain: "(empty_domain)".into(),
            preferred_ip: "198.51.100.7".into(),
            computer: "myhost".into(),
        });
        s
    }

    #[test]
    fn md5_ignores_volatile_fields() {
        let mut s = session();
        let a = md5_token(&s).unwrap();
        s.auth.as_mut().unwrap().authcookie = "other".into();
        s.auth.as_mut().unwrap().preferred_ip = "198.51.100.8".into();
        assert_eq!(md5_token(&s).unwrap(), a);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn report_is_wellformed_and_truthful() {
        let s = session();
        let r = build_report(&s, Ipv4Addr::new(198, 51, 100, 7), "01/02/2026 03:04:05").unwrap();
        let root = crate::anyconnect::xml::parse(&r).unwrap();
        assert_eq!(root.name, "hip-report");
        assert_eq!(root.child_text("user-name").as_deref(), Some("alice"));
        assert_eq!(root.child_text("domain").as_deref(), Some("(empty_domain)"));
        assert_eq!(root.child_text("md5-sum"), Some(md5_token(&s).unwrap()));
        assert!(!r.contains("antivirus") && !r.contains("encrypted"), "no invented products");
        let cats: Vec<_> = root.child("categories").unwrap().children_named("entry").filter_map(|e| e.attr("name")).collect();
        assert_eq!(cats[0], "host-info");
        assert!(cats.contains(&"firewall"));
    }
}
