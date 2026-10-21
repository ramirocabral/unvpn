//! Parser for `GET /remote/fortisslvpn_xml` — the tunnel configuration the
//! gateway returns after authentication (IP, DNS, search domain, split-tunnel
//! routes, DTLS flag, timeouts).
//!
//! Dependency-light on purpose (the whole engine only needs glibc + OpenSSL): a
//! small tolerant scanner over element start-tags, not a full XML parser. Field
//! set follows openconnect's `fortinet.c`.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct Route {
    pub net: Ipv4Addr,
    pub mask: Ipv4Addr,
}

#[derive(Debug, Clone, Default)]
pub struct TunnelConfig {
    pub dtls: bool,
    pub heartbeat: u32,
    pub idle_timeout: u32,
    pub assigned_ip: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domains: String,
    /// Include routes (split tunnel). Empty ⇒ default route (full tunnel).
    pub routes: Vec<Route>,
    /// Exclude routes (`negate="1"`).
    pub exclude: Vec<Route>,
}

/// Never fails: a malformed body yields an empty config (no IP ⇒ error upstream).
pub fn parse(xml: &str) -> TunnelConfig {
    let mut cfg = TunnelConfig::default();
    for (name, attrs) in start_tags(xml) {
        match name.as_str() {
            "sslvpn-tunnel" => {
                cfg.dtls = attrs.get("dtls").map(|v| v == "1").unwrap_or(false);
            }
            "dtls-config" => {
                if let Some(h) = attrs.get("heartbeat-interval").and_then(|v| v.parse().ok()) {
                    cfg.heartbeat = h;
                }
            }
            "idle-timeout" => {
                if let Some(v) = attrs.get("val").and_then(|v| v.parse().ok()) {
                    cfg.idle_timeout = v;
                }
            }
            "assigned-addr" => {
                if let Some(ip) = attrs.get("ipv4").and_then(|v| v.parse().ok()) {
                    cfg.assigned_ip = Some(ip);
                }
            }
            "dns" => {
                if let Some(ip) = attrs.get("ip").and_then(|v| v.parse::<Ipv4Addr>().ok()) {
                    if !cfg.dns.contains(&ip) {
                        cfg.dns.push(ip);
                    }
                }
                if let Some(d) = attrs.get("domain") {
                    push_domain(&mut cfg.domains, d);
                }
            }
            "domain" => {
                if let Some(d) = attrs.get("domain").or_else(|| attrs.get("name")) {
                    push_domain(&mut cfg.domains, d);
                }
            }
            "addr" => {
                // Inside <split-tunnel-info>: an include/exclude route.
                if let (Some(net), Some(mask)) = (
                    attrs.get("ip").and_then(|v| v.parse::<Ipv4Addr>().ok()),
                    attrs.get("mask").and_then(|v| v.parse::<Ipv4Addr>().ok()),
                ) {
                    let route = Route { net, mask };
                    if attrs.get("negate").map(|v| v == "1").unwrap_or(false) {
                        cfg.exclude.push(route);
                    } else {
                        cfg.routes.push(route);
                    }
                }
            }
            _ => {}
        }
    }
    cfg
}

fn push_domain(domains: &mut String, d: &str) {
    let d = d.trim();
    if d.is_empty() {
        return;
    }
    for part in d.split([',', ';', ' ']).filter(|s| !s.is_empty()) {
        if !domains.split(' ').any(|x| x == part) {
            if !domains.is_empty() {
                domains.push(' ');
            }
            domains.push_str(part);
        }
    }
}

fn start_tags(xml: &str) -> Vec<(String, BTreeMap<String, String>)> {
    let mut out = Vec::new();
    let bytes = xml.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        if xml[i..].starts_with("<!--") {
            if let Some(end) = xml[i..].find("-->") {
                i += end + 3;
                continue;
            } else {
                break;
            }
        }
        if xml[i..].starts_with("<?") || xml[i..].starts_with("</") || xml[i..].starts_with("<!") {
            if let Some(end) = xml[i..].find('>') {
                i += end + 1;
                continue;
            } else {
                break;
            }
        }
        let Some(close_rel) = xml[i..].find('>') else { break };
        let inner = &xml[i + 1..i + close_rel];
        let inner = inner.trim_end_matches('/').trim();
        if let Some((name, rest)) = split_name(inner) {
            out.push((name, parse_attrs(rest)));
        }
        i += close_rel + 1;
    }
    out
}

fn split_name(inner: &str) -> Option<(String, &str)> {
    let inner = inner.trim_start();
    if inner.is_empty() {
        return None;
    }
    let end = inner.find(|c: char| c.is_whitespace()).unwrap_or(inner.len());
    let name = inner[..end].to_string();
    Some((name, &inner[end..]))
}

fn parse_attrs(s: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && !(bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if key_start == i {
            break;
        }
        let key = s[key_start..i].to_string();
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            map.insert(key, String::new());
            continue;
        }
        i += 1;
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let quote = bytes[i];
        let val = if quote == b'"' || quote == b'\'' {
            i += 1;
            let vstart = i;
            while i < bytes.len() && bytes[i] != quote {
                i += 1;
            }
            let v = s[vstart..i].to_string();
            i += 1;
            v
        } else {
            let vstart = i;
            while i < bytes.len() && !(bytes[i] as char).is_whitespace() {
                i += 1;
            }
            s[vstart..i].to_string()
        };
        map.insert(key, val);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<sslvpn-tunnel ver="2" dtls="1" patch="1">
<dtls-config heartbeat-interval="10" heartbeat-fail-count="10"/>
<auth-timeout val="259200"/>
<idle-timeout val="300"/>
<fos platform="FG100F" major="7" minor="4" patch="3"/>
<ipv4>
<dns ip="10.10.0.53"/>
<dns ip="10.10.0.54" domain="corp.example.com"/>
<split-tunnel-info>
<addr ip="10.0.0.0" mask="255.0.0.0"/>
<addr ip="172.16.0.0" mask="255.240.0.0"/>
<addr ip="192.168.9.0" mask="255.255.255.0" negate="1"/>
</split-tunnel-info>
<assigned-addr ipv4="10.80.134.200"/>
</ipv4>
</sslvpn-tunnel>"#;

    #[test]
    fn parse_sample() {
        let c = parse(SAMPLE);
        assert!(c.dtls);
        assert_eq!(c.heartbeat, 10);
        assert_eq!(c.idle_timeout, 300);
        assert_eq!(c.assigned_ip, Some("10.80.134.200".parse().unwrap()));
        assert_eq!(c.dns.len(), 2);
        assert!(c.domains.contains("corp.example.com"));
        assert_eq!(c.routes.len(), 2);
        assert_eq!(c.exclude.len(), 1);
        assert_eq!(c.routes[0].net, "10.0.0.0".parse::<std::net::Ipv4Addr>().unwrap());
    }

    #[test]
    fn full_tunnel_when_no_split() {
        let xml = r#"<sslvpn-tunnel dtls="0"><ipv4><assigned-addr ipv4="10.1.2.3"/></ipv4></sslvpn-tunnel>"#;
        let c = parse(xml);
        assert!(!c.dtls);
        assert!(c.routes.is_empty());
        assert_eq!(c.assigned_ip, Some("10.1.2.3".parse().unwrap()));
    }
}
