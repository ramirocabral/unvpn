//! Parsers for the two XML documents the F5 APM portal returns after login:
//!
//!  1. the VPN *profile* — `GET /vdesk/vpn/index.php3?outform=xml&client_version=2.0`
//!     → `<favorites type="VPN"><favorite><params>resourcename=…</params>…` — from
//!     which we extract the `params` string for the next request;
//!  2. the tunnel *options* — `GET /vdesk/vpn/connect.php3?<params>&outform=xml…`
//!     → `<favorite><object><Session_ID>…</Session_ID><ur_Z>…</ur_Z>…</object>…`.
//!
//! Unlike Fortinet (data in attributes), F5 puts everything in **element text**,
//! with numbered tags (`DNS0`, `DNS1`, `LAN0`, `ExcludeSubnets0`, …). Field set and
//! semantics follow openconnect's `f5.c`. Dependency-light: a tolerant leaf-text
//! scanner, not a full XML parser.

use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct Route {
    pub net: Ipv4Addr,
    pub mask: Ipv4Addr,
}

#[derive(Debug, Clone, Default)]
pub struct F5Options {
    /// `Session_ID` — the `sess=` token for the `GET /myvpn?…` tunnel request.
    pub session_id: String,
    /// `ur_Z` — the `Z=` token for the same request.
    pub ur_z: String,
    pub ipv4: bool,
    pub ipv6: bool,
    /// `hdlc_framing`: wrap PPP in RFC1662 async-HDLC rather than the F5 4-byte header.
    pub hdlc: bool,
    pub dtls: bool,
    pub dtls_port: u16,
    pub dtls12: bool,
    pub idle_timeout: u32,
    /// `UseDefaultGateway0`: full tunnel (default route) vs. split-only.
    pub default_route: bool,
    pub dns: Vec<Ipv4Addr>,
    pub wins: Vec<Ipv4Addr>,
    pub domains: String,
    /// Split-include routes (`LAN<n>`). With `default_route` these are additive.
    pub routes: Vec<Route>,
    /// Split-exclude routes (`ExcludeSubnets<n>`).
    pub exclude: Vec<Route>,
}

/// Extract the first VPN resource's `params` string from the profile XML.
/// Returns `None` if there is no VPN favorite (e.g. a webtop-only portal).
pub fn parse_profile(xml: &str) -> Option<String> {
    // Be strict enough to avoid non-VPN webtop favorites: require a VPN favorites block.
    if !xml.contains("type=\"VPN\"") && !xml.contains("type='VPN'") {
        // Some portals omit the attribute; fall back to any params that looks like a resource.
        return leaf_texts(xml)
            .into_iter()
            .find(|(n, v)| n == "params" && v.contains("resourcename"))
            .map(|(_, v)| v);
    }
    leaf_texts(xml).into_iter().find(|(n, _)| n == "params").map(|(_, v)| v)
}

/// Parse the tunnel options XML. Tolerant: unknown elements ignored, missing
/// fields defaulted. The caller sanity-checks the essentials (session id, ur_Z,
/// at least one address family).
pub fn parse_options(xml: &str) -> F5Options {
    let mut o = F5Options::default();
    for (name, text) in leaf_texts(xml) {
        let text = text.trim();
        match name.as_str() {
            "Session_ID" => o.session_id = text.to_string(),
            "ur_Z" => o.ur_z = text.to_string(),
            "IPV4_0" => o.ipv4 = bool_or_int(text) != 0,
            "IPV6_0" => o.ipv6 = bool_or_int(text) != 0,
            "hdlc_framing" => o.hdlc = bool_or_int(text) != 0,
            "tunnel_dtls" => o.dtls = bool_or_int(text) != 0,
            "tunnel_port_dtls" => o.dtls_port = bool_or_int(text) as u16,
            "dtls_v1_2_supported" => o.dtls12 = bool_or_int(text) != 0,
            "idle_session_timeout" => o.idle_timeout = bool_or_int(text) as u32,
            "UseDefaultGateway0" => o.default_route = bool_or_int(text) != 0,
            // `SplitTunneling0` is the toggle real APM policies actually send (the
            // gw-f5 gateway sends this and omits `UseDefaultGateway0`): 1 = split
            // (only LAN<n> routes), 0 = full tunnel (default route). Authoritative.
            "SplitTunneling0" => o.default_route = bool_or_int(text) == 0,
            _ => {
                // Numbered families: DNS<n>, DNS6_<n>, WINS<n>, DNSSuffix<n>, LAN<n>,
                // LAN6_<n>, ExcludeSubnets<n>, ExcludeSubnets6_<n>.
                if is_numbered(&name, "DNS") || is_numbered(&name, "DNS6_") {
                    push_ips(&mut o.dns, text);
                } else if is_numbered(&name, "WINS") {
                    push_ips(&mut o.wins, text);
                } else if is_numbered(&name, "DNSSuffix") {
                    push_domain(&mut o.domains, text);
                } else if is_numbered(&name, "LAN") || is_numbered(&name, "LAN6_") {
                    push_routes(&mut o.routes, text);
                } else if is_numbered(&name, "ExcludeSubnets") || is_numbered(&name, "ExcludeSubnets6_") {
                    push_routes(&mut o.exclude, text);
                }
            }
        }
    }
    o
}

/// F5 booleans come as `yes`/`no`, `1`/`0`, or a bare integer (e.g. a port).
fn bool_or_int(s: &str) -> i64 {
    match s.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" => 1,
        "no" | "false" | "off" | "" => 0,
        other => other.parse::<i64>().unwrap_or(0),
    }
}

/// True if `name` is `prefix` followed by one or more digits (e.g. `DNS0`,
/// `LAN12`). For underscore-style prefixes (`DNS6_`) the digits follow the prefix.
fn is_numbered(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .map(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false)
}

/// Append IPv4 addresses from a tag whose text may hold several, space- or
/// comma-separated (F5 sends DNS both as separate `DNS<n>` tags and, sometimes,
/// multiple values in one — gof5 splits each tag, so we do too). Dedups.
fn push_ips(dst: &mut Vec<Ipv4Addr>, text: &str) {
    for w in text.split(|c: char| c.is_whitespace() || c == ',').filter(|s| !s.is_empty()) {
        if let Ok(ip) = w.parse::<Ipv4Addr>() {
            if !dst.contains(&ip) {
                dst.push(ip);
            }
        }
    }
}

/// Parse a list of `net/mask` route words (space- or comma-separated; mask dotted —
/// the real F5 wire form, e.g. `10.0.0.0/255.0.0.0`, cross-checked with gof5 — or a
/// CIDR prefix length) and append them.
fn push_routes(dst: &mut Vec<Route>, text: &str) {
    for word in text.split(|c: char| c.is_whitespace() || c == ',').filter(|s| !s.is_empty()) {
        let Some((net_s, mask_s)) = word.split_once('/') else {
            continue;
        };
        let Ok(net) = net_s.parse::<Ipv4Addr>() else { continue };
        if let Some(mask) = parse_mask(mask_s) {
            dst.push(Route { net, mask });
        }
    }
}

/// A netmask given either dotted (`255.255.0.0`) or as a prefix length (`16`).
fn parse_mask(s: &str) -> Option<Ipv4Addr> {
    if let Ok(m) = s.parse::<Ipv4Addr>() {
        return Some(m);
    }
    let prefix: u32 = s.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let bits: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Some(Ipv4Addr::from(bits))
}

fn push_domain(domains: &mut String, d: &str) {
    for part in d.split([',', ';', ' ']).filter(|s| !s.is_empty()) {
        if !domains.split(' ').any(|x| x == part) {
            if !domains.is_empty() {
                domains.push(' ');
            }
            domains.push_str(part);
        }
    }
}

// ───────────────────────── leaf-text XML scanner ────────────────────────────

/// Yield `(tag_name, text)` for every **leaf** element (one whose content is text,
/// not child elements). Tolerant of attributes, self-closing tags, comments and
/// the XML declaration. F5's option/profile documents are effectively flat lists
/// of leaves under `<object>` / `<favorite>`, so this captures every value.
fn leaf_texts(xml: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = xml.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        // Skip comments / declarations / processing instructions / closing tags.
        if xml[i..].starts_with("<!--") {
            match xml[i..].find("-->") {
                Some(e) => { i += e + 3; continue; }
                None => break,
            }
        }
        if xml[i..].starts_with("<?") || xml[i..].starts_with("</") || xml[i..].starts_with("<!") {
            match xml[i..].find('>') {
                Some(e) => { i += e + 1; continue; }
                None => break,
            }
        }
        // A start/empty tag.
        let Some(close_rel) = xml[i..].find('>') else { break };
        let tag_inner = &xml[i + 1..i + close_rel];
        let self_closing = tag_inner.ends_with('/');
        let name = tag_inner.trim_end_matches('/').trim_start();
        let name = name.split(|c: char| c.is_whitespace()).next().unwrap_or("").to_string();
        let content_start = i + close_rel + 1;
        i = content_start;
        if self_closing || name.is_empty() {
            continue;
        }
        // Content runs until the next '<'. If that '<' opens the matching close
        // tag, this is a leaf and the text in between is its value.
        let Some(next_lt_rel) = xml[content_start..].find('<') else { break };
        let next_lt = content_start + next_lt_rel;
        if xml[next_lt..].to_ascii_lowercase().starts_with(&format!("</{}", name.to_ascii_lowercase())) {
            let text = xml[content_start..next_lt].trim().to_string();
            out.push((name, text));
        }
        // else: container element — leave i at content_start to descend into children.
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<favorites type="VPN" limited="YES">
  <favorite id="/Common/demo_vpn_resource">
    <caption>demo_vpn_resource</caption>
    <name>/Common/demo_vpn_resource</name>
    <params>resourcename=/Common/demo_vpn_resource</params>
  </favorite>
</favorites>"#;

    const OPTIONS: &str = r#"<?xml version="1.0"?>
<favorite>
  <object>
    <ur_Z>AABBCCDD</ur_Z>
    <Session_ID>deadbeef1234</Session_ID>
    <IPV4_0>1</IPV4_0>
    <IPV6_0>0</IPV6_0>
    <hdlc_framing>no</hdlc_framing>
    <idle_session_timeout>900</idle_session_timeout>
    <tunnel_dtls>1</tunnel_dtls>
    <tunnel_port_dtls>4433</tunnel_port_dtls>
    <dtls_v1_2_supported>1</dtls_v1_2_supported>
    <UseDefaultGateway0>0</UseDefaultGateway0>
    <SplitTunneling0>1</SplitTunneling0>
    <DNS0>10.10.0.53</DNS0>
    <DNS1>10.10.0.54</DNS1>
    <DNSSuffix0>corp.example.com</DNSSuffix0>
    <LAN0>10.0.0.0/255.0.0.0 172.16.0.0/12</LAN0>
    <ExcludeSubnets0>192.168.9.0/255.255.255.0</ExcludeSubnets0>
  </object>
</favorite>"#;

    #[test]
    fn profile_params_extracted() {
        assert_eq!(
            parse_profile(PROFILE).as_deref(),
            Some("resourcename=/Common/demo_vpn_resource")
        );
    }

    #[test]
    fn options_parsed() {
        let o = parse_options(OPTIONS);
        assert_eq!(o.session_id, "deadbeef1234");
        assert_eq!(o.ur_z, "AABBCCDD");
        assert!(o.ipv4 && !o.ipv6 && !o.hdlc);
        assert!(o.dtls && o.dtls12);
        assert_eq!(o.dtls_port, 4433);
        assert_eq!(o.idle_timeout, 900);
        assert!(!o.default_route);
        assert_eq!(
            o.dns,
            vec!["10.10.0.53".parse::<Ipv4Addr>().unwrap(), "10.10.0.54".parse::<Ipv4Addr>().unwrap()]
        );
        assert!(o.domains.contains("corp.example.com"));
        assert_eq!(o.routes.len(), 2); // 10/8 (dotted) + 172.16/12 (prefix)
        assert_eq!(o.routes[1].mask, "255.240.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(o.exclude.len(), 1);
    }

    #[test]
    fn mask_forms() {
        assert_eq!(parse_mask("255.255.255.0"), Some("255.255.255.0".parse().unwrap()));
        assert_eq!(parse_mask("24"), Some("255.255.255.0".parse().unwrap()));
        assert_eq!(parse_mask("0"), Some("0.0.0.0".parse().unwrap()));
        assert_eq!(parse_mask("33"), None);
    }

    /// Shape captured live from a real BIG-IP APM (vpn-f5.example.com): split
    /// tunnel driven by `SplitTunneling0` with `UseDefaultGateway0` absent, DNS and
    /// `net/dotted-mask` routes space-separated with a trailing space, empty exclude.
    #[test]
    fn options_real_world_split_tunnel() {
        let xml = r#"<?xml version="1.0"?>
<favorite>
  <object>
    <Session_ID>SID</Session_ID>
    <ur_Z>ZZ</ur_Z>
    <IPV4_0>1</IPV4_0>
    <IPV6_0>0</IPV6_0>
    <hdlc_framing>no</hdlc_framing>
    <tunnel_dtls>0</tunnel_dtls>
    <dtls_v1_2_supported>1</dtls_v1_2_supported>
    <SplitTunneling0>1</SplitTunneling0>
    <DNS0>10.60.175.134 10.60.175.136</DNS0>
    <DNS6_0></DNS6_0>
    <DNSSuffix0>corp.example.net</DNSSuffix0>
    <LAN0>10.0.0.0/255.0.0.0 172.80.0.0/255.255.248.0 192.168.0.0/255.255.0.0 198.51.100.53/255.255.255.255 </LAN0>
    <ExcludeSubnets0> </ExcludeSubnets0>
  </object>
</favorite>"#;
        let o = parse_options(xml);
        assert!(o.ipv4 && !o.ipv6 && !o.hdlc && !o.dtls);
        // SplitTunneling0=1 and no UseDefaultGateway0 → split (no default route).
        assert!(!o.default_route);
        assert_eq!(
            o.dns,
            vec![
                "10.60.175.134".parse::<Ipv4Addr>().unwrap(),
                "10.60.175.136".parse::<Ipv4Addr>().unwrap(),
            ]
        );
        assert!(o.domains.contains("corp.example.net"));
        // Four space-separated net/dotted-mask words, trailing space ignored.
        assert_eq!(o.routes.len(), 4);
        assert_eq!(o.routes[0].net, "10.0.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(o.routes[0].mask, "255.0.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(o.routes[1].mask, "255.255.248.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(o.routes[3].mask, "255.255.255.255".parse::<Ipv4Addr>().unwrap());
        // Whitespace-only ExcludeSubnets0 → no excludes.
        assert_eq!(o.exclude.len(), 0);
    }

    /// Full-tunnel policy: `SplitTunneling0=0` with no `UseDefaultGateway0` must set
    /// the default route.
    #[test]
    fn options_split_tunneling_zero_is_full() {
        let xml = r#"<favorite><object><SplitTunneling0>0</SplitTunneling0></object></favorite>"#;
        assert!(parse_options(xml).default_route);
    }
}
