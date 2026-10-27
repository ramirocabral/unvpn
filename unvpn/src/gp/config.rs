//! The tunnel configuration from the gateway's `POST /ssl-vpn/getconfig.esp`.
//!
//! `<response status="success">` carries the assigned address, DNS, routes
//! (`access-routes` / `exclude-access-routes`), the SSL tunnel path, the tunnel
//! `timeout` (rekey interval) and — when the gateway allows IPsec — an `<ipsec>`
//! block with the ESP SPIs and keys, handed over directly (no IKE):
//!
//! ```text
//! <ipsec><udp-port>4501</udp-port><ipsec-mode>esp-tunnel</ipsec-mode>
//!   <enc-algo>aes-128-cbc</enc-algo><hmac-algo>sha1</hmac-algo>
//!   <c2s-spi>0x…</c2s-spi><s2c-spi>0x…</s2c-spi>
//!   <ekey-c2s><bits>128</bits><val>hex</val></ekey-c2s> … akey-s2c …</ipsec>
//! ```

use super::auth::{classify, Reply, Session};
use super::http::Form;
use crate::anyconnect::config::Route;
use crate::anyconnect::xml::Element;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Default)]
pub struct GpConfig {
    pub address: Option<Ipv4Addr>,
    pub netmask: Option<Ipv4Addr>,
    pub mtu: u32,
    pub dns: Vec<Ipv4Addr>,
    pub domains: Vec<String>,
    pub include: Vec<Route>,
    pub exclude: Vec<Route>,
    /// No split includes, or `0.0.0.0/0` among them.
    pub default_route: bool,
    pub tunnel_path: String,
    /// `<timeout>`: seconds until the tunnel must be re-established (0 = none).
    pub timeout: u64,
    /// `<lifetime>`: seconds the authcookie stays valid (0 = unknown).
    pub lifetime: u64,
    pub idle_timeout: u64,
    /// `<gw-address>`: where the ESP "magic" pings go.
    pub gw_address: Option<Ipv4Addr>,
    pub esp: Option<EspParams>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EspParams {
    pub udp_port: u16,
    pub enc: String,
    pub hmac: String,
    pub c2s_spi: u32,
    pub s2c_spi: u32,
    pub ekey_c2s: Vec<u8>,
    pub ekey_s2c: Vec<u8>,
    pub akey_c2s: Vec<u8>,
    pub akey_s2c: Vec<u8>,
}

impl EspParams {
    /// Build the SA: inbound = server→client keys, outbound = client→server.
    pub fn sa(&self) -> Result<crate::ike::esp::EspSa, String> {
        use openssl::{hash::MessageDigest, symm::Cipher};
        let cipher = match (self.enc.as_str(), self.ekey_c2s.len()) {
            ("aes-128-cbc" | "aes128", 16) => Cipher::aes_128_cbc(),
            ("aes-256-cbc" | "aes256", 32) => Cipher::aes_256_cbc(),
            (e, n) => return Err(format!("unsupported ESP cipher {e} ({n}-byte key)")),
        };
        // ICV lengths per RFC 2403/2404/4868 (what the gateway truncates to).
        let (digest, icv) = match self.hmac.as_str() {
            "sha1" => (MessageDigest::sha1(), 12),
            "md5" => (MessageDigest::md5(), 12),
            "sha256" => (MessageDigest::sha256(), 16),
            h => return Err(format!("unsupported ESP MAC {h}")),
        };
        if self.ekey_s2c.len() != self.ekey_c2s.len() || self.akey_c2s.is_empty() || self.akey_s2c.is_empty() {
            return Err("incomplete ESP keys".into());
        }
        Ok(crate::ike::esp::EspSa::from_keys(
            cipher,
            digest,
            icv,
            (self.s2c_spi, &self.ekey_s2c, &self.akey_s2c),
            (self.c2s_spi, &self.ekey_c2s, &self.akey_c2s),
        ))
    }
}

impl GpConfig {
    pub fn prefix(&self) -> u8 {
        self.netmask.map(crate::tun::mask_to_prefix).unwrap_or(32)
    }
}

/// `POST /ssl-vpn/getconfig.esp`. Each call issues fresh ESP keys (the old
/// ones die), so it is repeated on every reconnect/rekey; `preferred` asks to
/// keep the current address.
pub fn fetch(s: &mut Session, preferred: Option<Ipv4Addr>) -> Result<GpConfig, String> {
    let auth = s.auth.clone().ok_or("not authenticated")?;
    let mut f = Form::new();
    f.add("client-type", "1")
        .add("protocol-version", "p1")
        .add("internal", "no")
        .add("app-version", s.app_version.as_deref().unwrap_or(super::DEFAULT_APP_VERSION))
        .add("ipv6-support", "no")
        .add("clientos", &s.clientos)
        .add("os-version", &s.os_version)
        .add("hmac-algo", "sha1,md5,sha256")
        .add("enc-algo", "aes-128-cbc,aes-256-cbc");
    match preferred {
        Some(ip) => {
            f.add("preferred-ip", &ip.to_string());
            f.extend_encoded(&auth.query_filtered(&["preferred-ip"]));
        }
        None => {
            f.extend_encoded(&auth.query());
        }
    }
    let resp = s.post(false, "/ssl-vpn/getconfig.esp", &f.encode())?;
    if resp.status != 200 {
        return Err(format!("getconfig: HTTP {}", resp.status));
    }
    let body = resp.body_str();
    if body.trim() == "errors getting SSL/VPN config" {
        return Err("getconfig: the gateway rejected the session (errors getting SSL/VPN config)".into());
    }
    match classify(&body).map_err(|e| format!("getconfig: {e}"))? {
        Reply::Xml(root) => parse(&root),
        Reply::Challenge { .. } => Err("getconfig: unexpected challenge".into()),
    }
}

pub fn parse(root: &Element) -> Result<GpConfig, String> {
    if root.name != "response" {
        return Err(format!("unexpected getconfig reply <{}>", root.name));
    }
    let mut c = GpConfig { tunnel_path: "/ssl-tunnel-connect.sslvpn".into(), ..Default::default() };
    let members = |e: &Element| -> Vec<String> {
        e.children_named("member").map(|m| m.text.trim().to_string()).filter(|s| !s.is_empty()).collect()
    };
    for e in &root.children {
        let v = e.text.trim();
        match e.name.as_str() {
            "ip-address" => c.address = v.parse().ok(),
            "netmask" => c.netmask = v.parse().ok(),
            "mtu" => c.mtu = v.parse().unwrap_or(0),
            "timeout" => c.timeout = v.parse().unwrap_or(0),
            "lifetime" => c.lifetime = v.parse().unwrap_or(0),
            "disconnect-on-idle" => c.idle_timeout = v.parse().unwrap_or(0),
            "ssl-tunnel-url" if !v.is_empty() => c.tunnel_path = v.to_string(),
            "gw-address" => c.gw_address = v.parse().ok(),
            "dns" => {
                for m in members(e) {
                    if let Ok(ip) = m.parse::<Ipv4Addr>() {
                        if !c.dns.contains(&ip) {
                            c.dns.push(ip);
                        }
                    }
                }
            }
            "dns-suffix" => c.domains.extend(members(e)),
            "access-routes" => c.include.extend(members(e).iter().filter_map(|m| parse_route(m))),
            "exclude-access-routes" => c.exclude.extend(members(e).iter().filter_map(|m| parse_route(m))),
            "ipsec" => c.esp = parse_ipsec(e),
            _ => {}
        }
    }
    // A /0 include is GP's way of saying "full tunnel"; installed as two /1s.
    let had_default = c.include.iter().any(|r| r.prefix == 0);
    c.include.retain(|r| r.prefix != 0);
    c.default_route = had_default || c.include.is_empty();
    Ok(c)
}

fn parse_ipsec(e: &Element) -> Option<EspParams> {
    let mut p = EspParams::default();
    let spi = |s: &str| u32::from_str_radix(s.trim().trim_start_matches("0x").trim_start_matches("0X"), 16).ok();
    for m in &e.children {
        let v = m.text.trim();
        match m.name.as_str() {
            "udp-port" => p.udp_port = v.parse().unwrap_or(0),
            "enc-algo" => p.enc = v.to_ascii_lowercase(),
            "hmac-algo" => p.hmac = v.to_ascii_lowercase(),
            "c2s-spi" => p.c2s_spi = spi(v)?,
            "s2c-spi" => p.s2c_spi = spi(v)?,
            "ekey-c2s" => p.ekey_c2s = parse_key(m)?,
            "ekey-s2c" => p.ekey_s2c = parse_key(m)?,
            "akey-c2s" => p.akey_c2s = parse_key(m)?,
            "akey-s2c" => p.akey_s2c = parse_key(m)?,
            "ipsec-mode" if v != "esp-tunnel" => return None,
            _ => {}
        }
    }
    (p.udp_port != 0 && p.c2s_spi != 0 && p.s2c_spi != 0 && !p.ekey_c2s.is_empty()).then_some(p)
}

/// `<bits>N</bits><val>hex</val>` → bytes; the length must match `bits`.
fn parse_key(e: &Element) -> Option<Vec<u8>> {
    let bits: usize = e.child_text("bits")?.parse().ok()?;
    let hex = e.child_text("val")?;
    let bytes: Option<Vec<u8>> = (0..hex.len() / 2).map(|i| u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()).collect();
    bytes.filter(|b| bits.is_multiple_of(8) && b.len() == bits / 8)
}

/// `a.b.c.d/nn`, `a.b.c.d/m.m.m.m` or a bare host. IPv6 is skipped.
fn parse_route(s: &str) -> Option<Route> {
    if s.contains(':') {
        return None;
    }
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().ok().or_else(|| p.parse().ok().map(crate::tun::mask_to_prefix))?),
        None => (s, 32),
    };
    let net: Ipv4Addr = addr.trim().parse().ok()?;
    (prefix <= 32).then_some(Route { net, prefix })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anyconnect::xml;

    const SAMPLE: &str = r#"<response status="success">
  <need-tunnel>yes</need-tunnel>
  <ssl-tunnel-url>/ssl-tunnel-connect.sslvpn</ssl-tunnel-url>
  <portal>GP-Gateway-N</portal>
  <user>alice</user>
  <lifetime>2592000</lifetime>
  <timeout>10800</timeout>
  <disconnect-on-idle>3600</disconnect-on-idle>
  <bw-c2s>1000</bw-c2s>
  <bw-s2c>1000</bw-s2c>
  <gw-address>203.0.113.10</gw-address>
  <ip-address>198.51.100.7</ip-address>
  <netmask>255.255.255.255</netmask>
  <ip-address-preferred>yes</ip-address-preferred>
  <dns><member>198.51.100.53</member><member>198.51.100.54</member><member>198.51.100.53</member></dns>
  <wins/>
  <dns-suffix><member>corp.example.com</member><member>example.net</member></dns-suffix>
  <default-gateway>198.51.100.7</default-gateway>
  <mtu>0</mtu>
  <no-direct-access-to-local-network>no</no-direct-access-to-local-network>
  <access-routes><member>10.0.0.0/8</member><member>192.0.2.0/255.255.255.0</member><member>172.16.1.1</member><member>2001:db8::/32</member></access-routes>
  <exclude-access-routes><member>10.9.0.0/16</member></exclude-access-routes>
  <ipsec>
    <udp-port>4501</udp-port>
    <ipsec-mode>esp-tunnel</ipsec-mode>
    <enc-algo>aes-128-cbc</enc-algo>
    <hmac-algo>sha1</hmac-algo>
    <c2s-spi>0xCAFE0001</c2s-spi>
    <s2c-spi>0x0BEEF002</s2c-spi>
    <akey-s2c><bits>160</bits><val>0102030405060708090a0b0c0d0e0f1011121314</val></akey-s2c>
    <ekey-s2c><bits>128</bits><val>a0a1a2a3a4a5a6a7a8a9aaabacadaeaf</val></ekey-s2c>
    <akey-c2s><bits>160</bits><val>1112131415161718191a1b1c1d1e1f2021222324</val></akey-c2s>
    <ekey-c2s><bits>128</bits><val>b0b1b2b3b4b5b6b7b8b9babbbcbdbebf</val></ekey-c2s>
  </ipsec>
</response>"#;

    #[test]
    fn getconfig_parsed() {
        let c = parse(&xml::parse(SAMPLE).unwrap()).unwrap();
        assert_eq!(c.address, Some(Ipv4Addr::new(198, 51, 100, 7)));
        assert_eq!(c.prefix(), 32);
        assert_eq!(c.dns, vec![Ipv4Addr::new(198, 51, 100, 53), Ipv4Addr::new(198, 51, 100, 54)]);
        assert_eq!(c.domains, vec!["corp.example.com", "example.net"]);
        let inc: Vec<_> = c.include.iter().map(Route::to_cidr).collect();
        assert_eq!(inc, vec!["10.0.0.0/8", "192.0.2.0/24", "172.16.1.1/32"]);
        assert_eq!(c.exclude[0].to_cidr(), "10.9.0.0/16");
        assert!(!c.default_route);
        assert_eq!((c.timeout, c.lifetime, c.idle_timeout), (10800, 2592000, 3600));
        assert_eq!(c.gw_address, Some(Ipv4Addr::new(203, 0, 113, 10)));
        let esp = c.esp.unwrap();
        assert_eq!((esp.udp_port, esp.c2s_spi, esp.s2c_spi), (4501, 0xCAFE0001, 0x0BEEF002));
        assert_eq!(esp.ekey_c2s.len(), 16);
        assert_eq!(esp.akey_s2c.len(), 20);
        let sa = esp.sa().unwrap();
        assert_eq!((sa.spi_in, sa.spi_out), (0x0BEEF002, 0xCAFE0001));
    }

    #[test]
    fn full_tunnel_and_no_esp() {
        let doc = "<response status=\"success\"><ip-address>198.51.100.9</ip-address><access-routes><member>0.0.0.0/0</member></access-routes></response>";
        let c = parse(&xml::parse(doc).unwrap()).unwrap();
        assert!(c.default_route && c.include.is_empty() && c.esp.is_none());
        assert_eq!(c.tunnel_path, "/ssl-tunnel-connect.sslvpn");
    }

    #[test]
    fn bad_key_length_drops_esp() {
        let doc = "<response status=\"success\"><ipsec><udp-port>4501</udp-port><c2s-spi>0x1</c2s-spi><s2c-spi>0x2</s2c-spi><ekey-c2s><bits>128</bits><val>00</val></ekey-c2s></ipsec></response>";
        assert!(parse(&xml::parse(doc).unwrap()).unwrap().esp.is_none());
    }

    #[test]
    fn esp_keys_interoperate() {
        // Our outbound SA must be decodable by a peer holding the mirrored keys.
        let c = parse(&xml::parse(SAMPLE).unwrap()).unwrap();
        let esp = c.esp.unwrap();
        let client = esp.sa().unwrap();
        let mirrored = EspParams {
            c2s_spi: esp.s2c_spi,
            s2c_spi: esp.c2s_spi,
            ekey_c2s: esp.ekey_s2c.clone(),
            ekey_s2c: esp.ekey_c2s.clone(),
            akey_c2s: esp.akey_s2c.clone(),
            akey_s2c: esp.akey_c2s.clone(),
            ..esp.clone()
        };
        let server = mirrored.sa().unwrap();
        let pkt: Vec<u8> = (0..77).collect();
        assert_eq!(server.decode(&client.encode(&pkt).unwrap()).unwrap(), pkt);
        assert_eq!(client.decode(&server.encode(&pkt).unwrap()).unwrap(), pkt);
        for h in ["md5", "sha256"] {
            let p = EspParams { hmac: h.into(), ..mirrored.clone() };
            let q = EspParams { hmac: h.into(), ..esp.clone() };
            assert_eq!(q.sa().unwrap().decode(&p.sa().unwrap().encode(&pkt).unwrap()).unwrap(), pkt);
        }
    }
}
