//! Parse the tunnel configuration the gateway returns in the CSTP `CONNECT`
//! response headers (`X-CSTP-*` and `X-DTLS-*`), into the address, routes, DNS,
//! MTU and liveness timers the data plane needs.
//!
//! Header semantics follow the real client as implemented by openconnect
//! `cstp.c` (`start_cstp_connection`): `X-CSTP-Address`/`Netmask` give the
//! assigned IP; `Split-Include`/`Split-Exclude` are CIDR or `addr/mask` routes
//! (no splits + no "tunnel everything" marker ⇒ full tunnel); `DNS`, `NBNS`,
//! `Default-Domain`, `Split-DNS`; `MTU` the tunnel MTU; `Keepalive`, `DPD`,
//! `Rekey-Time`/`Rekey-Method`, `Idle-Timeout`, `Disconnected-Timeout`. DTLS
//! headers carry the UDP port, cipher and DTLS session id/keepalive.

use std::net::Ipv4Addr;

/// IPv6 split routes are recognised but ignored (the data plane is IPv4-only).
#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    pub net: Ipv4Addr,
    pub prefix: u8,
}

impl Route {
    pub fn to_cidr(&self) -> String {
        format!("{}/{}", self.net, self.prefix)
    }
}

#[derive(Debug, Clone, Default)]
pub struct TunnelConfig {
    pub address: Option<Ipv4Addr>,
    pub netmask: Option<Ipv4Addr>,
    pub mtu: u32,
    pub dns: Vec<Ipv4Addr>,
    pub nbns: Vec<Ipv4Addr>,
    pub domains: Vec<String>,
    pub split_dns: Vec<String>,
    pub split_include: Vec<Route>,
    pub split_exclude: Vec<Route>,
    pub default_route: bool,
    pub banner: Option<String>,

    // Liveness / lifetime (seconds; 0 = unset).
    pub keepalive: u32,
    pub dpd: u32,
    pub rekey: u32,
    pub rekey_ssl: bool, // rekey by SSL rehandshake vs new tunnel
    pub idle_timeout: u32,
    pub session_timeout: u32,
    pub disconnect_timeout: u32,

    pub dtls_port: u16,
    pub dtls_cipher: Option<String>,
    /// `X-DTLS12-CipherSuite`: the server's chosen DTLS 1.2 cipher. When set, the
    /// gateway is a modern ASA that wants DTLS 1.2 (not the legacy DTLS1_BAD_VER).
    pub dtls12_cipher: Option<String>,
    pub dtls_keepalive: u32,
    pub dtls_dpd: u32,
    /// `X-DTLS-Session-ID` decoded from hex (32 bytes) — the id for the fake
    /// session-resume DTLS handshake.
    pub dtls_session_id: Vec<u8>,
}

impl TunnelConfig {
    pub fn from_headers(headers: &[(String, String)]) -> Self {
        let mut c = TunnelConfig::default();
        for (k, v) in headers {
            let v = v.trim();
            if let Some(name) = strip_ci(k, "X-DTLS12-") {
                if name.eq_ignore_ascii_case("CipherSuite") {
                    c.dtls12_cipher = Some(v.to_string());
                }
            } else if let Some(name) = strip_ci(k, "X-CSTP-") {
                c.apply_cstp(&name.to_ascii_lowercase(), v);
            } else if let Some(name) = strip_ci(k, "X-DTLS-") {
                c.apply_dtls(&name.to_ascii_lowercase(), v);
            }
        }
        c.default_route = c.split_include.is_empty();
        c
    }

    fn apply_cstp(&mut self, name: &str, v: &str) {
        match name {
            "address" => {
                if let Ok(ip) = v.parse() {
                    self.address = Some(ip); // ignore IPv6 (has ':')
                }
            }
            "netmask" => {
                if let Ok(m) = v.parse() {
                    self.netmask = Some(m);
                }
            }
            "mtu" => self.mtu = v.parse().unwrap_or(self.mtu),
            "dns" => push_ip(&mut self.dns, v),
            "nbns" => push_ip(&mut self.nbns, v),
            "default-domain" => push_domains(&mut self.domains, v),
            "split-dns" => self.split_dns.push(v.to_string()),
            "split-include" => push_route(&mut self.split_include, v),
            "split-exclude" => push_route(&mut self.split_exclude, v),
            "banner" => self.banner = Some(decode_banner(v)),
            "keepalive" => self.keepalive = v.parse().unwrap_or(0),
            "dpd" => self.dpd = v.parse().unwrap_or(0),
            "rekey-time" => self.rekey = v.parse().unwrap_or(0),
            "rekey-method" => self.rekey_ssl = v.eq_ignore_ascii_case("ssl"),
            "idle-timeout" => self.idle_timeout = v.parse().unwrap_or(0),
            "session-timeout" => self.session_timeout = v.parse().unwrap_or(0),
            "disconnected-timeout" => self.disconnect_timeout = v.parse().unwrap_or(0),
            _ => {}
        }
    }

    fn apply_dtls(&mut self, name: &str, v: &str) {
        match name {
            "port" => self.dtls_port = v.parse().unwrap_or(0),
            "ciphersuite" => self.dtls_cipher = Some(v.to_string()),
            "keepalive" => self.dtls_keepalive = v.parse().unwrap_or(0),
            "dpd" => self.dtls_dpd = v.parse().unwrap_or(0),
            "session-id" => self.dtls_session_id = decode_hex(v),
            _ => {}
        }
    }

    pub fn prefix(&self) -> u8 {
        self.netmask.map(|m| u32::from(m).count_ones() as u8).unwrap_or(32)
    }
}

fn strip_ci<'a>(k: &'a str, prefix: &str) -> Option<&'a str> {
    if k.len() >= prefix.len() && k[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&k[prefix.len()..])
    } else {
        None
    }
}

fn push_ip(v: &mut Vec<Ipv4Addr>, s: &str) {
    if let Ok(ip) = s.parse() {
        v.push(ip);
    }
}

fn push_domains(v: &mut Vec<String>, s: &str) {
    for d in s.split([',', ' ', ';']).filter(|s| !s.is_empty()) {
        v.push(d.to_string());
    }
}

/// Parse a split route: `addr/prefix` or `addr/dotted-mask` or a bare `addr`
/// (host route). IPv6 (`:` present) is skipped.
fn push_route(v: &mut Vec<Route>, s: &str) {
    if s.contains(':') {
        return;
    }
    let (addr, pfx) = match s.split_once('/') {
        Some((a, p)) => {
            let prefix = p
                .parse::<u8>()
                .ok()
                .or_else(|| p.parse::<Ipv4Addr>().ok().map(|m| u32::from(m).count_ones() as u8));
            (a, prefix)
        }
        None => (s, Some(32)),
    };
    if let (Ok(net), Some(prefix)) = (addr.parse::<Ipv4Addr>(), pfx) {
        if prefix <= 32 {
            v.push(Route { net, prefix });
        }
    }
}

fn decode_hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let nyb = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut i = 0;
    while i + 1 < b.len() {
        match (nyb(b[i]), nyb(b[i + 1])) {
            (Some(h), Some(l)) => out.push((h << 4) | l),
            _ => return Vec::new(),
        }
        i += 2;
    }
    out
}

/// The banner may be URL-encoded (`%XX`) and `+`-spaced, like Cisco sends it.
fn decode_banner(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn full_tunnel_with_dns_and_mtu() {
        let c = TunnelConfig::from_headers(&h(&[
            ("X-CSTP-Address", "10.20.30.40"),
            ("X-CSTP-Netmask", "255.255.255.0"),
            ("X-CSTP-MTU", "1390"),
            ("X-CSTP-DNS", "10.0.0.53"),
            ("X-CSTP-DNS", "10.0.0.54"),
            ("X-CSTP-Default-Domain", "corp.example.com"),
            ("X-CSTP-Keepalive", "20"),
            ("X-CSTP-DPD", "30"),
            ("X-CSTP-Rekey-Time", "3600"),
            ("X-CSTP-Rekey-Method", "ssl"),
        ]));
        assert_eq!(c.address, Some("10.20.30.40".parse().unwrap()));
        assert_eq!(c.prefix(), 24);
        assert_eq!(c.mtu, 1390);
        let want_dns: Vec<Ipv4Addr> = vec!["10.0.0.53".parse().unwrap(), "10.0.0.54".parse().unwrap()];
        assert_eq!(c.dns, want_dns);
        assert_eq!(c.domains, vec!["corp.example.com".to_string()]);
        assert!(c.default_route);
        assert_eq!((c.keepalive, c.dpd, c.rekey), (20, 30, 3600));
        assert!(c.rekey_ssl);
    }

    #[test]
    fn split_tunnel_routes() {
        let c = TunnelConfig::from_headers(&h(&[
            ("X-CSTP-Address", "192.168.50.7"),
            ("X-CSTP-Split-Include", "10.0.0.0/255.0.0.0"),
            ("X-CSTP-Split-Include", "172.16.0.0/12"),
            ("X-CSTP-Split-Exclude", "172.16.9.0/24"),
            ("X-CSTP-Split-Include", "2001:db8::/32"),
            ("X-DTLS-Port", "443"),
            ("X-DTLS-CipherSuite", "DHE-RSA-AES256-SHA"),
            ("X-DTLS-Session-ID", "00112233445566778899aabbccddeeff00112233445566778899AABBCCDDEEFF"),
        ]));
        assert!(!c.default_route);
        assert_eq!(c.split_include, vec![
            Route { net: "10.0.0.0".parse().unwrap(), prefix: 8 },
            Route { net: "172.16.0.0".parse().unwrap(), prefix: 12 },
        ]);
        assert_eq!(c.split_exclude[0].to_cidr(), "172.16.9.0/24");
        assert_eq!(c.dtls_port, 443);
        assert_eq!(c.dtls_cipher.as_deref(), Some("DHE-RSA-AES256-SHA"));
        assert_eq!(c.dtls_session_id.len(), 32);
        assert_eq!(c.dtls_session_id[0], 0x00);
        assert_eq!(c.dtls_session_id[31], 0xff);
    }

    #[test]
    fn hex_decode() {
        assert_eq!(decode_hex("00ff10"), vec![0x00, 0xff, 0x10]);
        assert_eq!(decode_hex("DEAD"), vec![0xde, 0xad]);
        assert!(decode_hex("abc").is_empty());
        assert!(decode_hex("zz").is_empty());
    }

    #[test]
    fn banner_is_url_decoded() {
        let c = TunnelConfig::from_headers(&h(&[("X-CSTP-Banner", "Welcome+to%20the%20VPN")]));
        assert_eq!(c.banner.as_deref(), Some("Welcome to the VPN"));
    }

    #[test]
    fn host_route_and_case_insensitive_headers() {
        let c = TunnelConfig::from_headers(&h(&[("x-cstp-split-include", "10.1.2.3")]));
        assert_eq!(c.split_include, vec![Route { net: "10.1.2.3".parse().unwrap(), prefix: 32 }]);
    }
}
