//! `PUSH_REPLY` parsing: the server's per-client configuration.
//!
//! The reply is a comma-separated option list (`PUSH_REPLY,route 10.0.0.0
//! 255.0.0.0,ifconfig 10.8.0.6 10.8.0.5,peer-id 3,cipher AES-256-GCM,…`), split
//! over several messages when long (`push-continuation 2` = more follow, `1` =
//! last). Only options a client acts on are kept.

use super::config::Compress;
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topology {
    Net30,
    P2p,
    Subnet,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Route {
    pub net: Ipv4Addr,
    pub mask: Ipv4Addr,
    /// `net_gateway`: route OUTSIDE the tunnel (an exclude).
    pub bypass: bool,
}

impl Route {
    pub fn to_cidr(&self) -> String {
        format!("{}/{}", self.net, crate::tun::mask_to_prefix(self.mask))
    }
}

#[derive(Clone, Debug, Default)]
pub struct PushConfig {
    pub ifconfig: Option<(Ipv4Addr, Ipv4Addr)>,
    pub topology: Option<Topology>,
    pub route_gateway: Option<Ipv4Addr>,
    pub routes: Vec<Route>,
    pub redirect_gateway: bool,
    pub dns: Vec<Ipv4Addr>,
    pub domains: Vec<String>,
    pub peer_id: Option<u32>,
    pub cipher: Option<String>,
    pub auth: Option<String>,
    pub ping: Option<u64>,
    pub ping_restart: Option<u64>,
    pub tun_mtu: Option<u16>,
    pub compress: Option<Compress>,
    /// `key-derivation tls-ekm` / `protocol-flags … tls-ekm`.
    pub tls_ekm: bool,
    pub auth_token: Option<String>,
    pub auth_token_user: Option<String>,
    pub ignored: Vec<String>,
}

impl PushConfig {
    /// Returns true when this was the last part.
    pub fn merge(&mut self, msg: &str) -> bool {
        let body = msg.strip_prefix("PUSH_REPLY").unwrap_or(msg).trim_start_matches(',');
        let mut last = true;
        for opt in body.split(',') {
            let w: Vec<&str> = opt.split_whitespace().collect();
            if w.is_empty() {
                continue;
            }
            let a = |n: usize| w.get(n).copied();
            match w[0] {
                "push-continuation" => last = a(1) != Some("2"),
                "ifconfig" => {
                    if let (Some(l), Some(r)) = (a(1).and_then(ip), a(2).and_then(ip)) {
                        self.ifconfig = Some((l, r));
                    }
                }
                "topology" => {
                    self.topology = match a(1) {
                        Some("subnet") => Some(Topology::Subnet),
                        Some("p2p") => Some(Topology::P2p),
                        _ => Some(Topology::Net30),
                    }
                }
                "route-gateway" => self.route_gateway = a(1).and_then(ip),
                "route" => {
                    if let Some(r) = parse_route(&w[1..]) {
                        self.routes.push(r);
                    }
                }
                "redirect-gateway" | "redirect-private" => {
                    if w[0] == "redirect-gateway" {
                        self.redirect_gateway = true;
                    }
                }
                "dhcp-option" => self.dhcp_option(&w[1..]),
                // OpenVPN 2.6 `dns` option: `dns server <n> address <ip>…`, `dns search-domains …`.
                "dns" => match a(1) {
                    Some("server") if a(3) == Some("address") => {
                        for addr in &w[4..] {
                            // `ip[:port]` or an IPv6 literal — keep plain IPv4 only.
                            if let Some(v) = ip(addr.split(':').next().unwrap_or(addr)) {
                                if !self.dns.contains(&v) {
                                    self.dns.push(v);
                                }
                            }
                        }
                    }
                    Some("server") if a(3) == Some("resolve-domains") => self.domains.extend(w[4..].iter().map(|s| s.to_string())),
                    Some("search-domains") => self.domains.extend(w[2..].iter().map(|s| s.to_string())),
                    _ => {}
                },
                "peer-id" => self.peer_id = a(1).and_then(|s| s.parse().ok()),
                "cipher" => self.cipher = a(1).map(|s| s.to_ascii_uppercase()),
                "auth" => self.auth = a(1).map(|s| s.to_ascii_uppercase()),
                "ping" => self.ping = a(1).and_then(|s| s.parse().ok()),
                "ping-restart" => self.ping_restart = a(1).and_then(|s| s.parse().ok()),
                "tun-mtu" => self.tun_mtu = a(1).and_then(|s| s.parse().ok()),
                "comp-lzo" => self.compress = Some(Compress::Lzo),
                "compress" => {
                    self.compress = Some(match a(1) {
                        Some("stub-v2") | Some("lz4-v2") => Compress::StubV2,
                        Some("lzo") => Compress::Lzo,
                        _ => Compress::Stub,
                    })
                }
                "key-derivation" => self.tls_ekm |= a(1) == Some("tls-ekm"),
                "protocol-flags" => self.tls_ekm |= w[1..].contains(&"tls-ekm"),
                "auth-token" => self.auth_token = a(1).map(str::to_string),
                "auth-token-user" => {
                    self.auth_token_user = a(1).and_then(|b| openssl::base64::decode_block(b).ok()).and_then(|v| String::from_utf8(v).ok())
                }
                "route-ipv6" | "ifconfig-ipv6" | "tun-ipv6" | "block-outside-dns" | "register-dns" => {
                    self.ignored.push(w[0].to_string())
                }
                _ => {}
            }
        }
        last
    }

    pub fn dhcp_option(&mut self, w: &[&str]) {
        match w.first().copied() {
            Some("DNS") => {
                if let Some(v) = w.get(1).and_then(|s| ip(s)) {
                    if !self.dns.contains(&v) {
                        self.dns.push(v);
                    }
                }
            }
            Some("DOMAIN") | Some("DOMAIN-SEARCH") | Some("ADAPTER_DOMAIN_SUFFIX") => {
                if let Some(d) = w.get(1) {
                    if !self.domains.iter().any(|x| x == d) {
                        self.domains.push(d.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    pub fn topology(&self) -> Topology {
        if let Some(t) = self.topology {
            return t;
        }
        // No explicit topology: `ifconfig local mask` is subnet, `local remote` is p2p.
        match self.ifconfig {
            Some((_, b)) if is_netmask(b) => Topology::Subnet,
            _ => Topology::Net30,
        }
    }
}

/// `route <net> [mask] [gateway] [metric]`.
pub fn parse_route(w: &[&str]) -> Option<Route> {
    let net = ip(w.first()?)?;
    let mask = w.get(1).and_then(|m| ip(m)).unwrap_or(Ipv4Addr::BROADCAST);
    let bypass = w.get(2).is_some_and(|g| *g == "net_gateway");
    Some(Route { net, mask, bypass })
}

fn ip(s: &str) -> Option<Ipv4Addr> {
    s.parse().ok()
}

fn is_netmask(m: Ipv4Addr) -> bool {
    let v = u32::from(m);
    v != 0 && v.leading_ones() + v.trailing_zeros() == 32 && v.leading_ones() >= 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typical_reply() {
        let mut p = PushConfig::default();
        let last = p.merge(
            "PUSH_REPLY,route 10.20.0.0 255.255.0.0,route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 120,\
             dhcp-option DNS 10.20.0.2,dhcp-option DOMAIN corp.example,ifconfig 10.8.0.6 255.255.255.0,peer-id 3,\
             cipher AES-256-GCM,protocol-flags cc-exit tls-ekm dyn-tls-crypt,auth-token SESS_ID_xyz",
        );
        assert!(last);
        assert_eq!(p.ifconfig, Some(("10.8.0.6".parse().unwrap(), "255.255.255.0".parse().unwrap())));
        assert_eq!(p.topology(), Topology::Subnet);
        assert_eq!(p.routes, vec![Route { net: "10.20.0.0".parse().unwrap(), mask: "255.255.0.0".parse().unwrap(), bypass: false }]);
        assert_eq!(p.dns, vec!["10.20.0.2".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(p.domains, vec!["corp.example"]);
        assert_eq!((p.peer_id, p.ping, p.ping_restart), (Some(3), Some(10), Some(120)));
        assert_eq!(p.cipher.as_deref(), Some("AES-256-GCM"));
        assert!(p.tls_ekm);
        assert_eq!(p.auth_token.as_deref(), Some("SESS_ID_xyz"));
    }

    #[test]
    fn continuation_and_net30() {
        let mut p = PushConfig::default();
        assert!(!p.merge("PUSH_REPLY,route 192.168.1.0 255.255.255.0,push-continuation 2"));
        assert!(p.merge("PUSH_REPLY,ifconfig 10.8.0.6 10.8.0.5,redirect-gateway def1,push-continuation 1"));
        assert_eq!(p.routes.len(), 1);
        assert!(p.redirect_gateway);
        assert_eq!(p.topology(), Topology::Net30);
    }

    #[test]
    fn new_dns_option_and_bypass_route() {
        let mut p = PushConfig::default();
        p.merge("PUSH_REPLY,dns server 0 address 10.0.0.53 10.0.0.54,dns search-domains a.example b.example,route 1.2.3.4 255.255.255.255 net_gateway");
        assert_eq!(p.dns.len(), 2);
        assert_eq!(p.domains, vec!["a.example", "b.example"]);
        assert!(p.routes[0].bypass);
        assert_eq!(p.routes[0].to_cidr(), "1.2.3.4/32");
    }
}
