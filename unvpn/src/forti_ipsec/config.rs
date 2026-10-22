//! Turn the IKE_AUTH response's Configuration payload (CP, RFC 7296 §3.15) and the
//! responder traffic selectors (TSr) into the tunnel's IP, DNS, search domains and
//! split routes. FortiGate pushes the client's internal IP and DNS as CP attributes
//! and the reachable corporate subnets as `INTERNAL_IP4_SUBNET` attributes and/or
//! narrowed TSr ranges.

#![allow(dead_code)]

use std::net::Ipv4Addr;

use super::wire::{Payload, TrafficSelector};
use super::model::{CfgAttr, CfgType, TS_IPV4_ADDR_RANGE};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    pub assigned_ip: Option<Ipv4Addr>,
    pub netmask: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domains: String,
    /// Split-include routes as (network, prefix_len). Empty ⇒ full tunnel.
    pub routes: Vec<(Ipv4Addr, u8)>,
    pub app_version: Option<String>,
}

fn v4(b: &[u8]) -> Option<Ipv4Addr> {
    if b.len() == 4 {
        Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
    } else {
        None
    }
}

/// Build the tunnel config from the decrypted IKE_AUTH response payloads.
pub fn from_payloads(payloads: &[Payload]) -> TunnelConfig {
    let mut cfg = TunnelConfig::default();
    let mut domains: Vec<String> = Vec::new();

    for p in payloads {
        match p {
            Payload::Cp { cfg_type, attrs } if *cfg_type == u8::from(CfgType::Reply) => {
                for (t, val) in attrs {
                    match CfgAttr::from(*t) {
                        CfgAttr::InternalIp4Address => cfg.assigned_ip = v4(val).or(cfg.assigned_ip),
                        CfgAttr::InternalIp4Netmask => cfg.netmask = v4(val),
                        CfgAttr::InternalIp4Dns => {
                            if let Some(a) = v4(val) {
                                if !a.is_unspecified() {
                                    cfg.dns.push(a);
                                }
                            }
                        }
                        CfgAttr::InternalIp4Subnet => {
                            // addr(4) | mask(4)
                            if val.len() == 8 {
                                if let (Some(net), Some(mask)) = (v4(&val[0..4]), v4(&val[4..8])) {
                                    cfg.routes.push((net, prefix_of(mask)));
                                }
                            }
                        }
                        CfgAttr::InternalDnsDomain => {
                            if let Ok(s) = std::str::from_utf8(val) {
                                let s = s.trim_matches('\0').trim();
                                if !s.is_empty() {
                                    domains.push(s.to_string());
                                }
                            }
                        }
                        CfgAttr::ApplicationVersion => {
                            cfg.app_version = std::str::from_utf8(val).ok().map(|s| s.to_string());
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    // If the gateway didn't push explicit subnets, derive routes from the responder
    // traffic selectors (the ranges it agreed to route). A 0.0.0.0-255.255.255.255
    // TSr means a full tunnel → leave routes empty.
    if cfg.routes.is_empty() {
        for p in payloads {
            if let Payload::Tsr(ts) = p {
                for sel in ts {
                    if let Some((net, prefix)) = ts_route(sel) {
                        if !(net.is_unspecified() && prefix == 0) {
                            cfg.routes.push((net, prefix));
                        }
                    }
                }
            }
        }
    }

    cfg.domains = domains.join(" ");
    cfg
}

/// A TSr IPv4 range as a single CIDR route, when it is prefix-aligned (FortiGate
/// sends subnet-aligned selectors). Returns `None` for a non-IPv4 or ragged range.
fn ts_route(ts: &TrafficSelector) -> Option<(Ipv4Addr, u8)> {
    if ts.ts_type != TS_IPV4_ADDR_RANGE || ts.start_addr.len() != 4 || ts.end_addr.len() != 4 {
        return None;
    }
    let start = u32::from_be_bytes(ts.start_addr[..4].try_into().ok()?);
    let end = u32::from_be_bytes(ts.end_addr[..4].try_into().ok()?);
    range_to_prefix(start, end).map(|(net, p)| (Ipv4Addr::from(net), p))
}

/// The prefix length of a dotted netmask (e.g. 255.255.248.0 → 21).
pub fn prefix_of(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

/// If `[start, end]` is exactly one CIDR block, return `(network, prefix_len)`.
fn range_to_prefix(start: u32, end: u32) -> Option<(u32, u8)> {
    if start > end {
        return None;
    }
    let size = (end - start) as u64 + 1;
    if !size.is_power_of_two() {
        return None;
    }
    let prefix = 32 - size.trailing_zeros() as u8;
    // start must be aligned to the block.
    if size == (1u64 << 32) {
        return Some((0, 0));
    }
    if start % (size as u32) != 0 {
        return None;
    }
    Some((start, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::model::{CfgType, TS_IPV4_ADDR_RANGE};
    use super::super::wire::TrafficSelector;

    #[test]
    fn parse_cp_reply_ip_dns_subnets_domain() {
        let cp = Payload::Cp {
            cfg_type: CfgType::Reply.into(),
            attrs: vec![
                (CfgAttr::InternalIp4Address.into(), vec![10, 212, 134, 9]),
                (CfgAttr::InternalIp4Netmask.into(), vec![255, 255, 255, 255]),
                (CfgAttr::InternalIp4Dns.into(), vec![10, 0, 0, 53]),
                (CfgAttr::InternalIp4Dns.into(), vec![10, 0, 0, 54]),
                (CfgAttr::InternalIp4Subnet.into(), vec![10, 0, 0, 0, 255, 0, 0, 0]),
                (CfgAttr::InternalIp4Subnet.into(), vec![172, 16, 0, 0, 255, 240, 0, 0]),
                (CfgAttr::InternalDnsDomain.into(), b"corp.example.com".to_vec()),
            ],
        };
        let cfg = from_payloads(&[cp]);
        assert_eq!(cfg.assigned_ip, Some(Ipv4Addr::new(10, 212, 134, 9)));
        assert_eq!(cfg.dns, vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)]);
        assert_eq!(cfg.routes, vec![
            (Ipv4Addr::new(10, 0, 0, 0), 8),
            (Ipv4Addr::new(172, 16, 0, 0), 12),
        ]);
        assert_eq!(cfg.domains, "corp.example.com");
    }

    #[test]
    fn routes_fall_back_to_tsr_when_no_subnets() {
        let cp = Payload::Cp {
            cfg_type: CfgType::Reply.into(),
            attrs: vec![(CfgAttr::InternalIp4Address.into(), vec![10, 1, 1, 5])],
        };
        let tsr = Payload::Tsr(vec![TrafficSelector {
            ts_type: TS_IPV4_ADDR_RANGE,
            ip_protocol: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: vec![10, 50, 0, 0],
            end_addr: vec![10, 50, 255, 255],
        }]);
        let cfg = from_payloads(&[cp, tsr]);
        assert_eq!(cfg.routes, vec![(Ipv4Addr::new(10, 50, 0, 0), 16)]);
    }

    #[test]
    fn full_tunnel_tsr_yields_no_routes() {
        let tsr = Payload::Tsr(vec![TrafficSelector::ipv4_any()]);
        let cfg = from_payloads(&[tsr]);
        assert!(cfg.routes.is_empty());
    }

    #[test]
    fn range_to_prefix_cases() {
        assert_eq!(range_to_prefix(0x0a000000, 0x0a0000ff), Some((0x0a000000, 24)));
        assert_eq!(range_to_prefix(0x0a000000, 0x0affffff), Some((0x0a000000, 8)));
        assert_eq!(range_to_prefix(0, u32::MAX), Some((0, 0)));
        // Non-aligned start.
        assert_eq!(range_to_prefix(0x0a000001, 0x0a0000ff), None);
        // Non power-of-two size.
        assert_eq!(range_to_prefix(0x0a000000, 0x0a0000fe), None);
    }
}
