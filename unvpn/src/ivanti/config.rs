//! The tunnel configuration the gateway sends right after authentication.
//!
//! Juniper messages of type 1 on the IF-T/TLS connection, until one of type
//! 0x8f ends the list. Two kinds share a header (16 zero bytes, a kind word, a
//! zero word, the payload length): the main configuration — split routes as
//! address ranges, then type/length/value attributes (address, DNS, MTU, ESP
//! algorithms and port) — and the ESP keys for the client→gateway direction,
//! answered with our own keys for the other one. New ESP keys may arrive later on
//! the same connection (rekey).

use super::ift::{self, IftConn};
use crate::anyconnect::config::Route;
use crate::ike::esp::EspSa;
use std::net::Ipv4Addr;

const KIND_CONFIG: u32 = 0x2c20_f000;
/// Newer gateways: attribute blocks before the routes.
const KIND_CONFIG_LEADING_ATTRS: u32 = 0x2e20_f000;
pub const KIND_ESP: u32 = 0x2120_2400;

const ROUTE_INCLUDE: u32 = 0x0700_0010;
const ROUTE_EXCLUDE: u32 = 0xf100_0010;

const ENC_AES_128_CBC: u16 = 2;
const ENC_AES_256_CBC: u16 = 5;
const MAC_MD5: u16 = 1;
const MAC_SHA1: u16 = 2;
const MAC_SHA256: u16 = 3;

/// Size of the secrets field of an ESP key message.
const SECRETS_LEN: usize = 0x40;

#[derive(Debug, Clone, Default)]
pub struct IvantiConfig {
    pub address: Option<Ipv4Addr>,
    pub netmask: Option<Ipv4Addr>,
    pub mtu: u32,
    pub dns: Vec<Ipv4Addr>,
    pub domains: Vec<String>,
    pub include: Vec<Route>,
    pub exclude: Vec<Route>,
    /// ESP algorithms and port; keys come in their own message.
    pub esp_algs: Option<EspAlgs>,
    /// ESP keys, once exchanged.
    pub esp: Option<EspParams>,
}

impl IvantiConfig {
    pub fn prefix(&self) -> u8 {
        self.netmask.map(crate::tun::mask_to_prefix).unwrap_or(32)
    }

    /// Full tunnel: no split includes, or one covering everything.
    pub fn default_route(&self) -> bool {
        self.include.is_empty() || self.include.iter().any(|r| r.prefix == 0)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct EspAlgs {
    pub enc: u16,
    pub mac: u16,
    pub port: u16,
    /// Seconds without ESP replies before falling back to the SSL tunnel.
    pub fallback_secs: u32,
}

impl EspAlgs {
    fn key_lens(&self) -> Result<(usize, usize), String> {
        let enc = match self.enc {
            ENC_AES_128_CBC => 16,
            ENC_AES_256_CBC => 32,
            e => return Err(format!("unsupported ESP cipher {e:#x}")),
        };
        let mac = match self.mac {
            MAC_MD5 => 16,
            MAC_SHA1 => 20,
            MAC_SHA256 => 32,
            m => return Err(format!("unsupported ESP MAC {m:#x}")),
        };
        Ok((enc, mac))
    }

    pub fn describe(&self) -> String {
        let enc = match self.enc {
            ENC_AES_128_CBC => "aes-128-cbc",
            ENC_AES_256_CBC => "aes-256-cbc",
            _ => "?",
        };
        let mac = match self.mac {
            MAC_MD5 => "md5",
            MAC_SHA1 => "sha1",
            MAC_SHA256 => "sha256",
            _ => "?",
        };
        format!("{enc}/{mac} udp {}", self.port)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EspParams {
    pub algs: EspAlgs,
    /// Client → gateway: chosen by the gateway.
    pub out_spi: u32,
    pub out_enc: Vec<u8>,
    pub out_mac: Vec<u8>,
    /// Gateway → client: ours.
    pub in_spi: u32,
    pub in_enc: Vec<u8>,
    pub in_mac: Vec<u8>,
}

impl EspParams {
    pub fn sa(&self) -> Result<EspSa, String> {
        use openssl::{hash::MessageDigest, symm::Cipher};
        let cipher = match self.algs.enc {
            ENC_AES_128_CBC => Cipher::aes_128_cbc(),
            ENC_AES_256_CBC => Cipher::aes_256_cbc(),
            e => return Err(format!("unsupported ESP cipher {e:#x}")),
        };
        let (digest, icv) = match self.algs.mac {
            MAC_MD5 => (MessageDigest::md5(), 12),
            MAC_SHA1 => (MessageDigest::sha1(), 12),
            MAC_SHA256 => (MessageDigest::sha256(), 16),
            m => return Err(format!("unsupported ESP MAC {m:#x}")),
        };
        Ok(EspSa::from_keys(
            cipher,
            digest,
            icv,
            (self.in_spi, &self.in_enc, &self.in_mac),
            (self.out_spi, &self.out_enc, &self.out_mac),
        ))
    }
}

/// Read the configuration messages up to their end marker, answering the ESP
/// keys on the way unless `esp` is off (then the gateway keeps to the SSL tunnel).
pub fn fetch(c: &mut IftConn, esp: bool) -> Result<IvantiConfig, String> {
    let mut cfg = IvantiConfig::default();
    loop {
        let m = c.recv()?;
        if m.vendor != ift::VENDOR_JUNIPER {
            continue;
        }
        match m.msg_type {
            ift::J_CONFIG_END => break,
            ift::J_FATAL => return Err(ift::fatal_reason(&m.payload)),
            ift::J_CONFIG => {}
            _ => continue,
        }
        match kind(&m.payload) {
            Some(KIND_CONFIG | KIND_CONFIG_LEADING_ATTRS) => parse_main(&m.payload, &mut cfg)?,
            Some(KIND_ESP) if !esp => {}
            Some(KIND_ESP) => match cfg
                .esp_algs
                .ok_or_else(|| "no ESP algorithms".to_string())
                .and_then(|a| esp_answer(a, &m.payload))
            {
                Ok((params, reply)) => {
                    c.send(ift::VENDOR_JUNIPER, ift::J_CONFIG, &reply)?;
                    c.send(ift::VENDOR_JUNIPER, ift::J_ESP_ON, b"ncmo=1\n\0")?;
                    cfg.esp = Some(params);
                }
                Err(e) => out!("# ESP keys not usable ({e}) — SSL tunnel only"),
            },
            _ => out!("# ignoring an unknown configuration message"),
        }
    }
    if cfg.address.is_none() {
        return Err("the gateway assigned no IPv4 address".into());
    }
    Ok(cfg)
}

/// The kind word of a configuration message, if its header is well-formed.
pub fn kind(p: &[u8]) -> Option<u32> {
    let ok = p.len() >= 0x1c
        && p[..0x10].iter().all(|&b| b == 0)
        && ift::be32(p, 0x14) == 0
        && ift::be32(p, 0x18) as usize == p.len();
    ok.then(|| ift::be32(p, 0x10))
}

pub(crate) fn parse_main(p: &[u8], cfg: &mut IvantiConfig) -> Result<(), String> {
    let bad = |what: &str| format!("malformed configuration from the gateway ({what})");
    if p.len() < 0x1c {
        return Err(bad("header"));
    }
    let mut off = 0x1c;
    if ift::be32(p, 0x10) == KIND_CONFIG_LEADING_ATTRS {
        loop {
            if p.len() < off + 4 {
                return Err(bad("attribute block"));
            }
            let flag = ift::be16(p, off);
            let len = usize::from(ift::be16(p, off + 2));
            if len < 8 || p.len() < off + len {
                return Err(bad("attribute block length"));
            }
            attributes(&p[off..off + len], cfg)?;
            off += len;
            if flag == 0x2c00 {
                break;
            }
        }
    }
    if p.len() < off + 8 || ift::be16(p, off) != 0x2e00 {
        return Err(bad("routes"));
    }
    let routes_len = usize::from(ift::be16(p, off + 2));
    let count = usize::from(p[off + 4]);
    if routes_len != count * 16 + 8 || p.len() < off + routes_len + 4 {
        return Err(bad("route count"));
    }
    let attrs_at = off + routes_len;
    let attrs_len = ift::be32(p, attrs_at) as usize;
    if attrs_at + attrs_len != p.len() {
        return Err(bad("attribute length"));
    }
    for e in p[off + 8..attrs_at].as_chunks::<16>().0 {
        if ift::be32(e, 4) != 0xffff {
            return Err(bad("route entry"));
        }
        let start = Ipv4Addr::new(e[8], e[9], e[10], e[11]);
        let mask = Ipv4Addr::new(
            !(e[8] ^ e[12]),
            !(e[9] ^ e[13]),
            !(e[10] ^ e[14]),
            !(e[11] ^ e[15]),
        );
        let route = Route {
            net: start,
            prefix: crate::tun::mask_to_prefix(mask),
        };
        match ift::be32(e, 0) {
            ROUTE_INCLUDE => cfg.include.push(route),
            ROUTE_EXCLUDE => cfg.exclude.push(route),
            t => return Err(format!("unknown route type {t:#010x} from the gateway")),
        }
    }
    attributes(&p[attrs_at..], cfg)
}

/// `length | 03 00 00 00 | (type, length, value)…`
fn attributes(b: &[u8], cfg: &mut IvantiConfig) -> Result<(), String> {
    if b.len() < 8 || ift::be32(b, 4) != 0x0300_0000 {
        return Err("malformed configuration attributes".into());
    }
    let mut rest = &b[8..];
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err("truncated configuration attribute".into());
        }
        let ty = ift::be16(rest, 0);
        let len = usize::from(ift::be16(rest, 2));
        if rest.len() < 4 + len {
            return Err(format!("truncated configuration attribute {ty:#06x}"));
        }
        attribute(cfg, ty, &rest[4..4 + len]);
        rest = &rest[4 + len..];
    }
    Ok(())
}

fn attribute(cfg: &mut IvantiConfig, ty: u16, d: &[u8]) {
    let ip = || (d.len() == 4).then(|| Ipv4Addr::new(d[0], d[1], d[2], d[3]));
    let n16 = || (d.len() == 2).then(|| ift::be16(d, 0));
    let n32 = || (d.len() == 4).then(|| ift::be32(d, 0));
    match ty {
        0x0001 => cfg.address = ip().or(cfg.address),
        0x0002 => cfg.netmask = ip().or(cfg.netmask),
        0x0003 => cfg.dns.extend(ip()),
        0x4005 => cfg.mtu = n32().unwrap_or(cfg.mtu),
        0x4006 => {
            let text = String::from_utf8_lossy(d);
            cfg.domains.extend(
                text.trim_end_matches('\0')
                    .split([',', ' ', ';'])
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            );
        }
        0x4010 | 0x4011 | 0x4016 | 0x4017 => {
            let a = cfg.esp_algs.get_or_insert_with(EspAlgs::default);
            match ty {
                0x4010 => a.enc = n16().unwrap_or(a.enc),
                0x4011 => a.mac = n16().unwrap_or(a.mac),
                0x4016 => a.port = n16().unwrap_or(a.port),
                _ => a.fallback_secs = n32().unwrap_or(a.fallback_secs),
            }
        }
        _ => {}
    }
}

/// The gateway's ESP keys (client→gateway) and our answer carrying fresh keys
/// for the other direction.
pub fn esp_answer(algs: EspAlgs, p: &[u8]) -> Result<(EspParams, Vec<u8>), String> {
    if p.len() < 0x5a
        || ift::be32(p, 0x1c) as usize != p.len() - 0x1c
        || ift::be32(p, 0x20) != 0x0100_0000
        || usize::from(ift::be16(p, 0x28)) != SECRETS_LEN
        || p.len() < 0x2a + SECRETS_LEN
    {
        return Err("malformed ESP key message".into());
    }
    let (enc_len, mac_len) = algs.key_lens()?;
    if algs.port == 0 {
        return Err("no ESP port".into());
    }
    let secrets = &p[0x2a..0x2a + SECRETS_LEN];
    let out_spi = u32::from_le_bytes([p[0x24], p[0x25], p[0x26], p[0x27]]);

    let mut ours = vec![0u8; 4 + enc_len + mac_len];
    loop {
        openssl::rand::rand_bytes(&mut ours).map_err(|e| e.to_string())?;
        if u32::from_le_bytes([ours[0], ours[1], ours[2], ours[3]]) > 0xff {
            break;
        }
    }
    let in_spi = u32::from_le_bytes([ours[0], ours[1], ours[2], ours[3]]);
    let params = EspParams {
        algs,
        out_spi,
        out_enc: secrets[..enc_len].to_vec(),
        out_mac: secrets[enc_len..enc_len + mac_len].to_vec(),
        in_spi,
        in_enc: ours[4..4 + enc_len].to_vec(),
        in_mac: ours[4 + enc_len..].to_vec(),
    };

    let half = SECRETS_LEN + 6;
    let mut r = vec![0u8; 0x10];
    r.extend_from_slice(&KIND_ESP.to_be_bytes());
    r.extend_from_slice(&0u32.to_be_bytes());
    r.extend_from_slice(&((0x24 + 2 * half) as u32).to_be_bytes());
    r.extend_from_slice(&((0x08 + 2 * half) as u32).to_be_bytes());
    r.extend_from_slice(&0x0100_0000u32.to_be_bytes());
    r.extend_from_slice(&in_spi.to_le_bytes());
    r.extend_from_slice(&(SECRETS_LEN as u16).to_be_bytes());
    r.extend_from_slice(&params.in_enc);
    r.extend_from_slice(&params.in_mac);
    r.resize(r.len() + SECRETS_LEN - enc_len - mac_len, 0);
    r.extend_from_slice(&p[0x24..0x24 + half]);
    Ok((params, r))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(kind: u32, body: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 0x10];
        p.extend_from_slice(&kind.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&((0x1c + body.len()) as u32).to_be_bytes());
        p.extend_from_slice(body);
        p
    }

    fn attr(ty: u16, v: &[u8]) -> Vec<u8> {
        let mut a = ty.to_be_bytes().to_vec();
        a.extend_from_slice(&(v.len() as u16).to_be_bytes());
        a.extend_from_slice(v);
        a
    }

    fn main_config(leading: bool) -> Vec<u8> {
        let mut body = Vec::new();
        if leading {
            body.extend_from_slice(&[0x2e, 0, 0, 13, 3, 0, 0, 0]);
            body.extend(attr(0x4026, &[1]));
            body.extend_from_slice(&[0x2c, 0, 0, 13, 3, 0, 0, 0]);
            body.extend(attr(0x4025, &[1]));
        }
        body.extend_from_slice(&[0x2e, 0, 0, 8 + 32, 2, 0, 0, 0]);
        body.extend_from_slice(&ROUTE_INCLUDE.to_be_bytes());
        body.extend_from_slice(&0xffffu32.to_be_bytes());
        body.extend_from_slice(&[10, 0, 0, 0, 10, 0, 63, 255]);
        body.extend_from_slice(&ROUTE_EXCLUDE.to_be_bytes());
        body.extend_from_slice(&0xffffu32.to_be_bytes());
        body.extend_from_slice(&[10, 0, 8, 0, 10, 0, 8, 255]);
        let mut attrs = vec![3, 0, 0, 0];
        attrs.extend(attr(0x0001, &[10, 200, 200, 7]));
        attrs.extend(attr(0x0002, &[255, 255, 255, 0]));
        attrs.extend(attr(0x0003, &[10, 0, 0, 53]));
        attrs.extend(attr(0x0003, &[10, 0, 0, 54]));
        attrs.extend(attr(0x4005, &1400u32.to_be_bytes()));
        attrs.extend(attr(0x4006, b"corp.example\0"));
        attrs.extend(attr(0x4010, &ENC_AES_256_CBC.to_be_bytes()));
        attrs.extend(attr(0x4011, &MAC_SHA1.to_be_bytes()));
        attrs.extend(attr(0x4016, &4500u16.to_be_bytes()));
        attrs.extend(attr(0x4017, &15u32.to_be_bytes()));
        attrs.extend(attr(0x7777, &[1, 2, 3]));
        body.extend_from_slice(&((4 + attrs.len()) as u32).to_be_bytes());
        body.extend(attrs);
        header(
            if leading {
                KIND_CONFIG_LEADING_ATTRS
            } else {
                KIND_CONFIG
            },
            &body,
        )
    }

    #[test]
    fn parses_both_main_config_layouts() {
        for leading in [false, true] {
            let p = main_config(leading);
            assert!(matches!(
                kind(&p),
                Some(KIND_CONFIG | KIND_CONFIG_LEADING_ATTRS)
            ));
            let mut cfg = IvantiConfig::default();
            parse_main(&p, &mut cfg).unwrap();
            assert_eq!(cfg.address, Some(Ipv4Addr::new(10, 200, 200, 7)));
            assert_eq!(cfg.prefix(), 24);
            assert_eq!(cfg.dns.len(), 2);
            assert_eq!(cfg.mtu, 1400);
            assert_eq!(cfg.domains, ["corp.example"]);
            assert_eq!(cfg.include.len(), 1);
            assert_eq!(cfg.include[0].to_cidr(), "10.0.0.0/18");
            assert_eq!(cfg.exclude[0].to_cidr(), "10.0.8.0/24");
            assert!(!cfg.default_route());
            assert_eq!(
                cfg.esp_algs,
                Some(EspAlgs {
                    enc: ENC_AES_256_CBC,
                    mac: MAC_SHA1,
                    port: 4500,
                    fallback_secs: 15
                })
            );
        }
    }

    #[test]
    fn rejects_inconsistent_lengths() {
        let mut p = main_config(false);
        let n = p.len();
        p[n - 1] = 0;
        p.push(0); // trailing byte the attribute length doesn't cover
        let len = p.len() as u32;
        p[0x18..0x1c].copy_from_slice(&len.to_be_bytes());
        assert!(parse_main(&p, &mut IvantiConfig::default()).is_err());
    }

    fn esp_message(spi: u32, secrets: &[u8]) -> Vec<u8> {
        let mut inner = 0x0100_0000u32.to_be_bytes().to_vec();
        inner.extend_from_slice(&spi.to_le_bytes());
        inner.extend_from_slice(&(SECRETS_LEN as u16).to_be_bytes());
        inner.extend_from_slice(secrets);
        inner.resize(4 + 4 + 2 + SECRETS_LEN, 0);
        let mut body = ((4 + inner.len()) as u32).to_be_bytes().to_vec();
        body.extend(inner);
        header(KIND_ESP, &body)
    }

    #[test]
    fn esp_answer_mirrors_and_interoperates() {
        let algs = EspAlgs {
            enc: ENC_AES_128_CBC,
            mac: MAC_SHA1,
            port: 4500,
            fallback_secs: 0,
        };
        let mut secrets = vec![0xe5; 16];
        secrets.extend(vec![0x4a; 20]);
        let msg = esp_message(0x1234_5678, &secrets);
        assert_eq!(kind(&msg), Some(KIND_ESP));
        let (params, reply) = esp_answer(algs, &msg).unwrap();
        assert_eq!(params.out_spi, 0x1234_5678);
        assert_eq!(params.out_enc, vec![0xe5; 16]);
        assert_eq!(params.out_mac, vec![0x4a; 20]);
        // The reply is a well-formed ESP key message of its own …
        assert_eq!(kind(&reply), Some(KIND_ESP));
        assert_eq!(reply.len(), 0x24 + 2 * (SECRETS_LEN + 6));
        assert_eq!(
            u32::from_le_bytes(reply[0x24..0x28].try_into().unwrap()),
            params.in_spi
        );
        assert_eq!(&reply[0x2a..0x3a], &params.in_enc[..]);
        assert_eq!(&reply[0x3a..0x4e], &params.in_mac[..]);
        // … followed by the gateway's own block, unchanged.
        assert_eq!(
            &reply[0x2a + SECRETS_LEN..],
            &msg[0x24..0x24 + SECRETS_LEN + 6]
        );

        // The gateway's view: our outbound is its inbound and the other way round.
        let gw = EspParams {
            algs,
            out_spi: params.in_spi,
            out_enc: params.in_enc.clone(),
            out_mac: params.in_mac.clone(),
            in_spi: params.out_spi,
            in_enc: params.out_enc.clone(),
            in_mac: params.out_mac.clone(),
        }
        .sa()
        .unwrap();
        let me = params.sa().unwrap();
        let pkt: Vec<u8> = (0..60).collect();
        assert_eq!(gw.decode(&me.encode(&pkt).unwrap()).unwrap(), pkt);
        assert_eq!(me.decode(&gw.encode(&pkt).unwrap()).unwrap(), pkt);
    }

    #[test]
    fn esp_answer_needs_known_algorithms() {
        let msg = esp_message(1, &[0; 36]);
        let algs = EspAlgs {
            enc: 9,
            mac: MAC_SHA1,
            port: 4500,
            fallback_secs: 0,
        };
        assert!(esp_answer(algs, &msg).is_err());
        assert!(esp_answer(
            EspAlgs {
                enc: ENC_AES_128_CBC,
                ..algs
            },
            &msg[..0x50]
        )
        .is_err());
    }
}
