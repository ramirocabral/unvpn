//! The tunnel configuration the gateway hands over after login.
//!
//! On the IF-T/TLS data plane the address, DNS, routes and the optional
//! ESP-over-UDP keys arrive as binary attributes inside the configuration
//! messages. They are collected here into [`IvantiConfig`]; the ESP keys build
//! an [`EspSa`](crate::ike::esp::EspSa) exactly like the other back-ends, so the
//! same data-plane crypto is reused.

use crate::anyconnect::config::Route;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Default)]
pub struct IvantiConfig {
    pub address: Option<Ipv4Addr>,
    pub netmask: Option<Ipv4Addr>,
    pub mtu: u32,
    pub dns: Vec<Ipv4Addr>,
    pub domains: Vec<String>,
    pub include: Vec<Route>,
    pub exclude: Vec<Route>,
    /// Full tunnel (no split includes, or a `0.0.0.0/0` include).
    pub default_route: bool,
    /// Seconds until the session must be re-established (0 = none).
    pub timeout: u64,
    /// ESP-over-UDP data channel, when the gateway offers it.
    pub esp: Option<EspParams>,
}

impl IvantiConfig {
    pub fn prefix(&self) -> u8 {
        self.netmask.map(crate::tun::mask_to_prefix).unwrap_or(32)
    }
}

/// ESP-over-UDP parameters delivered by the gateway (no IKE).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EspParams {
        EspParams {
            udp_port: 4500,
            enc: "aes-128-cbc".into(),
            hmac: "sha1".into(),
            c2s_spi: 0xCAFE0001,
            s2c_spi: 0x0BEEF002,
            ekey_c2s: vec![0xb0; 16],
            ekey_s2c: vec![0xa0; 16],
            akey_c2s: vec![0x11; 20],
            akey_s2c: vec![0x01; 20],
        }
    }

    #[test]
    fn esp_keys_interoperate() {
        let esp = sample();
        let client = esp.sa().unwrap();
        assert_eq!((client.spi_in, client.spi_out), (0x0BEEF002, 0xCAFE0001));
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
    }

    #[test]
    fn rejects_incomplete_keys() {
        let bad = EspParams { akey_c2s: Vec::new(), ..sample() };
        assert!(bad.sa().is_err());
    }
}
