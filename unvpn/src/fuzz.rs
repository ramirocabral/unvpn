//! Entry points for fuzzing the parsers that read gateway data, which the
//! engine runs as root. Each takes arbitrary bytes and must neither panic nor
//! hang; results are discarded.

use crate::checkpoint::{ccc, cert};
use crate::net::http;
use crate::ppp::{self, Framing, PppConn};
use std::io::{Cursor, Read, Write};

fn text(data: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(data)
}

/// Control-channel HTTP: responses, chunked bodies, URLs, cookies.
pub fn http(data: &[u8]) {
    let _ = http::read_response(&mut Cursor::new(data), true);
    let _ = http::read_response(&mut Cursor::new(data), false);
    let _ = http::dechunk(data);
    let s = text(data);
    let _ = http::split_url(&s);
    let _ = http::same_host_path("gw.example.com", &s);
    let _ = http::percent_decode(&s);
    let _ = http::form_decode(&s);
    http::Cookies::new().absorb(&s);
}

/// A peer whose bytes are `data`, then silence; what we send is dropped.
struct Peer<'a>(Cursor<&'a [u8]>);

impl Read for Peer<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.read(buf)? {
            0 => Err(std::io::ErrorKind::WouldBlock.into()),
            n => Ok(n),
        }
    }
}

impl Write for Peer<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// PPP in the three framings: frame extraction, data-phase LCP and the
/// LCP/IPCP negotiation against a peer that says `data`.
pub fn ppp(data: &[u8]) {
    for framing in [Framing::Forti, Framing::F5, Framing::Hdlc] {
        let mut c = PppConn::new(Peer(Cursor::new(&[])), framing);
        c.feed(data);
        while let Ok(Some((proto, payload))) = c.take_frame() {
            if proto == ppp::PPP_LCP {
                let _ = ppp::handle_lcp_in(&mut c, &payload);
            }
        }
        let mut c = PppConn::new(Peer(Cursor::new(data)), framing);
        let _ = ppp::negotiate(&mut c, None);
    }
}

/// Check Point IKEv1 messages.
pub fn ikev1(data: &[u8]) {
    use crate::ike::{service, wire::IsakmpMessage};
    if let Ok(m) = IsakmpMessage::decode(data) {
        let _ = service::parse_chosen_suite(&m);
        let _ = service::parse_esp_proposal(&m);
    }
}

/// FortiClient IPsec IKEv2 messages and EAP.
pub fn ikev2(data: &[u8]) {
    use crate::forti_ipsec::{eap, wire};
    if let Ok((h, body)) = wire::parse_header(data) {
        let _ = wire::parse_payloads(h.first_payload, body);
    }
    if let Some((&first, rest)) = data.split_first() {
        let _ = wire::parse_payloads(first, rest);
    }
    let _ = eap::Eap::parse(data);
    let _ = eap::parse_mschap_challenge(data);
    let _ = eap::parse_mschap_success(data);
}

/// Check Point CCC answers.
pub fn ccc(data: &[u8]) {
    if let Ok(p) = ccc::parse(&text(data)) {
        let _ = ccc::encryption_domain(&p);
        let _ = cert::GatewayInfo::from_hello(&p);
    }
}

/// DER from the Check Point internal CA.
pub fn der(data: &[u8]) {
    let _ = cert::der::parse_all(data);
    let _ = cert::der::parse_single(data);
}

/// XML and HTML from AnyConnect, GlobalProtect, Fortinet and F5 gateways.
pub fn xml(data: &[u8]) {
    use crate::{anyconnect, f5, forti, gp};
    let s = text(data);
    if let Ok(root) = anyconnect::xml::parse(&s) {
        let _ = gp::config::parse(&root);
        let _ = gp::auth::parse_prelogin(&root);
        let _ = gp::auth::parse_portal(&root, None);
        let _ = gp::auth::parse_login(&root, "host");
    }
    let _ = anyconnect::xml::decode_entities(&s);
    let _ = anyconnect::auth::parse_reply(&s);
    let _ = gp::auth::parse_saml_result(&s);
    let _ = forti::config::parse(&s);
    let _ = forti::saml::parse_remote_info(&s);
    let _ = f5::config::parse_profile(&s);
    let _ = f5::config::parse_options(&s);
}

/// Tunnel parameters: AnyConnect CSTP headers, OpenVPN push replies and
/// control packets, Ivanti IF-T messages.
pub fn tunnel_config(data: &[u8]) {
    if let Ok((_, headers)) = http::parse_head(data) {
        let _ = crate::anyconnect::config::TunnelConfig::from_headers(&headers);
    }
    let mut push = crate::openvpn::push::PushConfig::default();
    let _ = push.merge(&text(data));
    if let Some((&op, rest)) = data.split_first() {
        let _ = crate::openvpn::packet::decode_rest(op, rest);
    }
    let _ = crate::ivanti::ift::IftMessage::decode(data);
}

/// Every entry point, for a corpus-free smoke run.
pub const ALL: &[(&str, fn(&[u8]))] = &[
    ("http", http),
    ("ppp", ppp),
    ("ikev1", ikev1),
    ("ikev2", ikev2),
    ("ccc", ccc),
    ("der", der),
    ("xml", xml),
    ("tunnel_config", tunnel_config),
];

#[cfg(test)]
mod tests {
    use super::ALL;

    /// xorshift64*: deterministic, so a failure reproduces.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    const SEEDS: &[&[u8]] = &[
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=b\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        b"HTTP/1.1 302 Found\r\nLocation: https://gw.example.com:443/x\r\nContent-Length: 0\r\n\r\n",
        b"\x00\x0c\x50\x50\x00\x06\xff\x03\xc0\x21\x01\x01\x00\x04",
        b"\xf5\x00\x00\x08\xff\x03\xc0\x21\x01\x01\x00\x04",
        b"\x7e\xff\x7d\x23\xc0\x21\x01\x01\x00\x04\x00\x00\x7e",
        b"(CCCserverResponse\n\t:ResponseHeader (\n\t\t:return_code (600)\n\t)\n\t:ResponseData (\n\t\t:ranges ((:from (10.0.0.0) :to (10.0.0.255)))\n\t)\n)\n",
        b"<?xml version=\"1.0\"?><config-auth type=\"auth-request\"><auth id=\"main\"><form><input type=\"text\" name=\"username\"/></form></auth></config-auth>",
        b"<response status=\"success\"><gateways><external><list><entry name=\"gw.example.com\"/></list></external></gateways></response>",
        b"\x30\x82\x00\x05\x02\x01\x01\x04\x00",
        b"PUSH_REPLY,route 10.0.0.0 255.0.0.0,dhcp-option DNS 10.0.0.1,ifconfig 10.8.0.2 255.255.255.0",
    ];

    #[test]
    fn entry_points_survive_mutated_input() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for (name, f) in ALL {
            for round in 0..1500 {
                let mut input = SEEDS[rng.below(SEEDS.len())].to_vec();
                for _ in 0..1 + rng.below(8) {
                    let at = rng.below(input.len() + 1);
                    match rng.below(4) {
                        0 if at < input.len() => input[at] = rng.next() as u8,
                        1 if at < input.len() => {
                            input.remove(at);
                        }
                        2 => input.insert(at, rng.next() as u8),
                        _ => input.truncate(at),
                    }
                }
                if round % 7 == 0 {
                    input = (0..rng.below(256)).map(|_| rng.next() as u8).collect();
                }
                f(&input);
            }
            let _ = name;
        }
    }
}
