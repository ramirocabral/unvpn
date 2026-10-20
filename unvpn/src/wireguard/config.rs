//! wg-quick style `.conf` parser (`wg-quick(8)` / `wg(8)` CONFIGURATION FILE FORMAT).
//!
//! ```text
//! [Interface]
//! PrivateKey = <base64>
//! Address = 10.0.0.2/32, fd00::2/128
//! DNS = 10.0.0.1, corp.example.com      # IPs → resolvers, names → search domains
//! MTU = 1420                            # optional
//! ListenPort = 51820                    # optional
//! Table = auto | off | <number>         # optional
//! FwMark = 0x1234 | off                 # optional
//!
//! [Peer]
//! PublicKey = <base64>
//! PresharedKey = <base64>               # optional
//! Endpoint = vpn.example.com:51820
//! AllowedIPs = 0.0.0.0/0, ::/0
//! PersistentKeepalive = 25              # optional
//! ```
//!
//! `PreUp`/`PostUp`/`PreDown`/`PostDown` hook commands are deliberately NOT run (we
//! run as root; a profile is data, not a script) — they're reported as ignored.

use super::keys::from_b64 as b64_key;
use std::net::IpAddr;
use std::path::Path;

/// An IP prefix. For `AllowedIPs` the host bits are cleared; for `Address` the
/// host address is kept (it's the interface address) — see [`Net::network`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Net {
    /// `a.b.c.d[/n]` or `x::y[/n]`; a bare address is a host prefix.
    pub fn parse(s: &str) -> Result<Net, String> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.trim().parse().map_err(|_| format!("bad IP address `{a}`"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p.trim().parse::<u8>().ok().filter(|&n| n <= max).ok_or_else(|| format!("bad prefix length in `{s}`"))?,
            None => max,
        };
        Ok(Net { addr, prefix })
    }

    /// The same prefix with the host bits cleared.
    pub fn network(&self) -> Net {
        Net { addr: mask(self.addr, self.prefix), prefix: self.prefix }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        ip.is_ipv4() == self.addr.is_ipv4() && mask(ip, self.prefix) == mask(self.addr, self.prefix)
    }

    pub fn is_default(&self) -> bool {
        self.prefix == 0
    }
}

impl std::fmt::Display for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v) => {
            let m = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) };
            IpAddr::V4((u32::from(v) & m).into())
        }
        IpAddr::V6(v) => {
            let m = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix as u32) };
            IpAddr::V6((u128::from(v) & m).into())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    /// Routes for every peer's AllowedIPs in the main table (default).
    Auto,
    /// No routes at all.
    Off,
    /// Routes in this table id (for policy routing set up by the user).
    Id(u32),
}

#[derive(Clone, Debug)]
pub struct Interface {
    pub private_key: [u8; 32],
    pub addresses: Vec<Net>,
    pub dns: Vec<IpAddr>,
    pub search: Vec<String>,
    pub mtu: Option<u16>,
    pub listen_port: Option<u16>,
    pub table: Table,
    pub fwmark: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct PeerCfg {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// `host:port` / `[v6]:port`, resolved when connecting.
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<Net>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub interface: Interface,
    pub peers: Vec<PeerCfg>,
    /// Hook commands we refused to run (`PostUp = …`), for a warning.
    pub ignored_hooks: Vec<String>,
    /// Keys we don't know.
    pub unsupported: Vec<String>,
}

pub fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse(&text)
}

#[derive(PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
}

pub fn parse(text: &str) -> Result<Config, String> {
    let mut sec = Section::None;
    let mut private_key = None;
    let mut iface = Interface {
        private_key: [0; 32],
        addresses: Vec::new(),
        dns: Vec::new(),
        search: Vec::new(),
        mtu: None,
        listen_port: None,
        table: Table::Auto,
        fwmark: None,
    };
    let mut peers: Vec<PeerCfg> = Vec::new();
    let mut peer_has_key: Vec<bool> = Vec::new();
    let mut ignored_hooks = Vec::new();
    let mut unsupported = Vec::new();
    let mut seen_interface = false;

    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let at = |e: String| format!("line {}: {e}", n + 1);
        if line.starts_with('[') {
            match line.to_ascii_lowercase().as_str() {
                "[interface]" => {
                    sec = Section::Interface;
                    seen_interface = true;
                }
                "[peer]" => {
                    sec = Section::Peer;
                    peers.push(PeerCfg {
                        public_key: [0; 32],
                        preshared_key: None,
                        endpoint: None,
                        allowed_ips: Vec::new(),
                        persistent_keepalive: None,
                    });
                    peer_has_key.push(false);
                }
                other => return Err(at(format!("unknown section {other}"))),
            }
            continue;
        }
        let (key, val) = line.split_once('=').ok_or_else(|| at(format!("expected `Key = Value`, got `{line}`")))?;
        let key = key.trim().to_ascii_lowercase();
        let val = val.trim();
        let list = || val.split(',').map(str::trim).filter(|s| !s.is_empty());
        match sec {
            Section::None => return Err(at("setting outside of [Interface]/[Peer]".into())),
            Section::Interface => match key.as_str() {
                "privatekey" => private_key = Some(b64_key(val).map_err(|e| at(format!("PrivateKey: {e}")))?),
                "address" => {
                    for a in list() {
                        iface.addresses.push(Net::parse(a).map_err(at)?);
                    }
                }
                "dns" => {
                    for d in list() {
                        match d.parse::<IpAddr>() {
                            Ok(ip) => iface.dns.push(ip),
                            Err(_) => iface.search.push(d.to_string()),
                        }
                    }
                }
                "mtu" => iface.mtu = Some(val.parse().map_err(|_| at(format!("bad MTU `{val}`")))?),
                "listenport" => iface.listen_port = Some(val.parse().map_err(|_| at(format!("bad ListenPort `{val}`")))?),
                "table" => {
                    iface.table = match val.to_ascii_lowercase().as_str() {
                        "auto" => Table::Auto,
                        "off" => Table::Off,
                        // `main` is what auto does anyway.
                        "main" => Table::Auto,
                        n => Table::Id(n.parse().map_err(|_| at(format!("bad Table `{val}`")))?),
                    }
                }
                "fwmark" => iface.fwmark = parse_fwmark(val).map_err(at)?,
                "preup" | "postup" | "predown" | "postdown" => ignored_hooks.push(line.to_string()),
                "saveconfig" => {}
                _ => unsupported.push(format!("[Interface] {key}")),
            },
            Section::Peer => {
                let i = peers.len() - 1;
                let p = &mut peers[i];
                match key.as_str() {
                    "publickey" => {
                        p.public_key = b64_key(val).map_err(|e| at(format!("PublicKey: {e}")))?;
                        peer_has_key[i] = true;
                    }
                    "presharedkey" => p.preshared_key = Some(b64_key(val).map_err(|e| at(format!("PresharedKey: {e}")))?),
                    "endpoint" => p.endpoint = Some(val.to_string()),
                    "allowedips" => {
                        for a in list() {
                            p.allowed_ips.push(Net::parse(a).map_err(at)?.network());
                        }
                    }
                    "persistentkeepalive" => {
                        p.persistent_keepalive = match val.to_ascii_lowercase().as_str() {
                            "off" | "0" => None,
                            v => Some(v.parse().map_err(|_| at(format!("bad PersistentKeepalive `{val}`")))?),
                        }
                    }
                    _ => unsupported.push(format!("[Peer] {key}")),
                }
            }
        }
    }

    if !seen_interface {
        return Err("no [Interface] section".into());
    }
    iface.private_key = private_key.ok_or("[Interface] has no PrivateKey")?;
    if let Some(i) = peer_has_key.iter().position(|&k| !k) {
        return Err(format!("[Peer] #{} has no PublicKey", i + 1));
    }
    if peers.is_empty() {
        return Err("no [Peer] section".into());
    }
    if iface.addresses.is_empty() {
        return Err("[Interface] has no Address".into());
    }
    unsupported.dedup();
    Ok(Config { interface: iface, peers, ignored_hooks, unsupported })
}

fn parse_fwmark(v: &str) -> Result<Option<u32>, String> {
    let v = v.trim().to_ascii_lowercase();
    if v == "off" || v == "0" {
        return Ok(None);
    }
    let n = match v.strip_prefix("0x") {
        Some(h) => u32::from_str_radix(h, 16),
        None => v.parse(),
    };
    n.map(Some).map_err(|_| format!("bad FwMark `{v}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const K2: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    #[test]
    fn full_config() {
        let text = format!(
            "# exported\n[Interface]\nPrivateKey = {K1}\nAddress = 10.8.0.2/24, fd00::2/64\nDNS = 10.8.0.1, fd00::1, corp.example.com\n\
             MTU = 1380\nListenPort=51821\nTable = off\nFwMark = 0xca6c\nPostUp = iptables -A FORWARD -j ACCEPT\n\n\
             [Peer]\nPublicKey = {K2}\nPresharedKey = {K1}\nEndpoint = vpn.example.com:51820\n\
             AllowedIPs = 0.0.0.0/0, ::/0\nAllowedIPs = 192.0.2.77/24\nPersistentKeepalive = 25\n"
        );
        let c = parse(&text).unwrap();
        let i = &c.interface;
        assert_eq!(i.addresses.len(), 2);
        assert_eq!(i.addresses[0].to_string(), "10.8.0.2/24", "Address keeps the host part");
        assert_eq!(i.dns.len(), 2);
        assert_eq!(i.search, vec!["corp.example.com"]);
        assert_eq!((i.mtu, i.listen_port, i.table, i.fwmark), (Some(1380), Some(51821), Table::Off, Some(0xca6c)));
        assert_eq!(c.ignored_hooks.len(), 1);
        let p = &c.peers[0];
        assert!(p.preshared_key.is_some());
        assert_eq!(p.endpoint.as_deref(), Some("vpn.example.com:51820"));
        let ips: Vec<String> = p.allowed_ips.iter().map(|n| n.to_string()).collect();
        assert_eq!(ips, vec!["0.0.0.0/0", "::/0", "192.0.2.0/24"], "AllowedIPs are normalised");
        assert_eq!(p.persistent_keepalive, Some(25));
    }

    #[test]
    fn errors() {
        assert!(parse("[Peer]\nPublicKey = x\n").is_err());
        assert!(parse(&format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\n")).is_err(), "needs a peer");
        assert!(parse(&format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/33\n[Peer]\nPublicKey = {K2}\n")).is_err());
        assert!(parse(&format!("[Interface]\nAddress = 10.0.0.2\n[Peer]\nPublicKey = {K2}\n")).is_err());
        assert!(parse(&format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2\n[Peer]\nEndpoint = a:1\n")).is_err());
    }

    #[test]
    fn net_ops() {
        let n = Net::parse("10.1.2.3/16").unwrap().network();
        assert_eq!(n.to_string(), "10.1.0.0/16");
        assert!(n.contains("10.1.255.1".parse().unwrap()));
        assert!(!n.contains("10.2.0.1".parse().unwrap()));
        assert!(!n.contains("::1".parse().unwrap()));
        assert!(Net::parse("::/0").unwrap().contains("2001:db8::1".parse().unwrap()));
        assert_eq!(Net::parse("2001:db8::1").unwrap().prefix, 128);
        assert!(Net::parse("0.0.0.0/0").unwrap().is_default());
    }
}
