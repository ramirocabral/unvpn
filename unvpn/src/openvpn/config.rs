//! `.ovpn` client-config parser.
//!
//! Reads the subset of OpenVPN's option language a client profile actually uses:
//! remotes (incl. `<connection>` blocks), proto/port, the TLS material (inline
//! `<ca>/<cert>/<key>/<tls-auth>/<tls-crypt>` blocks or file paths, relative to
//! the config's directory, and `pkcs12`), data-channel crypto (`cipher`,
//! `data-ciphers`, `auth`), server verification (`verify-x509-name`,
//! `remote-cert-tls`), `auth-user-pass`, `static-challenge`, compression framing,
//! timers, and the client-side routing knobs (`route-nopull`, `route`,
//! `redirect-gateway`, `dhcp-option`). Everything else is ignored.
//!
//! Directive syntax follows OpenVPN's: one directive per line, `#`/`;` comments,
//! double/single quotes and backslash escapes group words.

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Tcp,
}

impl Proto {
    fn parse(s: &str) -> Option<Proto> {
        let s = s.to_ascii_lowercase();
        if s.starts_with("udp") {
            Some(Proto::Udp)
        } else if s.starts_with("tcp") {
            Some(Proto::Tcp)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Remote {
    pub host: String,
    pub port: u16,
    pub proto: Proto,
}

/// `verify-x509-name <name> [subject|name|name-prefix]`.
#[derive(Clone, Debug, PartialEq)]
pub enum X509Name {
    /// The full subject DN in OpenVPN's print format (`C=AR, ST=…, CN=…`).
    Subject(String),
    /// Exact common name.
    Name(String),
    /// Common-name prefix.
    NamePrefix(String),
}

/// Where the compression framing comes from (we never compress, but a server with
/// `comp-lzo`/`compress` expects the matching per-packet header byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compress {
    None,
    /// `comp-lzo` / `compress lzo`: one leading byte, 0xFA = not compressed.
    Lzo,
    /// `compress` / `compress stub` / `compress lz4`: swap framing (0xFB).
    Stub,
    /// `compress stub-v2` / `compress lz4-v2`: no byte unless the packet starts with 0x50.
    StubV2,
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub remotes: Vec<Remote>,
    pub remote_random: bool,
    pub ca: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub pkcs12: Option<Vec<u8>>,
    /// Raw `-----BEGIN OpenVPN Static key V1-----` text of `tls-auth`.
    pub tls_auth: Option<String>,
    /// `key-direction` (or the direction argument of `tls-auth`).
    pub key_direction: Option<u8>,
    pub tls_crypt: Option<String>,
    pub tls_crypt_v2: bool,
    /// `cipher` — the legacy/fallback data cipher.
    pub cipher: Option<String>,
    /// `data-ciphers` (`ncp-ciphers`), in preference order.
    pub data_ciphers: Vec<String>,
    pub data_ciphers_fallback: Option<String>,
    /// `auth` digest (tls-auth HMAC + CBC data-channel HMAC). OpenVPN's default is SHA1.
    pub auth: String,
    pub auth_user_pass: bool,
    /// `auth-user-pass <file>` / inline block: user on line 1, password on line 2.
    pub auth_user: Option<String>,
    pub auth_pass: Option<String>,
    /// `static-challenge "<text>" <echo>`.
    pub static_challenge: Option<(String, bool)>,
    pub verify_x509: Option<X509Name>,
    pub remote_cert_tls_server: bool,
    pub tls_version_min: Option<String>,
    pub reneg_sec: Option<u64>,
    pub compress: Option<Compress>,
    pub ping: Option<u64>,
    pub ping_restart: Option<u64>,
    pub route_nopull: bool,
    /// Client-side `route <net> [mask] [gw]` lines (raw words).
    pub routes: Vec<Vec<String>>,
    pub redirect_gateway: bool,
    pub dhcp_options: Vec<Vec<String>>,
    pub explicit_exit_notify: bool,
    pub tun_mtu: Option<u16>,
    /// Directives we recognised as meaningful but don't support (reported).
    pub unsupported: Vec<String>,
}

pub fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let dir = path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    parse(&text, &dir)
}

pub fn parse(text: &str, dir: &Path) -> Result<Config, String> {
    let mut cfg = Config { auth: "SHA1".into(), ..Default::default() };
    let mut default_port: u16 = 1194;
    let mut default_proto = Proto::Udp;
    // Remotes as written, with optional per-remote port/proto; defaults are
    // applied at the end (a `port`/`proto` line may follow the `remote`).
    let mut pending: Vec<(String, Option<u16>, Option<Proto>)> = Vec::new();

    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        i += 1;
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(tag) = line.strip_prefix('<').and_then(|l| l.strip_suffix('>')) {
            if tag.starts_with('/') {
                continue;
            }
            let close = format!("</{tag}>");
            let mut body = String::new();
            while i < lines.len() && lines[i].trim() != close {
                body.push_str(lines[i]);
                body.push('\n');
                i += 1;
            }
            i += 1;
            if tag == "connection" {
                // A nested profile; we only need its remote(s).
                let sub = parse(&body, dir)?;
                for r in sub.remotes {
                    pending.push((r.host, Some(r.port), Some(r.proto)));
                }
                continue;
            }
            apply_inline(&mut cfg, tag, body)?;
            continue;
        }

        let w = split_words(line);
        if w.is_empty() {
            continue;
        }
        let name = w[0].trim_start_matches("--");
        let arg = |n: usize| w.get(n).map(String::as_str);
        match name {
            "remote" => {
                let host = arg(1).ok_or("remote without host")?.to_string();
                let port = arg(2).and_then(|p| p.parse().ok());
                let proto = arg(3).and_then(Proto::parse);
                pending.push((host, port, proto));
            }
            "port" | "rport" => default_port = arg(1).and_then(|p| p.parse().ok()).unwrap_or(default_port),
            "proto" => default_proto = arg(1).and_then(Proto::parse).unwrap_or(default_proto),
            "remote-random" => cfg.remote_random = true,
            "dev" | "dev-type" => {
                if arg(1).is_some_and(|d| d.starts_with("tap")) {
                    return Err("dev tap (layer-2) is not supported — only tun profiles".into());
                }
            }
            "ca" => cfg.ca = Some(read_text(dir, arg(1))?),
            "cert" => cfg.cert = Some(read_text(dir, arg(1))?),
            "key" => cfg.key = Some(read_text(dir, arg(1))?),
            "pkcs12" => cfg.pkcs12 = Some(read_bytes(dir, arg(1))?),
            "tls-auth" => {
                cfg.tls_auth = Some(read_text(dir, arg(1))?);
                if let Some(d) = arg(2).and_then(|d| d.parse().ok()) {
                    cfg.key_direction = Some(d);
                }
            }
            "key-direction" => cfg.key_direction = arg(1).and_then(|d| d.parse().ok()),
            "tls-crypt" => cfg.tls_crypt = Some(read_text(dir, arg(1))?),
            "tls-crypt-v2" => cfg.tls_crypt_v2 = true,
            "cipher" => cfg.cipher = arg(1).map(|c| c.to_ascii_uppercase()),
            "data-ciphers" | "ncp-ciphers" => {
                cfg.data_ciphers = arg(1).unwrap_or("").split(':').map(|c| c.to_ascii_uppercase()).filter(|c| !c.is_empty()).collect()
            }
            "data-ciphers-fallback" => cfg.data_ciphers_fallback = arg(1).map(|c| c.to_ascii_uppercase()),
            "auth" => cfg.auth = arg(1).unwrap_or("SHA1").to_ascii_uppercase(),
            "auth-user-pass" => {
                cfg.auth_user_pass = true;
                if let Some(f) = arg(1) {
                    // A credentials file is optional; a missing one just means "prompt".
                    if let Ok(t) = read_text(dir, Some(f)) {
                        apply_userpass(&mut cfg, &t);
                    }
                }
            }
            "static-challenge" => {
                let text = arg(1).unwrap_or("Response").to_string();
                let echo = arg(2) == Some("1");
                cfg.static_challenge = Some((text, echo));
            }
            "verify-x509-name" => {
                let v = arg(1).ok_or("verify-x509-name without a name")?.to_string();
                cfg.verify_x509 = Some(match arg(2).unwrap_or("subject") {
                    "name" => X509Name::Name(v),
                    "name-prefix" => X509Name::NamePrefix(v),
                    _ => X509Name::Subject(v),
                });
            }
            "remote-cert-tls" => cfg.remote_cert_tls_server = arg(1) == Some("server"),
            "ns-cert-type" => cfg.remote_cert_tls_server |= arg(1) == Some("server"),
            "tls-version-min" => cfg.tls_version_min = arg(1).map(str::to_string),
            "reneg-sec" => cfg.reneg_sec = arg(1).and_then(|s| s.parse().ok()),
            "comp-lzo" => cfg.compress = Some(Compress::Lzo),
            "compress" => cfg.compress = Some(compress_kind(arg(1))),
            "ping" => cfg.ping = arg(1).and_then(|s| s.parse().ok()),
            "ping-restart" => cfg.ping_restart = arg(1).and_then(|s| s.parse().ok()),
            "keepalive" => {
                cfg.ping = arg(1).and_then(|s| s.parse().ok());
                cfg.ping_restart = arg(2).and_then(|s| s.parse().ok());
            }
            "route-nopull" => cfg.route_nopull = true,
            "route" => cfg.routes.push(w[1..].to_vec()),
            "redirect-gateway" => cfg.redirect_gateway = true,
            "dhcp-option" => cfg.dhcp_options.push(w[1..].to_vec()),
            "explicit-exit-notify" => cfg.explicit_exit_notify = true,
            "tun-mtu" => cfg.tun_mtu = arg(1).and_then(|s| s.parse().ok()),
            "secret" => return Err("static-key (--secret) mode is not supported — only TLS client profiles".into()),
            "http-proxy" | "socks-proxy" | "fragment" | "pkcs11-providers" | "cryptoapicert" | "management-external-key" => {
                cfg.unsupported.push(name.to_string())
            }
            _ => {}
        }
    }

    for (host, port, proto) in pending {
        cfg.remotes.push(Remote { host, port: port.unwrap_or(default_port), proto: proto.unwrap_or(default_proto) });
    }
    if cfg.remotes.is_empty() {
        return Err("config has no `remote`".into());
    }
    if cfg.tls_crypt_v2 {
        return Err("tls-crypt-v2 is not supported yet (tls-auth and tls-crypt are)".into());
    }
    Ok(cfg)
}

fn apply_inline(cfg: &mut Config, tag: &str, body: String) -> Result<(), String> {
    match tag {
        "ca" => cfg.ca = Some(body),
        "cert" => cfg.cert = Some(body),
        "key" => cfg.key = Some(body),
        "tls-auth" => cfg.tls_auth = Some(body),
        "tls-crypt" => cfg.tls_crypt = Some(body),
        "tls-crypt-v2" => cfg.tls_crypt_v2 = true,
        "pkcs12" => {
            let b64: String = body.split_whitespace().collect();
            cfg.pkcs12 = Some(openssl::base64::decode_block(&b64).map_err(|e| format!("inline pkcs12: {e}"))?);
        }
        "auth-user-pass" => {
            cfg.auth_user_pass = true;
            apply_userpass(cfg, &body);
        }
        _ => {} // <extra-certs>, <dh>, … — irrelevant to a client
    }
    Ok(())
}

fn apply_userpass(cfg: &mut Config, text: &str) {
    let mut l = text.lines().map(str::trim).filter(|l| !l.is_empty());
    cfg.auth_user = l.next().map(str::to_string);
    cfg.auth_pass = l.next().map(str::to_string);
}

fn compress_kind(arg: Option<&str>) -> Compress {
    match arg {
        Some("stub-v2") | Some("lz4-v2") | Some("migrate") => Compress::StubV2,
        Some("lzo") => Compress::Lzo,
        _ => Compress::Stub,
    }
}

fn resolve(dir: &Path, f: &str) -> PathBuf {
    let p = Path::new(f);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        dir.join(p)
    }
}

fn read_text(dir: &Path, f: Option<&str>) -> Result<String, String> {
    let f = f.ok_or("missing file argument")?;
    if f == "[inline]" {
        return Ok(String::new());
    }
    let p = resolve(dir, f);
    std::fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))
}

fn read_bytes(dir: &Path, f: Option<&str>) -> Result<Vec<u8>, String> {
    let p = resolve(dir, f.ok_or("missing file argument")?);
    std::fs::read(&p).map_err(|e| format!("read {}: {e}", p.display()))
}

pub fn split_words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == q => quote = None,
            Some('"') if c == '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            Some(_) => cur.push(c),
            None => match c {
                '"' | '\'' => {
                    quote = Some(c);
                    in_word = true;
                }
                '\\' => {
                    if let Some(n) = chars.next() {
                        cur.push(n);
                        in_word = true;
                    }
                }
                '#' | ';' if !in_word => break,
                c if c.is_whitespace() => {
                    if in_word {
                        out.push(std::mem::take(&mut cur));
                        in_word = false;
                    }
                }
                c => {
                    cur.push(c);
                    in_word = true;
                }
            },
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_quotes_and_comments() {
        assert_eq!(split_words(r#"verify-x509-name "C=AR, CN=x y" subject"#), vec!["verify-x509-name", "C=AR, CN=x y", "subject"]);
        assert_eq!(split_words("remote a.b 1194 udp # comment"), vec!["remote", "a.b", "1194", "udp"]);
        assert_eq!(split_words(r"auth-user-pass a\ b"), vec!["auth-user-pass", "a b"]);
        assert!(split_words("  ").is_empty());
    }

    #[test]
    fn remotes_inherit_defaults() {
        let c = parse("client\nproto tcp\nport 443\nremote a.example\nremote b.example 1194 udp\n", Path::new(".")).unwrap();
        assert_eq!(c.remotes[0], Remote { host: "a.example".into(), port: 443, proto: Proto::Tcp });
        assert_eq!(c.remotes[1], Remote { host: "b.example".into(), port: 1194, proto: Proto::Udp });
    }

    #[test]
    fn inline_blocks_and_crypto() {
        let t = "remote 1.2.3.4 54893\ncipher AES-256-CBC\nauth SHA256\nverify-x509-name vpn_x name\n\
                 remote-cert-tls server\nauth-user-pass\n<ca>\nCA PEM\n</ca>\n<tls-crypt>\nKEY\n</tls-crypt>\n";
        let c = parse(t, Path::new(".")).unwrap();
        assert_eq!(c.ca.as_deref(), Some("CA PEM\n"));
        assert_eq!(c.tls_crypt.as_deref(), Some("KEY\n"));
        assert_eq!(c.cipher.as_deref(), Some("AES-256-CBC"));
        assert_eq!(c.auth, "SHA256");
        assert_eq!(c.verify_x509, Some(X509Name::Name("vpn_x".into())));
        assert!(c.remote_cert_tls_server && c.auth_user_pass);
    }

    #[test]
    fn connection_blocks_and_tap() {
        let t = "<connection>\nremote x.example 1196 udp\n</connection>\n<connection>\nremote y.example 443 tcp-client\n</connection>\n";
        let c = parse(t, Path::new(".")).unwrap();
        assert_eq!(c.remotes.len(), 2);
        assert_eq!(c.remotes[1].proto, Proto::Tcp);
        assert!(parse("remote a\ndev tap\n", Path::new(".")).is_err());
        assert!(parse("dev tun\n", Path::new(".")).is_err()); // no remote
    }

    #[test]
    fn subject_default_type() {
        let c = parse("remote a\nverify-x509-name \"C=AR, CN=v\"\n", Path::new(".")).unwrap();
        assert_eq!(c.verify_x509, Some(X509Name::Subject("C=AR, CN=v".into())));
    }
}
