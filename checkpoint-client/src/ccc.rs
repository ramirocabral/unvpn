//! Check Point CCC protocol — S-expression (de)serialization.
//!
//! Reverse-engineered from Endpoint Security VPN E84.30 (Trac 98.61.02307):
//! the control channel is `POST /clients/` over TLS/443, with
//! `Content-Type: application/x-www-form-urlencoded` and the S-expression
//! below as the raw body. Vocabulary (CCCclientRequest, CCCserverResponse,
//! ClientHello, client_info/client_type/client_mode, login_options_list, ...)
//! was taken from TrAPI.dll/TracSrvWrapper.exe strings + RTTI and the Trac
//! flow logs.
//!
//! ClientHello request shape (E84.30). Values are BARE symbols, NOT quoted:
//! confirmed from trac.log, which logs Check Point S-expressions with bare
//! values such as `transport (Auto-Detect)`, `username (u-123456)`,
//! `realm_display_name (Standard)`.
//! ```text
//! (CCCclientRequest
//!     :RequestHeader (
//!         :id (<n>)
//!         :type (ClientHello)
//!         :session_id ()
//!     )
//!     :RequestData (
//!         :client_info (
//!             :client_type (TRAC)
//!             :client_version (1)
//!             :client_support_saml (true)
//!         )
//!     )
//! )
//! ```
//!
//! VERIFIED against the live gateway: this yields `return_code (600)` with a
//! `login_options_data` block. Two things were essential:
//!   1. The body MUST be multi-line with tab indentation. A single-line body is
//!      rejected with `return_code (504)` and an empty header echo — the parser
//!      cannot even extract `type`.
//!   2. The RequestHeader carries NO `protocol_version`: that is a field the
//!      SERVER returns, nested as `:protocol_version (:protocol_version (100))`.
//!      Sending it in the request is the gateway's "bad protocol version number".
//! ClientInfo = client_type/client_version/client_support_saml (snx-rs proto.rs).

use std::fmt::Write as _;

/// A CCC value: the Check Point S-expression is a tree of these.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Empty value: `()`.
    Empty,
    /// Bare integer: `(100)`.
    Num(i64),
    /// Quoted string: `("TRAC")`.
    Str(String),
    /// Bare symbol: `(ClientHello)`.
    Sym(String),
    /// Keyed map: `(:key (val) :key2 (...))`.
    Map(Vec<(String, Value)>),
}

impl Value {
    /// Build a `Map` from borrowed keys.
    pub fn map(entries: Vec<(&str, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    pub fn str(s: &str) -> Value {
        Value::Str(s.to_string())
    }

    pub fn sym(s: &str) -> Value {
        Value::Sym(s.to_string())
    }

    /// Direct child lookup inside a `Map`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Recursive child lookup following a key path.
    pub fn path(&self, keys: &[&str]) -> Option<&Value> {
        let mut cur = self;
        for k in keys {
            cur = cur.get(k)?;
        }
        Some(cur)
    }

    /// Serialize a bare (unnamed) value — used for the IKE hybrid-auth blob,
    /// which is a nameless Check Point S-expression `(\n\t:k (v) ...\n)`.
    pub fn serialize_bare(&self) -> String {
        let mut out = String::new();
        self.write_indented(&mut out, 0);
        out
    }

    /// The scalar content as an owned string, if this is a scalar node.
    pub fn text(&self) -> Option<String> {
        match self {
            Value::Num(n) => Some(n.to_string()),
            Value::Str(s) | Value::Sym(s) => Some(s.clone()),
            _ => None,
        }
    }

    /// Serialize at the given indentation level. Check Point's gateway parser
    /// REQUIRES this multi-line, tab-indented layout: a single-line body is
    /// rejected with `return_code (504)` and an empty header echo. Verified
    /// against the live gateway; matches snx-rs's `encode_object`.
    fn write_indented(&self, out: &mut String, level: usize) {
        match self {
            Value::Empty => out.push_str("()"),
            Value::Num(n) => {
                let _ = write!(out, "({})", n);
            }
            Value::Str(s) => {
                let _ = write!(out, "(\"{}\")", escape(s));
            }
            Value::Sym(s) => {
                let _ = write!(out, "({})", s);
            }
            Value::Map(entries) if entries.is_empty() => out.push_str("()"),
            Value::Map(entries) => {
                out.push_str("(\n");
                for (k, v) in entries {
                    push_tabs(out, level + 1);
                    let _ = write!(out, ":{} ", k);
                    v.write_indented(out, level + 1);
                    out.push('\n');
                }
                push_tabs(out, level);
                out.push(')');
            }
        }
    }

    /// Human-readable indented rendering (for debugging responses).
    pub fn pretty(&self, indent: usize) -> String {
        let pad = "  ".repeat(indent);
        match self {
            Value::Empty => "()".to_string(),
            Value::Num(n) => n.to_string(),
            Value::Str(s) => format!("\"{}\"", s),
            Value::Sym(s) => s.clone(),
            Value::Map(entries) => {
                let mut out = String::from("{\n");
                for (k, v) in entries {
                    let _ = write!(out, "{}  {}: {}\n", pad, k, v.pretty(indent + 1));
                }
                let _ = write!(out, "{}}}", pad);
                out
            }
        }
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn push_tabs(out: &mut String, n: usize) {
    for _ in 0..n {
        out.push('\t');
    }
}

// ---------------------------------------------------------------------------
// Secret obfuscation (Check Point "snx" scheme), ported verbatim from snx-rs
// `util.rs`. username/password/prompt/active_key travel as hex of a per-index
// XOR against a fixed table, emitted in reversed byte order. `obfuscate` is
// what we send; `deobfuscate` reads prompt/active_key back from a response.
// ---------------------------------------------------------------------------

const XOR_TABLE: &[u8] = &[
    45, 79, 68, 73, 70, 73, 69, 68, 38, 87, 48, 82, 79, 80, 69, 82, 84, 89, 51, 72, 69, 69, 84, 55, 73, 84, 72, 47, 43,
    52, 72, 69, 51, 72, 69, 69, 84, 41, 36, 51, 63, 44, 36, 33, 48, 63, 33, 53, 63, 48, 50, 47, 48, 37, 50, 52, 41, 37,
    51, 46, 53, 44, 44, 16, 38, 55, 63, 55, 48, 63, 47, 34, 42, 37, 35, 52, 51,
];

fn translate_byte(i: usize, c: u8) -> u8 {
    match (c % 255) ^ XOR_TABLE[i % XOR_TABLE.len()] {
        0 => 255,
        v => v,
    }
}

/// Per-index XOR with the table, emitted in reverse byte order.
fn translate(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .rev()
        .map(|(i, &c)| translate_byte(i, c))
        .collect()
}

/// Obfuscate a secret into the hex form Check Point expects on the wire.
pub fn obfuscate(data: &[u8]) -> String {
    hex_encode(&translate(data))
}

/// Inverse of [`obfuscate`]: decode a hex secret from a server response.
pub fn deobfuscate(hexstr: &str) -> Result<Vec<u8>, String> {
    let mut unhexed = hex_decode(hexstr)?;
    unhexed.reverse();
    let mut decoded = translate(&unhexed);
    decoded.reverse();
    Ok(decoded)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("odd-length hex".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// A top-level CCC packet: a named root wrapping keyed entries.
#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    pub name: String,
    pub body: Value,
}

impl Packet {
    /// Serialize to the CCC wire form: `(Name :k (v) ...)`.
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        out.push('(');
        out.push_str(&self.name);
        if let Value::Map(entries) = &self.body {
            out.push('\n');
            for (k, v) in entries {
                push_tabs(&mut out, 1);
                let _ = write!(out, ":{} ", k);
                v.write_indented(&mut out, 1);
                out.push('\n');
            }
        }
        out.push(')');
        out
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.body.get(key)
    }

    pub fn path(&self, keys: &[&str]) -> Option<&Value> {
        self.body.path(keys)
    }
}

/// Build a CCC `ClientHello` request (first message of the handshake).
pub fn client_hello(request_id: i64) -> Packet {
    let header = Value::map(vec![
        ("id", Value::Num(request_id)),
        ("type", Value::sym("ClientHello")),
        ("session_id", Value::Empty),
    ]);
    let data = Value::map(vec![(
        "client_info",
        Value::map(vec![
            ("client_type", Value::sym("TRAC")),
            ("client_version", Value::Num(1)),
            ("client_support_saml", Value::sym("true")),
        ]),
    )]);
    Packet {
        name: "CCCclientRequest".to_string(),
        body: Value::map(vec![("RequestHeader", header), ("RequestData", data)]),
    }
}

/// Build a CCC `UserPass` auth request. For SecurID `pin_pad` the password is
/// empty here — the passcode is supplied in the following `MultiChallange`.
/// `selectedLoginOption` is the realm id from login_options (e.g. `vpn`).
pub fn auth_userpass(request_id: i64, username: &str, realm: &str) -> Packet {
    let header = Value::map(vec![
        ("id", Value::Num(request_id)),
        ("type", Value::sym("UserPass")),
        ("session_id", Value::Empty),
    ]);
    let data = Value::map(vec![
        ("client_type", Value::sym("TRAC")),
        ("username", Value::sym(&obfuscate(username.as_bytes()))),
        ("password", Value::Empty),
        ("selectedLoginOption", Value::sym(realm)),
    ]);
    Packet {
        name: "CCCclientRequest".to_string(),
        body: Value::map(vec![("RequestHeader", header), ("RequestData", data)]),
    }
}

/// Build the SSL-tunnel `client_hello` (the lowercase, non-CCC handshake sent
/// as a CONTROL frame once the data-plane TLS socket is up). `cookie` is the
/// deobfuscated `active_key` from CCC auth; `office_mode_ip` is `0.0.0.0` on the
/// first connect (or a prior address to request keeping it). The gateway replies
/// with `(hello_reply ...)` carrying the assigned Office Mode IP, routes and DNS.
pub fn tunnel_client_hello(cookie: &str, office_mode_ip: &str) -> Packet {
    let office_mode = Value::map(vec![
        ("ipaddr", Value::sym(office_mode_ip)),
        ("keep_address", Value::sym("false")),
    ]);
    let optional = Value::map(vec![("client_type", Value::sym("4"))]);
    Packet {
        name: "client_hello".to_string(),
        body: Value::map(vec![
            ("client_version", Value::Num(2)),
            ("protocol_version", Value::Num(2)),
            ("OM", office_mode),
            ("optional", optional),
            ("cookie", Value::sym(cookie)),
        ]),
    }
}

/// Build a CCC `MultiChallange` request (Check Point's own spelling) carrying
/// one user input — e.g. the SecurID passcode — tied to the auth session from
/// the preceding `continue` response.
pub fn multi_challenge(request_id: i64, session_id: &str, user_input: &str) -> Packet {
    let header = Value::map(vec![
        ("id", Value::Num(request_id)),
        ("type", Value::sym("MultiChallange")),
        ("session_id", Value::sym(session_id)),
    ]);
    let data = Value::map(vec![
        ("client_type", Value::sym("TRAC")),
        ("auth_session_id", Value::sym(session_id)),
        ("user_input", Value::sym(&obfuscate(user_input.as_bytes()))),
    ]);
    Packet {
        name: "CCCclientRequest".to_string(),
        body: Value::map(vec![("RequestHeader", header), ("RequestData", data)]),
    }
}

// ---------------------------------------------------------------------------
// Parser: recursive-descent over the CCC S-expression grammar.
// ---------------------------------------------------------------------------

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

/// Parse a CCC packet, e.g. a `(CCCserverResponse ...)` reply.
pub fn parse(input: &str) -> Result<Packet, String> {
    let mut p = Parser {
        s: input.as_bytes(),
        i: 0,
    };
    p.skip_ws();
    p.expect(b'(')?;
    let name = p.read_bare()?;
    let body = p.read_map_body()?;
    p.skip_ws();
    p.expect(b')')?;
    Ok(Packet { name, body })
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, c: u8) -> Result<(), String> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!(
                "expected '{}' at offset {}, found {:?}",
                c as char,
                self.i,
                self.peek().map(|b| b as char)
            ))
        }
    }

    /// Read a bare token up to whitespace or a paren.
    fn read_bare(&mut self) -> Result<String, String> {
        self.skip_ws();
        let start = self.i;
        while let Some(c) = self.peek() {
            if matches!(c, b' ' | b'\t' | b'\n' | b'\r' | b'(' | b')') {
                break;
            }
            self.i += 1;
        }
        if self.i == start {
            return Err(format!("expected token at offset {}", self.i));
        }
        Ok(String::from_utf8_lossy(&self.s[start..self.i]).into_owned())
    }

    fn read_quoted(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        while let Some(c) = self.peek() {
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    if let Some(n) = self.peek() {
                        self.i += 1;
                        out.push(n as char);
                    }
                }
                _ => out.push(c as char),
            }
        }
        Err("unterminated quoted string".to_string())
    }

    /// Read a parenthesized value: `()`, `(scalar)`, or `(:k (v) ...)`.
    fn read_value(&mut self) -> Result<Value, String> {
        self.skip_ws();
        self.expect(b'(')?;
        self.skip_ws();
        match self.peek() {
            Some(b')') => {
                self.i += 1;
                Ok(Value::Empty)
            }
            Some(b':') => {
                let m = self.read_map_body()?;
                self.skip_ws();
                self.expect(b')')?;
                Ok(m)
            }
            Some(b'"') => {
                let s = self.read_quoted()?;
                self.skip_ws();
                self.expect(b')')?;
                Ok(Value::Str(s))
            }
            _ => {
                let t = self.read_bare()?;
                self.skip_ws();
                self.expect(b')')?;
                Ok(match t.parse::<i64>() {
                    Ok(n) => Value::Num(n),
                    Err(_) => Value::Sym(t),
                })
            }
        }
    }

    /// Read a sequence of `:key value` pairs until a closing paren.
    fn read_map_body(&mut self) -> Result<Value, String> {
        let mut entries = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() == Some(b':') {
                self.i += 1;
                // Keys may be empty: Check Point encodes arrays as repeated
                // `: (value)` pairs (e.g. supported_data_tunnel_protocols,
                // internal_ca_fingerprint). An empty key yields ("", value).
                let key = self.read_key();
                let val = self.read_value()?;
                entries.push((key, val));
            } else {
                break;
            }
        }
        Ok(Value::Map(entries))
    }

    /// Read a map key: bare chars up to whitespace or a paren. May be empty
    /// (the array case above), so unlike `read_bare` it never errors.
    fn read_key(&mut self) -> String {
        self.skip_ws();
        let start = self.i;
        while let Some(c) = self.peek() {
            if matches!(c, b' ' | b'\t' | b'\n' | b'\r' | b'(' | b')') {
                break;
            }
            self.i += 1;
        }
        String::from_utf8_lossy(&self.s[start..self.i]).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_client_hello() {
        let got = client_hello(0).serialize();
        // Multi-line, tab-indented — the exact layout the gateway accepts (600).
        let want = "(CCCclientRequest\n\t:RequestHeader (\n\t\t:id (0)\n\t\t:type (ClientHello)\n\t\t:session_id ()\n\t)\n\t:RequestData (\n\t\t:client_info (\n\t\t\t:client_type (TRAC)\n\t\t\t:client_version (1)\n\t\t\t:client_support_saml (true)\n\t\t)\n\t)\n)";
        assert_eq!(got, want);
    }

    #[test]
    fn roundtrip_parse_serialize() {
        let pkt = client_hello(7);
        let text = pkt.serialize();
        let parsed = parse(&text).expect("parse");
        assert_eq!(parsed.serialize(), text);
        assert_eq!(parsed.name, "CCCclientRequest");
    }

    #[test]
    fn parse_server_response_login_options() {
        // Shape of a CCCserverResponse advertising a realm + auth method,
        // matching the `login_options_list` vocabulary seen in TrAPI.dll.
        let sample = r#"(CCCserverResponse
            :ResponseHeader (
                :id (0)
                :type (ClientHello)
                :session_id ()
                :return_code (600))
            :ResponseData (
                :protocol_version (:protocol_version (100))
                :login_options_data (
                    :login_options_list (
                        :0 (
                            :id (vpn)
                            :display_name ("Standard")
                            :factors (:0 (:factor_type (securid))))))))"#;
        let pkt = parse(sample).expect("parse response");
        assert_eq!(pkt.name, "CCCserverResponse");
        let rc = pkt.path(&["ResponseHeader", "return_code"]);
        assert_eq!(rc, Some(&Value::Num(600)));
        let realm = pkt.path(&[
            "ResponseData",
            "login_options_data",
            "login_options_list",
            "0",
            "id",
        ]);
        assert_eq!(realm, Some(&Value::Sym("vpn".to_string())));
    }

    #[test]
    fn parse_empty_and_scalars() {
        let v = parse("(X :a () :b (42) :c (\"hi\") :d (sym))").unwrap();
        assert_eq!(v.get("a"), Some(&Value::Empty));
        assert_eq!(v.get("b"), Some(&Value::Num(42)));
        assert_eq!(v.get("c"), Some(&Value::Str("hi".to_string())));
        assert_eq!(v.get("d"), Some(&Value::Sym("sym".to_string())));
    }

    #[test]
    fn parse_array_empty_keys() {
        // Check Point arrays: repeated `: (value)` with empty keys, seen in the
        // real ClientHello reply (supported_data_tunnel_protocols).
        let v = parse("(R :protos (\n\t: (IPSec)\n\t: (SSL)\n\t: (L2TP)\n))").unwrap();
        match v.get("protos") {
            Some(Value::Map(e)) => {
                assert_eq!(e.len(), 3);
                assert_eq!(e[0], (String::new(), Value::Sym("IPSec".to_string())));
                assert_eq!(e[2], (String::new(), Value::Sym("L2TP".to_string())));
            }
            other => panic!("expected map, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_real_login_options() {
        // A trimmed slice of the live gateway's return_code(600) reply: nested
        // protocol_version, hex features, empty-key array, quoted paths.
        let sample = "(CCCserverResponse\n\t:ResponseHeader (\n\t\t:id (2)\n\t\t:type (ClientHello)\n\t\t:return_code (600)\n\t)\n\t:ResponseData (\n\t\t:protocol_version (\n\t\t\t:protocol_version (100)\n\t\t\t:features (0x1)\n\t\t)\n\t\t:connectivity_info (\n\t\t\t:supported_data_tunnel_protocols (\n\t\t\t\t: (IPSec)\n\t\t\t\t: (SSL)\n\t\t\t)\n\t\t\t:tcpt_port (443)\n\t\t\t:cookie_name (CPCVPN_SESSION_ID)\n\t\t)\n\t)\n)";
        let pkt = parse(sample).expect("parse 600 reply");
        assert_eq!(pkt.name, "CCCserverResponse");
        assert_eq!(
            pkt.path(&["ResponseHeader", "return_code"]),
            Some(&Value::Num(600))
        );
        assert_eq!(
            pkt.path(&["ResponseData", "protocol_version", "protocol_version"]),
            Some(&Value::Num(100))
        );
        assert_eq!(
            pkt.path(&["ResponseData", "connectivity_info", "tcpt_port"]),
            Some(&Value::Num(443))
        );
        // features is hex (0x1): kept as a symbol since it is not a decimal int.
        assert_eq!(
            pkt.path(&["ResponseData", "protocol_version", "features"]),
            Some(&Value::Sym("0x1".to_string()))
        );
    }

    #[test]
    fn obfuscate_roundtrip() {
        for s in ["", "u-123456", "12345678", "PIN+token!", "áéí"] {
            let obf = obfuscate(s.as_bytes());
            assert!(obf.chars().all(|c| c.is_ascii_hexdigit()));
            let back = deobfuscate(&obf).expect("deobfuscate");
            assert_eq!(back, s.as_bytes(), "roundtrip failed for {s:?}");
        }
    }

    #[test]
    fn serialize_userpass() {
        let got = auth_userpass(1, "user", "vpn").serialize();
        assert!(got.starts_with(
            "(CCCclientRequest\n\t:RequestHeader (\n\t\t:id (1)\n\t\t:type (UserPass)\n\t\t:session_id ()\n\t)"
        ));
        assert!(got.contains(":client_type (TRAC)"));
        assert!(got.contains(":selectedLoginOption (vpn)"));
        assert!(got.contains(":password ()"));
        // username is obfuscated, never clear text.
        assert!(!got.contains("user\n") && !got.contains("(user)"));
    }

    #[test]
    fn serialize_multi_challenge() {
        let got = multi_challenge(3, "sess42", "1234").serialize();
        assert!(got.contains(":type (MultiChallange)"));
        assert!(got.contains(":session_id (sess42)"));
        assert!(got.contains(":auth_session_id (sess42)"));
        assert!(got.contains(":user_input ("));
    }
}
