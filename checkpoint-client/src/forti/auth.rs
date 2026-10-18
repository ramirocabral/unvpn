//! Fortinet SSL-VPN authentication over HTTPS.
//!
//! Wire formats are the exact `printf` templates recovered from the shipped
//! `/opt/forticlient/vpn` binary (see docs/forti-protocol-notes.md), and match
//! openfortivpn/openconnect which interoperate with real FortiGates:
//!
//!   login:      username=<u>&credential=<pw>&realm=<r>&ajax=1&redir=%2Fremote%2Findex&just_logged_in=1
//!   2FA answer: username=<u>&reqid=<..>&polid=<..>&grp=<..>&realm=<r>&peer=&code=<otp>&code2=&ajax=1&...
//!
//! Success is signalled by a `Set-Cookie: SVPNCOOKIE=<value>` (the session token,
//! analogous to Check Point's `active_key`). A `ret=2,...` body means the gateway
//! wants a second factor.

use super::http::{self, Cookies};
use std::time::Duration;

const LOGINCHECK: &str = "/remote/logincheck";
/// Common suffix the client appends to every logincheck body.
const REDIR_SUFFIX: &str = "&ajax=1&redir=%2Fremote%2Findex&just_logged_in=1";

/// Everything needed to talk to one gateway, plus the accumulating cookie jar.
pub struct Session {
    pub host: String,
    pub port: u16,
    pub realm: String,
    pub user: String,
    pub timeout: Duration,
    pub cookies: Cookies,
}

/// A second-factor challenge the gateway returned. Two wire flavors:
///  - ajax: `ret=2,reqid=,polid=,grp=,tokeninfo=` (openfortivpn style).
///  - HTML form: a page with hidden `<INPUT name="magic|reqid|grpid|polid">` and a
///    `credential`/`credential2` token field (older/other FortiOS).
#[derive(Debug, Default, Clone)]
pub struct Challenge {
    pub reqid: String,
    pub polid: String,
    pub grp: String,
    pub grpid: String,
    pub magic: String,
    pub tokeninfo: String,
    /// Human-readable prompt, if the gateway sent `chal_msg=`.
    pub message: String,
    /// The gateway offered FortiToken Mobile push (`ftm_push`/`tokeninfo` hints).
    pub ftm_push: bool,
    /// Answer via the HTML-form POST (magic/grpid/credential) rather than ajax.
    pub html_form: bool,
}

/// Result of a login / challenge step.
pub enum AuthOutcome {
    /// `SVPNCOOKIE` acquired — authenticated.
    Authenticated,
    /// Second factor required.
    Challenge(Challenge),
    /// Failure, with the gateway's message if any.
    Failed(String),
}

impl Session {
    pub fn new(host: String, port: u16, realm: String, user: String, timeout: Duration) -> Self {
        Session { host, port, realm, user, timeout, cookies: Cookies::new() }
    }

    /// True once a non-empty `SVPNCOOKIE` is in the jar.
    pub fn svpncookie(&self) -> Option<&str> {
        self.cookies.get("SVPNCOOKIE").filter(|v| !v.is_empty())
    }

    fn post_logincheck(&mut self, body: String) -> Result<http::Response, String> {
        http::request(
            &self.host,
            self.port,
            "POST",
            LOGINCHECK,
            &mut self.cookies,
            &[],
            body.as_bytes(),
            self.timeout,
        )
    }

    /// Step 1: username + password (+ realm). `ftm_push` adds `&ftmpush=1` so the
    /// gateway may drive a FortiToken Mobile push.
    pub fn login(&mut self, password: &str, offer_push: bool) -> Result<AuthOutcome, String> {
        // Warm-up GET so the gateway sets any initial session cookie it expects
        // echoed on the logincheck POST (some FortiOS builds reject a cold POST).
        let _ = http::request(
            &self.host, self.port, "GET", "/remote/login?lang=en",
            &mut self.cookies, &[], b"", self.timeout,
        );
        let body = format!(
            "username={}&credential={}&realm={}{}{}",
            http::urlencode(&self.user),
            http::urlencode(password),
            http::urlencode(&self.realm),
            REDIR_SUFFIX,
            if offer_push { "&ftmpush=1" } else { "" },
        );
        let resp = self.post_logincheck(body)?;
        Ok(self.interpret(&resp))
    }

    /// Step 2: answer a `ret=2` / HTML-form challenge with a one-time `code`
    /// (FortiToken, email, SMS). `code2` is almost always empty (2-prompt setups).
    pub fn answer_challenge(&mut self, ch: &Challenge, code: &str, code2: &str) -> Result<AuthOutcome, String> {
        let body = if ch.html_form {
            // HTML-form flavor: magic/grpid, token goes in `credential`.
            format!(
                "magic={}&username={}&reqid={}&grpid={}&credential={}&credential2={}&realm={}",
                http::urlencode(&ch.magic),
                http::urlencode(&self.user),
                http::urlencode(&ch.reqid),
                http::urlencode(&ch.grpid),
                http::urlencode(code),
                http::urlencode(code2),
                http::urlencode(&self.realm),
            )
        } else {
            format!(
                "username={}&reqid={}&polid={}&grp={}&realm={}&peer=&code={}&code2={}{}",
                http::urlencode(&self.user),
                http::urlencode(&ch.reqid),
                http::urlencode(&ch.polid),
                http::urlencode(&ch.grp),
                http::urlencode(&self.realm),
                http::urlencode(code),
                http::urlencode(code2),
                REDIR_SUFFIX,
            )
        };
        let resp = self.post_logincheck(body)?;
        Ok(self.interpret(&resp))
    }

    /// Classify a logincheck response.
    fn interpret(&mut self, resp: &http::Response) -> AuthOutcome {
        // The cookie jar already absorbed any Set-Cookie in http::request.
        if self.svpncookie().is_some() {
            return AuthOutcome::Authenticated;
        }
        let body = resp.body_str();
        let fields = parse_ret_fields(&body);
        let ret = fields.get("ret").map(|s| s.as_str()).unwrap_or("");

        // Some gateways return ret=1 with the cookie only after following `redir`;
        // but the ajax flow sets SVPNCOOKIE on this response, so no cookie here = fail.
        match ret {
            "2" => {
                let ch = Challenge {
                    reqid: fields.get("reqid").cloned().unwrap_or_default(),
                    polid: fields.get("polid").cloned().unwrap_or_default(),
                    grp: fields.get("grp").cloned().unwrap_or_default(),
                    tokeninfo: fields.get("tokeninfo").cloned().unwrap_or_default(),
                    message: fields.get("chal_msg").cloned().unwrap_or_default(),
                    ftm_push: body.contains("ftm_push") || fields.contains_key("ftm_push"),
                    ..Default::default()
                };
                AuthOutcome::Challenge(ch)
            }
            "1" => AuthOutcome::Failed("gateway returned ret=1 but no SVPNCOOKIE (unexpected)".into()),
            _ => {
                // No `ret=`: could be the HTML-form 2FA flavor, or an HTML error page.
                if let Some(ch) = parse_html_challenge(&body) {
                    return AuthOutcome::Challenge(ch);
                }
                AuthOutcome::Failed(clean_failure(&fields, &body, resp.status))
            }
        }
    }
}

/// Parse a FortiGate `ret=2,reqid=..,polid=..,grp=..,tokeninfo=..` style body into
/// key→value. Fields are comma-separated (sometimes `&`); values may be empty.
fn parse_ret_fields(body: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    // Use only the first logical line; tolerate both ',' and '&' separators.
    let line = body.lines().find(|l| l.contains('=')).unwrap_or("");
    for tok in line.split(['&', ',']) {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        if let Some((k, v)) = tok.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

/// Detect the HTML-form 2FA flavor: a page with a hidden `reqid` input (plus
/// `magic`/`grpid`) and a credential/token field. A plain login page (no `reqid`)
/// returns `None`, so an unknown-user response isn't mistaken for a challenge.
fn parse_html_challenge(body: &str) -> Option<Challenge> {
    let reqid = find_input(body, "reqid")?;
    Some(Challenge {
        reqid,
        polid: find_input(body, "polid").unwrap_or_default(),
        grpid: find_input(body, "grpid").unwrap_or_default(),
        magic: find_input(body, "magic").unwrap_or_default(),
        message: "FortiToken / 2FA code required".to_string(),
        html_form: true,
        ..Default::default()
    })
}

/// Value of the first `<input ... name="NAME" ... value="...">` in `body`.
fn find_input(body: &str, name: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let want = name.to_ascii_lowercase();
    let mut search = 0;
    while let Some(rel) = lower[search..].find("<input") {
        let start = search + rel;
        let end = body[start..].find('>').map(|e| start + e + 1).unwrap_or(body.len());
        let tag = &body[start..end];
        let tl = tag.to_ascii_lowercase();
        if tl.contains(&format!("name=\"{want}\"")) || tl.contains(&format!("name='{want}'")) {
            return attr_value(tag, "value");
        }
        search = end;
    }
    None
}

/// Extract an attribute value (quoted or bare) from a single HTML tag.
fn attr_value(tag: &str, attr: &str) -> Option<String> {
    let tl = tag.to_ascii_lowercase();
    let key = format!("{}=", attr.to_ascii_lowercase());
    let pos = tl.find(&key)? + key.len();
    let rest = &tag[pos..];
    let bytes = rest.as_bytes();
    match bytes.first() {
        Some(&q) if q == b'"' || q == b'\'' => {
            let qc = q as char;
            let end = rest[1..].find(qc)? + 1;
            Some(rest[1..end].to_string())
        }
        _ => {
            let end = rest.find(|c: char| c.is_whitespace() || c == '>' || c == '/').unwrap_or(rest.len());
            Some(rest[..end].to_string())
        }
    }
}

/// A concise failure message — never dump a whole HTML login page at the user.
fn clean_failure(fields: &std::collections::BTreeMap<String, String>, body: &str, status: u16) -> String {
    if let Some(m) = fields.get("chal_msg").or_else(|| fields.get("err")).filter(|m| !m.is_empty()) {
        return format!("login rejected: {m}");
    }
    let bl = body.to_ascii_lowercase();
    if bl.contains("<html") || bl.contains("fgt_lang") || bl.contains("<body") {
        return format!(
            "login rejected by gateway (HTTP {status}) — check username, password and realm \
             (gateway returned its login/error page, not an auth token)"
        );
    }
    if body.trim().is_empty() {
        format!("login rejected (HTTP {status})")
    } else {
        format!("login rejected: {}", body.trim())
    }
}
