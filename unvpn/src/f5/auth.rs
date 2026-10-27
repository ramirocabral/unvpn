//! APM login is a chain of HTML forms (there is no `ret=`-style API like Fortinet):
//!
//!   GET /                       → logon page, `<form id="auth_form">` (user+pass)
//!   POST <form action>          → success, or another form (group pick / 2FA / OTP)
//!   …repeat…                    → until both `MRHSession` and `F5_ST` cookies are set
//!
//! `MRHSession` alone is not sufficient — APM resets it repeatedly during the flow;
//! the presence of `F5_ST` (the session-timeout cookie) marks a completed logon.
//! Some portals build the form in JavaScript with no static HTML; there we fall back
//! to a plain username+password form.

use super::http::{self, Cookies};
use std::time::Duration;

/// Redirects to the logon page (`/my.policy`).
const START_PATH: &str = "/";
/// Default form target when a parsed form carries no `action`.
const DEFAULT_ACTION: &str = "/my.policy";

pub struct Session {
    pub host: String,
    pub port: u16,
    pub timeout: Duration,
    pub cookies: Cookies,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Password,
    Hidden,
    Other,
}

#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub value: String,
    pub kind: FieldKind,
}

#[derive(Debug, Clone)]
pub struct LoginForm {
    pub action: String,
    pub fields: Vec<Field>,
    /// Prompt text shown by the gateway, if any (e.g. OTP instructions).
    pub banner: String,
}

impl LoginForm {
    pub fn text_fields(&self) -> Vec<usize> {
        self.fields.iter().enumerate().filter(|(_, f)| f.kind == FieldKind::Text).map(|(i, _)| i).collect()
    }
    pub fn password_fields(&self) -> Vec<usize> {
        self.fields.iter().enumerate().filter(|(_, f)| f.kind == FieldKind::Password).map(|(i, _)| i).collect()
    }
}

pub enum Outcome {
    Authenticated,
    /// Another form (group selection / 2FA / OTP).
    NextForm(LoginForm),
    Failed(String),
}

impl Session {
    pub fn new(host: String, port: u16, timeout: Duration) -> Self {
        Session { host, port, timeout, cookies: Cookies::new() }
    }

    /// Session from a one-time launch token (the webtop "Start" / SSO handoff):
    ///
    ///   GET /vdesk/get_sessid_for_token.php3   (header `X-ACCESS-Session-Token: <otc>`)
    ///   → 200, response header `X-ACCESS-Session-ID: <MRHSession>`
    ///
    /// The returned session id is the `MRHSession` cookie; the browser already
    /// completed the access policy.
    pub fn from_handoff(host: String, port: u16, timeout: Duration, token: &str) -> Result<Session, String> {
        let mut cookies = Cookies::new();
        let extra = vec![format!("X-ACCESS-Session-Token: {token}")];
        let resp = http::request(
            &host, port, "GET", "/vdesk/get_sessid_for_token.php3",
            &mut cookies, &extra, b"", timeout,
        )?;
        if resp.status != 200 {
            return Err(format!(
                "token handoff failed: HTTP {} (the launch token is one-time and short-lived — click Start again)",
                resp.status
            ));
        }
        let sid = resp
            .header("X-ACCESS-Session-ID")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or("token handoff: server returned no X-ACCESS-Session-ID")?
            .to_string();
        let mut s = Session::new(host, port, timeout);
        s.cookies.0.insert("MRHSession".to_string(), sid);
        Ok(s)
    }

    pub fn authenticated(&self) -> bool {
        self.cookies.get("MRHSession").map(|v| !v.is_empty()).unwrap_or(false)
            && self.cookies.get("F5_ST").map(|v| !v.is_empty()).unwrap_or(false)
    }

    pub fn start(&mut self) -> Result<LoginForm, String> {
        let resp = http::request_follow(
            &self.host, self.port, "GET", START_PATH,
            &mut self.cookies, &[], b"", self.timeout, 5,
        )?;
        let body = resp.body_str();
        Ok(parse_form(&body).unwrap_or_else(fallback_form))
    }

    /// `answers` (name → value) override the form's default field values.
    pub fn submit(&mut self, form: &LoginForm, answers: &[(String, String)]) -> Result<Outcome, String> {
        let mut body = String::new();
        for f in &form.fields {
            let val = answers
                .iter()
                .find(|(n, _)| n == &f.name)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| f.value.clone());
            if !body.is_empty() {
                body.push('&');
            }
            body.push_str(&http::urlencode(&f.name));
            body.push('=');
            body.push_str(&http::urlencode(&val));
        }

        let action = if form.action.trim().is_empty() { DEFAULT_ACTION } else { form.action.trim() };
        let resp = http::request_follow(
            &self.host, self.port, "POST", action,
            &mut self.cookies, &[], body.as_bytes(), self.timeout, 5,
        )?;

        if self.authenticated() {
            return Ok(Outcome::Authenticated);
        }
        let text = resp.body_str();
        if let Some(next) = parse_form(&text) {
            return Ok(Outcome::NextForm(next));
        }
        Ok(Outcome::Failed(clean_failure(&text, resp.status)))
    }
}

pub fn try_parse_form(body: &str) -> Option<LoginForm> {
    parse_form(body)
}

/// The plain username+password form used when the portal serves only a
/// JavaScript-built form.
fn fallback_form() -> LoginForm {
    LoginForm {
        action: DEFAULT_ACTION.to_string(),
        fields: vec![
            Field { name: "username".into(), value: String::new(), kind: FieldKind::Text },
            Field { name: "password".into(), value: String::new(), kind: FieldKind::Password },
        ],
        banner: String::new(),
    }
}

/// Prefers the F5 `id="auth_form"`, else the first `<form>`.
fn parse_form(body: &str) -> Option<LoginForm> {
    let lower = body.to_ascii_lowercase();
    let form_start = find_auth_form_start(&lower).or_else(|| lower.find("<form"))?;
    let tag_end = body[form_start..].find('>')? + form_start + 1;
    let form_tag = &body[form_start..tag_end];
    let close_rel = lower[tag_end..].find("</form>");
    let inner_end = close_rel.map(|e| tag_end + e).unwrap_or(body.len());
    let inner = &body[tag_end..inner_end];

    let action = attr_value(form_tag, "action").unwrap_or_default();
    let fields = collect_inputs(inner);
    if fields.is_empty() {
        return None;
    }
    let has_secretish = fields
        .iter()
        .any(|f| f.kind == FieldKind::Password || f.kind == FieldKind::Text);
    if !has_secretish {
        return None;
    }
    let banner = extract_banner(inner);
    Some(LoginForm { action, fields, banner })
}

fn find_auth_form_start(lower: &str) -> Option<usize> {
    let mut i = 0;
    while let Some(rel) = lower[i..].find("<form") {
        let start = i + rel;
        let end = lower[start..].find('>').map(|e| start + e + 1).unwrap_or(lower.len());
        if lower[start..end].contains("auth_form") {
            return Some(start);
        }
        i = end;
    }
    None
}

fn collect_inputs(inner: &str) -> Vec<Field> {
    let mut out = Vec::new();
    let lower = inner.to_ascii_lowercase();
    let mut i = 0;
    while let Some(rel) = lower[i..].find("<input") {
        let start = i + rel;
        let end = inner[start..].find('>').map(|e| start + e + 1).unwrap_or(inner.len());
        let tag = &inner[start..end];
        i = end;
        let Some(name) = attr_value(tag, "name") else { continue };
        if name.is_empty() {
            continue;
        }
        let value = attr_value(tag, "value").unwrap_or_default();
        let kind = match attr_value(tag, "type").unwrap_or_default().to_ascii_lowercase().as_str() {
            "password" => FieldKind::Password,
            "hidden" => FieldKind::Hidden,
            "text" | "email" | "tel" | "number" | "" => FieldKind::Text,
            "submit" | "button" | "image" | "reset" | "checkbox" | "radio" | "file" => FieldKind::Other,
            _ => FieldKind::Other,
        };
        out.push(Field { name, value, kind });
    }
    out
}

/// Best-effort visible text of the form, used to surface OTP instructions.
fn extract_banner(inner: &str) -> String {
    let mut text = String::new();
    let mut in_tag = false;
    for c in inner.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => text.push(c),
            _ => {}
        }
    }
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    line.chars().take(160).collect::<String>().trim().to_string()
}

fn attr_value(tag: &str, attr: &str) -> Option<String> {
    let tl = tag.to_ascii_lowercase();
    let key = format!("{}=", attr.to_ascii_lowercase());
    // Match the attribute as a whole token (preceded by whitespace or tag start).
    let mut search = 0;
    let pos = loop {
        let rel = tl[search..].find(&key)?;
        let at = search + rel;
        let prev_ok = at == 0 || tl.as_bytes()[at - 1].is_ascii_whitespace();
        if prev_ok {
            break at + key.len();
        }
        search = at + key.len();
    };
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

/// Never dump a whole HTML page at the user.
fn clean_failure(body: &str, status: u16) -> String {
    let bl = body.to_ascii_lowercase();
    for needle in ["session has expired", "logon denied", "access was denied", "authentication failed", "invalid"] {
        if let Some(p) = bl.find(needle) {
            let snippet: String = body[p..].chars().take(80).collect();
            return format!("login rejected: {}", snippet.trim());
        }
    }
    if bl.contains("<html") || bl.contains("<body") {
        return format!(
            "login rejected by gateway (HTTP {status}) — check username/password \
             (the gateway returned a page, not a session cookie)"
        );
    }
    format!("login rejected (HTTP {status})")
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOGON: &str = r#"<html><body>
      <form id="auth_form" method="post" action="/my.policy" name="auth_form">
        <input type="hidden" name="vhost" value="standard">
        <input type="text" name="username" value="">
        <input type="password" name="password" autocomplete="off">
        <input type="submit" name="ok" value="Logon">
      </form></body></html>"#;

    const OTP: &str = r#"<html><body>
      <form id="auth_form" method="post" action="/my.policy">
        <div class="credentials_table_text">Enter your one-time passcode</div>
        <input type="hidden" name="vhost" value="standard">
        <input type="hidden" name="reference" value="abc123">
        <input type="password" name="password" value="">
      </form></body></html>"#;

    #[test]
    fn parses_logon_form() {
        let f = parse_form(LOGON).expect("form");
        assert_eq!(f.action, "/my.policy");
        assert_eq!(f.fields.len(), 4);
        let names: Vec<&str> = f.fields.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["vhost", "username", "password", "ok"]);
        assert_eq!(f.text_fields().len(), 1);
        assert_eq!(f.password_fields().len(), 1);
        assert_eq!(f.fields[0].kind, FieldKind::Hidden);
        assert_eq!(f.fields[0].value, "standard");
    }

    #[test]
    fn otp_form_has_banner_and_hidden_state() {
        let f = parse_form(OTP).expect("form");
        assert!(f.banner.to_lowercase().contains("one-time"));
        assert!(f.fields.iter().any(|x| x.name == "reference" && x.value == "abc123"));
        assert_eq!(f.password_fields().len(), 1);
        assert_eq!(f.text_fields().len(), 0);
    }

    #[test]
    fn body_submit_overrides_only_named() {
        let f = parse_form(LOGON).unwrap();
        let answers = vec![("username".to_string(), "alice".to_string()),
                           ("password".to_string(), "s3cr3t&=x".to_string())];
        // Reconstruct the body the way submit does, without network.
        let mut body = String::new();
        for fld in &f.fields {
            let val = answers.iter().find(|(n, _)| n == &fld.name).map(|(_, v)| v.clone()).unwrap_or(fld.value.clone());
            if !body.is_empty() { body.push('&'); }
            body.push_str(&http::urlencode(&fld.name));
            body.push('=');
            body.push_str(&http::urlencode(&val));
        }
        assert!(body.contains("username=alice"));
        assert!(body.contains("password=s3cr3t%26%3Dx"));
        assert!(body.contains("vhost=standard"));
        assert!(body.contains("ok=Logon"));
    }

    #[test]
    fn no_form_returns_none() {
        assert!(parse_form("<html><body>nothing here</body></html>").is_none());
    }
}
