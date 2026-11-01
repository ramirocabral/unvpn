//! Ivanti Connect Secure (Pulse) web authentication.
//!
//! The flow against a sign-in URL (`/dana-na/auth/url_<policy>/`):
//!
//! 1. `GET welcome.cgi` — the login form. It names the credential fields and,
//!    when the policy offers a choice, a `realm` `<select>`; it may also carry
//!    hidden form tokens that must be echoed back.
//! 2. `POST login.cgi` with username/password/realm (plus any hidden fields).
//!    On success the gateway sets a `DSID` session cookie.
//! 3. A reply may instead be a second-factor page, or a "session already open"
//!    confirmation that has to be re-posted to continue. Both are handled by
//!    re-posting the form the page asks for.
//!
//! The `DSID` cookie is what the data plane carries to open the tunnel.

use super::http::{self, Cookies, Endpoint, Form, Response};

#[derive(Debug)]
pub enum IvantiError {
    /// The host does not look like an Ivanti/Pulse sign-in endpoint.
    NotHere(String),
    /// Credentials rejected — a fresh attempt may help.
    BadCreds(String),
    /// Reached a step this skeleton does not yet drive (needs a capture).
    Unimplemented(String),
    Other(String),
}

impl std::fmt::Display for IvantiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IvantiError::NotHere(m)
            | IvantiError::BadCreds(m)
            | IvantiError::Unimplemented(m)
            | IvantiError::Other(m) => f.write_str(m),
        }
    }
}

impl From<String> for IvantiError {
    fn from(s: String) -> Self {
        IvantiError::Other(s)
    }
}

type Result<T> = std::result::Result<T, IvantiError>;

/// Credentials for a password login.
pub struct Creds {
    pub user: String,
    pub password: Option<String>,
}

/// Front-end callbacks for interactive input (TTY or GUI).
pub trait Prompter {
    fn password(&mut self, label: &str) -> std::result::Result<String, String>;
    fn challenge(&mut self, message: &str) -> std::result::Result<String, String>;
    fn info(&mut self, line: &str);
}

/// What `welcome.cgi` tells us before we authenticate.
#[derive(Debug, Default)]
pub struct Prelogin {
    pub user_label: String,
    pub pass_label: String,
    pub realms: Vec<String>,
    pub message: String,
}

pub struct Session {
    pub ep: Endpoint,
    pub cookies: Cookies,
    /// Sign-in policy URL segment, e.g. `url_default`.
    pub url: String,
    pub dsid: Option<String>,
}

impl Session {
    pub fn new(ep: Endpoint, url: &str) -> Self {
        Session { ep, cookies: Cookies::default(), url: url.to_string(), dsid: None }
    }

    fn auth_path(&self, page: &str) -> String {
        format!("{}/{}/{}", http::AUTH_BASE, self.url, page)
    }

    /// GET the login page and read what it asks for.
    pub fn prelogin(&mut self) -> Result<Prelogin> {
        let resp = http::get(&self.ep, &self.auth_path("welcome.cgi"), &mut self.cookies)?;
        let body = resp.body_str();
        if !looks_like_ivanti(&resp, &body) {
            return Err(IvantiError::NotHere(format!(
                "{} did not answer with an Ivanti/Pulse sign-in page (HTTP {})",
                self.ep.host_header(),
                resp.status
            )));
        }
        Ok(Prelogin {
            user_label: field_label(&body, "username").unwrap_or_else(|| "Username".into()),
            pass_label: field_label(&body, "password").unwrap_or_else(|| "Password".into()),
            realms: select_options(&body, "realm"),
            message: String::new(),
        })
    }

    /// Password sign-in. On success `self.dsid` holds the session cookie.
    pub fn login(&mut self, creds: &Creds, realm: Option<&str>, p: &mut dyn Prompter) -> Result<()> {
        // Prime the form page for cookies and hidden fields.
        let page = http::get(&self.ep, &self.auth_path("welcome.cgi"), &mut self.cookies)?;
        if !looks_like_ivanti(&page, &page.body_str()) {
            return Err(IvantiError::NotHere(format!("{} is not an Ivanti sign-in page", self.ep.host_header())));
        }
        let password = match creds.password.clone() {
            Some(pw) => pw,
            None => p.password("Password").map_err(IvantiError::Other)?,
        };

        let mut form = Form::new();
        form.add("tz_offset", "0")
            .add("username", &creds.user)
            .add("password", &password);
        if let Some(r) = realm {
            form.add("realm", r);
        }
        form.add("btnSubmit", "Sign In");
        for (k, v) in hidden_fields(&page.body_str()) {
            form.add(&k, &v);
        }

        let resp = http::post_form(&self.ep, &self.auth_path("login.cgi"), &mut self.cookies, &form.encode())?;
        self.absorb_dsid();
        if self.dsid.is_some() {
            return Ok(());
        }
        self.after_login(resp, p)
    }

    /// Classify a login reply that did not immediately yield a DSID.
    fn after_login(&mut self, resp: Response, p: &mut dyn Prompter) -> Result<()> {
        let body = resp.body_str().to_string();
        let low = body.to_ascii_lowercase();
        if low.contains("invalid") && (low.contains("username") || low.contains("password") || low.contains("credential")) {
            return Err(IvantiError::BadCreds("the gateway rejected the credentials".into()));
        }
        if low.contains("frmconfirmation") || low.contains("btncontinue") {
            // An older session is still open; the page must be re-posted to take over.
            p.info("a previous session is still open on the gateway — continuing it");
            return Err(IvantiError::Unimplemented(
                "session-takeover confirmation is not driven yet (needs a capture of login.cgi's continue form)".into(),
            ));
        }
        if low.contains("secondary") || low.contains("token") || low.contains("passcode") || low.contains("frmdefender") {
            let _ = p.challenge("Enter your second-factor code").map_err(IvantiError::Other)?;
            return Err(IvantiError::Unimplemented(
                "second-factor re-post is not driven yet (needs a capture of the challenge form)".into(),
            ));
        }
        Err(IvantiError::Unimplemented(format!(
            "login.cgi returned HTTP {} without a DSID and an unrecognized page — a capture is needed to drive it",
            resp.status
        )))
    }

    fn absorb_dsid(&mut self) {
        if let Some(v) = self.cookies.get("DSID") {
            self.dsid = Some(v.to_string());
        }
    }
}

/// Markers of the Ivanti/Pulse web front end.
fn looks_like_ivanti(resp: &Response, body: &str) -> bool {
    if resp.header("set-cookie").map(|c| c.contains("DSID") || c.contains("DSSIGNIN")).unwrap_or(false) {
        return true;
    }
    let b = body.to_ascii_lowercase();
    b.contains("/dana-na/") || b.contains("dsidformdatastr") || b.contains("frmlogin") || b.contains("pulse secure") || b.contains("ivanti")
}

/// Hidden `<input>` name/value pairs that must be echoed back on POST.
fn hidden_fields(html: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for tag in html.split('<').filter(|t| t.trim_start().to_ascii_lowercase().starts_with("input")) {
        let low = tag.to_ascii_lowercase();
        if !low.contains("type=\"hidden\"") && !low.contains("type='hidden'") {
            continue;
        }
        if let (Some(name), value) = (attr(tag, "name"), attr(tag, "value").unwrap_or_default()) {
            if !name.is_empty() {
                out.push((name, value));
            }
        }
    }
    out
}

/// A field's visible label, best-effort — falls back to the caller's default.
fn field_label(_html: &str, _field: &str) -> Option<String> {
    None
}

/// `<option value="...">` entries of a named `<select>`.
fn select_options(html: &str, name: &str) -> Vec<String> {
    let low = html.to_ascii_lowercase();
    let needle = format!("name=\"{}\"", name.to_ascii_lowercase());
    let Some(sel) = low.find(&needle) else { return Vec::new() };
    let end = low[sel..].find("</select>").map(|e| sel + e).unwrap_or(html.len());
    let mut out = Vec::new();
    for opt in html[sel..end].split('<').filter(|t| t.trim_start().to_ascii_lowercase().starts_with("option")) {
        if let Some(v) = attr(opt, "value") {
            if !v.is_empty() {
                out.push(v);
            }
        }
    }
    out
}

/// Read `attr="value"` or `attr='value'` out of a tag fragment.
fn attr(tag: &str, name: &str) -> Option<String> {
    let low = tag.to_ascii_lowercase();
    let key = format!("{}=", name.to_ascii_lowercase());
    let at = low.find(&key)? + key.len();
    let rest = &tag[at..];
    let quote = rest.chars().next()?;
    if quote == '"' || quote == '\'' {
        let rest = &rest[1..];
        let end = rest.find(quote)?;
        Some(rest[..end].to_string())
    } else {
        let end = rest.find(|c: char| c.is_whitespace() || c == '>' || c == '/').unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrapes_hidden_fields() {
        let html = r#"<form><input type="hidden" name="FormDataStr" value="abc123"><input type="text" name="username"><input type='hidden' name='xsauth_token' value='zz'></form>"#;
        let got = hidden_fields(html);
        assert_eq!(got, vec![("FormDataStr".to_string(), "abc123".to_string()), ("xsauth_token".to_string(), "zz".to_string())]);
    }

    #[test]
    fn reads_realm_options() {
        let html = r#"<select name="realm"><option value="Users">Users</option><option value="Admin">Admin</option></select>"#;
        assert_eq!(select_options(html, "realm"), vec!["Users", "Admin"]);
        assert!(select_options(html, "missing").is_empty());
    }

    #[test]
    fn detects_the_front_end() {
        let resp = Response { status: 200, headers: vec![], body: Vec::new() };
        assert!(looks_like_ivanti(&resp, "<a href=\"/dana-na/auth/url_default/welcome.cgi\">"));
        assert!(!looks_like_ivanti(&resp, "<html>nothing here</html>"));
    }
}
