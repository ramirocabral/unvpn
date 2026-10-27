//! AnyConnect "aggregate auth": the XML login dialogue that yields the `webvpn`
//! session cookie.
//!
//! The client POSTs `<config-auth type="init">` to the gateway (or its group URL);
//! the gateway answers `<config-auth type="auth-request">` carrying an opaque blob
//! (echoed back verbatim on every reply) and a form — username/password, a group
//! dropdown, a challenge (OTP / RADIUS answer), a new-password request, or an SSO
//! token field. The client answers `<config-auth type="auth-reply">` and repeats
//! until `<config-auth type="complete">` with `<auth id="success">` and the
//! `<session-token>` (= the `webvpn` cookie for the tunnel).
//!
//! Field mapping: `group_list` → `<group-select>`; `answer` / `new_password` /
//! `whichpin` → `<password>`; `verify_*` dropped; everything else →
//! `<name>value</name>` under `<auth>`.

use super::http::{self, Cookies, Endpoint};
use super::xml::{self, Element};

/// `<device-id>`: what the 64-bit Linux AnyConnect client reports.
pub const DEVICE_ID: &str = "linux-64";
pub const XML_CT: &str = "application/xml; charset=utf-8";

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Text,
    Password,
    Hidden,
    /// SSO token (`<input type="sso">`): obtained from a web login, not typed.
    Sso,
}

#[derive(Debug, Clone)]
pub struct Field {
    pub name: String,
    pub label: String,
    pub kind: Kind,
    pub value: Option<String>,
    /// Only asked when the chosen group does secondary auth (`second-auth="1"`).
    pub second_auth: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Choice {
    pub value: String,
    pub label: String,
    pub selected: bool,
    pub second_auth: bool,
    /// Group needs no AAA credentials (certificate-only).
    pub noaaa: bool,
    pub secondary_username: Option<String>,
    /// Parsed from the choice; kept for protocol completeness. We always use the
    /// preset secondary username when present, so the editable flag isn't branched on.
    #[allow(dead_code)]
    pub secondary_username_editable: bool,
}

#[derive(Debug, Clone)]
pub struct Select {
    pub name: String,
    pub label: String,
    pub choices: Vec<Choice>,
}

impl Select {
    pub fn default_index(&self) -> usize {
        self.choices.iter().position(|c| c.selected).unwrap_or(0)
    }
    pub fn find(&self, want: &str) -> Option<usize> {
        self.choices
            .iter()
            .position(|c| c.value.eq_ignore_ascii_case(want) || c.label.trim().eq_ignore_ascii_case(want))
    }
}

/// SAML "sso-v2" parameters from an `<auth>` node.
#[derive(Debug, Clone, Default)]
pub struct Sso {
    pub login: String,
    pub login_final: String,
    pub token_cookie: String,
    pub error_cookie: String,
    /// `external` when the gateway supports the external-browser flow.
    pub browser_mode: String,
}

/// A parsed `<auth>` node.
#[derive(Debug, Clone, Default)]
pub struct Form {
    pub auth_id: String,
    pub title: Option<String>,
    pub message: Option<String>,
    pub banner: Option<String>,
    pub error: Option<String>,
    /// Where to POST the reply (form `action`). `None`: the form didn't say, so
    /// reuse the current URL — the group path (`/SSOGROUP`) matters there: a
    /// SAML token posted to `/` instead is rejected ("Authentication failed").
    pub action: Option<String>,
    pub fields: Vec<Field>,
    pub selects: Vec<Select>,
    pub sso: Option<Sso>,
    /// `<authentication-complete/>`: post the (empty) reply once more to finish.
    pub complete_marker: bool,
}

impl Form {
    pub fn group_select(&self) -> Option<&Select> {
        self.selects.iter().find(|s| s.name == "group_list")
    }
    pub fn has(&self, name: &str) -> bool {
        self.fields.iter().any(|f| f.name == name)
    }
}

/// A parsed `<config-auth>` reply.
#[derive(Debug, Clone, Default)]
pub struct Reply {
    /// The `type` attribute (`auth-request`, `complete`).
    pub kind: String,
    pub form: Option<Form>,
    /// The raw `<opaque …>…</opaque>` element, to echo back.
    pub opaque: Option<String>,
    pub session_token: Option<String>,
    pub cert_requested: bool,
    /// The gateway wants a Cisco Secure Desktop / HostScan run.
    pub host_scan: bool,
    /// Top-level `<error>` (outside `<auth>`).
    pub error: Option<String>,
    /// Value-free structure of the document, for diagnostics.
    pub outline: String,
}

pub fn parse_reply(doc: &str) -> Result<Reply, String> {
    let root = xml::parse(doc).map_err(|e| format!("bad XML from gateway: {e}"))?;
    if root.name != "config-auth" {
        return Err(format!("unexpected XML root <{}> (not an AnyConnect gateway?)", root.name));
    }
    let mut r = Reply { kind: root.attr("type").unwrap_or("").to_string(), outline: root.outline(), ..Default::default() };
    for c in &root.children {
        match c.name.as_str() {
            "opaque" => r.opaque = Some(doc[c.span.0..c.span.1].to_string()),
            "auth" => r.form = Some(parse_auth(c)),
            "session-token" => r.session_token = Some(c.text.trim().to_string()).filter(|s| !s.is_empty()),
            "client-cert-request" | "multiple-client-cert-request" => r.cert_requested = true,
            "host-scan" => {
                r.host_scan = c.child("host-scan-ticket").is_some() || c.child("host-scan-token").is_some()
            }
            "error" => r.error = msg_text(c),
            _ => {}
        }
    }
    Ok(r)
}

/// Text of a `<message>`/`<error>` node with its `%s` placeholders filled from the
/// `param1`/`param2` attributes.
fn msg_text(e: &Element) -> Option<String> {
    let fmt = e.deep_text();
    if fmt.trim().is_empty() {
        return None;
    }
    let mut out = String::new();
    let mut params = [e.attr("param1"), e.attr("param2")].into_iter();
    let mut rest = fmt.as_str();
    while let Some(p) = rest.find("%s") {
        out.push_str(&rest[..p]);
        out.push_str(params.next().flatten().unwrap_or(""));
        rest = &rest[p + 2..];
    }
    out.push_str(rest);
    Some(out.trim().to_string())
}

fn parse_auth(a: &Element) -> Form {
    let mut f = Form { auth_id: a.attr("id").unwrap_or("").to_string(), ..Default::default() };
    let mut sso = Sso::default();
    for c in &a.children {
        match c.name.as_str() {
            "title" => f.title = msg_text(c),
            "message" => f.message = msg_text(c),
            "banner" => f.banner = msg_text(c),
            "error" => f.error = msg_text(c),
            "sso-v2-login" => sso.login = c.text.trim().to_string(),
            "sso-v2-login-final" => sso.login_final = c.text.trim().to_string(),
            "sso-v2-token-cookie-name" => sso.token_cookie = c.text.trim().to_string(),
            "sso-v2-error-cookie-name" => sso.error_cookie = c.text.trim().to_string(),
            "sso-v2-browser-mode" => sso.browser_mode = c.text.trim().to_string(),
            "authentication-complete" => f.complete_marker = true,
            "form" => {
                if let Some(act) = c.attr("action").filter(|s| !s.is_empty()) {
                    f.action = Some(act.to_string());
                }
                parse_form(c, &mut f);
            }
            _ => {}
        }
    }
    if !sso.login.is_empty() {
        f.sso = Some(sso);
    }
    f
}

fn parse_form(form: &Element, f: &mut Form) {
    for c in &form.children {
        match c.name.as_str() {
            "select" => {
                let choices: Vec<Choice> = c
                    .children_named("option")
                    .map(|o| {
                        let label = o.deep_text().trim().to_string();
                        Choice {
                            value: o.attr("value").map(str::to_string).unwrap_or_else(|| label.clone()),
                            label,
                            selected: o.attr("selected").is_some_and(|v| v.eq_ignore_ascii_case("true")),
                            second_auth: o.attr("second-auth") == Some("1"),
                            noaaa: o.attr("noaaa") == Some("1"),
                            secondary_username: o.attr("secondary_username").map(str::to_string),
                            secondary_username_editable: o.attr("secondary_username_editable") == Some("true"),
                        }
                    })
                    .collect();
                if let (Some(name), false) = (c.attr("name"), choices.is_empty()) {
                    f.selects.push(Select {
                        name: name.to_string(),
                        label: c.attr("label").unwrap_or(name).to_string(),
                        choices,
                    });
                }
            }
            "input" => {
                let (Some(ty), Some(name)) = (c.attr("type"), c.attr("name")) else { continue };
                let kind = match ty {
                    "text" => Kind::Text,
                    "password" => Kind::Password,
                    "hidden" => Kind::Hidden,
                    "sso" => Kind::Sso,
                    _ => continue,
                };
                f.fields.push(Field {
                    name: name.to_string(),
                    label: c.attr("label").map(str::to_string).unwrap_or_else(|| format!("{name}:")),
                    value: if kind == Kind::Hidden { c.attr("value").map(str::to_string) } else { None },
                    kind,
                    second_auth: c.attr("second-auth") == Some("1"),
                });
            }
            _ => {}
        }
    }
}

/// `<config-auth type="init">`. `group_access` is the URL the user aimed at;
/// `group` pre-selects a tunnel group; `cert_fail` tells the gateway we have no
/// client certificate.
pub fn build_init(version: &str, group_access: &str, group: Option<&str>, cert_fail: bool) -> String {
    let mut s = head("init", version);
    s.push_str(&format!("<group-access>{}</group-access>", xml::escape(group_access)));
    if cert_fail {
        s.push_str("<client-cert-fail></client-cert-fail>");
    }
    if let Some(g) = group {
        s.push_str(&format!("<group-select>{}</group-select>", xml::escape(g)));
    }
    s.push_str("</config-auth>");
    s
}

/// `<config-auth type="auth-reply">` with the opaque blob echoed back and the
/// answers mapped as the real client does.
pub fn build_reply(version: &str, opaque: Option<&str>, answers: &[(String, String)], group: Option<&str>) -> String {
    let mut s = head("auth-reply", version);
    if let Some(op) = opaque {
        s.push_str(op);
    }
    s.push_str("<auth>");
    for (name, value) in answers {
        let tag = match name.as_str() {
            "answer" | "whichpin" | "new_password" => "password",
            "verify_pin" | "verify_password" | "group_list" => continue,
            n => n,
        };
        if !is_xml_name(tag) {
            continue; // never let a gateway-supplied name break the document
        }
        s.push_str(&format!("<{tag}>{}</{tag}>", xml::escape(value)));
    }
    s.push_str("</auth>");
    if let Some(g) = group {
        s.push_str(&format!("<group-select>{}</group-select>", xml::escape(g)));
    }
    s.push_str("</config-auth>");
    s
}

fn head(kind: &str, version: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <config-auth client=\"vpn\" type=\"{kind}\" aggregate-auth-version=\"2\">\
         <version who=\"vpn\">{}</version><device-id>{DEVICE_ID}</device-id>\
         <capabilities><auth-method>single-sign-on-v2</auth-method></capabilities>",
        xml::escape(version)
    )
}

fn is_xml_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        && !s.starts_with(|c: char| c.is_ascii_digit() || c == '-' || c == '.')
}

/// How the login asks the user for things it doesn't already have. The CLI
/// implementation reads stdin and emits the `# AUTH-PROMPT:` markers the GUI
/// understands; tests use a scripted one.
pub trait Prompter {
    fn password(&mut self) -> Result<String, String>;
    /// A follow-up secret: OTP / token code / challenge answer / new password.
    /// `kind` is the GUI prompt kind (`code`, `answer`, `newpass`).
    fn ask(&mut self, kind: &str, message: &str) -> Result<String, String>;
    fn sso_token(&mut self, sso: &Sso) -> Result<String, String>;
    fn info(&mut self, line: &str);
}

pub struct Creds {
    pub user: String,
    pub password: Option<String>,
    pub group: Option<String>,
}

pub struct Session {
    pub ep: Endpoint,
    /// Path the user aimed at (`/` or a group URL like `/SSOGROUP`).
    pub path: String,
    pub version: String,
    pub cookies: Cookies,
    /// The `webvpn` session token once authenticated.
    pub token: Option<String>,
    pub group: Option<String>,
}

impl Session {
    pub fn new(ep: Endpoint, path: String, version: String) -> Self {
        Session { ep, path, version, cookies: Cookies::default(), token: None, group: None }
    }

    /// The `<group-access>` URL.
    pub fn group_access(&self, path: &str) -> String {
        format!("{}{}", self.ep.base_url(), path)
    }

    /// POST an XML body, returning the parsed reply. Cross-host redirects (load
    /// balancing to another cluster member) are followed by re-POSTing the same body
    /// to the new gateway, which becomes the session's endpoint. A same-host redirect
    /// means the gateway didn't take the XML login (an ancient non-aggregate-auth
    /// ASA); we report it.
    pub fn post_xml(&mut self, path: &mut String, body: &str) -> Result<Reply, String> {
        for _ in 0..5 {
            let resp = http::request(&self.ep, "POST", path, &mut self.cookies, Some(XML_CT), body.as_bytes())?;
            if (300..400).contains(&resp.status) {
                let loc = resp.header("location").ok_or("redirect without Location")?.to_string();
                let (h, p, newpath) = if loc.starts_with('/') {
                    (self.ep.host.clone(), self.ep.port, loc.clone())
                } else {
                    http::split_url(&loc)?
                };
                if h.eq_ignore_ascii_case(&self.ep.host) && p == self.ep.port {
                    return Err(format!(
                        "gateway redirected the XML login to {loc} — legacy (non aggregate-auth) login is not supported"
                    ));
                }
                out!("# gateway redirected to {h}:{p} (load balancing) — following");
                self.ep.host = h;
                self.ep.port = p;
                *path = newpath;
                continue;
            }
            if resp.status == 401 {
                return Err("gateway demands HTTP authentication (401) — not supported".into());
            }
            if resp.status != 200 {
                return Err(format!("gateway answered HTTP {}", resp.status));
            }
            let text = resp.body_str();
            if !text.trim_start().starts_with("<?xml") && !text.contains("<config-auth") {
                return Err("gateway did not answer with aggregate-auth XML (is this an AnyConnect gateway?)".into());
            }
            return parse_reply(&text);
        }
        Err("too many redirects".into())
    }

    /// On success `self.token` holds the cookie.
    pub fn login(&mut self, creds: &Creds, p: &mut dyn Prompter) -> Result<(), String> {
        let mut path = self.path.clone();
        let mut body = build_init(&self.version, &self.group_access(&path), creds.group.as_deref(), false);
        let mut opaque: Option<String> = None;
        let mut group_chosen = false;
        let mut cert_fail_sent = false;
        let mut password_sent = false;
        let mut sso_sent = false;
        let mut chosen_group: Option<String> = creds.group.clone();

        for _round in 0..12 {
            let reply = self.post_xml(&mut path, &body)?;
            if reply.opaque.is_some() {
                opaque = reply.opaque.clone();
            }

            let form_id = reply.form.as_ref().map(|f| f.auth_id.as_str()).unwrap_or("");
            let token = reply.session_token.clone().or_else(|| self.cookies.get("webvpn").map(str::to_string));
            if reply.kind == "complete" || form_id == "success" {
                let Some(token) = token else {
                    // `complete` + `<error>` = rejected (e.g. a bad/expired SSO token).
                    if let Some(e) = reply.error.as_deref().or(reply.form.as_ref().and_then(|f| f.error.as_deref())) {
                        return Err(format!("login failed: {}", one_line(e)));
                    }
                    let jar: Vec<&str> = self.cookies.0.keys().map(String::as_str).collect();
                    return Err(format!(
                        "login completed but the gateway sent no session token (reply: {}; cookies: [{}])",
                        reply.outline,
                        jar.join(", ")
                    ));
                };
                if let Some(b) = reply.form.as_ref().and_then(|f| f.banner.clone()) {
                    p.info(&format!("banner: {}", one_line(&b)));
                }
                self.cookies.set("webvpn", &token);
                self.token = Some(token);
                self.group = chosen_group;
                return Ok(());
            }

            if reply.cert_requested && reply.form.is_none() {
                if cert_fail_sent {
                    return Err("gateway requires a client certificate (not supported)".into());
                }
                p.info("gateway asked for a client certificate — telling it we have none");
                cert_fail_sent = true;
                body = build_init(&self.version, &self.group_access(&path), chosen_group.as_deref(), true);
                continue;
            }
            if reply.host_scan {
                return Err("gateway requires Cisco Secure Desktop / HostScan posture (not supported)".into());
            }
            let Some(form) = reply.form else {
                let e = reply.error.unwrap_or_else(|| "no <auth> form in the gateway reply".into());
                return Err(format!("login failed: {e}"));
            };

            if let Some(m) = &form.banner {
                p.info(&format!("banner: {}", one_line(m)));
            }
            if let Some(m) = &form.message {
                p.info(&format!("gateway: {}", one_line(m)));
            }
            // The gateway re-showing the first form with an error after we sent the
            // password means the credentials were rejected. Don't loop on them.
            if let Some(e) = form.error.as_deref().or(reply.error.as_deref()) {
                // A rejected SSO token comes back as a fresh SSO form + error: stop
                // (a new browser login is a new connection attempt, not a loop).
                if sso_sent && form.sso.is_some() {
                    return Err(format!("SSO login rejected: {}", one_line(e)));
                }
                if password_sent && form.has("password") && !matches!(form.auth_id.as_str(), "challenge") {
                    return Err(format!("login rejected: {}", one_line(e)));
                }
                p.info(&format!("gateway error: {}", one_line(e)));
                if form.fields.is_empty() && form.sso.is_none() {
                    return Err(format!("login failed: {}", one_line(e)));
                }
            }

            // Next POSTs go to the form action, else stay on the current URL
            //.
            if let Some(a) = &form.action {
                path = a.clone();
            }

            // Group dropdown: (re)start the dialogue once with the chosen group, so
            // the gateway serves that group's own form (it may ask for different
            // factors).
            let mut group_value: Option<String> = None;
            let mut choice: Option<Choice> = None;
            if let Some(sel) = form.group_select() {
                let idx = match chosen_group.as_deref() {
                    Some(want) => sel.find(want).ok_or_else(|| {
                        let avail: Vec<_> = sel.choices.iter().map(|c| c.label.as_str()).collect();
                        format!("group {want:?} not offered by the gateway (available: {})", avail.join(", "))
                    })?,
                    None => sel.default_index(),
                };
                let c = sel.choices[idx].clone();
                if !group_chosen {
                    group_chosen = true;
                    p.info(&format!("group: {} (of {})", c.label, sel.choices.len()));
                    chosen_group = Some(c.value.clone());
                    body = build_init(&self.version, &self.group_access(&path), chosen_group.as_deref(), cert_fail_sent);
                    continue;
                }
                group_value = Some(c.value.clone());
                choice = Some(c);
            }

            let answers = fill_form(&form, choice.as_ref(), creds, &mut password_sent, p)?;
            sso_sent |= form.fields.iter().any(|f| f.kind == Kind::Sso);
            if form.fields.is_empty() && !form.complete_marker {
                let e = form.error.or(form.message).unwrap_or_else(|| "gateway sent an empty form".into());
                return Err(format!("login failed: {}", one_line(&e)));
            }
            body = build_reply(&self.version, opaque.as_deref(), &answers, group_value.as_deref());
        }
        Err("authentication did not complete after 12 rounds".into())
    }
}

/// Decide a value for every field of `form`.
fn fill_form(
    form: &Form,
    choice: Option<&Choice>,
    creds: &Creds,
    password_sent: &mut bool,
    p: &mut dyn Prompter,
) -> Result<Vec<(String, String)>, String> {
    let challenge = form.auth_id == "challenge";
    let prompt_msg = |f: &Field| -> String {
        let label = f.label.trim().trim_end_matches(':').to_string();
        match form.message.as_deref() {
            Some(m) if !m.is_empty() => format!("{} ({label})", one_line(m)),
            _ => label,
        }
    };
    let mut answers = Vec::new();
    let mut new_password: Option<String> = None;
    for f in &form.fields {
        let ignored = choice.is_some_and(|c| c.noaaa || (!c.second_auth && f.second_auth));
        let value = if ignored {
            String::new()
        } else {
            match (&f.kind, f.name.as_str()) {
                (Kind::Hidden, _) => f.value.clone().unwrap_or_default(),
                (Kind::Sso, _) => {
                    let sso = form.sso.as_ref().ok_or("SSO token requested but no sso-v2 login URL")?;
                    p.sso_token(sso)?
                }
                (Kind::Text, "username") => {
                    if creds.user.is_empty() {
                        p.ask("answer", &prompt_msg(f))?
                    } else {
                        creds.user.clone()
                    }
                }
                (Kind::Text, "secondary_username") => match choice.and_then(|c| c.secondary_username.clone()) {
                    Some(u) => u,
                    None if !creds.user.is_empty() => creds.user.clone(),
                    None => p.ask("answer", &prompt_msg(f))?,
                },
                (Kind::Text, _) => p.ask("answer", &prompt_msg(f))?,
                (Kind::Password, "password") if !*password_sent && !challenge => {
                    *password_sent = true;
                    match &creds.password {
                        Some(pw) => pw.clone(),
                        None => p.password()?,
                    }
                }
                (Kind::Password, "new_password") => {
                    let v = p.ask("newpass", &prompt_msg(f))?;
                    new_password = Some(v.clone());
                    v
                }
                (Kind::Password, "verify_password") => new_password.clone().unwrap_or_default(),
                // secondary_password, answer, a re-asked password in a challenge, …
                (Kind::Password, _) => p.ask("code", &prompt_msg(f))?,
            }
        };
        answers.push((f.name.clone(), value));
    }
    Ok(answers)
}

/// Collapse gateway text to one line (it goes into single-line markers/logs).
pub fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const GW_A: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg">
<tunnel-group>AnyConnect_VPN</tunnel-group>
<aggauth-handle>4235996973563796626</aggauth-handle>
<auth-method>single-sign-on-v2</auth-method>
<group-alias>GROUP_A</group-alias>
<config-hash>1786604621138</config-hash>
</opaque>
<auth id="main">
<form>
<input type="text" name="username" label="Username:"></input>
<input type="password" name="password" label="Password:"></input>
<select name="group_list" label="GROUP:">
<option selected="true">GROUP_A</option>
<option>GROUP_B</option>
</select>
</form>
</auth>
</config-auth>"#;

    const SSO: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg"><tunnel-group>MFA_VPN</tunnel-group></opaque>
<auth id="main">
<message>Please complete the authentication process in the AnyConnect Login window.</message>
<sso-v2-login>https://gw/+CSCOE+/saml/sp/login?ctx=1&#x26;acsamlcap=v2</sso-v2-login>
<sso-v2-login-final>https://gw/+CSCOE+/saml_ac_login.html</sso-v2-login-final>
<sso-v2-token-cookie-name>acSamlv2Token</sso-v2-token-cookie-name>
<sso-v2-error-cookie-name>acSamlv2Error</sso-v2-error-cookie-name>
<form><input type="sso" name="sso-token"></input></form>
</auth>
</config-auth>"#;

    const COMPLETE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<session-id>12345</session-id>
<session-token>ABCDEF0123@12345@ABCD@0011</session-token>
<auth id="success"><banner>Authorized use only</banner><message id="0" param1="" param2=""></message></auth>
<capabilities><crypto-supported>ssl-dhe</crypto-supported></capabilities>
</config-auth>"#;

    #[test]
    fn parses_att_form() {
        let r = parse_reply(GW_A).unwrap();
        assert_eq!(r.kind, "auth-request");
        let f = r.form.unwrap();
        assert_eq!(f.auth_id, "main");
        assert_eq!(f.action, None);
        assert_eq!(f.fields.len(), 2);
        assert_eq!(f.fields[0].kind, Kind::Text);
        assert_eq!(f.fields[1].kind, Kind::Password);
        let g = f.group_select().unwrap();
        assert_eq!(g.default_index(), 0);
        assert_eq!(g.find("group_b"), Some(1));
        assert!(r.opaque.unwrap().contains("<aggauth-handle>4235996973563796626</aggauth-handle>"));
    }

    #[test]
    fn parses_sso_form() {
        let f = parse_reply(SSO).unwrap().form.unwrap();
        let s = f.sso.unwrap();
        assert_eq!(s.login, "https://gw/+CSCOE+/saml/sp/login?ctx=1&acsamlcap=v2");
        assert_eq!(s.token_cookie, "acSamlv2Token");
        assert_eq!(f.fields[0].kind, Kind::Sso);
    }

    #[test]
    fn parses_complete() {
        let r = parse_reply(COMPLETE).unwrap();
        assert_eq!(r.kind, "complete");
        assert_eq!(r.session_token.as_deref(), Some("ABCDEF0123@12345@ABCD@0011"));
        assert_eq!(r.form.unwrap().banner.as_deref(), Some("Authorized use only"));
    }

    #[test]
    fn message_params_are_substituted() {
        let r = parse_reply(
            r#"<config-auth type="auth-request"><auth id="main"><error id="88" param1="3" param2="">Login failed (%s attempts left).</error><form></form></auth></config-auth>"#,
        )
        .unwrap();
        assert_eq!(r.form.unwrap().error.as_deref(), Some("Login failed (3 attempts left)."));
    }

    #[test]
    fn reply_maps_fields_and_echoes_opaque() {
        let op = "<opaque is-for=\"sg\"><x>1</x></opaque>";
        let ans = vec![
            ("username".to_string(), "u<1>".to_string()),
            ("password".to_string(), "p&w".to_string()),
            ("answer".to_string(), "123456".to_string()),
            ("verify_password".to_string(), "zzz".to_string()),
            ("bad name".to_string(), "x".to_string()),
        ];
        let s = build_reply("v9.21", Some(op), &ans, Some("GROUP_A"));
        assert!(s.contains("type=\"auth-reply\""));
        assert!(s.contains(op));
        assert!(s.contains("<username>u&lt;1&gt;</username>"));
        assert!(s.contains("<password>p&amp;w</password>"));
        assert!(s.contains("<password>123456</password>"));
        assert!(!s.contains("zzz"));
        assert!(!s.contains("bad name"));
        assert!(s.contains("<group-select>GROUP_A</group-select>"));
        assert_eq!(xml::parse(&s).unwrap().name, "config-auth");
    }

    #[test]
    fn init_has_group_access_and_group() {
        let s = build_init("v9.21", "https://gw/grp", Some("G1"), false);
        let root = xml::parse(&s).unwrap();
        assert_eq!(root.attr("type"), Some("init"));
        assert_eq!(root.child_text("group-access").as_deref(), Some("https://gw/grp"));
        assert_eq!(root.child_text("group-select").as_deref(), Some("G1"));
        assert_eq!(root.child_text("device-id").as_deref(), Some("linux-64"));
    }

    struct Script {
        pw: String,
        asked: Vec<(String, String)>,
        answers: Vec<String>,
    }
    impl Prompter for Script {
        fn password(&mut self) -> Result<String, String> {
            Ok(self.pw.clone())
        }
        fn ask(&mut self, kind: &str, msg: &str) -> Result<String, String> {
            self.asked.push((kind.into(), msg.into()));
            self.answers.pop().ok_or_else(|| "no answer".into())
        }
        fn sso_token(&mut self, _: &Sso) -> Result<String, String> {
            Ok("TOK".into())
        }
        fn info(&mut self, _: &str) {}
    }

    #[test]
    fn fill_first_form_then_challenge() {
        let f = parse_reply(GW_A).unwrap().form.unwrap();
        let creds = Creds { user: "alice".into(), password: None, group: None };
        let mut s = Script { pw: "secret".into(), asked: vec![], answers: vec![] };
        let mut sent = false;
        let a = fill_form(&f, None, &creds, &mut sent, &mut s).unwrap();
        assert_eq!(a, vec![("username".into(), "alice".into()), ("password".into(), "secret".into())]);
        assert!(sent);

        let ch = parse_reply(
            r#"<config-auth type="auth-request"><auth id="challenge"><message>Enter your OTP</message><form><input type="password" name="answer" label="Response:"/></form></auth></config-auth>"#,
        )
        .unwrap()
        .form
        .unwrap();
        let mut s2 = Script { pw: String::new(), asked: vec![], answers: vec!["987654".into()] };
        let a2 = fill_form(&ch, None, &creds, &mut sent, &mut s2).unwrap();
        assert_eq!(a2, vec![("answer".into(), "987654".into())]);
        assert_eq!(s2.asked[0].0, "code");
        assert!(s2.asked[0].1.contains("Enter your OTP"));
    }

    #[test]
    fn noaaa_group_sends_empty_fields() {
        let f = parse_reply(GW_A).unwrap().form.unwrap();
        let c = Choice { noaaa: true, ..Default::default() };
        let creds = Creds { user: "u".into(), password: Some("p".into()), group: None };
        let mut s = Script { pw: String::new(), asked: vec![], answers: vec![] };
        let mut sent = false;
        let a = fill_form(&f, Some(&c), &creds, &mut sent, &mut s).unwrap();
        assert!(a.iter().all(|(_, v)| v.is_empty()));
    }
}
