//! GlobalProtect authentication: portal → gateway → authcookie.
//!
//! The flow the real client (and openconnect's `auth-globalprotect.c`) follows:
//!
//! 1. `POST /global-protect/prelogin.esp` (portal) or `/ssl-vpn/prelogin.esp`
//!    (gateway) — learn the form labels and whether SAML is in use. A host that
//!    is not a portal answers "GlobalProtect portal does not exist".
//! 2. Portal: `POST /global-protect/getconfig.esp` with the credentials → a
//!    `<policy>` listing the gateways, plus optional `portal-userauthcookie` /
//!    `portal-prelogonuserauthcookie` that let the gateway skip re-asking.
//! 3. Gateway: `POST /ssl-vpn/login.esp` with the same credentials (and the
//!    portal cookies) → a `<jnlp>` whose positional `<argument>`s carry the
//!    `authcookie`, portal, user and domain. Those, plus `computer`, form the
//!    session "cookie" query string every later request repeats.
//!
//! Any of the credential posts may instead answer a 2FA challenge — as XML
//! `<challenge>`, as bare JavaScript (`var respStatus = "Challenge"; …`), or as
//! that JavaScript wrapped in HTML. The answer is re-posted as `passwd` together
//! with the challenge's `inputStr`.

use super::http::{self, Cookies, Endpoint, Form};
use crate::anyconnect::xml::{self, Element};

/// Reported as `clientVer`; every client since GP 4.1 sends this literal.
const CLIENT_VER: &str = "4100";

#[derive(Debug)]
pub enum GpError {
    /// "GlobalProtect portal/gateway does not exist": this host isn't that role.
    NotHere(String),
    /// Bad username/password (HTTP 512) — retrying with new input may help.
    BadCreds(String),
    Other(String),
}

impl std::fmt::Display for GpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpError::NotHere(m) | GpError::BadCreds(m) | GpError::Other(m) => f.write_str(m),
        }
    }
}

impl From<String> for GpError {
    fn from(s: String) -> Self {
        GpError::Other(s)
    }
}

/// A server reply once errors are filtered out.
#[derive(Debug)]
pub enum Reply {
    Xml(Element),
    Challenge { prompt: String, input_str: String },
}

/// Classify a GP response body: XML document, 2FA challenge (in any of its
/// three encodings), or an error (`<response status="error">`, a prelogin
/// `<status>Error</status>`, or `respStatus = "Error"`).
pub fn classify(body: &str) -> Result<Reply, GpError> {
    let t = body.trim();
    if t.is_empty() {
        return Err(GpError::Other("empty response from server".into()));
    }
    if !t.starts_with('<') {
        return parse_javascript(t);
    }
    let root = xml::parse(t).map_err(|e| GpError::Other(format!("unparseable server response ({e})")))?;
    match root.name.as_str() {
        "response" if root.attr("status") == Some("error") => {
            let msg = root.child_text("error").unwrap_or_else(|| "server returned an error".into());
            Err(classify_error(msg))
        }
        "prelogin-response" => {
            if root.child_text("status").is_some_and(|s| s != "Success") {
                let msg = root.child_text("msg").unwrap_or_else(|| "prelogin failed".into());
                return Err(classify_error(msg));
            }
            Ok(Reply::Xml(root))
        }
        "challenge" => Ok(Reply::Challenge {
            prompt: root.child_text("respmsg").unwrap_or_else(|| "Challenge".into()),
            input_str: root.child_text("inputstr").unwrap_or_default(),
        }),
        "html" => match root.child("body") {
            Some(b) => parse_javascript(b.deep_text().trim()),
            None => Err(GpError::Other("unexpected HTML response from server".into())),
        },
        _ => Ok(Reply::Xml(root)),
    }
}

fn classify_error(msg: String) -> GpError {
    if msg == "GlobalProtect gateway does not exist" || msg == "GlobalProtect portal does not exist" {
        GpError::NotHere(msg)
    } else if msg.to_ascii_lowercase().contains("invalid username or password") || msg.contains("Authentication failed") {
        GpError::BadCreds(msg)
    } else {
        GpError::Other(msg)
    }
}

/// `var respStatus = "Challenge|Error";\nvar respMsg = "<prompt>";\n
/// thisForm.inputStr.value = "<inputStr>";` (openconnect `parse_javascript`).
fn parse_javascript(js: &str) -> Result<Reply, GpError> {
    let grab = |key: &str| -> Option<String> {
        let start = js.find(key)? + key.len();
        let rest = &js[start..];
        let rest = rest.trim_start().strip_prefix('=')?.trim_start().strip_prefix('"')?;
        // Up to the first unescaped quote; then undo JS string escapes.
        let mut out = String::new();
        let mut chars = rest.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => return Some(out),
                '\\' => match chars.next()? {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).collect();
                        out.extend(u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32));
                    }
                    other => out.push(other),
                },
                c => out.push(c),
            }
        }
        None
    };
    let status = grab("respStatus").ok_or_else(|| GpError::Other(format!("unrecognized server response: {}", preview(js))))?;
    let msg = grab("respMsg").unwrap_or_default();
    match status.as_str() {
        "Challenge" => Ok(Reply::Challenge { prompt: msg, input_str: grab("inputStr.value").unwrap_or_default() }),
        "Error" => Err(classify_error(if msg.is_empty() { "authentication error".into() } else { msg })),
        other => Err(GpError::Other(format!("unexpected respStatus {other:?}"))),
    }
}

fn preview(s: &str) -> String {
    let one = super::one_line(s);
    one.chars().take(160).collect()
}

/// What the prelogin page tells us about the login form.
#[derive(Debug, Default, Clone)]
pub struct Prelogin {
    pub message: String,
    pub user_label: String,
    pub pass_label: String,
    pub saml: Option<Saml>,
    pub region: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Saml {
    /// `REDIRECT` (an https URL) or `POST` (an auto-submitting HTML form).
    pub method: String,
    /// The IdP login: the URL for REDIRECT, a `data:text/html;base64,` URI for POST.
    pub url: String,
}

pub fn parse_prelogin(root: &Element) -> Prelogin {
    let get = |n: &str| root.child_text(n).unwrap_or_default();
    let saml = match (root.child_text("saml-auth-method"), root.child_text("saml-request")) {
        (Some(method), Some(req)) => {
            let url = if method.eq_ignore_ascii_case("POST") {
                format!("data:text/html;base64,{req}")
            } else {
                openssl::base64::decode_block(&req)
                    .ok()
                    .map(|v| String::from_utf8_lossy(&v).trim().to_string())
                    .unwrap_or_default()
            };
            (!url.is_empty()).then_some(Saml { method, url })
        }
        _ => None,
    };
    Prelogin {
        message: get("authentication-message"),
        user_label: get("username-label"),
        pass_label: get("password-label"),
        saml,
        region: root.child_text("region"),
    }
}

/// One gateway the portal offers.
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayEntry {
    /// `host[:port]` as listed by the portal.
    pub host: String,
    pub label: String,
    /// Lower is preferred; `u32::MAX` when the portal gives no rule for our region.
    pub priority: u32,
}

#[derive(Debug, Default, Clone)]
pub struct PortalConfig {
    pub gateways: Vec<GatewayEntry>,
    pub userauthcookie: Option<String>,
    pub prelogon_cookie: Option<String>,
    /// The portal's GP version, echoed back as our `app-version`.
    pub version: Option<String>,
    pub hip_interval: Option<u64>,
}

/// Parse the portal `<policy>`: gateways (sorted by priority for our region),
/// the reusable portal cookies, version and HIP report interval.
pub fn parse_portal(root: &Element, region: Option<&str>) -> Result<PortalConfig, String> {
    if root.name != "policy" {
        return Err(format!("unexpected portal reply <{}>", root.name));
    }
    let mut pc = PortalConfig::default();
    let real = |v: Option<String>| v.filter(|s| s != "empty");
    pc.userauthcookie = real(root.child_text("portal-userauthcookie"));
    pc.prelogon_cookie = real(root.child_text("portal-prelogonuserauthcookie"));
    pc.version = root.child_text("version");
    pc.hip_interval = root
        .child("hip-collection")
        .and_then(|h| h.child_text("hip-report-interval"))
        .and_then(|s| s.parse().ok());

    let list = root.child("gateways").and_then(|g| g.child("external")).and_then(|e| e.child("list"));
    for e in list.into_iter().flat_map(|l| l.children_named("entry")) {
        let Some(host) = e.attr("name").map(str::to_string) else { continue };
        let mut priority = u32::MAX;
        if let (Some(region), Some(rules)) = (region, e.child("priority-rule")) {
            for r in rules.children_named("entry") {
                if r.attr("name").is_some_and(|n| n == region || n == "Any") {
                    if let Some(p) = r.child_text("priority").and_then(|p| p.parse().ok()) {
                        priority = priority.min(p);
                    }
                }
            }
        }
        let label = e.child_text("description").unwrap_or_else(|| host.clone());
        pc.gateways.push(GatewayEntry { host, label, priority });
    }
    if pc.gateways.is_empty() {
        return Err("the portal configuration lists no gateways".into());
    }
    pc.gateways.sort_by_key(|g| g.priority);
    Ok(pc)
}

/// Pick the gateway: `want` matched against the host or label, else the
/// portal's preferred one.
pub fn choose_gateway<'a>(gws: &'a [GatewayEntry], want: Option<&str>) -> Result<&'a GatewayEntry, String> {
    let Some(w) = want.map(str::trim).filter(|w| !w.is_empty()) else {
        return gws.first().ok_or_else(|| "no gateways".to_string());
    };
    let host_only = |h: &str| h.split(':').next().unwrap_or(h).to_ascii_lowercase();
    gws.iter()
        .find(|g| g.host.eq_ignore_ascii_case(w) || host_only(&g.host) == w.to_ascii_lowercase())
        .or_else(|| gws.iter().find(|g| g.label.eq_ignore_ascii_case(w)))
        .ok_or_else(|| {
            let names: Vec<_> = gws.iter().map(|g| format!("{} ({})", g.label, g.host)).collect();
            format!("gateway {w:?} not offered by the portal; available: {}", names.join(", "))
        })
}

/// The session identity from `login.esp`, repeated (as a query string) by every
/// later request — getconfig, the tunnel GET, HIP and logout.
#[derive(Debug, Clone, Default)]
pub struct AuthCookie {
    pub authcookie: String,
    pub portal: String,
    pub user: String,
    pub domain: String,
    pub preferred_ip: String,
    pub computer: String,
}

impl AuthCookie {
    /// `authcookie=…&portal=…&user=…&domain=…[&preferred-ip=…]&computer=…`
    pub fn query(&self) -> String {
        self.query_filtered(&[])
    }

    pub fn query_filtered(&self, skip: &[&str]) -> String {
        let fields = [
            ("authcookie", &self.authcookie),
            ("portal", &self.portal),
            ("user", &self.user),
            ("domain", &self.domain),
            ("preferred-ip", &self.preferred_ip),
            ("computer", &self.computer),
        ];
        fields
            .iter()
            .filter(|(k, v)| !v.is_empty() && !skip.contains(k))
            .map(|(k, v)| format!("{k}={}", http::urlencode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }
}

/// Positional `<argument>`s of the `login.esp` `<jnlp>` reply (openconnect's
/// `gp_login_args`): 1 authcookie, 3 portal, 4 user, 5 auth source, 7 domain,
/// 12 connection-type ("tunnel"), 15 preferred-ip.
pub fn parse_login(root: &Element, computer: &str) -> Result<AuthCookie, String> {
    if root.name != "jnlp" {
        return Err(format!("unexpected login reply <{}>", root.name));
    }
    let desc = root.child("application-desc").ok_or("login reply has no <application-desc>")?;
    let args: Vec<String> = desc
        .children_named("argument")
        .map(|a| {
            let v = a.text.trim();
            if v == "(null)" || v == "-1" {
                String::new()
            } else {
                v.to_string()
            }
        })
        .collect();
    let arg = |i: usize| args.get(i).cloned().unwrap_or_default();
    let ac = AuthCookie {
        authcookie: arg(1),
        portal: http::percent_decode(&arg(3)),
        user: http::percent_decode(&arg(4)),
        domain: http::percent_decode(&arg(7)),
        preferred_ip: http::percent_decode(&arg(15)),
        computer: computer.to_string(),
    };
    if ac.authcookie.is_empty() || ac.user.is_empty() {
        return Err("login reply carries no authcookie/user".into());
    }
    let conn_type = arg(12);
    if !conn_type.is_empty() && conn_type != "tunnel" {
        return Err(format!("gateway offers connection-type {conn_type:?}, not a tunnel"));
    }
    Ok(ac)
}

/// The credentials posted to `getconfig.esp`/`login.esp`: the username plus one
/// secret field — `passwd`, or after SAML `prelogin-cookie` /
/// `portal-userauthcookie`.
#[derive(Debug, Clone, Default)]
pub struct Answers {
    pub user: String,
    pub secret_field: String,
    pub secret: String,
    /// Set by a challenge: echoed as `inputStr` with the answer.
    pub input_str: Option<String>,
    /// Whether the secret answered a 2FA challenge (single use: never replayed).
    pub from_challenge: bool,
}

/// What a prompter returns after a SAML login.
pub struct SamlResult {
    pub user: String,
    /// `prelogin-cookie` or `portal-userauthcookie`.
    pub field: String,
    pub value: String,
}

pub trait Prompter {
    fn username(&mut self, label: &str) -> Result<String, String>;
    fn password(&mut self, label: &str, message: &str) -> Result<String, String>;
    fn challenge(&mut self, message: &str) -> Result<String, String>;
    fn saml(&mut self, saml: &Saml) -> Result<SamlResult, String>;
    fn info(&mut self, line: &str);
}

pub struct Creds {
    pub user: String,
    pub password: Option<String>,
}

/// Which role the target host plays.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Role {
    Auto,
    Portal,
    Gateway,
}

#[derive(Clone)]
pub struct Session {
    /// The host the user named (portal, or the gateway itself).
    pub portal_ep: Endpoint,
    /// The gateway in use (after portal selection).
    pub ep: Endpoint,
    pub cookies: Cookies,
    pub clientos: String,
    pub os_version: String,
    pub computer: String,
    pub app_version: Option<String>,
    pub hip_interval: Option<u64>,
    pub auth: Option<AuthCookie>,
}

impl Session {
    pub fn new(ep: Endpoint, clientos: &str, os_version: &str, computer: &str) -> Self {
        Session {
            portal_ep: ep.clone(),
            ep,
            cookies: Cookies::default(),
            clientos: clientos.to_string(),
            os_version: os_version.to_string(),
            computer: computer.to_string(),
            app_version: None,
            hip_interval: None,
            auth: None,
        }
    }

    pub fn post(&mut self, ep_is_portal: bool, path: &str, body: &str) -> Result<http::Response, String> {
        let ep = if ep_is_portal { self.portal_ep.clone() } else { self.ep.clone() };
        http::post_form(&ep, path, &mut self.cookies, body)
    }

    pub fn prelogin(&mut self, portal: bool) -> Result<Prelogin, GpError> {
        let path = format!(
            "/{}/prelogin.esp?tmp=tmp&clientVer={CLIENT_VER}&clientos={}",
            if portal { "global-protect" } else { "ssl-vpn" },
            self.clientos
        );
        let resp = self.post(portal, &path, "cas-support=yes")?;
        if resp.status != 200 {
            return Err(GpError::Other(format!("prelogin: HTTP {}", resp.status)));
        }
        match classify(&resp.body_str())? {
            Reply::Xml(root) if root.name == "prelogin-response" => Ok(parse_prelogin(&root)),
            Reply::Xml(root) => Err(GpError::Other(format!("unexpected prelogin reply <{}>", root.name))),
            Reply::Challenge { .. } => Err(GpError::Other("unexpected challenge at prelogin".into())),
        }
    }

    /// Gather first-form answers: from SAML, or username + password.
    fn first_answers(&self, pre: &Prelogin, creds: &Creds, p: &mut dyn Prompter) -> Result<Answers, String> {
        if let Some(saml) = &pre.saml {
            p.info(&format!("SAML {} authentication required", saml.method));
            let r = p.saml(saml)?;
            let user = if r.user.is_empty() { creds.user.clone() } else { r.user };
            if user.is_empty() {
                return Err("SAML login returned no username — pass it with -u".into());
            }
            return Ok(Answers { user, secret_field: r.field, secret: r.value, ..Default::default() });
        }
        let user = if creds.user.is_empty() {
            p.username(if pre.user_label.is_empty() { "Username" } else { &pre.user_label })?
        } else {
            creds.user.clone()
        };
        let secret = match &creds.password {
            Some(pw) => pw.clone(),
            None => p.password(if pre.pass_label.is_empty() { "Password" } else { &pre.pass_label }, &pre.message)?,
        };
        Ok(Answers { user, secret_field: "passwd".into(), secret, ..Default::default() })
    }

    /// The fixed fields of a portal-getconfig / gateway-login POST.
    fn login_form(&self, host: &str, portal_cookies: &PortalConfig, a: &Answers) -> Form {
        let mut f = Form::new();
        f.add("jnlpReady", "jnlpReady")
            .add("ok", "Login")
            .add("direct", "yes")
            .add("clientVer", CLIENT_VER)
            .add("prot", "https:")
            .add("internal", "no")
            .add("ipv6-support", "no")
            .add("clientos", &self.clientos)
            .add("os-version", &self.os_version)
            .add("server", host)
            .add("computer", &self.computer);
        if let Some(c) = &portal_cookies.userauthcookie {
            f.add("portal-userauthcookie", c);
        }
        if let Some(c) = &portal_cookies.prelogon_cookie {
            f.add("portal-prelogonuserauthcookie", c);
        }
        if let Some(s) = &a.input_str {
            f.add("inputStr", s);
        }
        f.add("user", &a.user);
        f.add(&a.secret_field, &a.secret);
        f
    }

    /// POST the credentials (portal `getconfig.esp` or gateway `login.esp`),
    /// answering any number of 2FA challenges. Returns the final XML root and
    /// the answers that produced it.
    fn submit(
        &mut self,
        portal: bool,
        portal_cookies: &PortalConfig,
        mut a: Answers,
        p: &mut dyn Prompter,
    ) -> Result<(Element, Answers), GpError> {
        let (path, host) = if portal {
            ("/global-protect/getconfig.esp", self.portal_ep.host.clone())
        } else {
            ("/ssl-vpn/login.esp", self.ep.host.clone())
        };
        for _ in 0..8 {
            let body = self.login_form(&host, portal_cookies, &a).encode();
            let resp = self.post(portal, path, &body)?;
            match resp.status {
                200 => {}
                512 => {
                    // The server's own words, when it says something short and plain.
                    let text = crate::gp::one_line(&resp.body_str());
                    let detail = if !text.is_empty() && !text.starts_with('<') && text.len() <= 200 {
                        format!(" (server: {text})")
                    } else {
                        String::new()
                    };
                    return Err(GpError::BadCreds(format!("invalid username or password{detail}")));
                }
                513 => return Err(GpError::Other("the gateway requires a client certificate".into())),
                s => return Err(GpError::Other(format!("{path}: HTTP {s}"))),
            }
            match classify(&resp.body_str())? {
                Reply::Xml(root) => return Ok((root, a)),
                Reply::Challenge { prompt, input_str } => {
                    let code = p.challenge(&prompt).map_err(GpError::Other)?;
                    a.secret_field = "passwd".into();
                    a.secret = code;
                    a.input_str = Some(input_str);
                    a.from_challenge = true;
                }
            }
        }
        Err(GpError::Other("too many authentication challenges".into()))
    }

    /// Full login: portal (if it is one) → choose gateway → gateway login.
    /// On success `self.auth` holds the session cookie and `self.ep` the gateway.
    pub fn login(&mut self, creds: &Creds, role: Role, want_gw: Option<&str>, p: &mut dyn Prompter) -> Result<(), String> {
        let mut portal_cfg = PortalConfig::default();
        let mut replay: Option<Answers> = None;

        if role != Role::Gateway {
            match self.prelogin(true) {
                Ok(pre) => {
                    p.info(&format!("{} is a GlobalProtect portal", self.portal_ep.host_header()));
                    let (root, used) = self.portal_login(&pre, creds, p)?;
                    portal_cfg = parse_portal(&root, pre.region.as_deref())?;
                    for g in &portal_cfg.gateways {
                        let pri = if g.priority == u32::MAX { String::new() } else { format!(" [priority {}]", g.priority) };
                        p.info(&format!("  gateway: {} ({}){pri}", g.label, g.host));
                    }
                    let gw = choose_gateway(&portal_cfg.gateways, want_gw)?;
                    p.info(&format!("using gateway {} ({})", gw.label, gw.host));
                    let (host, port, _) = http::split_url(&gw.host)?;
                    self.ep = Endpoint { host, port, ..self.portal_ep.clone() };
                    if let Some(v) = &portal_cfg.version {
                        self.app_version = Some(v.clone());
                    }
                    self.hip_interval = portal_cfg.hip_interval;
                    // Replay the portal credentials on the gateway (openconnect's
                    // "blind retry"): fine with a portal cookie, or a plain
                    // password. A one-time challenge answer or a SAML cookie is not.
                    let has_cookie = portal_cfg.userauthcookie.is_some() || portal_cfg.prelogon_cookie.is_some();
                    if has_cookie || (!used.from_challenge && used.secret_field == "passwd") {
                        replay = Some(Answers { input_str: None, from_challenge: false, ..used });
                    }
                }
                Err(GpError::NotHere(_)) if role == Role::Auto => {
                    p.info(&format!("{} is not a portal — trying it as a gateway", self.portal_ep.host_header()));
                }
                Err(e) => return Err(format!("portal prelogin: {e}")),
            }
        }

        if let Some(a) = replay {
            match self.submit(false, &portal_cfg, a, p) {
                Ok((root, _)) => return self.finish_login(&root),
                Err(GpError::BadCreds(_)) => p.info("the gateway did not accept the portal login — authenticating again"),
                Err(e) => return Err(format!("gateway login: {e}")),
            }
        }

        let pre = self.prelogin(false).map_err(|e| format!("gateway prelogin: {e}"))?;
        let mut tries = 0;
        loop {
            let a = self.first_answers(&pre, creds, p)?;
            match self.submit(false, &portal_cfg, a, p) {
                Ok((root, _)) => return self.finish_login(&root),
                Err(GpError::BadCreds(m)) if creds.password.is_none() && pre.saml.is_none() && tries < 2 => {
                    tries += 1;
                    p.info(&format!("{m} — try again"));
                }
                Err(e) => return Err(format!("gateway login: {e}")),
            }
        }
    }

    fn portal_login(&mut self, pre: &Prelogin, creds: &Creds, p: &mut dyn Prompter) -> Result<(Element, Answers), String> {
        let mut tries = 0;
        loop {
            let a = self.first_answers(pre, creds, p)?;
            match self.submit(true, &PortalConfig::default(), a, p) {
                Ok(r) => return Ok(r),
                Err(GpError::BadCreds(m)) if creds.password.is_none() && pre.saml.is_none() && tries < 2 => {
                    tries += 1;
                    p.info(&format!("{m} — try again"));
                }
                Err(e) => return Err(format!("portal login: {e}")),
            }
        }
    }

    fn finish_login(&mut self, root: &Element) -> Result<(), String> {
        self.auth = Some(parse_login(root, &self.computer)?);
        Ok(())
    }

    pub fn cookie_query(&self) -> Result<String, String> {
        self.auth.as_ref().map(AuthCookie::query).ok_or_else(|| "not authenticated".into())
    }

    /// `POST /ssl-vpn/logout.esp` — the authcookie stays valid otherwise.
    pub fn logout(&mut self) -> Result<(), String> {
        let q = self.cookie_query()?;
        let resp = self.post(false, "/ssl-vpn/logout.esp", &q)?;
        match classify(&resp.body_str()) {
            Ok(_) if resp.status == 200 => Ok(()),
            Ok(_) => Err(format!("logout: HTTP {}", resp.status)),
            Err(e) => Err(format!("logout: {e}")),
        }
    }
}

/// Decode what a SAML login hands back: a `globalprotectcallback:<base64>` URL
/// (default-browser flow), or `name=value` pairs (`saml-username`,
/// `prelogin-cookie` / `portal-userauthcookie`, separated by `;`, `&` or
/// newlines — what the GUI's embedded browser reads from the final page's
/// headers), or a bare cookie value.
pub fn parse_saml_result(raw: &str) -> Option<SamlResult> {
    let raw = raw.trim().trim_matches('"');
    if raw.is_empty() {
        return None;
    }
    if let Some(data) = raw.strip_prefix("globalprotectcallback:") {
        let data = data.trim_start_matches('/');
        let decoded = openssl::base64::decode_block(&http::percent_decode(data)).ok()?;
        let text = String::from_utf8_lossy(&decoded);
        let tag = |t: &str| -> Option<String> {
            let open = format!("<{t}>");
            let s = text.find(&open)? + open.len();
            let e = text[s..].find("</")? + s;
            Some(text[s..e].trim().to_string()).filter(|v| !v.is_empty())
        };
        let user = tag("saml-username").unwrap_or_default();
        return tag("prelogin-cookie")
            .map(|v| ("prelogin-cookie", v))
            .or_else(|| tag("portal-userauthcookie").map(|v| ("portal-userauthcookie", v)))
            .map(|(f, value)| SamlResult { user, field: f.into(), value });
    }
    if raw.contains('=') {
        let mut user = String::new();
        let mut found = None;
        for kv in raw.split([';', '&', '\n']).map(str::trim) {
            let Some((k, v)) = kv.split_once('=') else { continue };
            let (k, v) = (k.trim().to_ascii_lowercase(), http::percent_decode(v.trim()));
            match k.as_str() {
                "saml-username" => user = v,
                "prelogin-cookie" | "portal-userauthcookie" if !v.is_empty() => found = Some((k, v)),
                _ => {}
            }
        }
        return found.map(|(field, value)| SamlResult { user, field, value });
    }
    Some(SamlResult { user: String::new(), field: "prelogin-cookie".into(), value: raw.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRELOGIN: &str = r#"<?xml version="1.0" encoding="UTF-8" ?>
<prelogin-response>
<status>Success</status>
<ccusername></ccusername>
<autosubmit>false</autosubmit>
<msg></msg>
<authentication-message>Enter login credentials</authentication-message>
<username-label>Username</username-label>
<password-label>Password</password-label>
<panos-version>1</panos-version>
<saml-default-browser>yes</saml-default-browser>
<region>AR</region>
</prelogin-response>"#;

    #[test]
    fn prelogin_password_form() {
        let Reply::Xml(root) = classify(PRELOGIN).unwrap() else { panic!() };
        let p = parse_prelogin(&root);
        assert_eq!(p.message, "Enter login credentials");
        assert_eq!(p.pass_label, "Password");
        assert!(p.saml.is_none());
        assert_eq!(p.region.as_deref(), Some("AR"));
    }

    #[test]
    fn prelogin_not_a_gateway() {
        let body = "<prelogin-response><status>Error</status><msg>GlobalProtect gateway does not exist</msg></prelogin-response>";
        assert!(matches!(classify(body), Err(GpError::NotHere(_))));
    }

    #[test]
    fn prelogin_saml_redirect() {
        let url = "https://idp.example.com/sso?SAMLRequest=abc";
        let body = format!(
            "<prelogin-response><status>Success</status><saml-auth-method>REDIRECT</saml-auth-method><saml-request>{}</saml-request></prelogin-response>",
            openssl::base64::encode_block(url.as_bytes())
        );
        let Reply::Xml(root) = classify(&body).unwrap() else { panic!() };
        let s = parse_prelogin(&root).saml.unwrap();
        assert_eq!(s.method, "REDIRECT");
        assert_eq!(s.url, url);
    }

    #[test]
    fn javascript_challenge() {
        let js = "var respStatus = \"Challenge\";\nvar respMsg = \"Enter the code sent to \\\"your phone\\\"\";\nthisForm.inputStr.value = \"5ef5ac0a\";\n";
        match classify(js).unwrap() {
            Reply::Challenge { prompt, input_str } => {
                assert_eq!(prompt, "Enter the code sent to \"your phone\"");
                assert_eq!(input_str, "5ef5ac0a");
            }
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn html_wrapped_challenge_and_js_error() {
        let html = "<html><head></head><body>var respStatus = \"Challenge\"; var respMsg = \"OTP\"; thisForm.inputStr.value = \"x1\";</body></html>";
        assert!(matches!(classify(html).unwrap(), Reply::Challenge { ref input_str, .. } if input_str == "x1"));
        let err = "var respStatus = \"Error\";\nvar respMsg = \"Invalid username or password\";";
        assert!(matches!(classify(err), Err(GpError::BadCreds(_))));
    }

    #[test]
    fn xml_challenge_and_error() {
        let c = "<challenge><user>alice</user><inputstr>abc</inputstr><respmsg>Token</respmsg></challenge>";
        assert!(matches!(classify(c).unwrap(), Reply::Challenge { ref prompt, .. } if prompt == "Token"));
        let e = "<response status=\"error\"><error>Invalid authentication cookie</error></response>";
        assert!(matches!(classify(e), Err(GpError::Other(ref m)) if m == "Invalid authentication cookie"));
    }

    const POLICY: &str = r#"<?xml version="1.0" encoding="UTF-8" ?>
<policy>
  <portal-name>GP-Portal</portal-name>
  <portal-config-version>4100</portal-config-version>
  <version>6.2.1-71</version>
  <portal-userauthcookie>empty</portal-userauthcookie>
  <portal-prelogonuserauthcookie>PRELOGON123</portal-prelogonuserauthcookie>
  <hip-collection><hip-report-interval>3600</hip-report-interval></hip-collection>
  <gateways>
    <cutoff-time>5</cutoff-time>
    <external>
      <list>
        <entry name="gw-b.example.com">
          <priority-rule><entry name="Any"><priority>3</priority></entry></priority-rule>
          <description>GW B</description>
        </entry>
        <entry name="gw-a.example.com:4443">
          <priority-rule><entry name="AR"><priority>1</priority></entry><entry name="Any"><priority>2</priority></entry></priority-rule>
          <description>GW A</description>
        </entry>
      </list>
    </external>
  </gateways>
</policy>"#;

    #[test]
    fn portal_policy_gateways_by_priority() {
        let Reply::Xml(root) = classify(POLICY).unwrap() else { panic!() };
        let pc = parse_portal(&root, Some("AR")).unwrap();
        assert_eq!(pc.gateways[0].host, "gw-a.example.com:4443");
        assert_eq!(pc.gateways[0].priority, 1);
        assert_eq!(pc.gateways[1].label, "GW B");
        assert_eq!(pc.userauthcookie, None, "\"empty\" means no cookie");
        assert_eq!(pc.prelogon_cookie.as_deref(), Some("PRELOGON123"));
        assert_eq!(pc.version.as_deref(), Some("6.2.1-71"));
        assert_eq!(pc.hip_interval, Some(3600));

        assert_eq!(choose_gateway(&pc.gateways, None).unwrap().label, "GW A");
        assert_eq!(choose_gateway(&pc.gateways, Some("gw b")).unwrap().host, "gw-b.example.com");
        assert_eq!(choose_gateway(&pc.gateways, Some("gw-a.example.com")).unwrap().label, "GW A");
        assert!(choose_gateway(&pc.gateways, Some("nope")).is_err());
    }

    #[test]
    fn jnlp_login_reply() {
        let doc = r#"<?xml version="1.0" encoding="utf-8"?><jnlp><application-desc>
<argument>(null)</argument>
<argument>0123456789abcdef0123456789abcdef</argument>
<argument>a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2</argument>
<argument>GP-Gateway-N</argument>
<argument>alice</argument>
<argument>LDAP-auth</argument>
<argument>vsys1</argument>
<argument>%28empty_domain%29</argument>
<argument></argument><argument></argument><argument></argument><argument></argument>
<argument>tunnel</argument>
<argument>-1</argument>
<argument>4100</argument>
<argument>198.51.100.7</argument>
</application-desc></jnlp>"#;
        let Reply::Xml(root) = classify(doc).unwrap() else { panic!() };
        let ac = parse_login(&root, "myhost").unwrap();
        assert_eq!(ac.authcookie, "0123456789abcdef0123456789abcdef");
        assert_eq!(ac.portal, "GP-Gateway-N");
        assert_eq!(ac.domain, "(empty_domain)");
        assert_eq!(ac.preferred_ip, "198.51.100.7");
        assert_eq!(
            ac.query(),
            "authcookie=0123456789abcdef0123456789abcdef&portal=GP-Gateway-N&user=alice&domain=%28empty_domain%29&preferred-ip=198.51.100.7&computer=myhost"
        );
        assert_eq!(ac.query_filtered(&["authcookie", "preferred-ip"]), "portal=GP-Gateway-N&user=alice&domain=%28empty_domain%29&computer=myhost");
    }

    #[test]
    fn saml_results() {
        let xml = "<html><!-- <saml-auth-status>1</saml-auth-status><prelogin-cookie>PC123</prelogin-cookie><saml-username>alice@example.com</saml-username> --></html>";
        let url = format!("globalprotectcallback:{}", openssl::base64::encode_block(xml.as_bytes()));
        let r = parse_saml_result(&url).unwrap();
        assert_eq!((r.user.as_str(), r.field.as_str(), r.value.as_str()), ("alice@example.com", "prelogin-cookie", "PC123"));

        let r = parse_saml_result("saml-username=bob; portal-userauthcookie=XYZ").unwrap();
        assert_eq!((r.user.as_str(), r.field.as_str(), r.value.as_str()), ("bob", "portal-userauthcookie", "XYZ"));

        let r = parse_saml_result("  RAWCOOKIE ").unwrap();
        assert_eq!((r.field.as_str(), r.value.as_str()), ("prelogin-cookie", "RAWCOOKIE"));
        assert!(parse_saml_result("   ").is_none());
    }
}
