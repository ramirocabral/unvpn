//! Ivanti Connect Secure (Pulse) authentication over IF-T/TLS.
//!
//! The client upgrades an HTTPS request on the sign-in URL to IF-T/TLS,
//! negotiates the version and sends its host information. Authentication is EAP
//! (expanded Juniper type) inside the client-auth messages: the gateway asks
//! for one thing at a time — a realm, a password, a token code, which old session
//! to close — and finally hands over the session cookie (`DSID`). The same
//! connection then carries the tunnel configuration and data. A reconnect
//! presents the cookie instead of credentials, and so does a SAML login, whose
//! cookie comes from the browser.

use super::ift::{self, IftConn, IftMessage};
use crate::net::http::{self, Cookies, Endpoint, Request};
use std::io::Write;

const AVP_REALM: u32 = 0xd4e;
const AVP_REALM_ENTRY: u32 = 0xd4f;
const AVP_REALM_ANSWER: u32 = 0xd50;
const AVP_REGION: u32 = 0xd51;
const AVP_REGION_ANSWER: u32 = 0xd52;
const AVP_COOKIE: u32 = 0xd53;
const AVP_SESSION_EXPIRY: u32 = 0xd5c;
const AVP_OS: u32 = 0xd5e;
const AVP_FAILURE: u32 = 0xd60;
const AVP_OLD_SESSION: u32 = 0xd65;
const AVP_OLD_SESSION_ID: u32 = 0xd66;
const AVP_OLD_SESSION_FROM: u32 = 0xd67;
const AVP_OLD_SESSION_TIME: u32 = 0xd68;
const AVP_KILL_SESSION: u32 = 0xd69;
const AVP_USERNAME: u32 = 0xd6d;
const AVP_USER_AGENT: u32 = 0xd70;
const AVP_PROMPT_MODE: u32 = 0xd73;
const AVP_IDLE_TIMEOUT: u32 = 0xd75;
const AVP_SIGNIN_MESSAGE: u32 = 0xd7b;
const AVP_SIGNIN_ACK: u32 = 0xd7c;
const AVP_PASS_PROMPT: u32 = 0xd81;
const AVP_PASS2_PROMPT: u32 = 0xd83;

/// Password requests (expanded Juniper type 2): the code byte.
const PASS_REQUEST: u8 = 0x01;
const PASS_RETRY: u8 = 0x81;
const PASS_CHANGE: u8 = 0x43;
const PASS_FAIL: u8 = 0xc5;

/// Rejected passwords or codes before giving up (the account may lock).
const MAX_RETRIES: u32 = 3;

#[derive(Debug)]
pub enum IvantiError {
    /// The host does not speak IF-T/TLS on this URL.
    NotHere(String),
    /// Credentials rejected.
    BadCreds(String),
    /// The gateway wants something unvpn doesn't do (Host Checker, certificates).
    Unsupported(String),
    Other(String),
}

impl std::fmt::Display for IvantiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IvantiError::NotHere(m)
            | IvantiError::BadCreds(m)
            | IvantiError::Unsupported(m)
            | IvantiError::Other(m) => f.write_str(m),
        }
    }
}

impl From<String> for IvantiError {
    fn from(s: String) -> Self {
        IvantiError::Other(s)
    }
}

impl From<IvantiError> for String {
    fn from(e: IvantiError) -> Self {
        e.to_string()
    }
}

type Result<T> = std::result::Result<T, IvantiError>;

/// What the gateway says when a reconnect's cookie is no longer valid.
pub const COOKIE_REJECTED: &str = "the gateway did not accept the session cookie";

pub struct Creds {
    pub user: String,
    pub password: Option<String>,
    pub realm: Option<String>,
}

/// Front-end callbacks for interactive input (TTY or GUI).
pub trait Prompter {
    /// The primary password; `retry` after the gateway rejected the last one.
    fn password(&mut self, label: &str, retry: bool) -> std::result::Result<String, String>;
    /// A one-time code, token code or secondary password.
    fn challenge(&mut self, message: &str) -> std::result::Result<String, String>;
    /// The new password when the gateway says the current one expired.
    fn new_password(&mut self, message: &str) -> std::result::Result<String, String>;
    fn info(&mut self, line: &str);
}

/// What the first authentication request of an unauthenticated session asks.
#[derive(Debug, Default)]
pub struct Probe {
    pub version: u8,
    pub realms: Vec<String>,
    pub asks: String,
    pub banner: Option<String>,
}

#[derive(Clone)]
pub struct Session {
    pub ep: Endpoint,
    /// Sign-in URL path (`/` for the default one).
    pub path: String,
    pub dsid: Option<String>,
    /// Seconds the gateway allows the session (`None` = not said).
    pub lifetime: Option<u64>,
    pub idle_timeout: Option<u64>,
}

impl Session {
    pub fn new(ep: Endpoint, path: &str) -> Self {
        Session {
            ep,
            path: if path.is_empty() {
                "/".into()
            } else {
                path.into()
            },
            dsid: None,
            lifetime: None,
            idle_timeout: None,
        }
    }

    /// Unauthenticated: up to the gateway's first question, then hang up.
    pub fn probe(&mut self) -> Result<Probe> {
        let mut c = self.open()?;
        let version = self.hello(&mut c, false)?;
        let m = c.recv()?;
        let eap = expanded_request(&m)?;
        let ask = Ask::parse(&eap[12..])?;
        Ok(Probe {
            version,
            realms: if ask.realms.is_empty() {
                ask.regions.clone()
            } else {
                ask.realms.clone()
            },
            asks: ask.describe(),
            banner: ask.banner.clone(),
        })
    }

    /// Full login. Returns the authenticated connection, which goes on to carry
    /// the tunnel; `self.dsid` holds the session cookie.
    pub fn login(&mut self, creds: Creds, p: &mut dyn Prompter) -> Result<IftConn> {
        self.dsid = None;
        let mut c = self.open()?;
        self.hello(&mut c, true)?;
        Login {
            s: self,
            c: &mut c,
            creds,
            p,
            primary: true,
            ask_user: true,
            ask_pass: true,
            retries: 0,
            last_password: None,
        }
        .run()?;
        Ok(c)
    }

    /// A new connection on the session cookie (reconnect, SAML): no questions.
    pub fn resume(&mut self) -> Result<IftConn> {
        if self.dsid.is_none() {
            return Err(IvantiError::Other("no session cookie".into()));
        }
        let mut c = self.open()?;
        self.hello(&mut c, true)?;
        loop {
            let m = c.recv()?;
            let eap = expanded_request(&m)?;
            let ident = eap[1];
            let ask = Ask::parse(&eap[12..])?;
            self.note_limits(&ask);
            if let Some(cookie) = ask.cookie {
                self.dsid = Some(cookie);
                finish(&mut c, ident)?;
                return Ok(c);
            }
            // A banner alone is acknowledged; anything else means a fresh login.
            match ask.banner {
                Some(_) if ask.is_banner_only() => {
                    respond(&mut c, ident, &ift::avp_u32(AVP_SIGNIN_ACK, 1))?
                }
                _ => return Err(IvantiError::Other(COOKIE_REJECTED.into())),
            }
        }
    }

    /// Ends the session on the gateway.
    pub fn logout(c: &mut IftConn) -> Result<()> {
        c.send(ift::VENDOR_JUNIPER, ift::J_LOGOUT, &[])?;
        Ok(())
    }

    /// TLS connection upgraded to IF-T/TLS.
    fn open(&self) -> Result<IftConn> {
        let mut tls = self.ep.connect()?;
        let headers = [
            "Content-Type: EAP".to_string(),
            "Upgrade: IF-T/TLS 1.0".to_string(),
            "Content-Length: 0".to_string(),
        ];
        let req = Request::get(&self.path)
            .headers(&headers)
            .without_cookies()
            .encode(&self.ep, &Cookies::default(), true);
        tls.write_all(&req)
            .and_then(|_| tls.flush())
            .map_err(|e| format!("IF-T/TLS upgrade: {e}"))?;
        let resp = http::read_response(&mut tls, false)?;
        if resp.status != 101 {
            return Err(IvantiError::NotHere(format!(
                "{} answered HTTP {} to the IF-T/TLS upgrade on {} (not an Ivanti Connect Secure sign-in URL)",
                self.ep.host_header(),
                resp.status,
                self.path
            )));
        }
        Ok(IftConn::new(tls, resp.body))
    }

    /// Version, client information, EAP identity and our client details (with
    /// the cookie when we have one). Returns the IF-T version.
    fn hello(&self, c: &mut IftConn, with_cookie: bool) -> Result<u8> {
        c.send(ift::VENDOR_TCG, ift::VERSION_REQUEST, &[0, 1, 2, 2])?;
        let m = c.recv()?;
        if !m.is(ift::VENDOR_TCG, ift::VERSION_RESPONSE) || m.payload.len() != 4 {
            return Err(IvantiError::NotHere(
                "unexpected reply to the IF-T/TLS version request".into(),
            ));
        }
        let version = m.payload[3];

        let ip = c
            .tls
            .get_ref()
            .local_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        let mut info = format!("clientHostName={}", crate::gp::local_hostname());
        if !ip.is_empty() {
            info.push_str(&format!(" clientIp={ip}"));
        }
        info.push_str(" clientCapabilities={}\n\0");
        c.send(ift::VENDOR_JUNIPER, ift::J_CLIENT_INFO, info.as_bytes())?;

        let m = c.recv()?;
        if !m.is(ift::VENDOR_TCG, ift::AUTH_CHALLENGE) || m.payload != ift::JUNIPER_1.to_be_bytes()
        {
            return Err(IvantiError::Other(
                "unexpected start of the IF-T/TLS authentication".into(),
            ));
        }
        let mut identity = vec![ift::EAP_TYPE_IDENTITY];
        identity.extend_from_slice(b"anonymous");
        c.send(
            ift::VENDOR_TCG,
            ift::AUTH_RESPONSE,
            &ift::auth_payload(&ift::eap(ift::EAP_RESPONSE, 1, &identity)),
        )?;

        let m = c.recv()?;
        let eap = ift::challenge_eap(&m)?;
        if eap[4] == ift::EAP_TYPE_TTLS {
            return Err(IvantiError::Unsupported(
                "the gateway authenticates with client certificates (EAP-TTLS), which unvpn does not support yet".into(),
            ));
        }
        if !ift::is_expanded(eap, 1) {
            return Err(IvantiError::Other(format!(
                "unexpected EAP type {:#x} from the gateway",
                eap[4]
            )));
        }
        let ident = eap[1];
        ift::parse_avps(&eap[12..])?;

        let mut avps = ift::avp(AVP_OS, b"Linux");
        avps.extend(ift::avp(
            AVP_USER_AGENT,
            client_version(&self.ep.user_agent).as_bytes(),
        ));
        if with_cookie {
            if let Some(d) = &self.dsid {
                avps.extend(ift::avp(AVP_COOKIE, d.as_bytes()));
            }
        }
        respond(c, ident, &avps)?;
        Ok(version)
    }

    fn note_limits(&mut self, ask: &Ask) {
        if let Some(s) = ask.expiry.filter(|&s| s > 0) {
            self.lifetime = Some(s.into());
        }
        if let Some(s) = ask.idle.filter(|&s| s > 0) {
            self.idle_timeout = Some(s.into());
        }
    }
}

/// The version string the gateway expects from its own client; ours appended.
fn client_version(user_agent: &str) -> String {
    if user_agent.starts_with("Pulse-Secure/") {
        user_agent.to_string()
    } else {
        format!("Pulse-Secure/22.2.1.1295 ({user_agent})")
    }
}

/// An EAP response of the expanded Juniper type 1 carrying `avps`.
fn respond(c: &mut IftConn, ident: u8, avps: &[u8]) -> Result<()> {
    let eap = ift::eap_expanded(ift::EAP_RESPONSE, ident, 1, avps);
    c.send(
        ift::VENDOR_TCG,
        ift::AUTH_RESPONSE,
        &ift::auth_payload(&eap),
    )?;
    Ok(())
}

/// Acknowledge the cookie and wait for the EAP success.
fn finish(c: &mut IftConn, ident: u8) -> Result<()> {
    respond(c, ident, &[])?;
    let m = c.recv()?;
    let ok = m.is(ift::VENDOR_TCG, ift::AUTH_SUCCESS)
        && m.payload.len() >= 8
        && ift::be32(&m.payload, 0) == ift::JUNIPER_1
        && m.payload[4] == ift::EAP_SUCCESS;
    if !ok {
        return Err(IvantiError::Other(format!(
            "expected the authentication success, got IF-T message {:#x}/{:#x}",
            m.vendor, m.msg_type
        )));
    }
    Ok(())
}

/// The EAP request of a challenge, which must be of the expanded Juniper type 1.
fn expanded_request(m: &IftMessage) -> Result<&[u8]> {
    let eap = ift::challenge_eap(m)?;
    if !ift::is_expanded(eap, 1) {
        return Err(IvantiError::Other(format!(
            "unexpected EAP type {:#x} in the authentication",
            eap[4]
        )));
    }
    Ok(eap)
}

struct Login<'a> {
    s: &'a mut Session,
    c: &'a mut IftConn,
    creds: Creds,
    p: &'a mut dyn Prompter,
    /// Primary (first factor) or secondary credentials.
    primary: bool,
    /// Which fields the gateway wants with the next password.
    ask_user: bool,
    ask_pass: bool,
    retries: u32,
    last_password: Option<String>,
}

impl Login<'_> {
    fn run(&mut self) -> Result<()> {
        loop {
            let m = self.c.recv()?;
            let eap = expanded_request(&m)?;
            let ident = eap[1];
            let ask = Ask::parse(&eap[12..])?;
            self.s.note_limits(&ask);
            if let Some(banner) = &ask.banner {
                self.p.info(&crate::sysnet::one_line(banner));
            }
            if let Some(mode) = ask.prompt_mode {
                // Second-factor round: the mode says which fields it wants.
                self.primary = false;
                self.ask_user = !matches!(mode, 3 | 15);
                self.ask_pass = mode != 5;
            }
            if let Some(cookie) = ask.cookie {
                self.s.dsid = Some(cookie);
                return finish(self.c, ident);
            }
            let reply = self.answer(&ask)?;
            respond(self.c, ident, &reply)?;
        }
    }

    /// The AVPs that answer one request.
    fn answer(&mut self, ask: &Ask) -> Result<Vec<u8>> {
        if ask.realm_entry {
            let realm = self.creds.realm.clone().ok_or_else(|| {
                IvantiError::Other(
                    "the gateway asks for a realm name — give one with --realm".into(),
                )
            })?;
            return Ok(ift::avp(AVP_REALM_ANSWER, realm.as_bytes()));
        }
        if !ask.realms.is_empty() {
            let realm = pick_realm(&ask.realms, self.creds.realm.as_deref())?;
            self.p.info(&format!("realm: {realm}"));
            return Ok(ift::avp(AVP_REALM_ANSWER, realm.as_bytes()));
        }
        if let Some(region) = ask.regions.first() {
            self.p
                .info(&format!("region: {region} (of {})", ask.regions.join(", ")));
            return Ok(ift::avp(AVP_REGION_ANSWER, region.as_bytes()));
        }
        if let Some(pw) = &ask.password {
            return self.password(ask, pw);
        }
        if let Some((ident, text)) = &ask.gtc {
            let message = [
                text.as_str(),
                self.pass_prompt(ask).unwrap_or_default(),
                "Token code",
            ]
            .into_iter()
            .find(|m| !m.trim().is_empty())
            .unwrap_or_default()
            .to_string();
            let code = self.p.challenge(&message).map_err(IvantiError::Other)?;
            let mut out = self.user_avp();
            let mut body = vec![ift::EAP_TYPE_GTC];
            body.extend_from_slice(code.as_bytes());
            out.extend(ift::avp_eap_message(&ift::eap(
                ift::EAP_RESPONSE,
                *ident,
                &body,
            )));
            return Ok(out);
        }
        if !ask.sessions.is_empty() {
            let oldest = ask
                .sessions
                .iter()
                .min_by_key(|s| s.when)
                .expect("non-empty");
            self.p.info(&format!(
                "session limit reached — closing the oldest session ({} from {})",
                oldest.id, oldest.from
            ));
            return Ok(ift::avp(AVP_KILL_SESSION, oldest.id.as_bytes()));
        }
        if ask.banner.is_some() {
            return Ok(ift::avp_u32(AVP_SIGNIN_ACK, 1));
        }
        Err(IvantiError::Other(
            "unhandled authentication request from the gateway".into(),
        ))
    }

    fn pass_prompt<'b>(&self, ask: &'b Ask) -> Option<&'b str> {
        if self.primary {
            ask.pass_prompt.as_deref()
        } else {
            ask.pass2_prompt.as_deref()
        }
    }

    fn user_avp(&self) -> Vec<u8> {
        if self.ask_user && !self.creds.user.is_empty() {
            ift::avp(AVP_USERNAME, self.creds.user.as_bytes())
        } else {
            Vec::new()
        }
    }

    fn password(&mut self, ask: &Ask, pw: &PassAsk) -> Result<Vec<u8>> {
        if pw.code == PASS_CHANGE {
            let old = match self.last_password.clone().or(self.creds.password.clone()) {
                Some(o) => o,
                None => self
                    .p
                    .password("Current password", false)
                    .map_err(IvantiError::Other)?,
            };
            let new = self
                .p
                .new_password("The password expired — choose a new one")
                .map_err(IvantiError::Other)?;
            if old.len() > 253 || new.len() > 253 {
                return Err(IvantiError::Other("password too long".into()));
            }
            let mut data = vec![0x02, 0x02, old.len() as u8 + 2];
            data.extend_from_slice(old.as_bytes());
            data.extend_from_slice(&[0x03, new.len() as u8 + 2]);
            data.extend_from_slice(new.as_bytes());
            self.last_password = Some(new);
            return Ok(ift::avp_eap_message(&ift::eap_expanded(
                ift::EAP_RESPONSE,
                pw.ident,
                2,
                &data,
            )));
        }

        let retry = pw.code == PASS_RETRY;
        if retry {
            self.retries += 1;
            if self.retries > MAX_RETRIES {
                return Err(IvantiError::BadCreds(
                    "the gateway rejected the credentials".into(),
                ));
            }
        }
        let label = self.pass_prompt(ask).map(str::to_string);
        let password = if !self.ask_pass {
            String::new()
        } else if self.primary {
            let label = label.unwrap_or_else(|| "Password".into());
            match self.creds.password.take().filter(|_| !retry) {
                Some(p) => p,
                None => self.p.password(&label, retry).map_err(IvantiError::Other)?,
            }
        } else {
            let mut msg = label.unwrap_or_else(|| "Secondary password or code".into());
            if retry {
                msg.push_str(" (the previous one was rejected)");
            }
            self.p.challenge(&msg).map_err(IvantiError::Other)?
        };
        if self.primary {
            self.last_password = Some(password.clone());
        }

        let mut out = self.user_avp();
        let inner = if pw.recent {
            // Fixed 18-byte field.
            let mut data = vec![0x01];
            let b = password.as_bytes();
            data.extend_from_slice(&b[..b.len().min(18)]);
            data.resize(19, 0);
            ift::eap_expanded(ift::EAP_RESPONSE, pw.ident, 5, &data)
        } else {
            if password.len() > 253 {
                return Err(IvantiError::Other("password too long".into()));
            }
            let mut data = vec![0x02, 0x02, password.len() as u8 + 2];
            data.extend_from_slice(password.as_bytes());
            ift::eap_expanded(ift::EAP_RESPONSE, pw.ident, 2, &data)
        };
        out.extend(ift::avp_eap_message(&inner));
        Ok(out)
    }
}

/// `wanted` among the gateway's realms (case-insensitive), or the only one.
fn pick_realm(realms: &[String], wanted: Option<&str>) -> Result<String> {
    match wanted {
        Some(w) => realms
            .iter()
            .find(|r| r.eq_ignore_ascii_case(w.trim()))
            .cloned()
            .ok_or_else(|| {
                IvantiError::Other(format!(
                    "realm {w:?} is not offered by the gateway (realms: {})",
                    realms.join(", ")
                ))
            }),
        None if realms.len() == 1 => Ok(realms[0].clone()),
        None => Err(IvantiError::Other(format!(
            "the gateway offers several realms ({}) — pick one with --realm",
            realms.join(", ")
        ))),
    }
}

#[derive(Debug, Clone, PartialEq)]
struct PassAsk {
    ident: u8,
    code: u8,
    /// The newer request format (fixed-size password field).
    recent: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct OldSession {
    id: String,
    from: String,
    when: u64,
}

/// One authentication request from the gateway.
#[derive(Debug, Default)]
pub(crate) struct Ask {
    cookie: Option<String>,
    realms: Vec<String>,
    realm_entry: bool,
    regions: Vec<String>,
    sessions: Vec<OldSession>,
    password: Option<PassAsk>,
    gtc: Option<(u8, String)>,
    banner: Option<String>,
    prompt_mode: Option<u32>,
    pass_prompt: Option<String>,
    pass2_prompt: Option<String>,
    expiry: Option<u32>,
    idle: Option<u32>,
}

impl Ask {
    pub(crate) fn parse(data: &[u8]) -> Result<Ask> {
        let mut a = Ask::default();
        for avp in ift::parse_avps(data)? {
            if avp.vendor == ift::VENDOR_JUNIPER2 {
                match avp.code {
                    AVP_COOKIE => a.cookie = Some(avp.text()),
                    AVP_REALM => a.realms.push(avp.text()),
                    AVP_REALM_ENTRY => a.realm_entry = true,
                    AVP_REGION => a.regions.push(avp.text()),
                    AVP_OLD_SESSION => a.sessions.push(old_session(avp.data)?),
                    AVP_FAILURE => return Err(failure(avp.u32())),
                    AVP_PROMPT_MODE => a.prompt_mode = avp.u32(),
                    AVP_SIGNIN_MESSAGE => a.banner = Some(avp.text()),
                    AVP_PASS_PROMPT => a.pass_prompt = Some(avp.text()),
                    AVP_PASS2_PROMPT => a.pass2_prompt = Some(avp.text()),
                    AVP_SESSION_EXPIRY => a.expiry = avp.u32(),
                    AVP_IDLE_TIMEOUT => a.idle = avp.u32(),
                    _ => {}
                }
                continue;
            }
            if avp.vendor == 0 && avp.code == ift::AVP_EAP_MESSAGE {
                a.inner_eap(avp.data)?;
                continue;
            }
            if avp.mandatory {
                return Err(IvantiError::Other(format!(
                    "unknown mandatory attribute {:#x}/{:#x} in the authentication",
                    avp.vendor, avp.code
                )));
            }
        }
        Ok(a)
    }

    /// An EAP request nested in an EAP-Message attribute.
    fn inner_eap(&mut self, e: &[u8]) -> Result<()> {
        if e.len() < 5 || e[0] != ift::EAP_REQUEST || usize::from(ift::be16(e, 2)) != e.len() {
            return Err(IvantiError::Other("malformed inner EAP request".into()));
        }
        let ident = e[1];
        if e[4] == ift::EAP_TYPE_GTC {
            self.gtc = Some((ident, String::from_utf8_lossy(&e[5..]).to_string()));
            return Ok(());
        }
        if e.len() >= 13 && ift::be32(e, 4) == ift::EXPANDED_JUNIPER {
            let code = e[12];
            return match ift::be32(e, 8) {
                2 if code == PASS_FAIL => {
                    let msg = if e.len() > 15 && e[13] == 0x01 && usize::from(e[14]) == e.len() - 13
                    {
                        String::from_utf8_lossy(&e[15..]).trim_end_matches('\0').to_string()
                    } else {
                        "password change failed".to_string()
                    };
                    Err(IvantiError::BadCreds(msg))
                }
                2 if e.len() == 13 && matches!(code, PASS_REQUEST | PASS_RETRY | PASS_CHANGE) => {
                    self.password = Some(PassAsk {
                        ident,
                        code,
                        recent: false,
                    });
                    Ok(())
                }
                3 => Err(IvantiError::Unsupported(
                    "the gateway requires Host Checker (endpoint posture checks), which unvpn does not run".into(),
                )),
                5 if e.len() == 18 && code == PASS_REQUEST => {
                    self.password = Some(PassAsk {
                        ident,
                        code,
                        recent: true,
                    });
                    Ok(())
                }
                t => Err(IvantiError::Other(format!(
                    "unknown password request (type {t}, code {code:#x})"
                ))),
            };
        }
        let ty = if e[4] == ift::EAP_TYPE_EXPANDED && e.len() >= 8 {
            ift::be32(e, 4)
        } else {
            e[4].into()
        };
        Err(if ty == u32::from(ift::EAP_TYPE_TLS) {
            IvantiError::Unsupported(
                "the gateway asks for a client certificate (EAP-TLS), which unvpn does not support yet".into(),
            )
        } else {
            IvantiError::Other(format!("unexpected EAP type {ty:#x} from the gateway"))
        })
    }

    fn is_banner_only(&self) -> bool {
        self.cookie.is_none()
            && self.realms.is_empty()
            && !self.realm_entry
            && self.regions.is_empty()
            && self.sessions.is_empty()
            && self.password.is_none()
            && self.gtc.is_none()
    }

    /// For `--probe`.
    fn describe(&self) -> String {
        if self.cookie.is_some() {
            "nothing (session cookie accepted)".into()
        } else if !self.realms.is_empty() || !self.regions.is_empty() {
            "a realm".into()
        } else if self.realm_entry {
            "a realm name".into()
        } else if let Some(p) = &self.password {
            match self.pass_prompt.as_deref() {
                Some(l) if !l.is_empty() && p.code != PASS_CHANGE => format!("a password ({l})"),
                _ => "a password".into(),
            }
        } else if let Some((_, t)) = &self.gtc {
            format!("a token code ({})", t.trim())
        } else if self.banner.is_some() {
            "accepting a sign-in notice".into()
        } else {
            "something unknown".into()
        }
    }
}

fn old_session(data: &[u8]) -> Result<OldSession> {
    let mut s = OldSession {
        id: String::new(),
        from: String::new(),
        when: 0,
    };
    for avp in ift::parse_avps(data)? {
        match avp.code {
            AVP_OLD_SESSION_ID if avp.vendor == ift::VENDOR_JUNIPER2 => s.id = avp.text(),
            AVP_OLD_SESSION_FROM if avp.vendor == ift::VENDOR_JUNIPER2 => s.from = avp.text(),
            AVP_OLD_SESSION_TIME if avp.vendor == ift::VENDOR_JUNIPER2 && avp.data.len() == 8 => {
                s.when = u64::from_be_bytes(avp.data.try_into().expect("8 bytes"))
            }
            _ => {}
        }
    }
    if s.id.is_empty() {
        return Err(IvantiError::Other("malformed session list".into()));
    }
    Ok(s)
}

fn failure(code: Option<u32>) -> IvantiError {
    match code {
        Some(0x0d) => IvantiError::BadCreds("authentication failed: account locked out".into()),
        Some(0x0e) => IvantiError::Unsupported(
            "authentication failed: the gateway requires a client certificate".into(),
        ),
        Some(c) => IvantiError::BadCreds(format!("authentication failed (code {c:#04x})")),
        None => IvantiError::BadCreds("authentication failed".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ift::{avp, avp_eap_message, avp_u32, eap, eap_expanded, EAP_REQUEST};

    fn j2(code: u8) -> Vec<u8> {
        avp_eap_message(&eap_expanded(EAP_REQUEST, 4, 2, &[code]))
    }

    #[test]
    fn password_request_with_prompts() {
        let mut data = avp(AVP_PASS_PROMPT, b"Password:");
        data.extend(j2(PASS_REQUEST));
        let a = Ask::parse(&data).unwrap();
        assert_eq!(
            a.password,
            Some(PassAsk {
                ident: 4,
                code: PASS_REQUEST,
                recent: false
            })
        );
        assert_eq!(a.pass_prompt.as_deref(), Some("Password:"));
        assert_eq!(a.describe(), "a password (Password:)");
    }

    #[test]
    fn recent_password_request() {
        let data = avp_eap_message(&eap_expanded(EAP_REQUEST, 2, 5, &[1, 0, 0, 0, 0, 0]));
        let a = Ask::parse(&data).unwrap();
        assert!(a.password.unwrap().recent);
    }

    #[test]
    fn realms_cookie_sessions_and_limits() {
        let mut data = avp(AVP_REALM, b"Users");
        data.extend(avp(AVP_REALM, b"Admins"));
        data.extend(avp_u32(AVP_SESSION_EXPIRY, 36000));
        let a = Ask::parse(&data).unwrap();
        assert_eq!(a.realms, ["Users", "Admins"]);
        assert_eq!(a.expiry, Some(36000));

        let a = Ask::parse(&avp(AVP_COOKIE, b"0123abcd")).unwrap();
        assert_eq!(a.cookie.as_deref(), Some("0123abcd"));

        let mut sess = avp(AVP_OLD_SESSION_ID, b"sid1");
        sess.extend(avp(AVP_OLD_SESSION_FROM, b"192.0.2.1"));
        sess.extend(avp(AVP_OLD_SESSION_TIME, &1_700_000_000u64.to_be_bytes()));
        let a = Ask::parse(&avp(AVP_OLD_SESSION, &sess)).unwrap();
        assert_eq!(
            a.sessions,
            [OldSession {
                id: "sid1".into(),
                from: "192.0.2.1".into(),
                when: 1_700_000_000
            }]
        );
    }

    #[test]
    fn gtc_and_failures() {
        let gtc = avp_eap_message(&eap(EAP_REQUEST, 7, b"\x06Enter SecurID PASSCODE"));
        let a = Ask::parse(&gtc).unwrap();
        assert_eq!(a.gtc, Some((7, "Enter SecurID PASSCODE".into())));

        let locked = Ask::parse(&avp_u32(AVP_FAILURE, 0x0d)).unwrap_err();
        assert!(matches!(locked, IvantiError::BadCreds(m) if m.contains("locked")));

        let hc = avp_eap_message(&eap_expanded(EAP_REQUEST, 1, 3, &[0]));
        assert!(matches!(
            Ask::parse(&hc).unwrap_err(),
            IvantiError::Unsupported(m) if m.contains("Host Checker")
        ));

        let mut msg = vec![PASS_FAIL, 0x01, 0];
        msg.extend_from_slice(b"Too short");
        msg[2] = (msg.len() - 1) as u8;
        let fail = avp_eap_message(&eap_expanded(EAP_REQUEST, 1, 2, &msg));
        assert!(matches!(
            Ask::parse(&fail).unwrap_err(),
            IvantiError::BadCreds(m) if m == "Too short"
        ));
    }

    #[test]
    fn realm_choice() {
        let realms = vec!["Users".to_string(), "Admins".to_string()];
        assert_eq!(pick_realm(&realms, Some("admins")).unwrap(), "Admins");
        assert!(pick_realm(&realms, None).is_err());
        assert!(pick_realm(&realms, Some("Other")).is_err());
        assert_eq!(pick_realm(&realms[..1], None).unwrap(), "Users");
    }

    #[test]
    fn version_string() {
        assert_eq!(client_version("Pulse-Secure/9.1 x"), "Pulse-Secure/9.1 x");
        assert_eq!(client_version("unvpn"), "Pulse-Secure/22.2.1.1295 (unvpn)");
    }
}
