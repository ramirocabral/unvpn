//! Fortinet SSL-VPN authentication over HTTPS: password, then any second factor.
//!
//! Wire formats come from three first-party sources, cross-checked: the
//! FortiClient 7.4 engine `/opt/forticlient/vpn` (its exact `printf` templates —
//! what the native client sends), the FortiOS portal's own `/sslvpn/js/login.js`
//! (what the gateway's web login sends; the reference for the ajax `ret=6` challenge/renew flow, which the engine doesn't
//! speak), and openfortivpn/openconnect for interop quirks:
//!
//!   login:        username=<u>&credential=<pw>&realm=<r>&ajax=1&redir=%2Fremote%2Findex&just_logged_in=1
//!   token code:   username=&reqid=&polid=&grp=&realm=&peer=&code=<otp>&code2=[<next>]&redir=…&just_logged_in=1
//!   FTM push:     username=&reqid=&polid=&grp=&realm=&peer=&redir=…&just_logged_in=1&ftmpush=1  (no code/magic)
//!   ret=6 answer: ajax=1&username=&realm=&magic=&reqid=<reqid>,<polid>&grpid=<grpid>,<pid>,<is_chal_rsp>
//!                 [&peer=]&credential=<password>&credential2=<answer>
//!   ret=6 renew:  …same prefix…&credential=<new password>       (skip: …&reqid=<reqid>…&skip=1)
//!   HTML form:    magic=&username=&reqid=&grpid=[&idx=]&credential=<answer>&realm=&redir=…  (legacy RSA/SMS page)
//!
//! Success is a non-empty `Set-Cookie: SVPNCOOKIE=…` and nothing else — not
//! `ret=1` (the engine, openfortivpn and openconnect all key off the cookie).

use super::http::{self, Cookies};
use crate::sysnet;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const LOGINCHECK: &str = "/remote/logincheck";
/// Suffix of the first (password) POST — live-validated.
const LOGIN_SUFFIX: &str = "&ajax=1&redir=%2Fremote%2Findex&just_logged_in=1";
/// Suffix the engine puts on code and HTML-form answers (0xbf8e48 — no `ajax=1`).
const ANSWER_SUFFIX: &str = "&redir=%2Fremote%2Findex&just_logged_in=1";
/// Suffix of the FortiToken Mobile push trigger (engine 0xbf90c8).
const PUSH_SUFFIX: &str = "&redir=%2Fremote%2Findex&just_logged_in=1&ftmpush=1";
/// FortiClient clamps the gateway's `remoteauthtimeout` to [30, 300] s and uses it
/// as the read timeout of every logincheck POST (a push or a RADIUS-MFA login is
/// held open that long).
const AUTH_BUDGET_MIN: u64 = 30;
const AUTH_BUDGET_MAX: u64 = 300;
/// The legacy challenge page the engine looks for (0xbf7b10; the new-password page
/// 0xbf7958 is the same tag plus `onsubmit=`). The modern login page's form starts
/// `<form class=…`, so this never matches a plain "wrong password" page.
const LEGACY_FORM: &str = "<form action=\"/remote/logincheck\" method=\"post\"";

#[derive(Clone)]
pub struct Session {
    pub host: String,
    pub port: u16,
    pub realm: String,
    pub user: String,
    pub timeout: Duration,
    /// Read timeout for `/remote/logincheck` POSTs (see [`AUTH_BUDGET_MIN`]).
    pub auth_budget: Duration,
    pub cookies: Cookies,
    /// Re-sent by the ret=6 challenge answer (portal login.js does the same).
    password: String,
    /// Portal globals that survive a reply that omits them (`pol_id`, `peer`).
    last_polid: String,
    last_peer: String,
    /// Past the password step: a refusal now is about the second factor.
    second_factor: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    /// ret=2: FortiToken code — or, with `tokeninfo=ftm_push`, a FortiToken Mobile push.
    Token,
    /// ret=3: a token code sent by email.
    Email,
    /// ret=4: a token code sent by SMS.
    Sms,
    /// ret=5: token clock drift — the gateway wants the next code as well.
    Drift,
    /// ret=6: RADIUS challenge-response (e.g. "please enter otp:").
    Answer,
    /// ret=6 with `pass_renew=1`: the password expired (or is about to).
    NewPassword,
    /// Legacy HTML challenge page (RSA PIN, SMS token): the answer goes in `credential`.
    HtmlAnswer,
    /// Legacy HTML new-password page (`credential` + `credential2` inputs).
    HtmlNewPassword,
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub kind: ChallengeKind,
    pub reqid: String,
    pub polid: String,
    pub grp: String,
    pub grpid: String,
    pub magic: String,
    pub peer: String,
    pub pid: String,
    pub is_chal_rsp: String,
    /// Legacy HTML form only; sent back only if the form had it.
    pub idx: Option<String>,
    /// URL-encoded destination for email/SMS (`tokeninfo`), or `ftm_push`, …
    pub tokeninfo: String,
    /// The gateway's own prompt (`chal_msg`, or the HTML form's `<b>` text).
    pub message: String,
    /// A FortiToken Mobile push is possible (ret=2 + `tokeninfo=ftm_push`).
    pub ftm_push: bool,
    /// ret=6 renew may be skipped (`allow_cancel=1` → portal "Skip").
    pub allow_cancel: bool,
    /// `to=`: seconds the gateway gives the user to answer, if it said.
    pub timeout: Option<u64>,
}

impl Challenge {
    fn new(kind: ChallengeKind) -> Self {
        Challenge {
            kind,
            reqid: String::new(),
            polid: String::new(),
            grp: String::new(),
            grpid: String::new(),
            magic: String::new(),
            peer: String::new(),
            pid: String::new(),
            is_chal_rsp: String::new(),
            idx: None,
            tokeninfo: String::new(),
            message: String::new(),
            ftm_push: false,
            allow_cancel: false,
            timeout: None,
        }
    }

    /// What to tell the user — FortiClient's own wording where it has one.
    /// `pushing`: a FortiToken Mobile push really is being sent for this prompt.
    pub fn prompt_text(&self, pushing: bool) -> String {
        const TOKEN: &str = "A FortiToken code is required for SSL-VPN login authentication.";
        let to = http::percent_decode(&self.tokeninfo);
        let own = |fallback: &str| if self.message.is_empty() { fallback.to_string() } else { self.message.clone() };
        match self.kind {
            ChallengeKind::Token if pushing => {
                "A push was sent to FortiToken Mobile — approve it, or type the code.".to_string()
            }
            // Push possible but not sent (--no-push / fallback): the gateway's chal_msg
            // ("…or no code to send a notification") would be wrong here.
            ChallengeKind::Token if self.ftm_push => TOKEN.to_string(),
            ChallengeKind::Token => own(TOKEN),
            ChallengeKind::Email if !to.is_empty() => {
                format!("An email message containing a Token Code will be sent to <{to}> in a moment.")
            }
            ChallengeKind::Email => "A Token Code was sent to you by email.".to_string(),
            ChallengeKind::Sms if !to.is_empty() => {
                format!("An SMS message containing a Token Code will be sent to <{to}> in a moment.")
            }
            ChallengeKind::Sms => "A Token Code was sent to you by SMS.".to_string(),
            ChallengeKind::Drift => {
                "FortiToken clock drift detected. Please input the next code and continue.".to_string()
            }
            ChallengeKind::Answer | ChallengeKind::HtmlAnswer => own("The gateway asks for additional verification."),
            ChallengeKind::NewPassword | ChallengeKind::HtmlNewPassword => {
                own("Your password is expired, please input a new password.")
            }
        }
    }
}

pub enum AuthOutcome {
    Authenticated,
    Challenge(Challenge),
    Failed(String),
}

impl Session {
    pub fn new(host: String, port: u16, realm: String, user: String, timeout: Duration) -> Self {
        Session {
            host,
            port,
            realm,
            user,
            timeout,
            auth_budget: Duration::from_secs(AUTH_BUDGET_MIN),
            cookies: Cookies::new(),
            password: String::new(),
            last_polid: String::new(),
            last_peer: String::new(),
            second_factor: false,
        }
    }

    pub fn svpncookie(&self) -> Option<&str> {
        self.cookies.get("SVPNCOOKIE").filter(|v| !v.is_empty())
    }

    /// POST to logincheck. The gateway may hold the request open (RADIUS out-of-band
    /// MFA) for the whole auth budget, so a `disconnect` from the GUI aborts it
    /// right away instead of after up to ~5 min.
    fn post_logincheck(&mut self, body: String) -> Result<http::Response, String> {
        if sysnet::stop_requested() {
            return Err("authentication cancelled".into());
        }
        // A little slack past the gateway's own deadline so we still read its reply.
        let t = self.auth_budget + Duration::from_secs(5);
        let cancel = http::Cancel::default();
        let done = Arc::new(AtomicBool::new(false));
        {
            let (cancel, done) = (cancel.clone(), done.clone());
            std::thread::spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    if sysnet::stop_requested() {
                        cancel.cancel();
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
        }
        let r = http::request_cancellable(&self.host, self.port, "POST", LOGINCHECK, &mut self.cookies, body.as_bytes(), t, &cancel);
        done.store(true, Ordering::SeqCst);
        if r.is_err() && sysnet::stop_requested() {
            return Err("authentication cancelled".into());
        }
        r
    }

    pub fn login(&mut self, password: &str) -> Result<AuthOutcome, String> {
        self.password = password.to_string();
        // Warm-up GET so the gateway sets any initial session cookie it expects
        // echoed on the logincheck POST (some FortiOS builds reject a cold POST).
        // Its `<!--remoteauthtimeout=N-->` sets our auth budget, like FortiClient.
        let page = http::request(
            &self.host, self.port, "GET", "/remote/login?lang=en",
            &mut self.cookies, &[], b"", self.timeout,
        )
        .map(|r| r.body_str().into_owned())
        .unwrap_or_default();
        let secs = remote_auth_timeout(&page)
            .or_else(|| super::saml::remote_info(&self.host, self.port).ok().and_then(|i| i.auth_timeout));
        self.auth_budget = Duration::from_secs(auth_budget(secs));

        let body = format!(
            "username={}&credential={}&realm={}{LOGIN_SUFFIX}",
            http::urlencode(&self.user),
            http::urlencode(password),
            http::urlencode(&self.realm),
        );
        let resp = self.post_logincheck(body)?;
        Ok(self.interpret(&resp))
    }

    /// Token challenge (ret=2/3/4/5). `code2` is empty except for clock drift.
    pub fn answer_code(&mut self, ch: &Challenge, code: &str, code2: &str) -> Result<AuthOutcome, String> {
        self.second_factor = true;
        let resp = self.post_logincheck(self.code_body(ch, code, code2))?;
        Ok(self.interpret(&resp))
    }

    /// Trigger a FortiToken Mobile push: one request that the gateway holds open
    /// until the user approves on the phone (or its timer runs out). `cancel` lets
    /// a typed code abort it, as the portal does.
    pub fn push(&mut self, ch: &Challenge, cancel: &http::Cancel) -> Result<AuthOutcome, String> {
        self.second_factor = true;
        let secs = self.auth_budget.as_secs().max(ch.timeout.unwrap_or(0)).min(AUTH_BUDGET_MAX);
        let body = self.push_body(ch);
        let started = std::time::Instant::now();
        let resp = http::request_cancellable(
            &self.host,
            self.port,
            "POST",
            LOGINCHECK,
            &mut self.cookies,
            body.as_bytes(),
            Duration::from_secs(secs + 5),
            cancel,
        )
        .map_err(|e| {
            if started.elapsed().as_secs() >= secs {
                format!("FortiToken push not approved within {secs}s")
            } else {
                format!("FortiToken push: {e}")
            }
        })?;
        Ok(self.interpret(&resp))
    }

    /// Answer a challenge-response or new-password step (ajax ret=6 or legacy HTML).
    pub fn answer(&mut self, ch: &Challenge, text: &str) -> Result<AuthOutcome, String> {
        self.second_factor = true;
        let body = match ch.kind {
            ChallengeKind::HtmlAnswer | ChallengeKind::HtmlNewPassword => self.html_body(ch, text),
            _ => self.ret6_body(ch, text),
        };
        let resp = self.post_logincheck(body)?;
        Ok(self.interpret(&resp))
    }

    /// Skip an optional password change (ret=6 renew with `allow_cancel=1`).
    pub fn skip_renew(&mut self, ch: &Challenge) -> Result<AuthOutcome, String> {
        self.second_factor = true;
        let resp = self.post_logincheck(self.skip_body(ch))?;
        Ok(self.interpret(&resp))
    }

    /// Engine template 0xbf92a8. Code order for drift: see do_login.
    fn code_body(&self, ch: &Challenge, code: &str, code2: &str) -> String {
        format!(
            "username={}&reqid={}&polid={}&grp={}&realm={}&peer={}&code={}&code2={}{ANSWER_SUFFIX}",
            http::urlencode(&self.user),
            http::urlencode(&ch.reqid),
            http::urlencode(&ch.polid),
            http::urlencode(&ch.grp),
            http::urlencode(&self.realm),
            ch.peer, // echoed verbatim, as the engine does (already in wire form)
            http::urlencode(code),
            http::urlencode(code2),
        )
    }

    /// Engine template 0xbf9090 + 0xbf90c8: no code, and never `magic` (magic plus
    /// ftmpush gets HTTP 405 — openconnect #555, openfortivpn #728).
    fn push_body(&self, ch: &Challenge) -> String {
        format!(
            "username={}&reqid={}&polid={}&grp={}&realm={}&peer={}{PUSH_SUFFIX}",
            http::urlencode(&self.user),
            http::urlencode(&ch.reqid),
            http::urlencode(&ch.polid),
            http::urlencode(&ch.grp),
            http::urlencode(&self.realm),
            ch.peer,
        )
    }

    /// The `ajax=1&username&realm&magic&reqid&grpid[&peer]` prefix login.js builds
    /// for ret=6, with its composite fields (`reqid=<reqid>,<polid>`,
    /// `grpid=<grpid>,<pid>,<is_chal_rsp>`); gateway values go back verbatim.
    fn ret6_prefix(&self, ch: &Challenge) -> String {
        let mut b = format!(
            "ajax=1&username={}&realm={}&magic={}&reqid={},{}&grpid={},{},{}",
            http::urlencode(&self.user),
            http::urlencode(&self.realm),
            ch.magic,
            ch.reqid,
            ch.polid,
            ch.grpid,
            ch.pid,
            ch.is_chal_rsp,
        );
        if !ch.peer.is_empty() {
            b.push_str(&format!("&peer={}", ch.peer));
        }
        b
    }

    /// ret=6: a challenge answer travels in `credential2` next to the original
    /// password; a new password travels alone in `credential` (login.js try_login).
    fn ret6_body(&self, ch: &Challenge, text: &str) -> String {
        let prefix = self.ret6_prefix(ch);
        match ch.kind {
            ChallengeKind::NewPassword => format!("{prefix}&credential={}", http::urlencode(text)),
            _ => format!(
                "{prefix}&credential={}&credential2={}",
                http::urlencode(&self.password),
                http::urlencode(text)
            ),
        }
    }

    /// login.js try_skip: here `reqid` is the bare reqid (no `,<polid>`).
    fn skip_body(&self, ch: &Challenge) -> String {
        let mut b = format!(
            "ajax=1&username={}&magic={}&realm={}&credential={}&reqid={}&grpid={},{},{}&skip=1",
            http::urlencode(&self.user),
            ch.magic,
            http::urlencode(&self.realm),
            http::urlencode(&self.password),
            ch.reqid,
            ch.grpid,
            ch.pid,
            ch.is_chal_rsp,
        );
        if !ch.peer.is_empty() {
            b.push_str(&format!("&peer={}", ch.peer));
        }
        b
    }

    /// Legacy HTML forms: the RSA/SMS answer is engine template 0xbf9210 (`idx`
    /// only when the form had one, no `credential2`); the new-password page gets
    /// new + confirm (0xbf9258, no suffix).
    fn html_body(&self, ch: &Challenge, text: &str) -> String {
        let head = format!(
            "magic={}&username={}&reqid={}&grpid={}",
            http::urlencode(&ch.magic),
            http::urlencode(&self.user),
            http::urlencode(&ch.reqid),
            http::urlencode(&ch.grpid),
        );
        let t = http::urlencode(text);
        let realm = http::urlencode(&self.realm);
        match ch.kind {
            ChallengeKind::HtmlNewPassword => format!("{head}&credential={t}&credential2={t}&realm={realm}"),
            _ => {
                let idx = ch.idx.as_deref().map(|i| format!("&idx={}", http::urlencode(i))).unwrap_or_default();
                format!("{head}{idx}&credential={t}&realm={realm}{ANSWER_SUFFIX}")
            }
        }
    }

    fn interpret(&mut self, resp: &http::Response) -> AuthOutcome {
        // The cookie jar already absorbed any Set-Cookie in http::request.
        if self.svpncookie().is_some() {
            return AuthOutcome::Authenticated;
        }
        let body = resp.body_str();
        let ajax = body.trim_start();
        if ajax.starts_with("ret=") {
            let f = parse_ret_fields(ajax);
            let get = |k: &str| f.get(k).cloned().unwrap_or_default();
            let ret = get("ret");
            // The engine dispatches on the first character of `ret`.
            let kind = match ret.chars().next() {
                Some('2') => ChallengeKind::Token,
                Some('3') => ChallengeKind::Email,
                Some('4') => ChallengeKind::Sms,
                Some('5') => ChallengeKind::Drift,
                Some('6') if get("pass_renew") == "1" => ChallengeKind::NewPassword,
                Some('6') => ChallengeKind::Answer,
                Some('1') => return AuthOutcome::Failed(ret1_failure(&get("redir"))),
                _ => return AuthOutcome::Failed(clean_failure(&f, &body, resp.status, self.second_factor)),
            };
            if !get("polid").is_empty() {
                self.last_polid = get("polid");
            }
            if !get("peer").is_empty() {
                self.last_peer = get("peer");
            }
            let mut ch = Challenge::new(kind);
            ch.reqid = get("reqid");
            ch.grp = get("grp");
            ch.magic = get("magic");
            ch.tokeninfo = get("tokeninfo");
            ch.message = get("chal_msg");
            ch.timeout = get("to").parse().ok().filter(|t| *t > 0);
            if matches!(kind, ChallengeKind::Answer | ChallengeKind::NewPassword) {
                // login.js keeps pol_id/peer from earlier rounds when a reply omits them.
                ch.polid = self.last_polid.clone();
                ch.peer = self.last_peer.clone();
                ch.grpid = get("grpid");
                ch.pid = get("pid");
                ch.is_chal_rsp = get("is_chal_rsp");
                ch.allow_cancel = get("allow_cancel") == "1";
            } else {
                // The engine clears peer when a token reply has none.
                ch.polid = get("polid");
                ch.peer = get("peer");
                ch.ftm_push = kind == ChallengeKind::Token && ch.tokeninfo == "ftm_push";
            }
            return AuthOutcome::Challenge(ch);
        }
        if let Some(ch) = parse_html_challenge(&body) {
            return AuthOutcome::Challenge(ch);
        }
        AuthOutcome::Failed(clean_failure(&BTreeMap::new(), &body, resp.status, self.second_factor))
    }
}

/// `<!--remoteauthtimeout=240-->` from the login page.
fn remote_auth_timeout(page: &str) -> Option<u64> {
    let rest = &page[page.find("<!--remoteauthtimeout=")? + 22..];
    rest[..rest.find("-->")?].trim().parse().ok()
}

/// FortiClient's clamp: unknown → 30 s, else [30, 300] s.
fn auth_budget(remote_auth_timeout: Option<u64>) -> u64 {
    remote_auth_timeout.unwrap_or(0).clamp(AUTH_BUDGET_MIN, AUTH_BUDGET_MAX)
}

/// Parse an ajax `ret=2,reqid=..,polid=..,grp=..,tokeninfo=..` body into key→value.
/// Fields are comma-separated (`redir` carries `&`s, which split out `err=`), except
/// `chal_msg`: login.js takes everything after it, commas and newlines included.
fn parse_ret_fields(body: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let b = body.trim_start();
    let (head, chal) = match b.find(",chal_msg=") {
        Some(i) if b.starts_with("ret=") => (&b[..i], Some(&b[i + 10..])),
        _ => (b, None),
    };
    let line = head.lines().find(|l| l.contains('=')).unwrap_or("");
    for tok in line.split(['&', ',']) {
        if let Some((k, v)) = tok.trim().split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    if let Some(c) = chal {
        // login.js also reads comma tokens past chal_msg (only `to=` matters).
        if let Some(to) = c.split(',').filter_map(|t| t.trim().strip_prefix("to=")).last() {
            map.entry("to".to_string()).or_insert_with(|| to.trim().to_string());
        }
        map.insert("chal_msg".to_string(), c.trim_end().to_string());
    }
    map
}

/// Detect a legacy HTML challenge page — the engine's test: the exact
/// `<FORM ACTION="/remote/logincheck" method="POST"…>` tag plus hidden
/// magic/reqid/grpid (magic non-empty). A login page re-served after a wrong
/// password has none of that, so it is never mistaken for a 2FA step.
fn parse_html_challenge(body: &str) -> Option<Challenge> {
    let start = body.to_ascii_lowercase().find(LEGACY_FORM)?;
    let form = &body[start..];
    let form = &form[..form.to_ascii_lowercase().find("</form>").map(|e| e + 7).unwrap_or(form.len())];
    let magic = find_input(form, "magic").filter(|m| !m.is_empty())?;
    let new_password = find_input(form, "credential2").is_some();
    let mut ch = Challenge::new(if new_password { ChallengeKind::HtmlNewPassword } else { ChallengeKind::HtmlAnswer });
    ch.magic = magic;
    ch.reqid = find_input(form, "reqid")?;
    ch.grpid = find_input(form, "grpid")?;
    ch.idx = find_input(form, "idx");
    ch.message = bold_text(form).unwrap_or_default();
    Some(ch)
}

/// Text of the first `<b>…</b>` (the engine reads the prompt from there).
fn bold_text(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let s = lower.find("<b>")? + 3;
    let e = s + lower[s..].find("</b>")?;
    let text = html[s..e].trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// Value of the first `<input ... name=NAME ... value=...>` in `body` (quoted or
/// bare attribute values, any case).
fn find_input(body: &str, name: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let want = name.to_ascii_lowercase();
    let mut search = 0;
    while let Some(rel) = lower[search..].find("<input") {
        let start = search + rel;
        let end = body[start..].find('>').map(|e| start + e + 1).unwrap_or(body.len());
        let tag = &body[start..end];
        if attr_value(tag, "name").is_some_and(|n| n.eq_ignore_ascii_case(&want)) {
            return Some(attr_value(tag, "value").unwrap_or_default());
        }
        search = end;
    }
    None
}

fn attr_value(tag: &str, attr: &str) -> Option<String> {
    let tl = tag.to_ascii_lowercase();
    let key = format!("{}=", attr.to_ascii_lowercase());
    // Whole attribute names only (`name=` must not match inside `rename=`).
    let mut from = 0;
    let pos = loop {
        let i = from + tl[from..].find(&key)?;
        if i > 0 && tl.as_bytes()[i - 1].is_ascii_whitespace() {
            break i + key.len();
        }
        from = i + key.len();
    };
    let rest = &tag[pos..];
    match rest.as_bytes().first() {
        Some(&q) if q == b'"' || q == b'\'' => {
            let end = rest[1..].find(q as char)? + 1;
            Some(rest[1..end].to_string())
        }
        _ => {
            let end = rest.find(|c: char| c.is_whitespace() || c == '>' || c == '/').unwrap_or(rest.len());
            Some(rest[..end].to_string())
        }
    }
}

/// ret=1 means the credentials were accepted ("go to redir"), but without a
/// SVPNCOOKIE there is no session — FortiClient (on_login_failed), openfortivpn
/// and openconnect all fail here. Seen on portals that demand a host check
/// (openfortivpn #774), which following `redir` alone doesn't satisfy.
fn ret1_failure(redir: &str) -> String {
    let target = redir.split('?').next().unwrap_or(""); // never print user/IP from the query
    let hint = if target.contains("hostcheck") {
        " — this portal requires a FortiClient host check, which unvpn does not support"
    } else {
        ""
    };
    format!(
        "credentials accepted (ret=1) but the gateway issued no SVPNCOOKIE (redir={}){hint}",
        if target.is_empty() { "-" } else { target }
    )
}

/// A concise failure message — never dump a whole HTML login page at the user.
/// `second_factor`: the password was already accepted, so don't blame it.
fn clean_failure(fields: &BTreeMap<String, String>, body: &str, status: u16, second_factor: bool) -> String {
    if let Some(err) = fields.get("err").filter(|e| !e.is_empty()) {
        return format!("login rejected: {}", describe_err(err));
    }
    if let Some(m) = fields.get("chal_msg").filter(|m| !m.is_empty()) {
        return format!("login rejected: {}", one_line(m));
    }
    // HTML error pages: the engine matches these strings (FUN_00472c40).
    for known in ["Two-factor Authentication failed", "Too many bad login attempts"] {
        if body.contains(known) {
            return format!("login rejected: {known}");
        }
    }
    if let Some(i) = body.find("<!--sslvpnerrmsg=") {
        let rest = &body[i + 17..];
        if let Some(e) = rest.find("-->") {
            return format!("login rejected: {}", one_line(rest[..e].trim()));
        }
    }
    if let Some(err) = ["sslvpn_login_permission_denied", "sslvpn_login_password_expired", "sslvpn_logindisable_errmsg"]
        .into_iter()
        .find(|e| body.contains(e))
    {
        return format!("login rejected: {}", describe_err(err));
    }
    if status == 405 {
        if second_factor {
            return "login rejected (HTTP 405) — the gateway refused this second-factor request".to_string();
        }
        // Fortinet answers bad credentials (or login throttling) with 405 — openconnect #484.
        return "login rejected (HTTP 405) — wrong username/password/realm, or the gateway is \
                throttling logins from this IP"
            .to_string();
    }
    let bl = body.to_ascii_lowercase();
    if ["<html", "<body", "<form", "fgt_lang"].iter().any(|m| bl.contains(m)) {
        return format!(
            "login rejected by gateway (HTTP {status}) — check username, password and realm \
             (gateway returned its login/error page, not an auth token)"
        );
    }
    if body.trim().is_empty() {
        format!("login rejected (HTTP {status})")
    } else {
        format!("login rejected: {}", one_line(body.trim()))
    }
}

/// FortiOS `err=` codes (portal language file) → words.
fn describe_err(err: &str) -> String {
    match err {
        "sslvpn_login_permission_denied" => "permission denied (wrong credentials or not allowed)".into(),
        "sslvpn_login_password_expired" => "password expired".into(),
        "sslvpn_login_insufficient_credential" => "insufficient credentials".into(),
        "sslvpn_login_change_password_failed" => "failed to change password".into(),
        "sslvpn_logindisable_errmsg" => "too many bad login attempts — login temporarily disabled".into(),
        other => one_line(other),
    }
}

/// One printable line, at most 300 chars: gateway text ends up in our stdout,
/// which the GUI parses line by line.
pub fn one_line(s: &str) -> String {
    let flat: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let flat = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(300).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        let mut s = Session::new("gw".into(), 443, "corp".into(), "ana".into(), Duration::from_secs(5));
        s.password = "p@ss word".into();
        s
    }

    fn resp(status: u16, body: &str) -> http::Response {
        http::Response { status, headers: vec![], body: body.as_bytes().to_vec() }
    }

    fn challenge(s: &mut Session, body: &str) -> Challenge {
        match s.interpret(&resp(200, body)) {
            AuthOutcome::Challenge(c) => c,
            AuthOutcome::Failed(m) => panic!("expected a challenge, got failure: {m}"),
            AuthOutcome::Authenticated => panic!("expected a challenge, got success"),
        }
    }

    fn failure(s: &mut Session, status: u16, body: &str) -> String {
        match s.interpret(&resp(status, body)) {
            AuthOutcome::Failed(m) => m,
            _ => panic!("expected a failure"),
        }
    }

    #[test]
    fn ret2_challenge_fields() {
        let f = parse_ret_fields("ret=2,reqid=12345,polid=1,grp=,tokeninfo=FTK,chal_msg=Enter token");
        assert_eq!(f.get("ret").map(|s| s.as_str()), Some("2"));
        assert_eq!(f.get("reqid").map(|s| s.as_str()), Some("12345"));
        assert_eq!(f.get("polid").map(|s| s.as_str()), Some("1"));
        assert_eq!(f.get("tokeninfo").map(|s| s.as_str()), Some("FTK"));
        assert_eq!(f.get("chal_msg").map(|s| s.as_str()), Some("Enter token"));
    }

    #[test]
    fn chal_msg_keeps_commas_ampersands_and_newlines() {
        let f = parse_ret_fields("ret=6,magic=1-ab,reqid=77,chal_msg=Wait, then enter PIN & code:\nOption (1-3):\r\n");
        assert_eq!(f.get("chal_msg").unwrap(), "Wait, then enter PIN & code:\nOption (1-3):");
        assert_eq!(f.get("reqid").unwrap(), "77");
        // `to=` after chal_msg is still read (login.js scans every comma token).
        let f = parse_ret_fields("ret=2,reqid=1,polid=2,grp=g,chal_msg=Enter code,to=60");
        assert_eq!(f.get("to").unwrap(), "60");
    }

    #[test]
    fn ret0_redir_yields_err() {
        let mut s = session();
        let m = failure(&mut s, 200, "ret=0,redir=/remote/login?&err=sslvpn_login_permission_denied&lang=en");
        assert!(m.contains("permission denied"), "{m}");
    }

    #[test]
    fn token_kinds_by_ret() {
        let mut s = session();
        // Real FortiGate reply (openconnect #555).
        let c = challenge(
            &mut s,
            "ret=2,reqid=1111111111,polid=1111111111,grp=alfa,portal=alfa-tunnel,magic=1111111111,\
             tokeninfo=ftm_push,chal_msg=Enter token code or no code to send a notification to your FortiToken Mobile",
        );
        assert_eq!(c.kind, ChallengeKind::Token);
        assert!(c.ftm_push);
        assert_eq!((c.reqid.as_str(), c.polid.as_str(), c.grp.as_str()), ("1111111111", "1111111111", "alfa"));
        assert!(!challenge(&mut s, "ret=2,reqid=1,polid=2,grp=g,tokeninfo=").ftm_push);
        assert!(!challenge(&mut s, "ret=2,reqid=1,polid=2,grp=g,tokeninfo=remote_token_auth").ftm_push);

        let c = challenge(&mut s, "ret=3,reqid=1,polid=2,grp=g,tokeninfo=user%2Bvpn%40example.com");
        assert_eq!(c.kind, ChallengeKind::Email);
        assert!(c.prompt_text(false).contains("<user+vpn@example.com>"), "{}", c.prompt_text(false));
        assert_eq!(challenge(&mut s, "ret=4,reqid=1,polid=2,grp=g,tokeninfo=%2B51999").kind, ChallengeKind::Sms);
        assert_eq!(challenge(&mut s, "ret=5,reqid=1,polid=2,grp=g").kind, ChallengeKind::Drift);
    }

    #[test]
    fn push_wording_only_when_pushing() {
        let mut s = session();
        let c = challenge(&mut s, "ret=2,reqid=1,polid=2,grp=g,tokeninfo=ftm_push,chal_msg=Enter token code or no code to send a notification");
        assert!(c.prompt_text(true).contains("push was sent"));
        // --no-push / fallback: neither our push wording nor the gateway's "no code ⇒ notification".
        assert_eq!(c.prompt_text(false), "A FortiToken code is required for SSL-VPN login authentication.");
        let c = challenge(&mut s, "ret=2,reqid=1,polid=2,grp=g,tokeninfo=,chal_msg=Enter token code");
        assert_eq!(c.prompt_text(false), "Enter token code");
    }

    #[test]
    fn http_405_blames_the_right_step() {
        let mut s = session();
        assert!(failure(&mut s, 405, "<html>405</html>").contains("wrong username/password"));
        s.second_factor = true;
        let m = failure(&mut s, 405, "<html>405</html>");
        assert!(m.contains("second-factor") && !m.contains("password"), "{m}");
    }

    #[test]
    fn ret6_challenge_and_renew() {
        let mut s = session();
        // FortiOS 7.6.2 (openfortivpn #1343).
        let c = challenge(
            &mut s,
            "ret=6,magic=1-62a7,actionurl=/remote/logincheck,reqid=31337,portal=,grpid=0,pid=266,is_chal_rsp=1,chal_msg=please enter otp:",
        );
        assert_eq!(c.kind, ChallengeKind::Answer);
        assert_eq!(c.message, "please enter otp:");
        assert_eq!(
            s.ret6_body(&c, "123456"),
            "ajax=1&username=ana&realm=corp&magic=1-62a7&reqid=31337,&grpid=0,266,1\
             &credential=p%40ss%20word&credential2=123456"
        );

        // openfortivpn commit 1437ed4f sample.
        let c = challenge(
            &mut s,
            "ret=6,actionurl=/remote/logincheck,magic=1-12345678,reqid=0,grpid=1,pid=249,is_chal_rsp=1,\
             pass_renew=1,allow_cancel=1,chal_msg=Your password will expire in 3 days. Would you like to change it?",
        );
        assert_eq!(c.kind, ChallengeKind::NewPassword);
        assert!(c.allow_cancel);
        assert_eq!(
            s.ret6_body(&c, "N3w pass"),
            "ajax=1&username=ana&realm=corp&magic=1-12345678&reqid=0,&grpid=1,249,1&credential=N3w%20pass"
        );
        assert_eq!(
            s.skip_body(&c),
            "ajax=1&username=ana&magic=1-12345678&realm=corp&credential=p%40ss%20word&reqid=0&grpid=1,249,1&skip=1"
        );
    }

    #[test]
    fn code_and_push_bodies_follow_the_engine() {
        let mut s = session();
        let c = challenge(&mut s, "ret=2,reqid=9,polid=1-1-ab,grp=Grupo VPN,magic=1-ab,tokeninfo=ftm_push,peer=pkiuser");
        assert_eq!(
            s.code_body(&c, "123456", ""),
            "username=ana&reqid=9&polid=1-1-ab&grp=Grupo%20VPN&realm=corp&peer=pkiuser&code=123456&code2=\
             &redir=%2Fremote%2Findex&just_logged_in=1"
        );
        let push = s.push_body(&c);
        assert_eq!(
            push,
            "username=ana&reqid=9&polid=1-1-ab&grp=Grupo%20VPN&realm=corp&peer=pkiuser\
             &redir=%2Fremote%2Findex&just_logged_in=1&ftmpush=1"
        );
        assert!(!push.contains("magic") && !push.contains("code"));
    }

    #[test]
    fn ret1_is_a_failure_with_a_hostcheck_hint() {
        let mut s = session();
        let m = failure(
            &mut s,
            200,
            "ret=1,redir=/remote/hostcheck_install?auth_type=1&user=ana&grpname=g&portal=p&rip=1.1.1.1&realm=",
        );
        assert!(m.contains("host check") && !m.contains("1.1.1.1") && !m.contains("ana"), "{m}");
    }

    #[test]
    fn modern_login_page_is_not_a_challenge() {
        // The page a FortiOS 7.x gateway re-serves after a wrong password (203.0.113.30).
        let page = r#"<form class="prompt legacy-prompt" action="/remote/logincheck" method="post" name="f" autocomplete="off">
            <input id="username" name="username" type="text"><input id="credential" name="credential" type="password">
            </form><input type=hidden name=magic id=magic_id value=""><input type=hidden name=reqid id=reqid_id value="0">
            <input type=hidden name=grpid id=grpid_id value=""><!--remoteauthtimeout=240-->"#;
        assert!(parse_html_challenge(page).is_none());
        let mut s = session();
        assert!(failure(&mut s, 200, page).contains("check username, password and realm"));
        assert_eq!(remote_auth_timeout(page), Some(240));
    }

    #[test]
    fn legacy_sms_form_challenge() {
        // Shape of the real 401 page in openconnect #332.
        let html = r#"<html><body><FORM ACTION="/remote/logincheck" method="POST">
            <TABLE><TR align=center valign=middle><TD colspan=2><b>Please type in the SMS token:</b></TD></TR>
            <INPUT TYPE="hidden" NAME="magic" VALUE="336-79a890ea">
            <INPUT TYPE="hidden" NAME="username" VALUE="user.name">
            <INPUT TYPE="hidden" NAME="reqid" VALUE="2033500319">
            <INPUT TYPE="hidden" NAME="grpid" VALUE="0,512,1">
            <INPUT TYPE="password" NAME="credential"></TABLE></FORM></body></html>"#;
        let mut s = session();
        let c = match s.interpret(&resp(401, html)) {
            AuthOutcome::Challenge(c) => c,
            _ => panic!("legacy SMS form not detected"),
        };
        assert_eq!(c.kind, ChallengeKind::HtmlAnswer);
        assert_eq!(c.message, "Please type in the SMS token:");
        assert_eq!(c.idx, None);
        assert_eq!(
            s.html_body(&c, "123456"),
            "magic=336-79a890ea&username=ana&reqid=2033500319&grpid=0%2C512%2C1&credential=123456&realm=corp\
             &redir=%2Fremote%2Findex&just_logged_in=1"
        );
    }

    #[test]
    fn legacy_new_password_form() {
        let html = r#"<FORM ACTION="/remote/logincheck" method="POST" onsubmit='if (!form_check()) return false;'>
            <b>Your password is expired, please input a new password.</b>
            <INPUT TYPE="password" NAME="credential"><INPUT TYPE="password" NAME="credential2">
            <INPUT TYPE="hidden" NAME="magic" VALUE="7-aa"><INPUT TYPE="hidden" NAME="username" VALUE="ana">
            <INPUT TYPE="hidden" NAME="reqid" VALUE="5"><INPUT TYPE="hidden" NAME="grpid" VALUE="1,2,1"></FORM>"#;
        let c = parse_html_challenge(html).expect("new-password form");
        assert_eq!(c.kind, ChallengeKind::HtmlNewPassword);
        assert_eq!(
            session().html_body(&c, "x y"),
            "magic=7-aa&username=ana&reqid=5&grpid=1%2C2%2C1&credential=x%20y&credential2=x%20y&realm=corp"
        );
    }

    #[test]
    fn find_input_quotes_and_attr_order() {
        assert_eq!(find_input("<input name='reqid' value='42'>", "reqid").as_deref(), Some("42"));
        assert_eq!(find_input(r#"<INPUT VALUE="abc" NAME="magic">"#, "magic").as_deref(), Some("abc"));
        assert_eq!(find_input("<input type=hidden name=grpid value=\"\">", "grpid").as_deref(), Some(""));
        assert_eq!(find_input("<input name=\"x\" value=\"y\">", "reqid"), None);
        assert_eq!(find_input("<input rename=\"reqid\" value=\"1\">", "reqid"), None);
    }

    #[test]
    fn budget_is_clamped_like_forticlient() {
        assert_eq!(auth_budget(None), 30);
        assert_eq!(auth_budget(Some(5)), 30);
        assert_eq!(auth_budget(Some(240)), 240);
        assert_eq!(auth_budget(Some(900)), 300);
    }

    #[test]
    fn one_line_strips_controls() {
        assert_eq!(one_line("a\r\nSAML-URL: x\tb"), "a SAML-URL: x b");
    }
}
