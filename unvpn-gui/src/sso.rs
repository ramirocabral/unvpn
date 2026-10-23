//! Embedded-browser SSO for SAML logins, like the vendors' own clients.
//!
//! AnyConnect (`sso-v2`): the client shows the IdP login itself and, once the
//! page reaches `sso-v2-login-final`, reads the token cookie (`acSamlv2Token`)
//! from its own cookie jar. GlobalProtect: the page that completes the flow
//! carries the result in its response headers (`saml-username`,
//! `prelogin-cookie` / `portal-userauthcookie`), or — when the portal is set to
//! use the default browser — the IdP redirects to a `globalprotectcallback:` URL.
//! The engine runs as root and has no display, so the GUI does that part: it
//! opens a WebKitGTK window on the login URL, captures the result and hands it
//! back (it is then piped to the engine's `# AUTH-PROMPT: sso:` on stdin).
//!
//! The web data lives in `$XDG_DATA_HOME/unvpn/webview`, so the IdP can remember
//! the account ("stay signed in") between connections.

use crate::engine::SsoWatch;
use adw::prelude::*;
use gtk::glib;
use std::cell::Cell;
use std::rc::Rc;
use webkit6::prelude::*;

fn xdg_dir(var: &str, fallback: &str) -> std::path::PathBuf {
    match std::env::var_os(var).filter(|v| !v.is_empty()) {
        Some(x) => std::path::PathBuf::from(x),
        None => std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(fallback),
    }
}

thread_local! {
    /// One network session for the app's lifetime: WebKit must not finalize it
    /// while a destroyed view's web process still references it (crashes on
    /// close), and two sessions must not share a data directory anyway.
    static SESSION: webkit6::NetworkSession = {
        let data = xdg_dir("XDG_DATA_HOME", ".local/share").join("unvpn/webview");
        let cache = xdg_dir("XDG_CACHE_HOME", ".cache").join("unvpn/webview");
        let s = webkit6::NetworkSession::new(data.to_str(), cache.to_str());
        // Cookies are memory-only unless told otherwise; keep them so the IdP can
        // remember the account between connections.
        if let (Some(cm), Some(db)) = (s.cookie_manager(), data.join("cookies.sqlite").to_str()) {
            cm.set_persistent_storage(db, webkit6::CookiePersistentStorage::Sqlite);
        }
        s
    };
}

/// Open the SSO window on `login`. `on_done` is called exactly once: `Ok(token)`
/// when `watch` saw the login complete, `Err(reason)` if the login failed or the
/// user closed the window. The caller keeps the returned window to close it if
/// the connection is aborted.
pub fn open(
    parent: &impl IsA<gtk::Window>,
    login: &str,
    watch: &SsoWatch,
    user_agent: Option<&str>,
    on_done: impl Fn(Result<String, String>) + 'static,
) -> adw::Window {
    let session = SESSION.with(|s| s.clone());
    let view = webkit6::WebView::builder().network_session(&session).vexpand(true).hexpand(true).build();

    // Override the User-Agent (e.g. present as Windows) before the first load, so
    // the IdP's device-platform check sees it.
    if let Some(ua) = user_agent.filter(|u| !u.is_empty()) {
        if let Some(s) = webkit6::prelude::WebViewExt::settings(&view) {
            s.set_user_agent(Some(ua));
        }
    }

    let shown_url = match watch {
        SsoWatch::Cookie { final_url, .. } => final_url.as_str(),
        SsoWatch::GpHeaders | SsoWatch::Loopback => login,
    };
    let host = if shown_url.starts_with("data:") { String::new() } else { shown_url.split('/').nth(2).unwrap_or_default().to_string() };
    let header = adw::HeaderBar::builder()
        .title_widget(&adw::WindowTitle::new("VPN sign-in", &host))
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&view));

    let win = adw::Window::builder()
        .title("VPN sign-in")
        .default_width(900)
        .default_height(760)
        .transient_for(parent)
        .content(&toolbar)
        .build();

    // Report once: the final page, a login error, or the window closing first.
    let done = Rc::new(Cell::new(false));
    let on_done = Rc::new(on_done);
    let finish: Rc<dyn Fn(Result<String, String>)> = {
        let done = done.clone();
        let on_done = on_done.clone();
        Rc::new(move |r| {
            if !done.replace(true) {
                on_done(r);
            }
        })
    };

    let (final_url, cookie) = match watch {
        SsoWatch::Cookie { final_url, cookie } => (final_url.clone(), cookie.clone()),
        SsoWatch::GpHeaders => {
            watch_gp(&view, &win, finish.clone());
            (String::new(), String::new())
        }
        SsoWatch::Loopback => {
            watch_loopback(&view, &win, finish.clone());
            (String::new(), String::new())
        }
    };
    let (final_for_clear, cookie_name) = (final_url.clone(), cookie.clone());
    view.connect_load_changed({
        let finish = finish.clone();
        let win = win.downgrade();
        move |v, ev| {
            if ev != webkit6::LoadEvent::Finished {
                return;
            }
            let Some(uri) = v.uri() else { return };
            if final_url.is_empty() || !uri.starts_with(final_url.as_str()) {
                return;
            }
            let Some(cm) = v.network_session().and_then(|s| s.cookie_manager()) else {
                finish(Err("no cookie manager in the SSO window".into()));
                return;
            };
            let finish = finish.clone();
            let win = win.clone();
            let cookie = cookie.clone();
            cm.cookies(&uri, None::<&gtk::gio::Cancellable>, move |r| {
                // (soup's accessors take `&mut`; flatten to plain name/value pairs.)
                let cookies: Vec<(String, String)> = r
                    .unwrap_or_default()
                    .iter_mut()
                    .filter_map(|c| Some((c.name()?.to_string(), c.value()?.to_string())))
                    .collect();
                let get = |name: &str| {
                    cookies.iter().find(|(n, v)| n == name && !v.is_empty()).map(|(_, v)| v.clone())
                };
                let res = match get(&cookie) {
                    Some(t) => Ok(t),
                    None => Err(match get("acSamlv2Error") {
                        Some(e) => format!("SSO login failed: {e}"),
                        None => format!("SSO finished but no {cookie} cookie was set"),
                    }),
                };
                finish(res);
                // Not from inside WebKit's own callback: tear the view down later.
                glib::idle_add_local_once(move || {
                    if let Some(w) = win.upgrade() {
                        w.close();
                    }
                });
            });
        }
    });

    win.connect_close_request({
        let finish = finish.clone();
        move |_| {
            finish(Err("SSO window closed".into()));
            glib::Propagation::Proceed
        }
    });

    // Drop any token cookie a previous login left in the (persistent) jar, so the
    // final page can only yield a fresh one; then start the login.
    let start = {
        let view = view.clone();
        let login = login.to_string();
        Rc::new(move || view.load_uri(&login))
    };
    match session.cookie_manager().filter(|_| !cookie_name.is_empty()) {
        Some(cm) => {
            let cm2 = cm.clone();
            let name = cookie_name.clone();
            cm.cookies(&final_for_clear, None::<&gtk::gio::Cancellable>, move |r| {
                let mut stale: Vec<_> = r.unwrap_or_default();
                stale.retain_mut(|c| c.name().as_deref() == Some(name.as_str()));
                if stale.is_empty() {
                    return start();
                }
                let left = Rc::new(Cell::new(stale.len()));
                for c in &stale {
                    let (left, start) = (left.clone(), start.clone());
                    cm2.delete_cookie(c, None::<&gtk::gio::Cancellable>, move |_| {
                        left.set(left.get() - 1);
                        if left.get() == 0 {
                            start();
                        }
                    });
                }
            });
        }
        None => start(),
    }
    win.present();
    win
}

/// Fortinet: the login ends by redirecting to the engine's loopback listener
/// (`http://127.0.0.1:<port>` / `http://localhost:<port>`). Nothing to scrape —
/// once the window reaches loopback the engine already took the token, so finish
/// and close the window. The data path comes up from the engine side.
fn watch_loopback(view: &webkit6::WebView, win: &adw::Window, finish: Rc<dyn Fn(Result<String, String>)>) {
    view.connect_load_changed({
        let finish = finish.clone();
        let win = win.downgrade();
        move |v, ev| {
            if ev != webkit6::LoadEvent::Finished {
                return;
            }
            let Some(uri) = v.uri() else { return };
            if uri.starts_with("http://127.0.0.1") || uri.starts_with("http://localhost") {
                finish(Ok(String::new()));
                let win = win.clone();
                glib::idle_add_local_once(move || {
                    if let Some(w) = win.upgrade() {
                        w.close();
                    }
                });
            }
        }
    });
}

/// GlobalProtect: finish on the response headers of a page that completes the
/// SAML flow, or on a `globalprotectcallback:` navigation (never followed). The
/// answer for the engine is `saml-username=…;<cookie-name>=…` (values
/// percent-encoded) or the callback URL itself.
fn watch_gp(view: &webkit6::WebView, win: &adw::Window, finish: Rc<dyn Fn(Result<String, String>)>) {
    let close_later = |win: glib::WeakRef<adw::Window>| {
        glib::idle_add_local_once(move || {
            if let Some(w) = win.upgrade() {
                w.close();
            }
        });
    };

    view.connect_decide_policy({
        let finish = finish.clone();
        let win = win.downgrade();
        move |_, decision, _| {
            let Some(nav) = decision.downcast_ref::<webkit6::NavigationPolicyDecision>() else { return false };
            let uri = nav.navigation_action().and_then(|a| a.request()).and_then(|r| r.uri()).unwrap_or_default();
            if !uri.starts_with("globalprotectcallback:") {
                return false;
            }
            decision.ignore();
            finish(Ok(uri.to_string()));
            close_later(win.clone());
            true
        }
    });

    view.connect_load_changed({
        let win = win.downgrade();
        move |v, ev| {
            if ev != webkit6::LoadEvent::Finished {
                return;
            }
            let Some(h) = v.main_resource().and_then(|r| r.response()).and_then(|r| r.http_headers()) else { return };
            let get = |n: &str| h.one(n).map(|v| v.to_string()).filter(|v| !v.is_empty());
            if get("saml-auth-status").as_deref() == Some("-1") {
                finish(Err("SAML login failed (saml-auth-status -1)".into()));
                close_later(win.clone());
                return;
            }
            let found = ["prelogin-cookie", "portal-userauthcookie"].into_iter().find_map(|n| get(n).map(|v| (n, v)));
            let Some((name, value)) = found else { return };
            let user = get("saml-username").unwrap_or_default();
            finish(Ok(format!("saml-username={};{name}={}", pct(&user), pct(&value))));
            close_later(win.clone());
        }
    });
}

/// Percent-encode everything but unreserved characters (the engine decodes).
fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
