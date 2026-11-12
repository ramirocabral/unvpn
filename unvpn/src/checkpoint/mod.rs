//! Check Point Remote Access VPN: CCC over HTTPS for the gateway's site
//! information and encryption domain, IKEv1 with Office Mode for the login,
//! ESP over NAT-T for the data plane.

pub mod ccc;
pub mod cert;
mod login;
mod probe;
mod ssl;
mod tunnel;

pub use login::cmd_ike;
pub use probe::{cmd_deob, cmd_hello, cmd_login};
pub use ssl::cmd_tunnel;
pub use tunnel::cmd_tunnel_up;

use crate::net::http;
use crate::{sysnet, tun};
use std::time::Duration;

const USER_AGENT: &str = "Mozilla/5.0 (compatible; CPSC 5.0; Windows NT 5.0)";

const CCC_PATH: &str = "/clients/";

/// A non-zero request id. The gateway echoes it back in the response header;
/// Derived from the clock.
fn new_request_id() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1);
    (nanos % 100_000) as i64 + 1
}

/// Used when the gateway's encryption domain can't be fetched.
const CP_FALLBACK_ROUTE: (std::net::Ipv4Addr, u8) = (std::net::Ipv4Addr::new(10, 0, 0, 0), 8);

/// The site's encryption domain as prefixes, from a CCC `ClientSettings` request
/// on the session Office Mode handed out.
fn fetch_encryption_domain(
    host: &str,
    session_id: &str,
) -> Result<Vec<(std::net::Ipv4Addr, u8)>, String> {
    let body = ccc::client_settings(new_request_id(), session_id).serialize();
    let resp = ccc_post(host, &body)?;
    let pkt =
        ccc::parse(&resp.body_str()).map_err(|e| format!("bad ClientSettings answer: {e}"))?;
    let ranges = ccc::encryption_domain(&pkt)?;
    let mut nets: Vec<(std::net::Ipv4Addr, u8)> = ranges
        .into_iter()
        .flat_map(|(f, t)| tun::range_to_prefixes(f, t))
        .collect();
    nets.sort();
    nets.dedup();
    Ok(nets)
}

/// The routes to send into the tunnel: the encryption domain, or the fallback.
fn cp_routes(host: &str, session_id: Option<&str>) -> Vec<(std::net::Ipv4Addr, u8)> {
    let got = match session_id {
        Some(sid) => fetch_encryption_domain(host, sid),
        None => Err("Office Mode gave no CCC session".into()),
    };
    match got {
        Ok(nets) if !nets.is_empty() => {
            let shown: Vec<String> = nets
                .iter()
                .take(8)
                .map(|(n, l)| format!("{n}/{l}"))
                .collect();
            let more = if nets.len() > 8 {
                format!(" (+{} more)", nets.len() - 8)
            } else {
                String::new()
            };
            out!("# encryption domain: {}{more}", shown.join(" "));
            nets
        }
        Ok(_) => cp_fallback("the gateway listed no ranges"),
        Err(e) => cp_fallback(&e),
    }
}

fn cp_fallback(why: &str) -> Vec<(std::net::Ipv4Addr, u8)> {
    let (n, l) = CP_FALLBACK_ROUTE;
    out!(
        "# encryption domain unavailable ({}) — routing {n}/{l} into the tunnel",
        sysnet::one_line(why)
    );
    vec![CP_FALLBACK_ROUTE]
}

fn ccc_endpoint(host: &str) -> http::Endpoint {
    let mut ep = http::Endpoint::new(host, 443, USER_AGENT, Duration::from_secs(15));
    ep.headers = vec!["Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5".into()];
    ep
}

/// One CCC request to the gateway's port 443.
fn ccc_post(host: &str, body: &str) -> Result<http::Response, String> {
    let req = http::Request::form(CCC_PATH, body);
    http::send(&ccc_endpoint(host), req, &mut http::Cookies::new())
}

/// The gateway's CCC ClientHello answer (site information, login options).
pub(crate) fn gateway_hello(host: &str) -> Result<ccc::Packet, String> {
    let body = ccc::client_hello(new_request_id()).serialize();
    let resp = ccc_post(host, &body)?;
    ccc::parse(&resp.body_str()).map_err(|e| format!("bad ClientHello answer: {e}"))
}
