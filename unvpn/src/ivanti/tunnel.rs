//! Ivanti Connect Secure (Pulse) data plane.
//!
//! After login the client opens a second TLS connection carrying the `DSID`
//! cookie and runs the IF-T/TLS handshake ([`ift`](super::ift)): a client
//! hello, EAP authentication bound to the session, then configuration messages
//! that yield [`IvantiConfig`](super::config::IvantiConfig). Payload then flows
//! either as IF-T data messages over that TLS link or, when the gateway offers
//! it, as ESP-over-UDP (keys from the config, decoded by the shared
//! [`EspSa`](crate::ike::esp::EspSa)).
//!
//! The handshake byte sequence is not reconstructed yet — it needs a capture of
//! a real client/gateway exchange. `run` wires up what is already known (the
//! framing and the authenticated session) and stops at that boundary with a
//! clear error rather than guessing on the wire.

use super::auth::Session;
use super::ift::{IftMessage, PEN_JUNIPER};

pub struct RunOpts {
    pub no_routes: bool,
    pub no_esp: bool,
    pub watch_stdin: bool,
}

impl Default for RunOpts {
    fn default() -> Self {
        RunOpts { no_routes: false, no_esp: false, watch_stdin: true }
    }
}

/// Needs root once the tunnel is up (tun device, routes, DNS).
pub fn run(session: &mut Session, _opts: RunOpts) -> Result<(), String> {
    let dsid = session.dsid.clone().ok_or("no DSID session cookie — log in first")?;

    // The first IF-T/TLS message a client sends is a vendor (Juniper) control
    // message on the fresh tunnel connection. Built here to keep the framing
    // exercised; the exact type/payload is pending a capture.
    let _client_hello = IftMessage::new(PEN_JUNIPER, 0, 1, Vec::new()).encode();
    let _ = dsid;

    Err("ivanti data plane not implemented yet: the IF-T/TLS handshake needs a capture of a real session".into())
}
