//! FortiClient-private IKE_AUTH payloads: `FORTICLIENT_CONNECT` and the EMS serial
//! number (`EMSSN=…`). FortiGate dialup configured for EMS/ZTNA validates the EMS
//! serial in-band — the `iked` binary carries the literal error "IPsec VPN login
//! failed due to mismatched pre-shared key, client certificate, or EMS serial
//! number" and the senders `ikev2_add_forticlient_connect` / `ikev2_add_adc_emssn`
//! (`fct_get_emssn`, string `EMSSN=`).
//!
//! STATUS: the EMS serial is only obtainable by registering to the gateway's own
//! EMS (an authorisation/onboarding step); it cannot be fabricated. This module
//! presents a serial the operator already holds — read from the locally installed,
//! EMS-registered FortiClient, or supplied via `--emssn` / `UNVPN_EMSSN`. The exact
//! Notify numeric types and payload framing are PROVISIONAL (pending decompilation
//! of `ikev2_add_adc_emssn`); the wire shape below is a best-effort placeholder and
//! must be confirmed against a packet capture before it will satisfy a real gateway.

#![allow(dead_code)]

use super::model::{EMSSN_PREFIX, FORTICLIENT_CONNECT_TAG};
use super::wire::{Notify, Payload};

/// FortiClient private Notify message types (private-use range 40960-65535).
/// PROVISIONAL values — not yet confirmed from iked.
const N_FORTICLIENT_CONNECT: u16 = 40960;
const N_EMSSN: u16 = 40961;

/// Where to get the EMS serial the gateway expects.
#[derive(Debug, Clone)]
pub enum EmsSerial {
    /// Supplied explicitly (flag/env).
    Explicit(String),
    /// None — skip the FortiClient payloads (works against a FortiGate dialup that
    /// does not enforce EMS/ZTNA).
    None,
}

impl EmsSerial {
    /// Resolve from an explicit value, else the `UNVPN_EMSSN` env var, else try the
    /// locally installed FortiClient's registered serial, else None.
    pub fn resolve(explicit: Option<&str>) -> EmsSerial {
        if let Some(s) = explicit.filter(|s| !s.is_empty()) {
            return EmsSerial::Explicit(s.to_string());
        }
        if let Ok(s) = std::env::var("UNVPN_EMSSN") {
            if !s.is_empty() {
                return EmsSerial::Explicit(s);
            }
        }
        if let Some(s) = read_local_forticlient_emssn() {
            return EmsSerial::Explicit(s);
        }
        EmsSerial::None
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            EmsSerial::Explicit(s) => Some(s),
            EmsSerial::None => None,
        }
    }
}

/// Best-effort read of the EMS serial from a locally installed FortiClient that is
/// already registered to the EMS. PROVISIONAL: the real location is iked's
/// `fct_get_emssn` (shared memory / the config DB). Returns `None` for now; wired as
/// the extension point so onboarding + RE can fill it in without touching callers.
fn read_local_forticlient_emssn() -> Option<String> {
    // TODO(RE): read from /opt/forticlient config DB or shm (epctrl_ems_serial), or
    // parse `forticlient ... ` CLI output, once the field is located and the box is
    // EMS-registered. Intentionally not guessing a value that would fail the gateway.
    None
}

/// The FortiClient IKE_AUTH payloads to append, given the resolved serial. Empty
/// when there is no serial (non-EMS-enforcing gateway).
pub fn auth_payloads(serial: &EmsSerial) -> Vec<Payload> {
    let Some(sn) = serial.as_str() else {
        return Vec::new();
    };
    let mut emssn = EMSSN_PREFIX.to_vec();
    emssn.extend_from_slice(sn.as_bytes());
    vec![
        Payload::Notify(Notify { protocol: 0, spi: vec![], ntype: N_FORTICLIENT_CONNECT, data: FORTICLIENT_CONNECT_TAG.to_vec() }),
        Payload::Notify(Notify { protocol: 0, spi: vec![], ntype: N_EMSSN, data: emssn }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_serial_means_no_payloads() {
        assert!(auth_payloads(&EmsSerial::None).is_empty());
    }

    #[test]
    fn explicit_serial_builds_two_notifies_with_emssn_prefix() {
        let ps = auth_payloads(&EmsSerial::Explicit("EMS1234567890".into()));
        assert_eq!(ps.len(), 2);
        match &ps[1] {
            Payload::Notify(n) => {
                assert_eq!(n.ntype, N_EMSSN);
                assert!(n.data.starts_with(EMSSN_PREFIX));
                assert!(n.data.ends_with(b"EMS1234567890"));
            }
            _ => panic!("expected EMSSN notify"),
        }
    }

    #[test]
    fn resolve_prefers_explicit_over_env() {
        assert_eq!(EmsSerial::resolve(Some("ABC")).as_str(), Some("ABC"));
    }
}
