//! Native IKEv1 / IPSec data plane for Check Point (M3).
//!
//! Phase-1 Main Mode with either hybrid auth (0xfadd: the gateway signs, the user
//! answers a SecurID challenge) or RSA signatures with a user certificate. Any
//! user challenge (SecurID, an e-mailed code) runs inside IKE as ISAKMP-CFG
//! Transaction attributes.
#![allow(dead_code)]

pub mod crypto;
pub mod esp;
pub mod model;
pub mod service;
pub mod session;
pub mod transport;
pub mod wire;
