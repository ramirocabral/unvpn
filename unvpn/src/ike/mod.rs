//! Native IKEv1 / IPSec data plane for Check Point (M3).
//!
//! Reverse-engineered from the Endpoint Security VPN E84.30 Main Mode capture
//! and mapped against the `isakmp` crate + its `cp-ikev1` example. Phase-1
//! proposal: AES-CBC/256, SHA2-256, DH group 2, auth 0xfadd (Hybrid), 28800s.
//! The SecurID challenge runs *inside* IKE (hybrid auth via ISAKMP-CFG
//! Transaction attributes).
#![allow(dead_code)]

pub mod crypto;
pub mod esp;
pub mod model;
pub mod service;
pub mod session;
pub mod transport;
pub mod wire;
