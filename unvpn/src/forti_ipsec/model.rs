//! IKEv2 numeric registries (RFC 7296 + IANA) used by the Fortinet IPsec back-end,
//! plus FortiClient's private notify types.
//!
//! EMS-managed FortiGate dialup uses IKEv2 with EAP user authentication
//! (`EAP-MSCHAPV2` for user/password, `EAP-GTC` for the token/OTP) and the gateway
//! authenticating by certificate or PSK.

#![allow(dead_code)]

/// Declare a wire enum: known values plus an `Other(repr)` fallback so unknown
/// values survive a decode/encode cycle unchanged. (Same shape as `ike::model`.)
macro_rules! reg {
    ($(#[$m:meta])* $name:ident : $repr:ty { $($variant:ident = $value:expr),* $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $($variant,)*
            Other($repr),
        }
        impl From<$repr> for $name {
            fn from(v: $repr) -> Self {
                match v { $($value => Self::$variant,)* o => Self::Other(o) }
            }
        }
        impl From<$name> for $repr {
            fn from(v: $name) -> Self {
                match v { $($name::$variant => $value,)* $name::Other(o) => o }
            }
        }
    };
}

/// IKEv2 header: SPIs(16) + next(1) + version(1) + exchange(1) + flags(1) +
/// message_id(4) + length(4).
pub const IKE_HEADER_LEN: usize = 28;
pub const IKEV2_VERSION: u8 = 0x20;

// Header flags (RFC 7296 §3.1).
pub const FLAG_INITIATOR: u8 = 0b0000_1000;
pub const FLAG_VERSION: u8 = 0b0001_0000;
pub const FLAG_RESPONSE: u8 = 0b0010_0000;

reg! {
    /// Payload types (RFC 7296 §3.2, IANA registry).
    PayloadType: u8 {
        None = 0,
        SecurityAssociation = 33, // SA
        KeyExchange = 34,         // KE
        IdInitiator = 35,         // IDi
        IdResponder = 36,         // IDr
        Certificate = 37,         // CERT
        CertRequest = 38,         // CERTREQ
        Authentication = 39,      // AUTH
        Nonce = 40,               // Ni, Nr
        Notify = 41,              // N
        Delete = 42,              // D
        VendorId = 43,            // V
        TrafficSelectorI = 44,    // TSi
        TrafficSelectorR = 45,    // TSr
        Encrypted = 46,           // SK
        Configuration = 47,       // CP
        Eap = 48,                 // EAP
    }
}

reg! {
    /// Exchange types (RFC 7296 §3.1).
    ExchangeType: u8 {
        IkeSaInit = 34,
        IkeAuth = 35,
        CreateChildSa = 36,
        Informational = 37,
    }
}

reg! {
    /// Transform types inside a Proposal (RFC 7296 §3.3.2).
    TransformType: u8 {
        Encryption = 1,  // ENCR
        Prf = 2,         // PRF
        Integrity = 3,   // INTEG
        DiffieHellman = 4, // D-H
        Esn = 5,         // Extended Sequence Numbers
    }
}

// ENCR transform IDs.
pub const ENCR_3DES: u16 = 3;
pub const ENCR_AES_CBC: u16 = 12;
pub const ENCR_AES_GCM_16: u16 = 20;

// PRF transform IDs.
pub const PRF_HMAC_SHA1: u16 = 2;
pub const PRF_HMAC_SHA256: u16 = 5;
pub const PRF_HMAC_SHA384: u16 = 6;
pub const PRF_HMAC_SHA512: u16 = 7;

// INTEG transform IDs (and their truncated ICV lengths).
pub const INTEG_HMAC_SHA1_96: u16 = 2;
pub const INTEG_HMAC_SHA256_128: u16 = 12;
pub const INTEG_HMAC_SHA384_192: u16 = 13;
pub const INTEG_HMAC_SHA512_256: u16 = 14;

// D-H group IDs (MODP groups shared with the IKEv1 crypto; ECP pending).
pub const DH_MODP1024: u16 = 2;
pub const DH_MODP1536: u16 = 5;
pub const DH_MODP2048: u16 = 14;
pub const DH_ECP256: u16 = 19;
pub const DH_ECP384: u16 = 20;

// ESN values.
pub const ESN_NONE: u16 = 0;
pub const ESN_ENABLED: u16 = 1;

/// Transform attribute type: Key Length (TV-form, the only one IKEv2 defines).
pub const ATTR_KEY_LENGTH: u16 = 14;

// Protocol IDs (proposal / Notify / Delete).
pub const PROTO_IKE: u8 = 1;
pub const PROTO_AH: u8 = 2;
pub const PROTO_ESP: u8 = 3;

// Authentication methods (AUTH payload, RFC 7296 §3.8).
pub const AUTH_RSA_SIG: u8 = 1;
pub const AUTH_PSK: u8 = 2;
pub const AUTH_DSS_SIG: u8 = 3;
pub const AUTH_DIGITAL_SIGNATURE: u8 = 14; // RFC 7427

reg! {
    /// ID types (IDi/IDr, RFC 7296 §3.5).
    IdType: u8 {
        Ipv4Addr = 1,
        Fqdn = 2,
        Rfc822Addr = 3, // user@domain — FortiClient uses this (or KeyId) for the user
        Ipv6Addr = 5,
        DerAsn1Dn = 9,
        KeyId = 11,
    }
}

reg! {
    /// Notify message types we act on (RFC 7296 §3.10.1 + IANA). Errors are < 16384,
    /// status ≥ 16384. FortiClient's private notifies live in the private-use range.
    NotifyType: u16 {
        UnsupportedCriticalPayload = 1,
        InvalidIkeSpi = 4,
        InvalidMajorVersion = 5,
        InvalidSyntax = 7,
        InvalidMessageId = 9,
        InvalidSpi = 11,
        NoProposalChosen = 14,
        InvalidKePayload = 17,
        AuthenticationFailed = 24,
        SinglePairRequired = 34,
        NoAdditionalSas = 35,
        InternalAddressFailure = 36,
        FailedCpRequired = 37,
        TsUnacceptable = 38,
        InvalidSelectors = 39,
        TemporaryFailure = 43,
        ChildSaNotFound = 44,
        InitialContact = 16384,
        SetWindowSize = 16385,
        AdditionalTsPossible = 16386,
        IpcompSupported = 16387,
        NatDetectionSourceIp = 16388,
        NatDetectionDestinationIp = 16389,
        Cookie = 16390,
        UseTransportMode = 16391,
        HttpCertLookupSupported = 16392,
        RekeySa = 16393,
        EspTfcPaddingNotSupported = 16394,
        NonFirstFragmentsAlso = 16395,
        MobikeSupported = 16396,
        EapOnlyAuthentication = 16417,
        RedirectSupported = 16406,
        IkeFragmentationSupported = 16430,
    }
}

reg! {
    /// Configuration payload (CP) types (RFC 7296 §3.15.1).
    CfgType: u8 {
        Request = 1,
        Reply = 2,
        Set = 3,
        Ack = 4,
    }
}

reg! {
    /// Configuration attribute types (RFC 7296 §3.15.1 + IANA). FortiGate pushes
    /// the client's internal IP, DNS and split subnets here in the CFG_REPLY.
    CfgAttr: u16 {
        InternalIp4Address = 1,
        InternalIp4Netmask = 2,
        InternalIp4Dns = 3,
        InternalIp4Nbns = 4,
        InternalIp4Dhcp = 6,
        ApplicationVersion = 7,
        InternalIp6Address = 8,
        InternalIp6Dns = 10,
        InternalIp4Subnet = 13,  // split-include network (addr + mask)
        InternalIp6Subnet = 15,
        InternalDnsDomain = 25,  // split-DNS / default domain
        // FortiGate private (0x4000-range) — split DNS / banner, decoded best-effort.
        FortiSplitDns = 0x4003,
    }
}

// Traffic Selector types (RFC 7296 §3.13.1).
pub const TS_IPV4_ADDR_RANGE: u8 = 7;
pub const TS_IPV6_ADDR_RANGE: u8 = 8;

// FortiClient private Notify message types.
pub const N_FORTINET_VPN_NETWORK_ID: u16 = 0xF050;
/// Carries the FortiClient endpoint info blob (incl. the EMS serial the gateway
/// validates). Payload = `\n`-separated `KEY=value` text (see emssn.rs).
pub const N_FORTINET_FORTICLIENT_CONNECT: u16 = 0xF100;
pub const N_FORTINET_DEV_ID_NOTIFY: u16 = 0xF103;
pub const N_FORTINET_CLIENT_RESUME: u16 = 0xF118;

/// Default FortiClient version reported in the `FCTVER=` field.
pub const FORTICLIENT_TVER: &str = "7.2.15.1309";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_type_roundtrip() {
        for v in [0u8, 33, 46, 48, 200] {
            assert_eq!(u8::from(PayloadType::from(v)), v);
        }
        assert_eq!(PayloadType::from(46), PayloadType::Encrypted);
        assert_eq!(PayloadType::from(200), PayloadType::Other(200));
    }

    #[test]
    fn exchange_and_notify_roundtrip() {
        assert_eq!(ExchangeType::from(34), ExchangeType::IkeSaInit);
        assert_eq!(u8::from(ExchangeType::IkeAuth), 35);
        assert_eq!(NotifyType::from(16388), NotifyType::NatDetectionSourceIp);
        assert_eq!(u16::from(NotifyType::AuthenticationFailed), 24);
        assert_eq!(NotifyType::from(40999), NotifyType::Other(40999));
    }

    #[test]
    fn cfg_attr_roundtrip() {
        assert_eq!(CfgAttr::from(1), CfgAttr::InternalIp4Address);
        assert_eq!(CfgAttr::from(13), CfgAttr::InternalIp4Subnet);
        assert_eq!(u16::from(CfgAttr::InternalIp4Dns), 3);
    }
}
