//! IKEv1 numeric registries (RFC 2407/2408/2409) plus Check Point's proprietary
//! extensions.
//!
//! The Phase-1 proposal Check Point uses: AES-CBC/256, SHA2-256, DH group 2,
//! auth method 0xfadd (Hybrid), 28800s.

/// Declare a wire enum: known values plus an `Other(repr)` fallback so unknown
/// values survive a decode/encode cycle unchanged.
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

pub const ISAKMP_HEADER_LEN: usize = 28;
pub const PAYLOAD_HEADER_LEN: usize = 4;
pub const IKEV1_VERSION: u8 = 0x10;

pub const FLAG_ENCRYPTION: u8 = 0b0000_0001;
pub const FLAG_COMMIT: u8 = 0b0000_0010;
pub const FLAG_AUTHENTICATION: u8 = 0b0000_0100;

pub const VID_CHECKPOINT: &[u8] = &[
    0xde, 0xfb, 0x99, 0xe6, 0x9a, 0x9f, 0x1f, 0x6e, 0x06, 0xf1, 0x50, 0x06, 0xb1, 0xf1, 0x66, 0xae,
];
pub const VID_IPSEC_NAT_T: &[u8] = &[
    0x90, 0xcb, 0x80, 0x91, 0x3e, 0xbb, 0x69, 0x6e, 0x08, 0x63, 0x81, 0xb5, 0xec, 0x42, 0x7b, 0x1f,
];

// Phase-1 IKE SA transform attribute values (RFC 2409 Appendix A).
pub const IKE_ENC_AES_CBC: u16 = 7;
pub const IKE_ENC_3DES: u16 = 5;
pub const IKE_HASH_MD5: u16 = 1;
pub const IKE_HASH_SHA1: u16 = 2;
pub const IKE_HASH_SHA256: u16 = 4;
pub const IKE_HASH_SHA384: u16 = 5;
pub const IKE_HASH_SHA512: u16 = 6;
pub const IKE_GROUP_MODP1024: u16 = 2;
pub const IKE_GROUP_MODP2048: u16 = 14;
pub const IKE_AUTH_HYBRID_INIT_RSA: u16 = 64221; // 0xfadd — Check Point hybrid
pub const IKE_LIFE_SECONDS: u16 = 1;

reg! {
    /// Payload types, RFC 2408 §3.1.
    PayloadType: u8 {
        None = 0,
        SecurityAssociation = 1,
        Proposal = 2,
        Transform = 3,
        KeyExchange = 4,
        Identification = 5,
        Certificate = 6,
        CertificateRequest = 7,
        Hash = 8,
        Signature = 9,
        Nonce = 10,
        Notification = 11,
        Delete = 12,
        VendorId = 13,
        Attributes = 14,
        Natd = 20,
    }
}

reg! {
    /// Exchange types, RFC 2408 §3.1.
    ExchangeType: u8 {
        None = 0,
        Base = 1,
        IdentityProtection = 2,
        AuthenticationOnly = 3,
        Aggressive = 4,
        Informational = 5,
        Transaction = 6,
        Quick = 32,
    }
}

reg! {
    ProtocolId: u8 {
        Isakmp = 1,
        IpsecAh = 2,
        IpsecEsp = 3,
    }
}

reg! {
    TransformId: u8 {
        KeyIke = 1,
        Esp3Des = 3,
        EspAesCbc = 12,
    }
}

reg! {
    /// IKE SA attribute types, RFC 2409 Appendix A.
    IkeAttributeType: u16 {
        EncryptionAlgorithm = 1,
        HashAlgorithm = 2,
        AuthenticationMethod = 3,
        GroupDescription = 4,
        LifeType = 11,
        LifeDuration = 12,
        KeyLength = 14,
    }
}

reg! {
    /// IPsec SA attribute types, RFC 2407 §4.5.
    EspAttributeType: u16 {
        LifeType = 1,
        LifeDuration = 2,
        EncapsulationMode = 4,
        AuthenticationAlgorithm = 5,
        KeyLength = 6,
    }
}

reg! {
    /// ISAKMP-config (Office Mode) attribute types, RFC 2407 + Check Point's
    /// private 0x40xx range. The SecurID challenge/response rides here during
    /// hybrid auth (UserName / Passcode / Challenge / Message).
    ConfigAttributeType: u16 {
        Ipv4Address = 1,
        Ipv4Netmask = 2,
        Ipv4Dns = 3,
        AddressExpiry = 5,
        AuthType = 13,
        UserName = 14,
        UserPassword = 15,
        Passcode = 16,
        Message = 17,
        Challenge = 18,
        Domain = 19,
        Status = 20,
        NextPin = 21,
        Answer = 22,
        InternalDomainName = 0x4003,
        MacAddress = 0x4004,
        CccSessionId = 0x4045,
        CccVariableLeaseTime = 0x4046,
        CccOfficeModeAllowed = 0x4047,
        CccConnectAllowed = 0x404c,
    }
}

// ESP (Phase 2 / Quick Mode) attribute values (RFC 2407).
pub const ESP_AUTH_HMAC_SHA96: u16 = 2;
pub const ESP_AUTH_HMAC_SHA256: u16 = 5;
pub const ESP_AUTH_HMAC_SHA160: u16 = 7;
pub const ESP_AUTH_HMAC_SHA256_V2: u16 = 12;
pub const ESP_ENCAP_UDP_TUNNEL: u16 = 3;
pub const ESP_ENCAP_CHECKPOINT_ESP_IN_UDP: u16 = 0xf003;

reg! {
    /// Transaction (ISAKMP-CFG) message kinds, carried as the first octet of an
    /// Attributes payload.
    AttributesPayloadType: u8 {
        Request = 1,
        Reply = 2,
        Set = 3,
        Ack = 4,
    }
}

reg! {
    IdentityType: u8 {
        Ipv4Address = 1,
        UserFqdn = 3,
        Ipv4Subnet = 4,
        DerAsn1Dn = 9,
    }
}

reg! {
    /// Notify message types, RFC 2408 + Check Point's CCC auth blob at 0x8004.
    NotifyMessageType: u16 {
        InvalidPayloadType = 1,
        NoProposalChosen = 14,
        PayloadMalformed = 16,
        InvalidIdInformation = 18,
        AuthenticationFailed = 24,
        Connected = 31,
        ResponderLifetime = 37,
        CccAuth = 0x8004,
    }
}
