//! Connection profiles (see the `unvpn-profiles` crate), plus how the form's
//! back-end dropdown maps onto them.

pub use unvpn_profiles::*;

pub trait BackendSlot {
    fn index(self) -> u32;
    fn from_index(i: u32) -> Self;
}

impl BackendSlot for Backend {
    /// Position in the backend `ComboRow`; must match its model order. Both
    /// FortiClient variants share one "FortiClient" entry — the SSL-VPN/IPsec
    /// choice is a separate selector in the form — so `FortiIpsec` maps to the
    /// same slot as `Forti`.
    fn index(self) -> u32 {
        match self {
            Backend::CheckPoint => 0,
            Backend::Forti | Backend::FortiIpsec => 1,
            Backend::F5 => 2,
            Backend::AnyConnect => 3,
            Backend::GlobalProtect => 4,
            Backend::OpenVpn => 5,
            Backend::WireGuard => 6,
        }
    }

    /// The dropdown slot's primary backend. Slot 1 ("FortiClient") resolves to
    /// `Forti`; the form's protocol selector promotes it to `FortiIpsec`.
    fn from_index(i: u32) -> Backend {
        match i {
            1 => Backend::Forti,
            2 => Backend::F5,
            3 => Backend::AnyConnect,
            4 => Backend::GlobalProtect,
            5 => Backend::OpenVpn,
            6 => Backend::WireGuard,
            _ => Backend::CheckPoint,
        }
    }
}
