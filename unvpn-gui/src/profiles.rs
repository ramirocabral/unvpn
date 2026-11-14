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
            Backend::Ivanti => 5,
            Backend::OpenVpn => 6,
            Backend::WireGuard => 7,
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
            5 => Backend::Ivanti,
            6 => Backend::OpenVpn,
            7 => Backend::WireGuard,
            _ => Backend::CheckPoint,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropdown_slots_round_trip() {
        for b in [
            Backend::CheckPoint,
            Backend::Forti,
            Backend::F5,
            Backend::AnyConnect,
            Backend::GlobalProtect,
            Backend::Ivanti,
            Backend::OpenVpn,
            Backend::WireGuard,
        ] {
            assert_eq!(Backend::from_index(b.index()), b);
        }
        assert_eq!(Backend::FortiIpsec.index(), Backend::Forti.index());
    }
}
