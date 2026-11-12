//! Which connection-form fields each back-end shows and requires.

use crate::profiles::Backend;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Hidden,
    Optional,
    Required,
}

impl Field {
    pub fn shown(self) -> bool {
        self != Field::Hidden
    }

    /// Whether `text` satisfies the field.
    pub fn filled(self, text: &str) -> bool {
        self != Field::Required || !text.is_empty()
    }
}

/// The form choices that change the layout within one back-end.
#[derive(Clone, Copy, Debug, Default)]
pub struct Choices {
    /// SSO picked as the login method.
    pub sso: bool,
    /// Check Point certificate login picked.
    pub cp_cert: bool,
    /// The OpenVPN profile asks for a username and password.
    pub ovpn_userpass: bool,
    /// The OpenVPN profile's key may be encrypted.
    pub ovpn_keypass: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub gateway_title: &'static str,
    /// The gateway field is a file path with a browse button.
    pub gateway_file: bool,
    /// The file must exist before connecting.
    pub gateway_must_exist: bool,
    /// The FortiClient SSL-VPN / IPsec selector.
    pub forti_protocol: bool,
    pub sso_choice: bool,
    pub sso_user_agent: bool,
    pub cp_auth_choice: bool,
    pub user: Field,
    pub password: Field,
    pub password_title: &'static str,
    pub remember_password: bool,
    pub token: Field,
    /// The certificate file, with its enrollment row.
    pub cert: Field,
    /// Realm, group, gateway or Local ID, by back-end.
    pub realm: Field,
    pub realm_title: &'static str,
    pub psk: Field,
    /// FortiClient IPsec's EMS serial and FortiClient version.
    pub advanced: bool,
    pub key_pass: bool,
    pub killswitch: bool,
    pub no_dtls: bool,
}

impl Layout {
    pub fn of(b: Backend, c: Choices) -> Layout {
        use Field::*;
        let sso = b.has_sso() && c.sso;
        let cp_cert = b == Backend::CheckPoint && c.cp_cert;
        let creds = match b {
            Backend::OpenVpn if c.ovpn_userpass => Required,
            Backend::OpenVpn | Backend::WireGuard => Hidden,
            _ if sso => Hidden,
            _ => Required,
        };
        let (realm, realm_title) = match b {
            Backend::CheckPoint if cp_cert => (Optional, "Login option (optional)"),
            Backend::AnyConnect => (Optional, "Group (optional)"),
            Backend::GlobalProtect => (Optional, "Gateway (optional)"),
            Backend::FortiIpsec => (Optional, "Local ID (optional)"),
            Backend::Forti => (Optional, "Realm (optional)"),
            _ => (Hidden, "Realm (optional)"),
        };
        let (password, password_title) = match b {
            Backend::CheckPoint if cp_cert => (Required, "Certificate password"),
            // PIN+tokencode or just the tokencode: the PIN may be empty.
            Backend::CheckPoint => (Optional, "PIN"),
            _ => (creds, "Password"),
        };
        Layout {
            gateway_title: match b {
                Backend::OpenVpn => "Profile (.ovpn file)",
                Backend::WireGuard => "Config (.conf file)",
                Backend::GlobalProtect => "Portal",
                _ => "Gateway",
            },
            gateway_file: b.uses_profile_file(),
            // A /etc/wireguard config isn't even stat-able as the user; the engine
            // reads it as root and reports a bad path itself.
            gateway_must_exist: b == Backend::OpenVpn,
            forti_protocol: matches!(b, Backend::Forti | Backend::FortiIpsec),
            sso_choice: b.has_sso(),
            sso_user_agent: sso,
            cp_auth_choice: b == Backend::CheckPoint,
            user: if cp_cert { Hidden } else { creds },
            password,
            password_title,
            remember_password: password.shown(),
            token: if b == Backend::CheckPoint && !cp_cert {
                Required
            } else {
                Hidden
            },
            cert: if cp_cert { Required } else { Hidden },
            realm,
            realm_title,
            psk: if b == Backend::FortiIpsec {
                Required
            } else {
                Hidden
            },
            advanced: b == Backend::FortiIpsec,
            key_pass: b == Backend::OpenVpn && c.ovpn_keypass,
            // WireGuard is dual-stack and kernel-routed: the kill switch doesn't apply.
            killswitch: b != Backend::WireGuard,
            no_dtls: b.uses_dtls(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Field::*;
    use super::*;

    fn required(l: &Layout) -> Vec<&'static str> {
        [
            ("user", l.user),
            ("password", l.password),
            ("token", l.token),
            ("cert", l.cert),
            ("psk", l.psk),
        ]
        .into_iter()
        .filter(|(_, f)| *f == Required)
        .map(|(n, _)| n)
        .collect()
    }

    #[test]
    fn required_fields_per_backend() {
        let none = Choices::default();
        let sso = Choices { sso: true, ..none };
        let cert = Choices {
            cp_cert: true,
            ..none
        };
        let cases: &[(Backend, Choices, &[&str])] = &[
            (Backend::Forti, none, &["user", "password"]),
            (Backend::Forti, sso, &[]),
            (Backend::AnyConnect, sso, &[]),
            (Backend::GlobalProtect, none, &["user", "password"]),
            (Backend::F5, sso, &["user", "password"]),
            (Backend::FortiIpsec, none, &["user", "password", "psk"]),
            (Backend::CheckPoint, none, &["user", "token"]),
            (Backend::CheckPoint, cert, &["password", "cert"]),
            (Backend::OpenVpn, none, &[]),
            (
                Backend::OpenVpn,
                Choices {
                    ovpn_userpass: true,
                    ..none
                },
                &["user", "password"],
            ),
            (Backend::WireGuard, none, &[]),
        ];
        for (b, c, want) in cases {
            assert_eq!(required(&Layout::of(*b, *c)), *want, "{b:?} {c:?}");
        }
    }

    #[test]
    fn labels_and_toggles() {
        let none = Choices::default();
        let cp = Layout::of(Backend::CheckPoint, none);
        assert_eq!((cp.password, cp.password_title), (Optional, "PIN"));
        assert!(cp.remember_password && !cp.realm.shown());
        let cert = Layout::of(
            Backend::CheckPoint,
            Choices {
                cp_cert: true,
                ..none
            },
        );
        assert_eq!(cert.realm_title, "Login option (optional)");
        assert_eq!(cert.user, Hidden);
        let wg = Layout::of(Backend::WireGuard, none);
        assert!(wg.gateway_file && !wg.gateway_must_exist && !wg.killswitch);
        assert!(!wg.remember_password);
        let gp = Layout::of(Backend::GlobalProtect, none);
        assert_eq!(
            (gp.gateway_title, gp.realm_title),
            ("Portal", "Gateway (optional)")
        );
        let sso_ua = Layout::of(Backend::AnyConnect, Choices { sso: true, ..none });
        assert!(sso_ua.sso_user_agent && sso_ua.no_dtls && !sso_ua.remember_password);
        // SSO is ignored where the back-end has none.
        assert!(!Layout::of(Backend::F5, Choices { sso: true, ..none }).sso_user_agent);
        let ovpn = Layout::of(
            Backend::OpenVpn,
            Choices {
                ovpn_keypass: true,
                ..none
            },
        );
        assert!(ovpn.key_pass && ovpn.gateway_must_exist && !ovpn.forti_protocol);
    }
}
