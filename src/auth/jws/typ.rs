//! The `typ` values a signed document may carry, and the key kinds allowed to
//! sign each.

use std::fmt;

/// A kind of signing key, as told apart by its kid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyKind {
    /// The vendor key, `vendor-release-<number>` or `vendor-test-<number>`,
    /// which signs deployment certificates.
    Vendor,
    /// An installation's signing key, `install-<install id>:<version>`.
    InstallSigning,
    /// A customer key, `endpoint-<uuid>:<version>`.
    Customer,
    /// An installation's recovery key, `recovery-<install id>:<version>`.
    Recovery,
}

impl KeyKind {
    /// Every key kind.
    pub const ALL: [Self; 4] = [
        Self::Vendor,
        Self::InstallSigning,
        Self::Customer,
        Self::Recovery,
    ];

    /// Returns a short English name for the key kind, for messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vendor => "vendor key",
            Self::InstallSigning => "install signing key",
            Self::Customer => "customer key",
            Self::Recovery => "recovery key",
        }
    }
}

impl fmt::Display for KeyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A JWS `typ`: what a signed document is, which fixes the key kinds allowed
/// to sign it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Typ {
    /// `senta-deployment-cert`, signed by the vendor key.
    DeploymentCert,
    /// `senta-install-config`, signed by an install signing key.
    InstallConfig,
    /// `senta-keyset`, signed by a customer key or a recovery key.
    Keyset,
    /// `senta-recovery-key`, signed by a recovery key.
    RecoveryKey,
    /// `senta-enroll`, signed by a customer key.
    Enroll,
    /// `senta-enroll-result`, signed by a customer key.
    EnrollResult,
    /// `senta-policy`, signed by a customer key.
    Policy,
    /// `senta-assign`, signed by a customer key.
    Assign,
    /// `senta-addresses`, signed by a customer key.
    Addresses,
    /// `senta-update`, signed by a customer key.
    Update,
    /// `senta-command`, signed by a customer key.
    Command,
}

impl Typ {
    /// Every `typ`.
    pub const ALL: [Self; 11] = [
        Self::DeploymentCert,
        Self::InstallConfig,
        Self::Keyset,
        Self::RecoveryKey,
        Self::Enroll,
        Self::EnrollResult,
        Self::Policy,
        Self::Assign,
        Self::Addresses,
        Self::Update,
        Self::Command,
    ];

    /// Returns the `typ` string carried in the JWS header.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeploymentCert => "senta-deployment-cert",
            Self::InstallConfig => "senta-install-config",
            Self::Keyset => "senta-keyset",
            Self::RecoveryKey => "senta-recovery-key",
            Self::Enroll => "senta-enroll",
            Self::EnrollResult => "senta-enroll-result",
            Self::Policy => "senta-policy",
            Self::Assign => "senta-assign",
            Self::Addresses => "senta-addresses",
            Self::Update => "senta-update",
            Self::Command => "senta-command",
        }
    }

    /// Returns the key kinds allowed to sign a document of this `typ`.
    #[must_use]
    pub const fn allowed_key_kinds(self) -> &'static [KeyKind] {
        match self {
            Self::DeploymentCert => &[KeyKind::Vendor],
            Self::InstallConfig => &[KeyKind::InstallSigning],
            Self::Keyset => &[KeyKind::Customer, KeyKind::Recovery],
            Self::RecoveryKey => &[KeyKind::Recovery],
            Self::Enroll
            | Self::EnrollResult
            | Self::Policy
            | Self::Assign
            | Self::Addresses
            | Self::Update
            | Self::Command => &[KeyKind::Customer],
        }
    }

    /// Returns whether a key of `kind` may sign a document of this `typ`.
    #[must_use]
    pub fn allows(self, kind: KeyKind) -> bool {
        self.allowed_key_kinds().contains(&kind)
    }
}

impl fmt::Display for Typ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_match_the_table() {
        let strings: Vec<&str> = Typ::ALL.iter().map(|typ| typ.as_str()).collect();
        assert_eq!(
            strings,
            [
                "senta-deployment-cert",
                "senta-install-config",
                "senta-keyset",
                "senta-recovery-key",
                "senta-enroll",
                "senta-enroll-result",
                "senta-policy",
                "senta-assign",
                "senta-addresses",
                "senta-update",
                "senta-command",
            ]
        );
    }

    #[test]
    fn allowed_kinds_match_the_table() {
        use KeyKind::{Customer, InstallSigning, Recovery, Vendor};
        let expected: [(Typ, &[KeyKind]); 11] = [
            (Typ::DeploymentCert, &[Vendor]),
            (Typ::InstallConfig, &[InstallSigning]),
            (Typ::Keyset, &[Customer, Recovery]),
            (Typ::RecoveryKey, &[Recovery]),
            (Typ::Enroll, &[Customer]),
            (Typ::EnrollResult, &[Customer]),
            (Typ::Policy, &[Customer]),
            (Typ::Assign, &[Customer]),
            (Typ::Addresses, &[Customer]),
            (Typ::Update, &[Customer]),
            (Typ::Command, &[Customer]),
        ];
        for (typ, allowed) in expected {
            for kind in KeyKind::ALL {
                assert_eq!(
                    typ.allows(kind),
                    allowed.contains(&kind),
                    "{typ} and {kind}"
                );
            }
        }
    }
}
