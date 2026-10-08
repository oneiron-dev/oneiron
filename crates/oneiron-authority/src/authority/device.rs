//! Device authority material and the folded-device consent predicates.

use crate::error::Result;
use std::collections::BTreeMap;

use super::*;

/// Folded roster entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedDevice {
    /// Authority key.
    pub key: AuthorityKey,
    /// Assurance tier.
    pub tier: AuthorityTier,
    /// Role bits after most-restrictive conflict folding.
    pub roles: u16,
    /// Whether any valid revocation tombstone removed this key.
    pub revoked: bool,
}

/// Device authority material carried by genesis/enroll/rotate/recovery ops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthority {
    /// Authority key.
    pub key: AuthorityKey,
    /// Transport key binding; all-zero for genesis when unavailable.
    pub transport_key_binding: [u8; 32],
    /// Attestation envelope.
    pub attestation: AuthorityAttestation,
    /// Assurance tier.
    pub tier: AuthorityTier,
    /// Role bits.
    pub roles: u16,
}

impl DeviceAuthority {
    /// Public so `oneiron`'s authority code calls it across the crate line.
    pub fn validate(&self) -> Result<()> {
        if self.roles == 0 {
            return Err(invalid_authority());
        }
        if (self.roles & !ROLE_DEFINED_MASK) != 0 {
            return Err(invalid_authority());
        }
        self.key.validate()?;
        self.attestation.validate()
    }

    // Structural owner-capable shape only. Posture-specific authorization is
    // decided by FoldContext, never by the replay codec.
    /// Public so `oneiron`'s authority code calls it across the crate line.
    pub fn can_authority_consent(&self) -> bool {
        (self.roles & (ROLE_OWNER | ROLE_ADMIN)) != 0
    }
}

pub fn roster_has_live_owner(
    roster: &BTreeMap<AuthorityKey, FoldedDevice>,
    key: &AuthorityKey,
) -> bool {
    roster
        .get(key)
        .is_some_and(|device| !device.revoked && device.roles & ROLE_OWNER != 0)
}

pub fn folded_device_can_authority_consent(device: &FoldedDevice) -> bool {
    !device.revoked
        && (device.roles & (ROLE_OWNER | ROLE_ADMIN)) != 0
        && (device.roles & ROLE_CLOUD) == 0
        && device.tier != AuthorityTier::CloudCustodial
}

/// The host-key-premise consent predicate: owner/admin and-not-revoked IS the
/// whole test, with `ROLE_CLOUD` and `CloudCustodial` markings IGNORED.
///
/// Sits BESIDE [`folded_device_can_authority_consent`] and never replaces it —
/// the local fold's consent semantics do not change. The inversion is confined
/// to the PEER side because that is where it is forced: under host-root
/// (S-AUTH1B) the peer host's genesis key is the peer's trust root, and a
/// predicate that selects peer consent keys by EXCLUDING host/cloud markings
/// would admit every user device the peer enrolled while excluding exactly the
/// key host-root makes the root.
pub fn folded_peer_device_is_consent_root(device: &FoldedDevice) -> bool {
    !device.revoked && (device.roles & (ROLE_OWNER | ROLE_ADMIN)) != 0
}

/// Managed hosts are owner roots; this arm is never used by self-host folds.
pub fn folded_host_device_can_consent(device: &FoldedDevice) -> bool {
    !device.revoked && (device.roles & (ROLE_OWNER | ROLE_ADMIN)) != 0
}

pub fn tier_meets_floor(tier: AuthorityTier, floor: AuthorityTier) -> bool {
    match floor {
        AuthorityTier::Software => true,
        AuthorityTier::Hardware => tier == AuthorityTier::Hardware,
        AuthorityTier::CloudCustodial => tier == AuthorityTier::CloudCustodial,
    }
}
