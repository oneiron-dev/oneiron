//! ARCH-0069 S1 custody classes and tiers. `oneiron::secret_custody` re-exports them
//! next to the bindings, floors and records that name them.

use serde::{Deserialize, Serialize};

use crate::register::Register;

// ---------------------------------------------------------------------------
// Custody classes & tiers
// ---------------------------------------------------------------------------

/// ARCH-0069 S1 custody classes. Wire strings are canon nouns.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema, Register,
)]
#[serde(rename_all = "kebab-case")]
#[register("custody.class")]
pub enum CustodyClass {
    /// The value may replicate beyond this device (the default reach).
    CustodyPortable,
    /// The value is pinned to this device (device-pin locality posture under
    /// slip authority — not a hardware/device custody tier).
    CustodyDeviceBound,
    /// Door-only: the value never replicates at all.
    CrossVault,
}

impl CustodyClass {
    /// Parses the canon kebab-case wire noun.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        <Self as Register>::named(s)
    }
}

/// SECRET-02 owns tier mechanics; the enum is declared here because
/// `oneiron::secret_custody`'s `SecretBinding`s and `SecretCustodyFloor` name it,
/// and so does the custody-tier refusal in [`crate::error::SecretError`].
///
/// Ordering is exposure of the secret VALUE: `T0Doored < T1Leased <
/// T2LocalRegistered`. `T0` is always the least-exposed bound. Authority is
/// never tier-shaped: the custody principal is the host-minted capability
/// slip (OF-452 D1/D7), not a device tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CustodyTier {
    /// Least exposed: value only reachable at the door.
    T0Doored,
    /// Value reachable under a lease.
    T1Leased,
    /// Value reachable as a locally-registered reference.
    T2LocalRegistered,
}

impl CustodyTier {
    /// The integer wire grade (`T0`=0 … `T2`=2).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::T0Doored => 0,
            Self::T1Leased => 1,
            Self::T2LocalRegistered => 2,
        }
    }

    /// Parses from the integer wire grade.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::T0Doored),
            1 => Some(Self::T1Leased),
            2 => Some(Self::T2LocalRegistered),
            _ => None,
        }
    }
}
