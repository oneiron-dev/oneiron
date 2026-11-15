//! Moved from `crates/oneiron/src/booking/conversion/policy.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookingPolicyPrecedence {
    NestedNarrowing,
    HolderOverrideCappedAtVault,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BookingPolicyScope {
    Vault,
    Nested,
    Holder,
}
