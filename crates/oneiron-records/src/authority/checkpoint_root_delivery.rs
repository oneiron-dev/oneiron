//! Moved from `crates/oneiron/src/authority/checkpoint_root_delivery.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
use serde::Deserialize;
use serde::Serialize;

/// Where a root's attestation of a home's head stands, as this install knows
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootAttestationDeliveryState {
    /// Signed here; the home's intake has not taken it.
    SignedNotUploaded,
    /// The home's intake took it; the home has not reported the root
    /// accepted for that head yet.
    Delivered,
    /// The home's head no longer awaits the root.
    Accepted,
}
