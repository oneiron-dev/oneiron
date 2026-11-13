//! Moved from `crates/oneiron/src/authority/clock_repair.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Cursor;
use std::time::Instant;

/// What one repair found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityClockRepairOutcome {
    /// The floor reads whole, or no floor exists yet: nothing was written.
    Sound,
    /// The damaged floor was replaced by the proven one.
    Repaired,
    /// The floor is damaged and this vault cannot prove its committed
    /// high-water: nothing was written.
    Unproven,
}

/// `vault.authority.clock.repair`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityClockRepair {
    pub outcome: AuthorityClockRepairOutcome,
    /// The floor that stands after the repair, in unix seconds; None while it
    /// is absent or still damaged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<u64>,
    /// The first-seen stamps the proof read.
    pub observations: u64,
    /// This handle's anchored reading the proof read, when it holds one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchored: Option<u64>,
}
