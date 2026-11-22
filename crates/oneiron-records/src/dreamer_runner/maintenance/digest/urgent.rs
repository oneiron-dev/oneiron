//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/digest/urgent.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// One stored claim a candidate names, at the exact body bytes it was read
/// at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestVersionRef {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub claim_ref: EntityId,
    /// BLAKE3 of the claim's body as stored.
    pub body_hash: [u8; 32],
}

/// The pending result a candidate asks about: a proposal at its digest
/// revision, and the derived group it renders under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestHarmResult {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub claim_ref: EntityId,
    /// The proposal's digest revision: BLAKE3 of its body as stored.
    pub revision: [u8; 32],
    pub group: String,
}

/// A factual time the intent's need falls due, with the record that states
/// it: evidence the question reads, never a gate of its own. The native
/// producer reads it from the same intent when the owner states a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestNeededBefore {
    pub at_unix_secs: u64,
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub source_ref: EntityId,
    pub source_body_hash: [u8; 32],
}
