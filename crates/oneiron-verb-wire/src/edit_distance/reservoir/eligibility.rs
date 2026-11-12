//! Moved from `crates/oneiron/src/edit_distance/reservoir/eligibility.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// FIX 11352: who a source a training run's corpus would hold to the
/// owner's tick holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReservoirSourcePeople {
    /// Someone other than the acting owner and the vault's own agents.
    Others,
    /// People that cannot be read.
    Unknown,
}

/// FIX 11352: one source a training run's corpus would hold to the owner's
/// "I obtained consent" tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReservoirSourceRow {
    /// The key a tick names: a TURN's conversation, else the source row.
    pub source: EntityId,
    pub people: ReservoirSourcePeople,
    /// The scope's pairs that rest on it.
    pub pairs: u64,
    /// Whether the ticks the preview was given name it.
    pub consented: bool,
}

/// FIX 11352: what a training run's corpus over one reservoir scope would
/// hold, read before the owner prepares it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReservoirSourcePreview {
    /// The pairs the corpus would carry under the ticks given.
    pub carried: u64,
    /// The pairs the source check would leave out under them, by reason
    /// code.
    pub excluded: BTreeMap<String, u64>,
    /// Each source with other people or people that cannot be read, in key
    /// order: what the owner ticks.
    pub sources: Vec<ReservoirSourceRow>,
}
