//! Moved from `crates/oneiron/src/tagging/provisional.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
#[cfg(feature = "sync")]
use std::collections::BTreeSet;

/// A cold entity a save minted, waiting for the Dreamer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionalEntity {
    pub kind: u8,
    /// The text of a span that keys to it, in [`Self::origin`].
    pub name: String,
    /// The turn that span is in. When that turn no longer names the entity,
    /// another turn that does takes its place; when none does, the entity
    /// is retired.
    pub origin: EntityId,
    /// The facet of the turn it was minted from: a derivation is born under
    /// its source's facet (ARCH-0022).
    pub facet: Option<EntityId>,
    /// Store-clock seconds of the mint.
    pub minted_at: u64,
}
