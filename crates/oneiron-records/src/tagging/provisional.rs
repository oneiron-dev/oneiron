//! Moved from `crates/oneiron/src/tagging/provisional.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

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
    /// For a role phrase (`my manager`), its possessor: the one author of
    /// the message it was said in, whose relation it names. `None` for any
    /// other mention, and for a role phrase of no single author. A role
    /// phrase's lookup finds only its own possessor's (FIX
    /// LINKER-ROLE-PROVISIONAL-PER-SPEAKER); a row minted before reads `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub possessor: Option<EntityId>,
}
