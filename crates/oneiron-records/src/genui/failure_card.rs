//! Moved from `crates/oneiron/src/genui/failure_card.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::failure_ladder::lineage::HealerRepairRoute;
use serde::Deserialize;
use serde::Serialize;

/// Where the healer's diagnosis stands when the card is emitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureDiagnosisState {
    /// A configured healer has the case but has not answered yet.
    NotRun,
    /// The scope's healer slot is explicitly reserved. This is a first-class
    /// state, never a generic failure string and never [`Self::NotRun`].
    ReservedHealerSlot,
    Diagnosed(HealerRepairRoute),
}

/// One referenced Q&A message. The body stays in the MESSAGE record; the card
/// never inlines a replacement transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealerQaEntryRef {
    /// Lowercase-hex MESSAGE EntityId spelling.
    pub message_ref: String,
    /// Lowercase-hex witnessed author EntityId spelling.
    pub actor_ref: String,
    pub occurred_at: u64,
}

/// The reference-backed healer/human Q&A feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealerQaFeed {
    /// Lowercase-hex thread EntityId spelling.
    pub thread_ref: String,
    #[serde(default)]
    pub entries: Vec<HealerQaEntryRef>,
}
