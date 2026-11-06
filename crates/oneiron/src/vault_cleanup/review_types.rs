//! Core half of `vault_cleanup::review_types`: its store-layer items live in `oneiron_store::vault_cleanup::review_types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::vault_cleanup::review_types::*;

use super::CleanupKind;
use crate::entity_id::EntityId;
use crate::note::NoteReadView;
use crate::ports::ScopedReadResult;
use crate::vault::entity_view::EntityView;
use serde::{Deserialize, Serialize};

/// One open proposal, every slot disclosed in proposal order.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CleanupReviewView {
    /// The proposal's id.
    pub proposal: EntityId,
    /// The 32-hex attempt id of the run that opened it.
    pub attempt: String,
    /// When the run opened it, in recorded seconds.
    pub created_at: u64,
    /// When this review was read, in recorded seconds; ages are measured
    /// against it.
    pub read_at: u64,
    /// 64-hex BLAKE3 over the proposal's slots and each slot's stored bytes
    /// as this review read them. Send it back as `expected_revision` to
    /// decide only on what was reviewed.
    pub revision: String,
    /// The task retention period in days the TASK and attempt arms measure
    /// against now; `0` turns those arms off.
    pub task_retention_days: u64,
    /// How many slots the proposal holds, by kind.
    pub counts: CleanupReviewCounts,
    /// Every slot, in proposal order, an erased one too.
    pub items: Vec<CleanupReviewItem>,
}

/// One slot of the proposal, as it stands now.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CleanupReviewItem {
    /// The slot's place in the proposal; a decision names it.
    pub slot: usize,
    /// How the slot stands now.
    pub state: CleanupItemState,
    /// The record, or the completed attempt's id; none for an erased slot.
    pub entity: Option<EntityId>,
    /// The arm that proposed it; none for an erased slot.
    pub kind: Option<CleanupKind>,
    /// 64-hex BLAKE3 of its stored bytes now: the encoded record, with a
    /// NOTE's base-vault document version after it, or the attempt's queue
    /// row. A room document keeps its own version in its content read.
    /// None when erased or gone, or when a record does not read.
    pub revision: Option<String>,
    /// Why its arm proposes it, read now; none when erased, gone or
    /// unreadable.
    pub evidence: Option<CleanupReviewEvidence>,
    /// Its full current content; none when erased or gone.
    pub content: Option<CleanupReviewContent>,
    /// What accepting this slot does.
    pub accept: CleanupAcceptEffect,
    /// `Some(true)` when its stored bytes kept changing across every read
    /// the review took (FIX 10502). Content and facts still share the
    /// returned snapshot; it may be older than now, never a newer content
    /// read beside older facts. `None` otherwise.
    pub changed_during_review: Option<bool>,
}

/// A slot's full current content, through the reads the owner already has.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CleanupReviewContent {
    /// A record as `vault.get` reads it for the owner, with that read's
    /// narrowing receipt; its value is none when that read withholds it.
    pub record: Option<ScopedReadResult<Option<EntityView>>>,
    /// A NOTE's document as `vault.notes.read` reads it for the owner.
    pub note: Option<ScopedReadResult<Option<NoteReadView>>>,
    /// A completed attempt: every field of its stored queue row, read under
    /// the owner's proof.
    pub attempt: Option<serde_json::Value>,
    /// Each read that refused, as `code: message`; the slot stays.
    pub refused: Vec<String>,
}
