//! Moved from `crates/oneiron/src/memory/diary_read.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::authorship::*;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::memory::diary_read::DiaryEntry;
pub use oneiron_verb_wire::memory::diary_read::DiaryReadHold;
pub use oneiron_verb_wire::memory::diary_read::DiaryReadOutcome;
pub use oneiron_verb_wire::memory::diary_read::DiaryReadRecord;
pub use oneiron_verb_wire::memory::diary_read::DiaryReadRequest;
pub use oneiron_verb_wire::memory::diary_read::DiaryReadsRequest;
pub use oneiron_verb_wire::memory::diary_read::DiaryReviewAnswer;
pub use oneiron_verb_wire::memory::diary_read::DiaryReviewState;
pub use oneiron_verb_wire::memory::diary_read::SealedPadReader;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::btree_map::Entry;

/// What a finished gate did for one agent's diary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiaryAgentRead {
    pub agent: EntityId,
    /// The read logged for the entries admitted, if any were.
    pub read: Option<EntityId>,
    pub entries: u64,
    /// The entries held, by why.
    pub held: Vec<(DiaryReadHold, u64)>,
    /// The review request standing for this reader's reason, if one does.
    pub request: Option<EntityId>,
    /// Whether a Grant covers the agent's whole diary.
    pub whole_diary: bool,
}

/// What a finished gate logged and held, one row per agent read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiaryReadReceipt {
    pub reason: String,
    pub agents: Vec<DiaryAgentRead>,
}

/// `self.memory.diary.reads`'s answer: who read the agent's diary and why,
/// newest first, and the readers' reasons its review holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiaryReadsView {
    /// Whether the agent reviews each read first.
    pub review: bool,
    pub reads: Vec<DiaryReadRecord>,
    /// The persisted review requests, newest first: pending, approved or
    /// declined, and spent ones too when the input asked with `include_used`.
    pub requests: Vec<DiaryReadRequest>,
}
