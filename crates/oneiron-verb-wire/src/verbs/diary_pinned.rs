//! Moved from `crates/oneiron/src/verbs/diary_pinned.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::verbs::diary::DiaryQueryOutcome;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::revision_ref::RevisionRef;
use serde::Deserialize;
use serde::Serialize;

/// One pinned diary entry: its NOTE id and the LIVE revision of that NOTE in the serving
/// transaction. `None` is a NOTE with no retained revision there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DiaryPinnedEntry {
    pub id: EntityId,
    pub revision: Option<RevisionRef>,
}

/// `self.memory.diary.pinned`'s answer: the door's [`DiaryQueryOutcome`] on the wire, in the same
/// shape `self.memory.diary.query` answers, with the live NOTE revision of each entry it read.
/// `pins` holds exactly the granted entries, in their order; it is empty unless `outcome` is
/// granted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DiaryPinnedOutcome {
    pub outcome: DiaryQueryOutcome,
    pub pins: Vec<DiaryPinnedEntry>,
}
