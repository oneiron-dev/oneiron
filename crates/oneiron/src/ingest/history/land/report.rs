//! One conversation's import report: what landed, what was skipped, refused
//! or left pending, and who reads a conversation the source shared.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::entity_id::EntityId;
use crate::ingest::history::{
    HistoryConversation, HistorySharingCounts, HistorySkips, HistoryThreadKind,
};

/// One conversation's import, in counts. It names the conversation by the
/// source's id and carries no text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HistoryImportReport {
    pub conversation: String,
    pub kind: HistoryThreadKind,
    /// Messages the reader kept.
    pub messages: u32,
    /// Not imported before: landed, or in a dry run would land.
    pub new: u32,
    /// Imported before and unchanged: nothing written.
    pub skipped: u32,
    /// Imported before with other text: landed as a revision.
    pub changed: u32,
    /// Refused at the write door; nothing written, and the next import tries
    /// again.
    pub refused: u32,
    /// Not landed because other imports kept landing the same messages until
    /// [`LEDGER_RACE_WINDOW`](super::LEDGER_RACE_WINDOW) passed; nothing written, and the next import
    /// lands them.
    pub pending: u32,
    /// Why, as reason codes.
    pub refusal_reasons: BTreeSet<String>,
    /// What the reader did not keep.
    pub not_kept: HistorySkips,
    /// Who reads a conversation the source shared, in counts; absent for
    /// one the source did not share, and in a dry run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sharing: Option<HistorySharingCounts>,
    /// The TURNs that took the messages landed new or as a revision, each
    /// once, in landing order: what a hosted import's progress counts for
    /// embeddings. Not part of the report's wire form.
    #[serde(skip)]
    pub turns: Vec<EntityId>,
}

impl HistoryImportReport {
    pub(in crate::ingest::history) fn new(conversation: &HistoryConversation) -> Self {
        Self {
            conversation: conversation.native_id.clone(),
            kind: conversation.kind,
            messages: 0,
            new: 0,
            skipped: 0,
            changed: 0,
            refused: 0,
            pending: 0,
            refusal_reasons: BTreeSet::new(),
            not_kept: conversation.skipped,
            sharing: None,
            turns: Vec::new(),
        }
    }
}
