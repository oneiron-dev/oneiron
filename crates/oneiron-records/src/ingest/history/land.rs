//! Moved from `crates/oneiron/src/ingest/history/land.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::ingest::history::HistoryConversation;
use crate::ingest::history::HistorySkips;
use crate::ingest::history::HistoryThreadKind;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value as Msgpack;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::time::Duration;
use std::time::Instant;

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
    /// [`LEDGER_RACE_WINDOW`] passed; nothing written, and the next import
    /// lands them.
    pub pending: u32,
    /// Why, as reason codes.
    pub refusal_reasons: BTreeSet<String>,
    /// What the reader did not keep.
    pub not_kept: HistorySkips,
    /// The TURNs that took the messages landed new or as a revision, each
    /// once, in landing order: what a hosted import's progress counts for
    /// embeddings. Not part of the report's wire form.
    #[serde(skip)]
    pub turns: Vec<EntityId>,
}

impl HistoryImportReport {
    pub fn new(conversation: &HistoryConversation) -> Self {
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
            turns: Vec::new(),
        }
    }
}

pub fn derive(domain: &[u8], parts: &[&str]) -> Result<EntityId> {
    let parts: Vec<&[u8]> = parts.iter().map(|part| part.as_bytes()).collect();
    EntityId::derive(domain, &parts)
}
