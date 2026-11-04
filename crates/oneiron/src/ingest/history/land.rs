//! Landing a decoded conversation as an imported transcript (ARCH-0027).
//!
//! Messages group into one-speaker TURNs, each the longest run of one side (up
//! to [`TURN_MESSAGE_CAP`] messages). Conversation, turn and message ids derive
//! from the source's own, so a re-run, a crash retry or an appended session
//! lands the same rows at the same ids. A new message takes the next order its
//! turn has free, so a later export that regroups a run never collides with
//! what landed before. A turn whose order space is full continues in the next
//! turn of its chain, each derived from the run's turn and its place, so every
//! import of the run walks the same chain. Each turn lands through the witness
//! program's import door, which runs the same ceiling door and write-door
//! secret scan as any witnessed turn, with the ledger rows of its new messages
//! in the same transaction. The ledger is read again inside that transaction:
//! when another import landed one of the turn's messages since the first
//! read, the turn is read and built again, until [`LEDGER_RACE_WINDOW`] has
//! passed, so no import overwrites what another landed. A refused turn is
//! counted and the import goes on; the next import tries it again.

use std::cell::Cell;
use std::collections::{BTreeSet, HashSet};
use std::time::{Duration, Instant};

use rmpv::Value as Msgpack;
use serde::Serialize;
use serde_json::{Map, Value};

use super::ledger::{self, LedgerRow, content_hash};
use super::{
    HistoryConversation, HistoryMessage, HistoryRole, HistorySkips, HistorySource,
    HistoryThreadKind,
};
use crate::TimeRange;
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, derived_domains};
use crate::error::Result;
use crate::gate::MAX_WITNESS_MESSAGE_ORDER;
use crate::memory::{
    IMPORTED_SOURCE_KEY, ImportedTurnStamp, MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE,
    Memory, MemoryError, MemoryResult, WitnessAuthor, WitnessMessage, WitnessTurn,
    next_witness_message_order,
};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CONVERSATION;
use crate::side_table::SideTableDbs;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The most messages one TURN holds; a longer run of one side (an agent's long
/// unattended stretch) continues in the next turn.
const TURN_MESSAGE_CAP: usize = 256;

/// Tool names one message's metadata lists; the rest are counted.
const MAX_TOOL_LABELS: usize = 64;

/// Bytes of an id or a label kept in metadata.
const MAX_LABEL_BYTES: usize = 512;

/// The imported CONVERSATION body key naming the folder the session ran in.
const IMPORT_CWD_KEY: &str = "import_cwd";

/// How long a turn is read and built again while other imports keep landing
/// its messages first. Past that its messages are counted as pending: nothing
/// of them is written, and the next import lands them.
const LEDGER_RACE_WINDOW: Duration = Duration::from_secs(60);

#[cfg(test)]
thread_local! {
    /// Runs once between a turn's ledger read and its write transaction, so a
    /// test can land a concurrent import there.
    pub(super) static BETWEEN_READ_AND_WRITE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

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
}

impl HistoryImportReport {
    pub(super) fn new(conversation: &HistoryConversation) -> Self {
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
        }
    }
}

/// Where one message stands against the ledger.
pub(super) enum Standing {
    New,
    Same,
    Changed(LedgerRow),
}

/// The conversation's messages with each id once, as one-speaker runs.
pub(super) fn runs<'c>(
    conversation: &'c HistoryConversation,
    report: &mut HistoryImportReport,
) -> Vec<Vec<&'c HistoryMessage>> {
    let mut seen = HashSet::new();
    let mut runs: Vec<Vec<&HistoryMessage>> = Vec::new();
    for message in &conversation.messages {
        if !seen.insert(message.native_id.as_str()) {
            report.not_kept.duplicates += 1;
            continue;
        }
        report.messages += 1;
        match runs.last_mut() {
            Some(run) if run[0].role == message.role && run.len() < TURN_MESSAGE_CAP => {
                run.push(message);
            }
            _ => runs.push(vec![message]),
        }
    }
    runs
}

pub(super) fn standing(
    dbs: &impl SideTableDbs,
    txn: &heed::RoTxn<'_>,
    source: HistorySource,
    message: &HistoryMessage,
) -> Result<Standing> {
    Ok(match ledger::find(dbs, txn, source, message)? {
        None => Standing::New,
        // A text erased since it landed is not landed again.
        Some(row) if row.holds(message) || row.held_erased(source, message)? => Standing::Same,
        Some(row) => Standing::Changed(row),
    })
}

fn label(text: &str) -> String {
    if text.len() <= MAX_LABEL_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_LABEL_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

pub(super) fn derive(domain: &[u8], parts: &[&str]) -> Result<EntityId> {
    let parts: Vec<&[u8]> = parts.iter().map(|part| part.as_bytes()).collect();
    EntityId::derive(domain, &parts)
}

/// The MESSAGE an imported message lands as. The dry run builds the same one
/// to scan exactly the bytes the write door would.
pub(super) fn imported_message(
    source: HistorySource,
    conversation: &HistoryConversation,
    message: &HistoryMessage,
    previous: Option<&LedgerRow>,
    id: Option<EntityId>,
    order: u32,
) -> WitnessMessage {
    WitnessMessage {
        id: id.map(|id| id.to_hex()),
        author: match message.role {
            HistoryRole::User => WitnessAuthor::User,
            HistoryRole::Assistant => WitnessAuthor::Companion,
        },
        message_type: format!("import.{}", source.source_id()),
        content: message.text.clone(),
        metadata: Some(provenance(source, conversation, message, previous)),
        is_visible: true,
        order,
        quote: None,
    }
}

/// The imported CONVERSATION's body: its source, the source's id for it and,
/// for a branch or subagent thread, the conversation it belongs to.
pub(super) fn conversation_body(
    source: HistorySource,
    conversation: &HistoryConversation,
) -> MemoryResult<Vec<u8>> {
    let mut fields = vec![
        (
            Msgpack::from(IMPORTED_SOURCE_KEY),
            Msgpack::from(source.source_id()),
        ),
        (
            Msgpack::from("import_conversation"),
            Msgpack::from(label(&conversation.native_id)),
        ),
        (
            Msgpack::from("import_kind"),
            Msgpack::from(conversation.kind.as_str()),
        ),
    ];
    if let Some(parent) = &conversation.parent {
        fields.push((Msgpack::from("import_parent"), Msgpack::from(label(parent))));
    }
    if let Some(title) = &conversation.title {
        fields.push((Msgpack::from("title"), Msgpack::from(label(title))));
    }
    if let Some(cwd) = &conversation.cwd {
        fields.push((Msgpack::from(IMPORT_CWD_KEY), Msgpack::from(label(cwd))));
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Msgpack::Map(fields))
        .map_err(|_| MemoryError::bad_request("imported conversation body is not encodable"))?;
    Ok(out)
}

/// A message's provenance, as its MESSAGE metadata: who said it in the
/// source, where it sat, when, and what it went on to call.
fn provenance(
    source: HistorySource,
    conversation: &HistoryConversation,
    message: &HistoryMessage,
    revises: Option<&LedgerRow>,
) -> Value {
    let mut fields = Map::new();
    fields.insert("source".into(), Value::from(source.source_id()));
    fields.insert(
        "conversation".into(),
        Value::from(label(&conversation.native_id)),
    );
    fields.insert("id".into(), Value::from(label(&message.native_id)));
    let role = match message.role {
        HistoryRole::User => "user",
        HistoryRole::Assistant => "assistant",
    };
    fields.insert("role".into(), Value::from(role));
    if let Some(parent) = &message.parent_id {
        fields.insert("parent".into(), Value::from(label(parent)));
    }
    if let Some(at) = message.at_ms {
        fields.insert("at_ms".into(), Value::from(at));
    }
    if let Some(said_by) = message.said_by {
        fields.insert("said_by".into(), Value::from(said_by));
    }
    if !message.tools.is_empty() {
        let tools: Vec<Value> = message
            .tools
            .iter()
            .take(MAX_TOOL_LABELS)
            .map(|tool| Value::from(label(tool)))
            .collect();
        fields.insert("tools".into(), Value::from(tools));
        if message.tools.len() > MAX_TOOL_LABELS {
            fields.insert(
                "tools_more".into(),
                Value::from(message.tools.len() - MAX_TOOL_LABELS),
            );
        }
    }
    if let Some(previous) = revises {
        fields.insert("revision".into(), Value::from(previous.next_revision()));
        // The latest text still in the vault; an erased one is never named.
        if let Some(latest) = previous.messages.last() {
            fields.insert("revises".into(), Value::from(latest.to_hex()));
        }
    }
    let mut metadata = Map::new();
    metadata.insert("import".into(), Value::Object(fields));
    Value::Object(metadata)
}

/// A refusal the import counts and goes past: the write door or a gate said
/// no to this turn. `None` for a failure of the vault itself.
fn refusal(error: &MemoryError) -> Option<Vec<String>> {
    if let Some(denial) = &error.gate_denial {
        return Some(denial.reason_codes.clone());
    }
    (error.code != MEMORY_CODE_INTERNAL).then(|| {
        vec![format!(
            "{}: {}",
            error.code.to_ascii_lowercase(),
            error.message
        )]
    })
}

impl Vault {
    /// Imports one decoded conversation into this vault as an imported
    /// transcript, for its owner (ARCH-0027).
    ///
    /// Each message becomes a MESSAGE grouped into one-speaker TURNs under one
    /// CONVERSATION, BM25-indexed at once. The source's speaker is the author:
    /// no `AuthoredBy` edge names the importer, and a source system prompt is
    /// never landed. Each MESSAGE occurred when its source says and every row
    /// is learned at `imported_at`. The TURN carries the import stamp, so the
    /// Dreamer treats what it extracts from it as `Imported` evidence, which
    /// never auto-approves. A message whose text the ledger already holds is
    /// skipped; with other text it lands as a revision beside what landed
    /// before.
    ///
    /// # Errors
    ///
    /// A failure of the vault itself. A turn the write door or a gate refuses
    /// is counted in the report instead, and the import goes on.
    pub fn import_history(
        &self,
        owner: &AuthenticatedOwner,
        source: HistorySource,
        conversation: &HistoryConversation,
        imported_at: u64,
    ) -> MemoryResult<HistoryImportReport> {
        let mut report = HistoryImportReport::new(conversation);
        let import = Import {
            vault: self,
            memory: self.memory(owner.revalidate(self)?, EdgeActorClass::Human),
            owner,
            source,
            conversation,
            conversation_id: derive(
                derived_domains::HISTORY_CONVERSATION,
                &[source.source_id(), &conversation.native_id],
            )?,
            conversation_body: conversation_body(source, conversation)?,
            fallback_ms: conversation
                .started_at_ms
                .unwrap_or_else(|| imported_at.saturating_mul(1000)),
            imported_at,
        };
        for run in runs(conversation, &mut report) {
            let deadline = Instant::now() + LEDGER_RACE_WINDOW;
            while !import.turn(&run, Instant::now() >= deadline, &mut report)? {
                // The import that landed first may hold more of the run: it
                // goes first, and this one reads what it left.
                std::thread::yield_now();
            }
        }
        import.settle(&mut report)?;
        Ok(report)
    }

    /// How many messages of `source` this vault has imported.
    ///
    /// # Errors
    ///
    /// A storage error reading the ledger.
    pub fn history_import_ledger_len(&self, source: HistorySource) -> Result<usize> {
        let txn = self.store.env.read_txn()?;
        ledger::count(&self.store, &txn, source)
    }
}

/// One conversation's import: what each of its turns lands with.
struct Import<'v> {
    vault: &'v Vault,
    memory: Memory<'v>,
    owner: &'v AuthenticatedOwner,
    source: HistorySource,
    conversation: &'v HistoryConversation,
    conversation_id: EntityId,
    conversation_body: Vec<u8>,
    fallback_ms: u64,
    imported_at: u64,
}

impl Import<'_> {
    /// Puts the session's start time and folder on its conversation: the row
    /// occurs when the thread's source says it began, and its body names the
    /// folder. A conversation imported before the import kept them gets them
    /// from the next import of its log, which changes nothing else of it; one
    /// that already holds them is not written. A conversation that never
    /// landed, was since erased or archived, or is not this import's is left
    /// alone.
    fn settle(&self, report: &mut HistoryImportReport) -> MemoryResult<()> {
        let started = self.conversation.own_started_at_ms.map(|ms| ms / 1000);
        let cwd = self.conversation.cwd.as_deref().map(label);
        if started.is_none() && cwd.is_none() {
            return Ok(());
        }
        let id = self.conversation_id;
        // The importer's write door: in a shared vault, its content-write
        // grant as of this transaction, as for every turn the import lands.
        let settled = self.memory.with_verified_actor_write_txn(|wtxn| {
            let store = &self.vault.store;
            let LiveEntityRow::Live { entity_type, body } =
                live_entity_row_in_txn(store, wtxn, &id)?
            else {
                return Ok(());
            };
            if entity_type != ENTITY_TYPE_CONVERSATION
                || self.vault.archive_tombstone_in_txn(wtxn, &id)?.is_some()
            {
                return Ok(());
            }
            let Some(record) = store.port_entity_record(wtxn, &id)? else {
                return Ok(());
            };
            let Ok(Msgpack::Map(mut fields)) = rmpv::decode::read_value(&mut body.as_slice())
            else {
                return Ok(());
            };
            // Only the conversation this import landed: a row another writer
            // put at the derived id is not this source's thread.
            let field = |name: &str| {
                fields
                    .iter()
                    .find(|(key, _)| key.as_str() == Some(name))
                    .and_then(|(_, value)| value.as_str())
            };
            if field(IMPORTED_SOURCE_KEY) != Some(self.source.source_id())
                || field("import_conversation")
                    != Some(label(&self.conversation.native_id).as_str())
            {
                return Ok(());
            }
            let mut changed = false;
            if let Some(cwd) = &cwd
                && !fields
                    .iter()
                    .any(|(key, _)| key.as_str() == Some(IMPORT_CWD_KEY))
            {
                fields.push((Msgpack::from(IMPORT_CWD_KEY), Msgpack::from(cwd.as_str())));
                changed = true;
            }
            let occurred = started.map_or(record.occurred, |at| TimeRange { start: at, end: at });
            if !changed && occurred == record.occurred {
                return Ok(());
            }
            self.owner.revalidate_in_txn(self.vault, wtxn)?;
            let mut out = Vec::new();
            rmpv::encode::write_value(&mut out, &Msgpack::Map(fields))
                .map_err(|_| crate::error::Error::InvalidConfig("conversation body".into()))?;
            self.vault
                .batch_in()
                .put(
                    &id,
                    ENTITY_TYPE_CONVERSATION,
                    occurred,
                    self.imported_at,
                    &out,
                )
                .apply(wtxn)?;
            Ok(())
        });
        match settled {
            Ok(()) => Ok(()),
            Err(error) => {
                let reasons = refusal(&error).ok_or(error)?;
                report.refusal_reasons.extend(reasons);
                Ok(())
            }
        }
    }

    /// The id of `run`'s own turn (`place` 0), or of the turn at `place` in
    /// its chain of continuations.
    fn chain_turn(&self, run: &[&HistoryMessage], place: u32) -> Result<EntityId> {
        let source = self.source.source_id();
        let conversation = self.conversation.native_id.as_str();
        if place == 0 {
            return derive(
                derived_domains::HISTORY_TURN,
                &[source, conversation, &run[0].native_id],
            );
        }
        derive(
            derived_domains::HISTORY_TURN,
            &[source, conversation, &run[0].native_id, &place.to_string()],
        )
    }

    /// The turn `count` new messages of `run` land in, and the first order
    /// free there: the first turn of the run's chain whose order space holds
    /// them all. A turn not stored yet holds a whole run, so the walk ends.
    fn turn_with_room(
        &self,
        txn: &heed::RoTxn<'_>,
        run: &[&HistoryMessage],
        count: u32,
    ) -> MemoryResult<(EntityId, u32)> {
        let mut place = 0;
        loop {
            let turn_id = self.chain_turn(run, place)?;
            let next_order = next_witness_message_order(&self.vault.store, txn, &turn_id)?;
            if next_order.saturating_add(count) <= MAX_WITNESS_MESSAGE_ORDER.saturating_add(1) {
                return Ok((turn_id, next_order));
            }
            place += 1;
        }
    }

    /// Lands one run as a turn and counts it. `false`, with nothing counted,
    /// when another import landed one of its messages between this read of
    /// the ledger and the write; the caller reads the run again. On the
    /// `last` attempt its messages are counted as pending instead.
    fn turn(
        &self,
        run: &[&HistoryMessage],
        last: bool,
        report: &mut HistoryImportReport,
    ) -> MemoryResult<bool> {
        let (source, conversation) = (self.source, self.conversation);
        let mut skipped = 0;
        let mut pending = Vec::new();
        let (turn_id, mut next_order, count) = {
            let txn = self
                .vault
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)?;
            for message in run {
                match standing(&self.vault.store, &txn, source, message)? {
                    Standing::Same => skipped += 1,
                    Standing::New => pending.push((*message, None)),
                    Standing::Changed(row) => pending.push((*message, Some(row))),
                }
            }
            let count = u32::try_from(pending.len()).unwrap_or(u32::MAX);
            let (turn_id, next_order) = self.turn_with_room(&txn, run, count)?;
            (turn_id, next_order, count)
        };
        #[cfg(test)]
        if let Some(between) = BETWEEN_READ_AND_WRITE.with_borrow_mut(Option::take) {
            between();
        }
        if pending.is_empty() {
            report.skipped += skipped;
            return Ok(true);
        }
        let mut messages = Vec::with_capacity(pending.len());
        let mut occurred = Vec::with_capacity(pending.len());
        let mut rows = Vec::with_capacity(pending.len());
        for (message, previous) in &pending {
            let hash = content_hash(message);
            let id = derive(
                derived_domains::HISTORY_MESSAGE,
                &[source.source_id(), &message.native_id, &hash],
            )?;
            messages.push(imported_message(
                source,
                conversation,
                message,
                previous.as_ref(),
                Some(id),
                next_order,
            ));
            next_order += 1;
            occurred.push(message.at_ms.unwrap_or(self.fallback_ms) / 1000);
            rows.push((
                message.native_id.as_str(),
                LedgerRow {
                    conversation: conversation.native_id.clone(),
                    message: id,
                    turn: turn_id,
                    hashes: previous
                        .as_ref()
                        .map_or_else(Vec::new, |row| row.hashes.clone())
                        .into_iter()
                        .chain(std::iter::once(hash))
                        .collect(),
                    messages: previous
                        .as_ref()
                        .map_or_else(Vec::new, |row| row.messages.clone())
                        .into_iter()
                        .chain(std::iter::once(id))
                        .collect(),
                    erased: previous
                        .as_ref()
                        .map_or_else(Vec::new, |row| row.erased.clone()),
                    successor: previous.as_ref().and_then(|row| row.successor.clone()),
                },
            ));
        }
        let turn = WitnessTurn {
            conversation_ref: self.conversation_id.to_hex(),
            turn_ref: Some(turn_id.to_hex()),
            thread_audience: None,
            messages,
            occurred_at: occurred[0],
            assertions: Default::default(),
        };
        let stamp = ImportedTurnStamp {
            source: source.source_id(),
            imported_at: self.imported_at,
            conversation_body: self.conversation_body.clone(),
            message_occurred: occurred,
        };
        let moved = Cell::new(false);
        let landed = self.memory.witness_imported(&turn, &stamp, |wtxn| {
            self.owner.revalidate_in_txn(self.vault, wtxn)?;
            // The rows this turn was built on, read again where they are
            // written: another import may have landed a message since.
            for (message, previous) in &pending {
                if ledger::find(&self.vault.store, wtxn, source, message)? != *previous {
                    moved.set(true);
                    return Err(MemoryError::new(
                        MEMORY_CODE_INVALID_STATE,
                        "another import landed this turn's messages first",
                        &[],
                    ));
                }
            }
            for (message, previous) in &pending {
                ledger::mark_successor(
                    &self.vault.store,
                    wtxn,
                    source,
                    message,
                    previous.as_ref(),
                )?;
            }
            for (native_id, row) in &rows {
                ledger::put(&self.vault.store, wtxn, source, native_id, row)?;
            }
            Ok(())
        });
        if moved.get() && !last {
            return Ok(false);
        }
        report.skipped += skipped;
        if moved.get() {
            report.pending += count;
            return Ok(true);
        }
        match landed {
            Ok(_) => {
                for (_, previous) in &pending {
                    if previous.is_some() {
                        report.changed += 1;
                    } else {
                        report.new += 1;
                    }
                }
            }
            Err(error) => {
                let reasons = refusal(&error).ok_or(error)?;
                report.refused += count;
                report.refusal_reasons.extend(reasons);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
