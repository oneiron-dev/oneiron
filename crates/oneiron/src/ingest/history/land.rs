//! Landing a decoded conversation as an imported transcript (ARCH-0027).
//!
//! Messages group into one-speaker TURNs, each the longest run of one side (up
//! to [`TURN_MESSAGE_CAP`] messages). Conversation, turn and message ids derive
//! from the source's own, so a re-run, a crash retry or an appended session
//! lands the same rows at the same ids. A new message takes the next order its
//! turn has free, so a later export that regroups a run never collides with
//! what landed before. Each turn lands through the witness program's import
//! door, which runs the same ceiling door and write-door secret scan as any
//! witnessed turn, with the ledger rows of its new messages in the same
//! transaction. The ledger is read again inside that transaction: when another
//! import landed one of the turn's messages since the first read, the turn is
//! read and built again, so no import overwrites what another landed. A
//! refused turn is counted and the import goes on; the next import tries it
//! again.

use std::cell::Cell;
use std::collections::{BTreeSet, HashSet};

use rmpv::Value as Msgpack;
use serde::Serialize;
use serde_json::{Map, Value};

use super::ledger::{self, LedgerRow, content_hash};
use super::{
    HistoryConversation, HistoryMessage, HistoryRole, HistorySkips, HistorySource,
    HistoryThreadKind,
};
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
use crate::side_table::SideTableDbs;

/// The most messages one TURN holds; a longer run of one side (an agent's long
/// unattended stretch) continues in the next turn.
const TURN_MESSAGE_CAP: usize = 256;

/// The reason a turn with no free order left is refused.
const TURN_FULL: &str = "import.turn_full";

/// Tool names one message's metadata lists; the rest are counted.
const MAX_TOOL_LABELS: usize = 64;

/// Bytes of an id or a label kept in metadata.
const MAX_LABEL_BYTES: usize = 512;

/// How many times a turn is read and built again when other imports keep
/// landing its messages first. Past that it is counted as refused, and the
/// next import tries it again.
const LEDGER_ATTEMPTS: usize = 4;

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
        Some(row) if row.holds(&content_hash(message)) => Standing::Same,
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
        fields.insert("revises".into(), Value::from(previous.message.to_hex()));
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
            memory: self.memory(owner.actor(), EdgeActorClass::Human),
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
            let turn_id = derive(
                derived_domains::HISTORY_TURN,
                &[
                    source.source_id(),
                    &conversation.native_id,
                    &run[0].native_id,
                ],
            )?;
            let mut attempt = 1;
            while !import.turn(&run, turn_id, attempt == LEDGER_ATTEMPTS, &mut report)? {
                attempt += 1;
            }
        }
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
    /// Lands one run as a turn and counts it. `false`, with nothing counted,
    /// when another import landed one of its messages between this read of
    /// the ledger and the write; the caller reads the run again. On the
    /// `last` attempt that is counted as a refusal instead.
    fn turn(
        &self,
        run: &[&HistoryMessage],
        turn_id: EntityId,
        last: bool,
        report: &mut HistoryImportReport,
    ) -> MemoryResult<bool> {
        let (source, conversation) = (self.source, self.conversation);
        let mut skipped = 0;
        let mut pending = Vec::new();
        let mut next_order = {
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
            next_witness_message_order(&self.vault.store, &txn, &turn_id)?
        };
        #[cfg(test)]
        if let Some(between) = BETWEEN_READ_AND_WRITE.with_borrow_mut(Option::take) {
            between();
        }
        if pending.is_empty() {
            report.skipped += skipped;
            return Ok(true);
        }
        let count = u32::try_from(pending.len()).unwrap_or(u32::MAX);
        if next_order.saturating_add(count) > MAX_WITNESS_MESSAGE_ORDER.saturating_add(1) {
            report.skipped += skipped;
            report.refused += count;
            report.refusal_reasons.insert(TURN_FULL.to_owned());
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
                },
            ));
        }
        let turn = WitnessTurn {
            conversation_ref: self.conversation_id.to_hex(),
            turn_ref: Some(turn_id.to_hex()),
            messages,
            occurred_at: occurred[0],
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
            for (native_id, row) in &rows {
                ledger::put(&self.vault.store, wtxn, source, native_id, row)?;
            }
            Ok(())
        });
        if moved.get() && !last {
            return Ok(false);
        }
        report.skipped += skipped;
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
