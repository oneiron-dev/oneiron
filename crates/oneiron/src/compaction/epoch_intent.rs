//! The intent a compaction epoch is born from (ARCH-0035 Rule A; owner
//! 2026-09-17: a summary's birth names the prompt it was born from as an
//! input a reader can open, and what caused it as its trigger). Each pass
//! that mints an epoch mints one explicit-only intent NOTE beside it, in the
//! same transaction, and the summary's birth names it as its Prompt. A run's
//! epoch names the run as its trigger while the run's replay record stands
//! where the epoch lands; a birth missing either is minted without it.

use crate::batch::{BatchBuilder, BatchOp};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::note::{COMPACTION_INTENT_NOTE_KIND, NoteBody, NoteKind, encode_note_body};
use crate::provenance::birth::{MAX_BIRTH_INPUTS, RowBirth};
use crate::provenance::made_by::{MadeByClass, MadeByInputRole, MadeByTrigger};
use crate::registry::ENTITY_TYPE_NOTE;
use crate::store::ManifestDbs;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

use super::driver::{CompactionRequest, WindowLog};

/// The process an epoch's birth names.
const EPOCH_PROCESS: &str = "compaction.epoch";

/// The pass's intent NOTE: the span its summary covers and the summary's
/// budget, the agent's note and the lines it must keep word for word, and
/// every record the window was read from, by ref. A pass with a source
/// erased or withdrawn before the mint (`withdrawn`) keeps only the span and
/// the refs: its note and pins are words of the window, and the summary they
/// prompted is born withdrawn. The one hook a ruling on the intent's text
/// changes.
pub(super) fn intent_note_body(
    request: &CompactionRequest,
    author: EntityId,
    summary: EntityId,
    withdrawn: bool,
) -> Result<Vec<u8>> {
    let through = request
        .window
        .last()
        .map_or(request.turn_start, |message| message.turn);
    let mut markdown = format!(
        "Compaction intent: an epoch summary of steps {} through {through}, in at most {} \
         tokens.\n",
        request.turn_start, request.summary_token_budget
    );
    if let WindowLog::Host { run: Some(run), .. } = request.log {
        markdown.push_str(&format!("Run: {}\n", run.to_hex()));
    }
    if withdrawn {
        markdown.push_str(
            "\nA record the window was read from was erased before this summary was minted, so \
             its note and pins are not kept here.\n",
        );
    } else {
        if let Some(note) = &request.note {
            markdown.push_str(&format!("\nNote: {note}\n"));
        }
        if !request.pins.is_empty() {
            markdown.push_str("\nKept word for word:\n");
            for pin in &request.pins {
                markdown.push_str(&format!("- {pin}\n"));
            }
        }
    }
    markdown.push_str(&format!("\nRead from {} records:\n", request.sources.len()));
    for source in &request.sources {
        markdown.push_str(&format!("- {}\n", source.to_hex()));
    }
    encode_note_body(&NoteBody {
        kind: NoteKind::parse(COMPACTION_INTENT_NOTE_KIND).ok_or(Error::InvariantViolation(
            "the compaction intent NOTE kind is shipped",
        ))?,
        author_ref: author,
        markdown,
        source_revision_ref: *summary.as_bytes(),
    })
}

/// The epoch's birth (Rule A): `intent` first, as its Prompt; then every
/// record the window was read from; then, for a conversation, each window
/// message and its turn (a host log's per-step ids name no row). Ids are
/// deduplicated before the first `MAX_BIRTH_INPUTS` are kept, so a repeat
/// takes no slot. The input hash is over the window's text as summarized.
pub(super) fn epoch_birth(
    request: &CompactionRequest,
    byline: WriteActor,
    at: u64,
    intent: EntityId,
    trigger: Option<MadeByTrigger>,
) -> Option<RowBirth> {
    let window = request
        .window
        .iter()
        .filter(|_| request.log == WindowLog::Conversation)
        .flat_map(|message| [message.message_id, message.turn_id]);
    let mut seen = std::collections::BTreeSet::new();
    let inputs: Vec<EntityId> = std::iter::once(intent)
        .chain(request.sources.iter().copied())
        .chain(window)
        .filter(|id| seen.insert(*id))
        .take(MAX_BIRTH_INPUTS)
        .collect();
    let read: Vec<&[u8]> = request
        .window
        .iter()
        .map(|message| message.content.as_bytes())
        .collect();
    let mut birth = RowBirth::written(
        byline,
        MadeByClass::Concluded,
        EPOCH_PROCESS,
        &inputs,
        &read,
        at,
    )?;
    if let Some(prompt) = birth.made_by.inputs.first_mut() {
        prompt.role = MadeByInputRole::Prompt;
    }
    birth.made_by.trigger = trigger;
    Some(birth)
}

/// The run a host log's epoch was caused by, while its replay record stands
/// in the store the epoch lands in. `None` for a conversation, or for a run
/// whose record sits elsewhere (a Base-route run's lives in its room).
pub(super) fn run_trigger_in(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    request: &CompactionRequest,
) -> Result<Option<MadeByTrigger>> {
    let WindowLog::Host { run: Some(run), .. } = request.log else {
        return Ok(None);
    };
    let trigger = MadeByTrigger::Run(run);
    Ok(crate::provenance::birth::trigger_is_live_in_txn(store, txn, &trigger)?.then_some(trigger))
}

/// Whether any of `sources` was erased or withdrawn, as `store` reads it.
pub(super) fn any_withdrawn_in(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    sources: &[EntityId],
) -> Result<bool> {
    for source in sources {
        let state = crate::ports::TombstoneStoreRead::port_deletion_state(store, txn, source)?;
        if state.deleted || state.stale {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The intent NOTE `intent`'s rows beside summary `summary`, for a room's
/// epoch: the NOTE, authored by `author` and about the summary, derived from
/// each of `sources` (those the summary takes an edge to, at its weight), so
/// erasing one reaches the NOTE's words as it reaches the summary's.
pub(super) fn intent_ops(
    intent: EntityId,
    author: EntityId,
    summary: EntityId,
    at: u64,
    body: Vec<u8>,
    sources: &[EntityId],
) -> Vec<BatchOp> {
    let edge = |kind: EdgeKind, tgt: EntityId| BatchOp::Edge {
        src: intent,
        kind,
        tgt,
        weight: edge_weight(kind),
        vad: crate::affect::Vad::NEUTRAL,
    };
    let mut ops = vec![
        BatchOp::Put {
            id: intent,
            entity_type: ENTITY_TYPE_NOTE,
            occurred: TimeRange { start: at, end: at },
            learned_at: at,
            data: body,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        },
        edge(EdgeKind::AuthoredBy, author),
        edge(EdgeKind::About, summary),
    ];
    ops.extend(
        sources
            .iter()
            .map(|source| edge(EdgeKind::DerivedFrom, *source)),
    );
    ops
}

/// The weight of an intent NOTE's `kind` edge: a NOTE door's registered
/// prior for its authorship and subject, and the summary's own `1.0` for a
/// source.
fn edge_weight(kind: EdgeKind) -> f32 {
    match kind {
        EdgeKind::DerivedFrom => 1.0,
        _ => kind.default_weight().unwrap_or(1.0),
    }
}

/// Stages the intent NOTE on a base mint's `batch` (see [`intent_ops`]).
pub(super) fn stage_intent<'v>(
    batch: BatchBuilder<'v>,
    intent: EntityId,
    author: EntityId,
    summary: EntityId,
    at: u64,
    body: &[u8],
    sources: &[EntityId],
) -> BatchBuilder<'v> {
    let mut batch = batch
        .put_authored_note(&intent, &author, TimeRange { start: at, end: at }, at, body)
        .edge(
            &intent,
            EdgeKind::AuthoredBy,
            &author,
            edge_weight(EdgeKind::AuthoredBy),
        )
        .edge(
            &intent,
            EdgeKind::About,
            &summary,
            edge_weight(EdgeKind::About),
        );
    for source in sources {
        batch = batch.edge(
            &intent,
            EdgeKind::DerivedFrom,
            source,
            edge_weight(EdgeKind::DerivedFrom),
        );
    }
    batch
}
