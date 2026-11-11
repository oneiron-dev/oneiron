//! OF-063: one check that every record a write names resolves for its writer.
//!
//! The owner's ruling (2026-10-17): check that the records an AI says it
//! created, or cites, really exist; refuse invented ones and log the refusal.
//!
//! A verb-table row declares its typed ref slots as JSON pointers (`refs` in
//! `scripts/sdk/verbs/`, where `*` takes every item of an array).
//! The row's generated engine fn calls [`admit_row_references`] before the
//! engine call, so every door that reaches the row (the HTTP facade, the MCP
//! dispatch, code mode and the SDK) meets this check once, and no door
//! carries a second, hand-written one.
//!
//! Every named ref must resolve under the WRITER's own scoped read. An
//! invented ref, a missing record and a record the writer may not read are
//! one refusal, so the writer learns nothing it could not read. The refusal
//! names the field pointer, never the ref, and it is receipted on its own
//! write ([`crate::receipt::ReceiptKind::ReferenceRefusal`]) before the
//! caller hears it. The refused write never runs. Inside an anonymous
//! off-record session the refusal stands but no receipt is written (Engine
//! ruling 10-17, matching OF-538).
//!
//! Only typed slots carry authority. Prose links (OF-063 prose links:
//! Engine ruling 10-17) are the one exception this file reads in text, and
//! only for display: [`parse_record_links`] finds Markdown links
//! `[label](oneiron://<ref>)`, reference-style links `[label][id]` with an
//! `[id]: oneiron://<ref>` definition, and autolinks `<oneiron://<ref>>`
//! (Engine ruling 10-18), outside code spans, fences, indented code and raw
//! HTML, bounded in count and length. A reader's link resolves under the
//! reader's own read (`vault.refs.links`, through the `vault.refs.resolve`
//! door); an AI-written link that does not resolve for its writer never
//! refuses or rewrites the text, it leaves the same reference-refusal receipt
//! with the outcome `unlinked` ([`unlinked_prose_links`]). The receipt
//! means landed speech only (Engine ruling 10-18): the links are read before
//! the engine call, and the receipt is written only once that call has
//! landed the text ([`receipt_landed_prose`]), so an attempt that never
//! lands leaves none. The witness program reads every AI-written message it
//! lands this way, whatever door it came through ([`witness_prose_unlinked`]),
//! and a streamed continuation its appended text ([`prose_text_unlinked`]).
//! No grant, scope or authority path reads a prose link.

use serde_json::Value;

use crate::memory::Memory;
use crate::receipt::{ReferenceOutcome, ReferenceRefusalFacts, receipt_reference_refusals};
use oneiron_contracts::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INVENTED_REFERENCE, MEMORY_CODE_NOT_FOUND, MemoryError,
    MemoryResult,
};

pub(crate) use crate::store::record_references::{NamedRecordRef, ReferenceRefusal};

/// Checks that every ref in `refs` resolves under `read`, the writer's own
/// scoped read. The first ref that does not is the refusal; a ref named twice
/// is read once.
pub(crate) fn validate_record_references(
    read: &Memory<'_>,
    refs: &[NamedRecordRef],
) -> Result<(), ReferenceRefusal> {
    check_record_references(refs, |reference| {
        read.get_entity(reference)
            .map(|result| result.value.is_some())
    })
}

/// [`validate_record_references`] read as [`Memory::peek_entity`] reads: the
/// same scoped read with no grant time persisted, so the check writes nothing
/// (FIX 22102). A preflight checks its refs this way.
pub(crate) fn peek_record_references(
    read: &Memory<'_>,
    refs: &[NamedRecordRef],
) -> Result<(), ReferenceRefusal> {
    check_record_references(refs, |reference| {
        read.peek_entity(reference)
            .map(|result| result.value.is_some())
    })
}

/// The first ref in `refs` that `resolves` does not find is the refusal; a
/// ref named twice is read once. A ref the read refuses as not found or
/// malformed does not resolve.
fn check_record_references(
    refs: &[NamedRecordRef],
    resolves: impl Fn(&str) -> MemoryResult<bool>,
) -> Result<(), ReferenceRefusal> {
    let unresolved = validate_record_references_with(refs, |reference| match resolves(reference) {
        Ok(found) => Ok(found),
        Err(error)
            if error.code == MEMORY_CODE_NOT_FOUND || error.code == MEMORY_CODE_BAD_REQUEST =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    })
    .map_err(ReferenceRefusal::Read)?;
    match unresolved {
        None => Ok(()),
        Some(pointer) => Err(ReferenceRefusal::Unresolved {
            pointer: pointer.to_owned(),
        }),
    }
}

pub(crate) use crate::store::record_references::{
    record_references_at, validate_record_references_with,
};

/// The generated check one verb-table row with `refs` runs before its engine
/// call: every ref `input` names at `pointers` must resolve for `memory`'s
/// writer. A refusal is receipted on its own write, naming the actor, `row`,
/// the field pointer and the time, and only then returned as
/// [`MEMORY_CODE_INVENTED_REFERENCE`]; if the receipt cannot be written the
/// store's error is returned instead, never a refusal claiming it was logged.
/// Inside an anonymous off-record session the refusal is returned with no
/// receipt, and says so.
pub(crate) fn admit_row_references<T: serde::Serialize>(
    memory: &Memory<'_>,
    row: &'static str,
    input: &T,
    pointers: &[&str],
) -> MemoryResult<()> {
    let value = serde_json::to_value(input).map_err(|_| {
        MemoryError::bad_request("the verb input could not be read for the records it names")
    })?;
    let refs = record_references_at(&value, pointers);
    let refs = without_archived_evidence_subject(memory, row, &value, refs)?;
    match validate_record_references(memory, &refs) {
        Ok(()) => Ok(()),
        Err(ReferenceRefusal::Read(error)) => Err(error),
        Err(ReferenceRefusal::Unresolved { pointer }) => {
            let recorded = receipt_reference_refusals(
                memory,
                &[ReferenceRefusalFacts {
                    actor: memory.actor(),
                    actor_class: memory.actor_class(),
                    row,
                    field: pointer.clone(),
                    outcome: ReferenceOutcome::Refused,
                }],
            )?;
            Err(invented_reference(&pointer, recorded))
        }
    }
}

/// The one slot that may name a record a cleanup archive filed away (FIX
/// 21997): the subject of the resolver's confidence evidence, a
/// `provider.enrichment` CLAIM. ARCH-0073 §6 keeps the archive visible to
/// entity resolution, and a re-mention restores the same record from that
/// evidence (`ingest::resolution`), so the vault owner writes it on the
/// archived subject without restoring it. Every other row, slot and
/// predicate keeps the live-read rule.
const ARCHIVED_EVIDENCE_SLOT: (&str, &str) = ("vault.claims.upsert", "/subject_ref");

/// `refs` less the archived subject [`ARCHIVED_EVIDENCE_SLOT`] admits:
/// `input` is resolver confidence evidence and
/// [`archived_subject_admitted`] holds for its subject. A live subject, and
/// every other ref, stays to be read as before.
fn without_archived_evidence_subject(
    memory: &Memory<'_>,
    row: &str,
    input: &Value,
    refs: Vec<NamedRecordRef>,
) -> MemoryResult<Vec<NamedRecordRef>> {
    let (slot_row, slot_pointer) = ARCHIVED_EVIDENCE_SLOT;
    if row != slot_row
        || input.get("predicate").and_then(Value::as_str)
            != Some(crate::provider_confidence::PREDICATE_PROVIDER_ENRICHMENT)
    {
        return Ok(refs);
    }
    let mut kept = Vec::with_capacity(refs.len());
    for named in refs {
        if named.pointer == slot_pointer && archived_subject_admitted(memory, &named.reference)? {
            continue;
        }
        kept.push(named);
    }
    Ok(kept)
}

/// Whether `reference` names the archived subject
/// [`archived_evidence_subject_in_txn`] admits for a `predicate` CLAIM
/// written under `memory`'s read. An unresolvable ref names no such record
/// and stays for the ordinary refusal.
fn archived_subject_admitted(memory: &Memory<'_>, reference: &str) -> MemoryResult<bool> {
    let owner = memory
        .read_lane(crate::claim::ClaimReadStatus::Recorded)?
        .actor_key()
        .reads_as_vault_owner();
    let vault = memory.vault();
    let Ok(id) = crate::vault::entity_refs::resolve_entity_ref(vault, reference) else {
        return Ok(false);
    };
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    Ok(archived_evidence_subject_in_txn(
        vault,
        &txn,
        owner,
        crate::provider_confidence::PREDICATE_PROVIDER_ENRICHMENT,
        &id,
    )?)
}

/// Whether `subject`, the subject of a `predicate` CLAIM, is the archived
/// record the resolver's evidence may name, judged in `txn` (FIX 21997): the
/// predicate is `provider.enrichment`, the writer reads as the vault owner
/// (`owner`), the record's row is stored, its archive marker is a cleanup
/// archive, and nothing else withholds its words (no removal, stale mark,
/// legal-hold use limit or withdrawn source; `raw_exportable_in_txn`). The
/// pre-call admission and the committing writer's own reference check both
/// ask it, so the one exception holds in the final snapshot too.
pub(crate) fn archived_evidence_subject_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    owner: bool,
    predicate: &str,
    subject: &crate::EntityId,
) -> crate::Result<bool> {
    if !owner || predicate != crate::provider_confidence::PREDICATE_PROVIDER_ENRICHMENT {
        return Ok(false);
    }
    let cleanup_archive = vault
        .archive_tombstone_in_txn(txn, subject)?
        .is_some_and(|marker| {
            marker.reason == Some(crate::deletion::TombstoneReason::ArchivedByCleanup)
        });
    if !cleanup_archive {
        return Ok(false);
    }
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, subject)?
    else {
        return Ok(false);
    };
    crate::ports::raw_exportable_in_txn(&vault.store, txn, subject, &raw)
}

/// The refusal a write naming an unresolved record ref gets: the field
/// pointer, never the ref. `recorded` says whether the refusal was
/// receipted; inside an anonymous off-record session it never is.
pub(crate) fn invented_reference(pointer: &str, recorded: bool) -> MemoryError {
    let kept = if recorded {
        "the refusal receipted"
    } else {
        "no record kept, as this anonymous session keeps none"
    };
    MemoryError::new(
        MEMORY_CODE_INVENTED_REFERENCE,
        format!(
            "the record named at `{pointer}` does not resolve for this writer; the write was refused and {kept}"
        ),
        &[
            "Name only records this writer can read, by the ref the engine issued (a short id or a 32-hex id).",
            "A missing record and one this writer may not read give this same refusal.",
        ],
    )
}

pub(crate) use crate::store::record_links::{
    MAX_PROSE_LINK_LABEL_BYTES, MAX_PROSE_LINKS, MAX_PROSE_SCAN_BYTES, PROSE_LINK_SCHEME,
    ProseLink, ProseLinks, parse_prose_links, parse_record_links,
};

/// The most text slots one write is read for links.
const MAX_PROSE_SLOTS: usize = 256;
/// How deep an opaque value is walked for its text.
const MAX_PROSE_DEPTH: usize = 32;

/// One text slot a write's prose links are read from.
struct ProseSlot<'v> {
    /// The slot's concrete pointer: the declared one, with array indices.
    pointer: String,
    text: &'v str,
    /// The slot sits behind a `*[key=value]` filter, so its item declares
    /// it AI-written whoever wrote it.
    declared: bool,
}

/// The text `input` holds at `pointers`. A pointer may name a string, or a
/// value whose every string is read (under the declared pointer, never a
/// key the caller chose); `*` takes every array item, and `*[key=value]`
/// only those whose `key` is the string `value`.
fn prose_slots_at<'v>(input: &'v Value, pointers: &[&str]) -> Vec<ProseSlot<'v>> {
    let mut slots = Vec::new();
    for pointer in pointers {
        let segments: Vec<&str> = pointer.split('/').skip(1).collect();
        prose_at(input, &segments, String::new(), false, &mut slots);
    }
    slots
}

fn prose_at<'v>(
    value: &'v Value,
    segments: &[&str],
    at: String,
    declared: bool,
    slots: &mut Vec<ProseSlot<'v>>,
) {
    let Some((head, rest)) = segments.split_first() else {
        texts_in(value, &at, declared, 0, slots);
        return;
    };
    if let Some(filter) = head.strip_prefix('*') {
        let Value::Array(items) = value else {
            return;
        };
        let wanted = filter
            .strip_prefix('[')
            .and_then(|filter| filter.strip_suffix(']'))
            .and_then(|filter| filter.split_once('='));
        for (index, item) in items.iter().enumerate() {
            if let Some((key, expected)) = wanted
                && item.get(key).and_then(Value::as_str) != Some(expected)
            {
                continue;
            }
            prose_at(
                item,
                rest,
                format!("{at}/{index}"),
                declared || wanted.is_some(),
                slots,
            );
        }
        return;
    }
    if let Some(child) = value.as_object().and_then(|members| members.get(*head)) {
        prose_at(child, rest, format!("{at}/{head}"), declared, slots);
    }
}

/// Every string in `value`, each as a slot at `pointer`.
fn texts_in<'v>(
    value: &'v Value,
    pointer: &str,
    declared: bool,
    depth: usize,
    slots: &mut Vec<ProseSlot<'v>>,
) {
    if slots.len() >= MAX_PROSE_SLOTS || depth > MAX_PROSE_DEPTH {
        return;
    }
    match value {
        Value::String(text) => slots.push(ProseSlot {
            pointer: pointer.to_owned(),
            text,
            declared,
        }),
        Value::Array(items) => {
            for item in items {
                texts_in(item, pointer, declared, depth + 1, slots);
            }
        }
        Value::Object(members) => {
            for member in members.values() {
                texts_in(member, pointer, declared, depth + 1, slots);
            }
        }
        _ => {}
    }
}

/// The generated prose-link read a row with `prose_links` runs before its
/// engine call (OF-063 prose links: Engine ruling 10-17).
///
/// Each AI-written text slot (its writer is an agent or a system actor, or
/// its item declares it AI-written through a `*[key=value]` filter) is read
/// for `oneiron://` links, and each link must resolve under the writer's own
/// scoped read. A slot with a link that does not earns one reference
/// refusal with the outcome `unlinked`: the actor, `row`, the slot's pointer
/// and the time, never the ref. The text is neither refused nor rewritten,
/// and the write goes on; a reader sees such a link as its plain label.
/// Nothing is written here: the generated fn hands these facts to
/// [`receipt_landed_prose`] once its engine call has landed the write
/// (Engine ruling 10-18: the receipt means landed speech only), so a write
/// that fails, is refused or never runs leaves none. A read that fails
/// returns its error.
pub(crate) fn unlinked_prose_links<T: serde::Serialize>(
    memory: &Memory<'_>,
    row: &'static str,
    input: &T,
    pointers: &[&str],
) -> MemoryResult<Vec<ReferenceRefusalFacts>> {
    let writer_is_ai = memory.actor_class() != crate::EdgeActorClass::Human;
    if !writer_is_ai && !pointers.iter().any(|pointer| pointer.contains("*[")) {
        return Ok(Vec::new());
    }
    let value = serde_json::to_value(input).map_err(|_| {
        MemoryError::bad_request("the verb input could not be read for the records its text links")
    })?;
    let mut unlinked: Vec<ReferenceRefusalFacts> = Vec::new();
    for slot in prose_slots_at(&value, pointers) {
        if !(writer_is_ai || slot.declared)
            || unlinked.iter().any(|facts| facts.field == slot.pointer)
        {
            continue;
        }
        if let Some(facts) = unlinked_text(memory, row, slot.pointer, slot.text, 0)? {
            unlinked.push(facts);
        }
    }
    Ok(unlinked)
}

/// Receipts the `unlinked` facts of text that has now landed, each on its
/// own grouped write (Engine ruling 10-18: the durable unlinked-prose
/// receipt means landed speech only). Called only after the write that
/// carried the text returned success. Inside an anonymous off-record
/// session nothing is written. Best effort, as every receipt of a landed
/// effect: a receipt that cannot be written is logged and the landed write's
/// answer stands.
pub(crate) fn receipt_landed_prose(memory: &Memory<'_>, unlinked: &[ReferenceRefusalFacts]) {
    if let Err(error) = receipt_reference_refusals(memory, unlinked) {
        tracing::warn!(%error, "landed AI text's unresolved links went unreceipted");
    }
}

/// The `unlinked` facts one AI-written `text` at `pointer` earns for its
/// links that end past byte `from`: `None` when each of them resolves for
/// `memory`'s writer.
fn unlinked_text(
    memory: &Memory<'_>,
    row: &'static str,
    pointer: String,
    text: &str,
    from: usize,
) -> MemoryResult<Option<ReferenceRefusalFacts>> {
    let refs: Vec<NamedRecordRef> = parse_record_links(text)
        .into_iter()
        .filter(|link| link.end > from)
        .map(|link| NamedRecordRef {
            pointer: pointer.clone(),
            reference: link.reference,
        })
        .collect();
    match validate_record_references(memory, &refs) {
        Ok(()) => Ok(None),
        Err(ReferenceRefusal::Unresolved { pointer }) => Ok(Some(ReferenceRefusalFacts {
            actor: memory.actor(),
            actor_class: memory.actor_class(),
            row,
            field: pointer,
            outcome: ReferenceOutcome::Unlinked,
        })),
        Err(ReferenceRefusal::Read(error)) => Err(error),
    }
}

/// The facts of `unlinked` ([`witness_prose_unlinked`]) whose message the
/// witness landed new: `lands_new[i]` for the turn's message `i` (FIX 3284),
/// read from each fact's slot pointer. A message an exact retry found stored
/// landed nothing, so its links earn no second receipt.
pub(crate) fn landed_witness_prose(
    unlinked: Vec<ReferenceRefusalFacts>,
    lands_new: &[bool],
) -> Vec<ReferenceRefusalFacts> {
    unlinked
        .into_iter()
        .filter(|facts| {
            facts
                .field
                .strip_prefix("/messages/")
                .and_then(|rest| rest.split('/').next())
                .and_then(|index| index.parse::<usize>().ok())
                .is_some_and(|index| lands_new.get(index) == Some(&true))
        })
        .collect()
}

/// The row every witnessed message's prose links are receipted under.
pub(crate) const WITNESS_PROSE_ROW: &str = "vault.witness";
/// The AI-written text of a witnessed turn: each companion message's content.
const WITNESS_PROSE_SLOT: &str = "/messages/*[author=companion]/content";

/// The witness program's prose-link read (OF-063 prose links: Engine
/// ruling 10-17), run once for every turn it lands, at base or in a
/// non-anonymous off-record session's overlay, whatever door the turn came
/// through: the verb table's `vault.witness` and `vault.rooms.speak`,
/// first-party speech, a streamed message's final witness, the AI chat
/// reply. An imported turn is not read. Each companion message is read as
/// [`unlinked_prose_links`] reads a declared slot, before the writer opens;
/// the program hands the facts to [`receipt_landed_prose`] once the turn has
/// landed. It never refuses or rewrites the message, and a read that fails
/// is logged and reads as no link.
pub(crate) fn witness_prose_unlinked(
    memory: &Memory<'_>,
    turn: &crate::memory::WitnessTurn,
) -> Vec<ReferenceRefusalFacts> {
    // Most turns name no link: they are not read at all.
    if !turn.messages.iter().any(|message| {
        message.author == crate::memory::WitnessAuthor::Companion
            && message.content.contains(PROSE_LINK_SCHEME)
    }) {
        return Vec::new();
    }
    unlinked_prose_links(memory, WITNESS_PROSE_ROW, turn, &[WITNESS_PROSE_SLOT]).unwrap_or_else(
        |error| {
            tracing::warn!(%error, "witnessed AI text's links could not be read");
            Vec::new()
        },
    )
}

/// The prose-link read of text appended to an AI-written message (a
/// streamed continuation's finalize), before its writer opens: `text` is
/// the message's whole text, whose first `from` bytes were read when they
/// landed, so only links that end past them are read. The finalize hands
/// the facts to [`receipt_landed_prose`] once it has landed; a read that
/// fails is logged and reads as no link.
pub(crate) fn prose_text_unlinked(
    memory: &Memory<'_>,
    row: &'static str,
    field: &str,
    text: &str,
    from: usize,
) -> Vec<ReferenceRefusalFacts> {
    match unlinked_text(memory, row, field.to_owned(), text, from) {
        Ok(facts) => facts.into_iter().collect(),
        Err(error) => {
            tracing::warn!(%error, "appended AI text's links could not be read");
            Vec::new()
        }
    }
}

/// The prose-link check of AI-written text that has already landed (a DAG
/// append's or a summary reply's TURN prose, read once its writer closed):
/// links that end past byte `from` of `text` are read and receipted under
/// `row` at `field`, receipt-only: a read or receipt that fails is logged
/// and the landed write's answer stands.
pub(crate) fn admit_prose_text(
    memory: &Memory<'_>,
    row: &'static str,
    field: &str,
    text: &str,
    from: usize,
) {
    let receipted = unlinked_text(memory, row, field.to_owned(), text, from).and_then(|facts| {
        receipt_reference_refusals(memory, facts.as_slice()).map_err(MemoryError::from)
    });
    if let Err(error) = receipted {
        tracing::warn!(%error, "appended AI text's unresolved links went unreceipted");
    }
}
