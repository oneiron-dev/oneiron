//! The per-item cleanup review (FIX 1758; ARCH-0073: a proposal is
//! "reviewed per item with full disclosure"): every slot of one open
//! proposal, read for the owner.
//!
//! Each slot answers what it names, why its arm proposes it, how it stands
//! now, the revision of its stored bytes and what accepting it does, all from
//! one read snapshot under the owner's proof. A completed attempt's whole
//! stored row is read in that snapshot too. A record's content is read after
//! it, through the owner's own `vault.get` and `vault.notes.read` reads; the
//! review answers once its `revision` reads the same after those reads as in
//! the snapshot, so the content beside each fact is what the revision binds,
//! and else reads again, up to [`CLEANUP_REVIEW_READ_ATTEMPTS`] times; past that it answers
//! its latest read with each slot that changed under it marked (FIX 10502).
//! Nothing is copied into a store and nothing is cut short. An erased, gone
//! or unreadable slot keeps its place as a typed fact.

use super::attempt_retention::eligible;
use super::codec_receipts::PROPOSAL;
use super::marks::{self, Revision};
use super::person_provenance;
use super::retention::{note_retention_in_txn, retention_days_in_txn};
use super::review_types::{
    CleanupAcceptEffect, CleanupItemState, CleanupReviewContent, CleanupReviewCounts,
    CleanupReviewEvidence, CleanupReviewItem, CleanupReviewRequest, CleanupReviewView,
};
use super::tripwire::{SUMMARY_MEMBER_EDGE_KINDS, has_any_edge_in_txn};
use super::{
    CleanupCandidate, CleanupKind, CleanupProposal, decode_proposal, zero_live_members_in_txn,
};
use crate::Vault;
use crate::attempt_queue::{AttemptId, decode_record};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::memory::{MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult};
use crate::note::NoteReadRequest;
use crate::ports::{EdgeDirection, EntityStoreRead, JobQueueRead};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The BLAKE3 context of a review's revision.
const REVIEW_CONTEXT: &str = "oneiron vault_cleanup review revision v1";

/// The reason a NOTE's document read records.
const NOTE_READ_REASON: &str = "the owner's cleanup review";

/// How many times a review reads while slots change under it before it
/// answers its latest read with those slots marked (FIX 10502).
const CLEANUP_REVIEW_READ_ATTEMPTS: usize = 3;

/// A record whose content is read after the snapshot.
struct RecordRead {
    entity: EntityId,
    note: bool,
}

/// Reviews one open cleanup proposal slot by slot, as the authenticated
/// owner (FIX 1758). Every slot answers, an erased one too; no slot is cut
/// short and nothing is stored.
///
/// # Errors
///
/// `NOT_FOUND` when the proposal is no longer open; a lapsed owner proof;
/// storage errors. A read that refuses one slot's content is named on that
/// slot and the review still answers.
pub fn review_cleanup_proposal_as(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CleanupReviewRequest,
) -> MemoryResult<CleanupReviewView> {
    let mut read = 1;
    loop {
        let Some((mut view, reads)) = snapshot(memory.vault(), owner, &input.proposal)? else {
            return Err(proposal_not_open(&input.proposal));
        };
        read_content(memory, &mut view, reads);
        // A slot written while its content was read moves the revision:
        // the review reads again, so no content is newer than its facts.
        let Some((revision, slots)) = revision_now(memory.vault(), &input.proposal)? else {
            return Err(proposal_not_open(&input.proposal));
        };
        if revision == view.revision {
            return Ok(view);
        }
        if read >= CLEANUP_REVIEW_READ_ATTEMPTS {
            for (item, now) in view.items.iter_mut().zip(&slots) {
                if item.revision != *now {
                    item.changed_during_review = Some(true);
                }
            }
            return Ok(view);
        }
        read += 1;
    }
}

/// Each record's content, read for the owner after the snapshot: the
/// snapshot's read transaction is closed, and each read opens its own, as
/// the owner's reads do. A read that refuses is named on its slot.
fn read_content(memory: &Memory<'_>, view: &mut CleanupReviewView, reads: Vec<Option<RecordRead>>) {
    for (item, read) in view.items.iter_mut().zip(reads) {
        let Some(read) = read else {
            continue;
        };
        let content = item
            .content
            .get_or_insert_with(CleanupReviewContent::default);
        match memory.get_entity(&read.entity.to_hex()) {
            Ok(record) => content.record = Some(record),
            Err(error) => content.refused.push(refusal(&error)),
        }
        if read.note {
            let request = NoteReadRequest {
                note_ref: read.entity.to_hex(),
                reason: Some(NOTE_READ_REASON.to_owned()),
                version: None,
                spans: Vec::new(),
            };
            match memory.read_note(&request) {
                Ok(note) => content.note = Some(note),
                Err(error) => content.refused.push(refusal(&error)),
            }
        }
    }
}

/// The review's revision and each slot's, as a fresh snapshot reads them;
/// none once the proposal is no longer open.
fn revision_now(
    vault: &Vault,
    proposal: &EntityId,
) -> Result<Option<(String, Vec<Option<String>>)>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = PROPOSAL.get(&vault.store, &rtxn, proposal)? else {
        return Ok(None);
    };
    let row = decode_proposal(*proposal, &raw)?;
    let mut hasher = review_hasher(&raw);
    let mut slots = Vec::with_capacity(row.candidates.len());
    for candidate in &row.candidates {
        let revision = slot_revision_in_txn(vault, &rtxn, candidate.as_ref())?;
        fold_revision(&mut hasher, revision.as_ref());
        slots.push(revision.map(|revision| bytes_to_hex_lower(&revision)));
    }
    Ok(Some((
        bytes_to_hex_lower(hasher.finalize().as_bytes()),
        slots,
    )))
}

/// The answer for a proposal that is no longer open.
pub(super) fn proposal_not_open(proposal: &EntityId) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_NOT_FOUND,
        format!(
            "cleanup proposal {} is no longer open; review again",
            proposal.to_hex()
        ),
        &["Run the owner cleanup review for the proposals that wait."],
    )
}

/// The review's revision as `txn` reads it: the proposal row, then each
/// slot's stored bytes, as [`review_cleanup_proposal_as`] folds them.
pub(super) fn review_revision_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    raw: &[u8],
    row: &CleanupProposal,
) -> Result<String> {
    let mut hasher = review_hasher(raw);
    for candidate in &row.candidates {
        let revision = slot_revision_in_txn(vault, txn, candidate.as_ref())?;
        fold_revision(&mut hasher, revision.as_ref());
    }
    Ok(bytes_to_hex_lower(hasher.finalize().as_bytes()))
}

type Snapshot = (CleanupReviewView, Vec<Option<RecordRead>>);

/// Everything but record content, in one read snapshot under the owner's
/// proof; none when the proposal is not open.
fn snapshot(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    proposal: &EntityId,
) -> Result<Option<Snapshot>> {
    let rtxn = vault.store.env.read_txn()?;
    owner.revalidate_in_txn(vault, &rtxn)?;
    let Some(raw) = PROPOSAL.get(&vault.store, &rtxn, proposal)? else {
        return Ok(None);
    };
    let row = decode_proposal(*proposal, &raw)?;
    let task_retention_days = retention_days_in_txn(vault, &rtxn)?;
    let mut hasher = review_hasher(&raw);
    let mut counts = CleanupReviewCounts {
        total: row.candidates.len(),
        ..CleanupReviewCounts::default()
    };
    let mut items = Vec::with_capacity(row.candidates.len());
    let mut reads = Vec::with_capacity(row.candidates.len());
    for (slot, candidate) in row.candidates.iter().enumerate() {
        let revision = slot_revision_in_txn(vault, &rtxn, candidate.as_ref())?;
        fold_revision(&mut hasher, revision.as_ref());
        count(&mut counts, candidate.as_ref());
        let Some(candidate) = candidate else {
            items.push(erased_item(slot));
            reads.push(None);
            continue;
        };
        let mut item = CleanupReviewItem {
            slot,
            state: CleanupItemState::Gone,
            entity: Some(candidate.entity),
            kind: Some(candidate.kind),
            revision: revision.map(|revision| bytes_to_hex_lower(&revision)),
            evidence: None,
            content: None,
            accept: CleanupAcceptEffect::Skip,
            changed_during_review: None,
        };
        let read = if candidate.kind == CleanupKind::CompletedAttempt {
            review_attempt(
                vault,
                &rtxn,
                candidate.entity,
                task_retention_days,
                &mut item,
            )?;
            None
        } else {
            review_record(vault, &rtxn, candidate, task_retention_days, &mut item)?
        };
        items.push(item);
        reads.push(read);
    }
    let view = CleanupReviewView {
        proposal: row.id,
        attempt: bytes_to_hex_lower(row.attempt.as_bytes()),
        created_at: row.created_at,
        read_at: vault.now_recorded_at(),
        revision: bytes_to_hex_lower(hasher.finalize().as_bytes()),
        task_retention_days,
        counts,
        items,
    };
    Ok(Some((view, reads)))
}

/// One completed attempt: its eligibility, evidence and whole stored row.
fn review_attempt(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: EntityId,
    retention_days: u64,
    item: &mut CleanupReviewItem,
) -> Result<()> {
    let id = AttemptId::from_bytes(entity.as_bytes())?;
    let Some(raw) = JobQueueRead::port_job_row(&vault.store, txn, &id)? else {
        return Ok(());
    };
    item.accept = accept_effect(eligible(vault, txn, id, &raw).map(|record| record.is_some()))?;
    let mut content = CleanupReviewContent::default();
    match decode_record(&raw, id) {
        Ok(record) => {
            let holds_now = item.accept == CleanupAcceptEffect::Archive;
            item.state = held(holds_now);
            item.evidence = Some(CleanupReviewEvidence {
                since: Some(record.updated_at),
                keep_days: Some(retention_days),
                ..evidence(CleanupKind::CompletedAttempt, holds_now)
            });
            match serde_json::to_value(&record) {
                Ok(value) => content.attempt = Some(value),
                Err(error) => content.refused.push(format!("attempt: {error}")),
            }
        }
        Err(error) => {
            unreadable(error)?;
            item.state = CleanupItemState::Unreadable;
            content
                .refused
                .push("attempt: its stored queue row does not read".to_owned());
        }
    }
    item.content = Some(content);
    Ok(())
}

/// One record: its eligibility and evidence; its content is read after the
/// snapshot.
fn review_record(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    candidate: &CleanupCandidate,
    retention_days: u64,
    item: &mut CleanupReviewItem,
) -> Result<Option<RecordRead>> {
    let entity = candidate.entity;
    let learned_at = match vault.store.port_entity_record(txn, &entity) {
        Ok(Some(record)) => record.learned_at,
        Ok(None) => return Ok(None),
        Err(error) => {
            unreadable(error)?;
            item.state = CleanupItemState::Unreadable;
            item.accept = CleanupAcceptEffect::Fails;
            return Ok(Some(RecordRead {
                entity,
                note: false,
            }));
        }
    };
    let check =
        zero_live_members_in_txn(vault, txn, &entity).map(|kind| kind == Some(candidate.kind));
    item.accept = accept_effect(check)?;
    if item.accept == CleanupAcceptEffect::Fails {
        item.state = CleanupItemState::Unreadable;
        return Ok(Some(RecordRead {
            entity,
            note: false,
        }));
    }
    let holds_now = item.accept == CleanupAcceptEffect::Archive;
    item.state = held(holds_now);
    let mut found = evidence(candidate.kind, holds_now);
    match candidate.kind {
        CleanupKind::ClaimlessExtractionPerson => {
            found.live_claims = Some(live_claims(vault, txn, &entity)?);
            found.extraction_minted = Some(person_provenance::is_extraction_minted_person_in_txn(
                vault, txn, &entity,
            )?);
        }
        CleanupKind::EmptySummary => {
            found.live_claims = Some(live_claims(vault, txn, &entity)?);
            found.linked_edges = linked_edges(vault, txn, &entity)?;
        }
        CleanupKind::CompletedTask => {
            found.since = crate::task_verb::completed_task_at_in_txn(vault, txn, entity)?;
            found.keep_days = Some(retention_days);
        }
        CleanupKind::RetainedNote => {
            found.since = Some(learned_at);
            found.keep_days =
                note_retention_in_txn(vault, txn, &entity)?.map(|(days, _)| u64::from(days));
        }
        CleanupKind::CompletedAttempt => {}
    }
    item.evidence = Some(found);
    Ok(Some(RecordRead {
        entity,
        note: candidate.kind == CleanupKind::RetainedNote,
    }))
}

/// The state a readable slot is in, by whether its rule holds now.
const fn held(holds_now: bool) -> CleanupItemState {
    if holds_now {
        CleanupItemState::Eligible
    } else {
        CleanupItemState::Changed
    }
}

/// Evidence for `kind` with only its rule filled.
fn evidence(kind: CleanupKind, holds_now: bool) -> CleanupReviewEvidence {
    CleanupReviewEvidence {
        rule: rule(kind).to_owned(),
        holds_now,
        live_claims: None,
        linked_edges: Vec::new(),
        extraction_minted: None,
        since: None,
        keep_days: None,
    }
}

/// Each arm's rule, in words.
const fn rule(kind: CleanupKind) -> &'static str {
    match kind {
        CleanupKind::ClaimlessExtractionPerson => {
            "a PERSON an extraction minted, with no live claim about it"
        }
        CleanupKind::EmptySummary => {
            "a SUMMARY with no live claim about it and no member or reference edge in either \
             direction"
        }
        CleanupKind::CompletedTask => "a TASK that finished longer ago than the retention period",
        CleanupKind::CompletedAttempt => {
            "a completed attempt last updated longer ago than the retention period"
        }
        CleanupKind::RetainedNote => "a NOTE learned longer ago than the days its kind keeps it",
    }
}

/// What accepting a slot does, by the arm's own check: a row the check cannot
/// read fails the decision as a whole, as an accept would; a storage fault
/// fails the review.
fn accept_effect(check: Result<bool>) -> Result<CleanupAcceptEffect> {
    match check {
        Ok(true) => Ok(CleanupAcceptEffect::Archive),
        Ok(false) => Ok(CleanupAcceptEffect::Skip),
        Err(error) => unreadable(error).map(|()| CleanupAcceptEffect::Fails),
    }
}

/// A row that does not read is a fact about its slot; a storage fault fails
/// the review.
fn unreadable(error: Error) -> Result<()> {
    match error {
        Error::Storage(_) | Error::Io(_) => Err(error),
        _ => Ok(()),
    }
}

/// A content read's refusal, as the slot names it.
fn refusal(error: &MemoryError) -> String {
    format!("{}: {}", error.code, error.message)
}

/// The revision of a slot's stored bytes now: the encoded record, or the
/// attempt's queue row. None for an erased slot, one with nothing stored, or
/// a record that does not read.
fn slot_revision_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    candidate: Option<&CleanupCandidate>,
) -> Result<Option<Revision>> {
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    if candidate.kind == CleanupKind::CompletedAttempt {
        let id = AttemptId::from_bytes(candidate.entity.as_bytes())?;
        return Ok(
            JobQueueRead::port_job_row(&vault.store, txn, &id)?.map(|raw| marks::revision_of(&raw))
        );
    }
    match vault.store.port_entity_record(txn, &candidate.entity) {
        Ok(record) => Ok(record.map(|row| marks::revision_of(&row.encode()))),
        Err(error) => unreadable(error).map(|()| None),
    }
}

fn review_hasher(raw: &[u8]) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new_derive_key(REVIEW_CONTEXT);
    hasher.update(blake3::hash(raw).as_bytes());
    hasher
}

fn fold_revision(hasher: &mut blake3::Hasher, revision: Option<&Revision>) {
    match revision {
        Some(revision) => {
            hasher.update(&[1]);
            hasher.update(revision);
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn count(counts: &mut CleanupReviewCounts, candidate: Option<&CleanupCandidate>) {
    let slot = match candidate.map(|candidate| candidate.kind) {
        None => &mut counts.erased,
        Some(CleanupKind::ClaimlessExtractionPerson) => &mut counts.claimless_extraction_persons,
        Some(CleanupKind::EmptySummary) => &mut counts.empty_summaries,
        Some(CleanupKind::CompletedTask) => &mut counts.completed_tasks,
        Some(CleanupKind::CompletedAttempt) => &mut counts.completed_attempts,
        Some(CleanupKind::RetainedNote) => &mut counts.retained_notes,
    };
    *slot = slot.saturating_add(1);
}

fn erased_item(slot: usize) -> CleanupReviewItem {
    CleanupReviewItem {
        slot,
        state: CleanupItemState::Erased,
        entity: None,
        kind: None,
        revision: None,
        evidence: None,
        content: None,
        accept: CleanupAcceptEffect::Nothing,
        changed_during_review: None,
    }
}

/// The live claims about `subject`: a tombstoned claim's shell is no claim.
fn live_claims(vault: &Vault, txn: &heed::RoTxn<'_>, subject: &EntityId) -> Result<u64> {
    let mut live = 0_u64;
    for claim in vault.claims_for_subject_in_txn(txn, subject)? {
        if matches!(
            live_entity_row_in_txn(&vault.store, txn, &claim)?,
            LiveEntityRow::Live { .. }
        ) {
            live = live.saturating_add(1);
        }
    }
    Ok(live)
}

/// The member or reference edge kinds a SUMMARY has, in or out.
fn linked_edges(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Vec<String>> {
    let mut kinds = Vec::new();
    for kind in SUMMARY_MEMBER_EDGE_KINDS {
        if has_any_edge_in_txn(vault, txn, EdgeDirection::In, id, kind)?
            || has_any_edge_in_txn(vault, txn, EdgeDirection::Out, id, kind)?
        {
            kinds.push(kind.name().to_owned());
        }
    }
    Ok(kinds)
}
