//! The owner's per-item cleanup decision (FIX 1758): one complete verdict,
//! an Accept or a Reject for every slot of one open proposal, committed in
//! one write.
//!
//! Accepted live slots go through the stale-candidate guard a whole accept
//! runs. Rejected slots archive nothing and pin nothing, and are recorded as
//! rejected, never as skipped. A verdict that accepts something records one
//! digest, and one run snapshot when anything archived. A verdict that
//! accepts nothing records no digest, as a whole reject. Either way the
//! proposal is consumed and its review reaches the oversight ledger once.
//! Whole-proposal accept and reject stay as they are.

use super::codec_receipts::PROPOSAL;
use super::review_types::{
    CleanupDecideRequest, CleanupDecideView, CleanupItemChoice, CleanupItemDecision,
    CleanupItemOutcome, CleanupItemResult,
};
use super::review_view::{proposal_not_open, review_revision_in_txn};
use super::run_snapshot::{self, CleanupRunSnapshot};
use super::{
    CleanupCandidate, CleanupDecision, CleanupDigest, CleanupProposal, apply_archives_in_txn,
    cleanup_posture_in_txn, decode_proposal, fresh_row_id, live_slots, put_digest_in_txn,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, MaintenanceError, Result};
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult,
};

/// What a decision came to inside its write.
pub(super) enum Decided {
    /// Committed.
    Done(CleanupDecideView),
    /// The verdict is not one choice per slot; nothing was written.
    Invalid(String),
    /// The review changed since the caller's `expected_revision`, now this
    /// revision; nothing was written.
    Changed(String),
}

impl Decided {
    /// The answer a transport returns for `decided`.
    pub(super) fn answer(
        decided: Result<Self>,
        proposal: &EntityId,
    ) -> MemoryResult<CleanupDecideView> {
        match decided {
            Ok(Self::Done(view)) => Ok(view),
            Ok(Self::Invalid(message)) => Err(MemoryError::new(
                MEMORY_CODE_BAD_REQUEST,
                message,
                &["Send exactly one choice for every slot the review lists."],
            )),
            Ok(Self::Changed(current)) => Err(MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                format!(
                    "cleanup proposal {} changed since its review (revision now {current}); \
                     review again",
                    proposal.to_hex()
                ),
                &["Review the proposal again and decide on what it shows now."],
            )),
            Err(Error::Maintenance(MaintenanceError::VaultCleanupProposalNotFound { .. })) => {
                Err(proposal_not_open(proposal))
            }
            Err(error) => Err(MemoryError::from(error)),
        }
    }
}

/// Decides `input` in the caller's write transaction. A verdict that is not
/// one choice per slot, or a review that changed since the caller's
/// `expected_revision`, writes nothing.
///
/// # Errors
///
/// [`MaintenanceError::VaultCleanupProposalNotFound`] when no such proposal
/// is open; storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub(super) fn decide_cleanup_proposal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    input: &CleanupDecideRequest,
) -> Result<Decided> {
    let Some(raw) = PROPOSAL.get(&vault.store, wtxn, &input.proposal)? else {
        return Err(Error::Maintenance(
            MaintenanceError::VaultCleanupProposalNotFound {
                proposal: input.proposal.to_hex(),
            },
        ));
    };
    let row = decode_proposal(input.proposal, &raw)?;
    let choices = match verdict(row.candidates.len(), &input.choices) {
        Ok(choices) => choices,
        Err(message) => return Ok(Decided::Invalid(message)),
    };
    if let Some(expected) = &input.expected_revision {
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Ok(Decided::Invalid(
                "expected_revision must be the review's 64-hex revision".to_owned(),
            ));
        }
        let current = review_revision_in_txn(vault, wtxn, &raw, &row)?;
        if !expected.eq_ignore_ascii_case(&current) {
            return Ok(Decided::Changed(current));
        }
    }
    let at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for (candidate, choice) in row.candidates.iter().zip(&choices) {
        match (candidate, choice) {
            (Some(candidate), CleanupItemDecision::Accept) => accepted.push(*candidate),
            (Some(candidate), CleanupItemDecision::Reject) => rejected.push(candidate.entity),
            // An erased slot names no one: nothing is looked up for it.
            (None, _) => {}
        }
    }
    let (digest, archived) = if accepted.is_empty() {
        (None, Vec::new())
    } else {
        let (digest, archived) =
            archive_accepted_in_txn(vault, wtxn, &row, &accepted, rejected, at)?;
        (Some(digest), archived)
    };
    PROPOSAL.delete(&vault.store, wtxn, &row.id)?;
    // The owner's verdict is the proposal's review, and it reached a person.
    crate::failure_ladder::oversight::reviewed_in_txn(
        vault,
        wtxn,
        &row.id.to_hex(),
        row.created_at,
        at,
        true,
    )?;
    Ok(Decided::Done(CleanupDecideView {
        proposal: row.id,
        items: outcomes(&row, &choices, &archived),
        digest,
    }))
}

/// Archives the accepted slots and records the decision's one digest, with
/// the rejected ids, and the run's snapshot when anything archived. Answers
/// the digest and the ids archived, in slot order.
fn archive_accepted_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    row: &CleanupProposal,
    accepted: &[CleanupCandidate],
    rejected: Vec<EntityId>,
    at: u64,
) -> Result<(EntityId, Vec<EntityId>)> {
    let applied = apply_archives_in_txn(vault, wtxn, &row.attempt, accepted)?;
    let digest = CleanupDigest {
        id: fresh_row_id(vault)?,
        attempt: Some(row.attempt),
        proposal: Some(row.id),
        // The owner accepted part of the proposal: what he rejected rides
        // `rejected`, under the same decision.
        decision: CleanupDecision::ProposalAccepted,
        posture: cleanup_posture_in_txn(vault, wtxn)?,
        at,
        archived: live_slots(applied.archived.clone()),
        skipped: live_slots(applied.skipped),
        rejected: live_slots(rejected),
    };
    put_digest_in_txn(vault, wtxn, &digest)?;
    run_snapshot::record_accept_in_txn(
        vault,
        wtxn,
        row,
        &CleanupRunSnapshot {
            at,
            decision: CleanupDecision::ProposalAccepted,
            digest: digest.id,
            entries: live_slots(applied.entries),
        },
    )?;
    Ok((digest.id, applied.archived))
}

/// The verdict as one choice per slot, in slot order; why not when a choice
/// names a slot past the proposal, names one twice, or a slot has none.
fn verdict(
    slots: usize,
    choices: &[CleanupItemChoice],
) -> std::result::Result<Vec<CleanupItemDecision>, String> {
    let mut chosen: Vec<Option<CleanupItemDecision>> = vec![None; slots];
    for choice in choices {
        let Some(place) = chosen.get_mut(choice.slot) else {
            return Err(format!(
                "slot {} is past the proposal's {slots} slots",
                choice.slot
            ));
        };
        if place.replace(choice.decision).is_some() {
            return Err(format!("slot {} is chosen twice", choice.slot));
        }
    }
    chosen
        .into_iter()
        .enumerate()
        .map(|(slot, choice)| {
            choice.ok_or_else(|| format!("slot {slot} has no choice: a verdict names every slot"))
        })
        .collect()
}

/// Each slot's outcome. `archived` holds the accepted slots that archived, in
/// slot order, so an accepted slot archived exactly when it is the next one.
fn outcomes(
    row: &CleanupProposal,
    choices: &[CleanupItemDecision],
    archived: &[EntityId],
) -> Vec<CleanupItemOutcome> {
    let mut archived = archived.iter().peekable();
    row.candidates
        .iter()
        .zip(choices)
        .enumerate()
        .map(|(slot, (candidate, choice))| {
            let outcome = match (candidate, choice) {
                (None, _) => CleanupItemResult::Erased,
                (Some(_), CleanupItemDecision::Reject) => CleanupItemResult::Rejected,
                (Some(candidate), CleanupItemDecision::Accept) => {
                    if archived.next_if_eq(&&candidate.entity).is_some() {
                        CleanupItemResult::Archived
                    } else {
                        CleanupItemResult::Skipped
                    }
                }
            };
            CleanupItemOutcome {
                slot,
                entity: candidate.as_ref().map(|candidate| candidate.entity),
                kind: candidate.as_ref().map(|candidate| candidate.kind),
                outcome,
            }
        })
        .collect()
}
