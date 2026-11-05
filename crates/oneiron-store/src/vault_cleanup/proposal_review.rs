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

use crate::vault_cleanup::cleanup_types::CleanupCandidate;
use crate::vault_cleanup::cleanup_types::CleanupDecision;
use crate::vault_cleanup::cleanup_types::CleanupDigest;
use crate::vault_cleanup::cleanup_types::CleanupKind;
use crate::vault_cleanup::cleanup_types::CleanupProposal;
use crate::vault_cleanup::cleanup_types::live_slots;
use crate::vault_cleanup::codec_receipts::decode_proposal;
use crate::vault_cleanup::review_types::CleanupDecideRequest;
use crate::vault_cleanup::review_types::CleanupDecideView;
use crate::vault_cleanup::review_types::CleanupItemChoice;
use crate::vault_cleanup::review_types::CleanupItemDecision;
use crate::vault_cleanup::review_types::CleanupItemOutcome;
use crate::vault_cleanup::review_types::CleanupItemResult;
use crate::vault_cleanup::run_snapshot::CleanupRunSnapshot;
use oneiron_base::error::Error;
use oneiron_base::error::MaintenanceError;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult,
};

/// The verdict as one choice per slot, in slot order; why not when a choice
/// names a slot past the proposal, names one twice, or a slot has none.
pub fn verdict(
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
pub fn outcomes(
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
