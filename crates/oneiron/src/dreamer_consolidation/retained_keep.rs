//! Keeping a conflict's retained alternative (OF-023, FIX 496): where the
//! Keep lands it, and what a Keep of imported words does instead.
//!
//! The alternative's id is its stable selector, the id a responder keeps it
//! by. A first Keep lands it at that id. A revert retracts that landing and
//! the signed claim never reopens, so a Keep after the revert lands it again
//! at a fresh id, one per settlement, which the answer links to the selector
//! and which the next revert retracts in turn (FIX 5752). A landing a
//! reverted settlement made is no member of the conflict: the alternative it
//! landed stays keepable beside the members.
//!
//! An alternative whose evidence meets at `Imported` never lands Auto. Its
//! Keep stages it in the review of the import its words came from, as a
//! promotion of those words is, and settles nothing: no answer is written,
//! no member is superseded, and the marker stays open (FIX 5754). Once the
//! owner approves it there it stands as a member the conflict names.

use super::retained_conflict::RetainedAlternative;
use super::settle::{
    ConflictSettleReceipt, MATERIALIZED_KEY, SettledConflict, marker_ids, string_at,
};
use super::support::invalid_consolidation;
use crate::claim::{ClaimLifecycleStatus, PREDICATE_CONFLICT_RESOLVED, claim_surfaceable};
use crate::dreamer_promotion::KeptLanding;
use crate::{EntityId, Result, Vault};

/// The resolution key naming the retained alternative a landing was made
/// of: its selector.
pub(super) const SELECTOR_KEY: &str = "selector";

/// A Keep of a retained alternative from imported words, staged in its
/// import's review: the conflict stays open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedKeep {
    pub marker: EntityId,
    /// The retained alternative the Keep named.
    pub alternative: EntityId,
    /// The claim staged Proposed in the review.
    pub staged: EntityId,
    /// The import review it waits in; `None` when it waits with its round's
    /// run.
    pub review: Option<String>,
}

/// A responder's settlement as it stands: applied, or a kept alternative
/// staged in its import's review with the conflict left open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictSettleOutcome {
    Settled(ConflictSettleReceipt),
    ImportReviewPending {
        staged: StagedKeep,
        /// The Gate receipt naming the responder's Keep.
        receipt_ref: String,
    },
}

/// What applying a settlement wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SettlementApplied {
    Settled(SettledConflict),
    ImportReviewPending(StagedKeep),
}

/// Where a Keep put a retained alternative.
pub(super) enum KeptAlternative {
    /// Landed and standing at this id.
    Landed(EntityId),
    ImportReview(StagedKeep),
}

/// The landings reverted settlements of `marker`, on `subject`, made of its
/// retained alternatives, as (selector, landing): each answer the owner
/// retracted that names one, while that landing no longer stands.
pub(super) fn reverted_landings_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    marker: EntityId,
    subject: EntityId,
) -> Result<Vec<(EntityId, EntityId)>> {
    let mut landings = Vec::new();
    for id in vault.claims_for_subject_in_txn(txn, &subject)? {
        let Some(answer) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if answer.predicate != PREDICATE_CONFLICT_RESOLVED
            || answer.lifecycle != ClaimLifecycleStatus::Retracted
            || !marker_ids(&answer.value, "open_marker").any(|named| named == marker)
        {
            continue;
        }
        let Some(resolution) = string_at(&answer.value, "resolution") else {
            continue;
        };
        let Some(landed) = marker_ids(resolution, MATERIALIZED_KEY).next() else {
            continue;
        };
        if vault
            .get_claim_in_txn(txn, &landed)?
            .is_some_and(|body| claim_surfaceable(&body))
        {
            continue;
        }
        let selector = marker_ids(resolution, SELECTOR_KEY)
            .next()
            .unwrap_or(landed);
        landings.push((selector, landed));
    }
    Ok(landings)
}

/// The retained alternatives a responder may keep: each one no member
/// stands in for, with the reverted landings made of it.
pub(super) fn keepable(
    alternatives: Vec<RetainedAlternative>,
    members: &[EntityId],
    landings: &[(EntityId, EntityId)],
) -> Vec<RetainedAlternative> {
    alternatives
        .into_iter()
        .filter(|alternative| !members.contains(&alternative.id))
        .map(|mut alternative| {
            alternative.landings = landings
                .iter()
                .filter(|(selector, _)| *selector == alternative.id)
                .map(|(_, landed)| *landed)
                .collect();
            alternative
        })
        .collect()
}

/// Keeps `alternative` of the conflict `marker` in the settlement's
/// transaction: lands it at its own id the first time, at a fresh id after
/// a revert took a landing of it back, or stages it in its import's review.
/// Words from an import a revert already landed refuse as before: a staged
/// copy at a fresh id would stand apart from the conflict.
pub(super) fn keep_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    marker: EntityId,
    alternative: &RetainedAlternative,
    now: u64,
) -> Result<KeptAlternative> {
    let landing = if alternative.landings.is_empty() {
        alternative.id
    } else {
        EntityId::now()
    };
    match super::retained_conflict::land_in_txn(vault, txn, alternative, landing, now)? {
        KeptLanding::Landed => Ok(KeptAlternative::Landed(landing)),
        KeptLanding::ImportReview(review) if landing == alternative.id => {
            Ok(KeptAlternative::ImportReview(StagedKeep {
                marker,
                alternative: alternative.id,
                staged: landing,
                review,
            }))
        }
        KeptLanding::ImportReview(_) => Err(invalid_consolidation(
            "an alternative from imported words lands only through its import's review",
        )),
    }
}
