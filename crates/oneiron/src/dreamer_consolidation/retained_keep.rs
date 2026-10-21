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
//! owner approves it there it stands as a member the conflict names. After a
//! revert it is staged at a fresh id like any landing, and its provenance
//! links it to the marker and its selector, so it is a member all the same
//! and stands for that alternative (FIX 6152). The owner may approve such a
//! staged member and keep it in one step, beside the plain Approve and Keep
//! (FIX 6151).

use super::retained_conflict::{RetainedAlternative, retained_alternatives};
use super::settle::{
    ConflictSettleReceipt, MATERIALIZED_KEY, OpenConflict, SettledConflict, marker_ids, string_at,
};
use super::support::invalid_consolidation;
use crate::claim::{
    ClaimApprovalStatus, ClaimLifecycleStatus, PREDICATE_CONFLICT_RESOLVED, claim_surfaceable,
};
use crate::dreamer_promotion::{KeptConflictLink, KeptLanding};
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

/// What the reverted settlements of a conflict left of its retained
/// alternatives, each as (selector, claim).
#[derive(Debug, Default)]
pub(super) struct RevertedKeeps {
    /// The landings those settlements made, each retracted with its answer
    /// and no longer standing: a Keep after them lands afresh (FIX 5752).
    pub(super) landings: Vec<(EntityId, EntityId)>,
    /// The Keeps staged since in their import's review, each linked to the
    /// marker by its provenance (FIX 6152): a member standing for its
    /// alternative.
    pub(super) staged: Vec<(EntityId, EntityId)>,
}

/// What the reverted settlements of `marker`, on `subject`, left of its
/// retained alternatives: each landing they made while it no longer stands,
/// by the answers the owner retracted that name one, and each Keep staged
/// since that names the marker.
pub(super) fn reverted_keeps_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    marker: EntityId,
    subject: EntityId,
) -> Result<RevertedKeeps> {
    let mut kept = RevertedKeeps::default();
    for id in vault.claims_for_subject_in_txn(txn, &subject)? {
        let Some(claim) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if let Some(link) = KeptConflictLink::of_claim(&claim) {
            if link.marker == marker {
                kept.staged.push((link.selector, id));
            }
            continue;
        }
        if claim.predicate != PREDICATE_CONFLICT_RESOLVED
            || claim.lifecycle != ClaimLifecycleStatus::Retracted
            || !marker_ids(&claim.value, "open_marker").any(|named| named == marker)
        {
            continue;
        }
        let Some(resolution) = string_at(&claim.value, "resolution") else {
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
        kept.landings.push((selector, landed));
    }
    Ok(kept)
}

/// The retained alternatives a responder may keep: each one no member
/// stands in for, by its own id or as a staged Keep of it, with the
/// reverted landings made of it.
pub(super) fn keepable(
    alternatives: Vec<RetainedAlternative>,
    members: &[EntityId],
    kept: &RevertedKeeps,
) -> Vec<RetainedAlternative> {
    alternatives
        .into_iter()
        .filter(|alternative| {
            !members.contains(&alternative.id)
                && !kept
                    .staged
                    .iter()
                    .any(|(selector, _)| *selector == alternative.id)
        })
        .map(|mut alternative| {
            alternative.landings = kept
                .landings
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
/// a revert took a landing of it back, or stages it in its import's review
/// at that same id, linked to `marker` and the alternative so it stays a
/// member of the conflict (FIX 6152).
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
    let link = KeptConflictLink {
        marker,
        selector: alternative.id,
    };
    match super::retained_conflict::land_in_txn(vault, txn, alternative, landing, link, now)? {
        KeptLanding::Landed => Ok(KeptAlternative::Landed(landing)),
        KeptLanding::ImportReview(review) => Ok(KeptAlternative::ImportReview(StagedKeep {
            marker,
            alternative: alternative.id,
            staged: landing,
            review,
        })),
    }
}

impl OpenConflict {
    /// Refuses unless `staged` is a Keep of this conflict still waiting in
    /// its import's review (FIX 6151): a member, active and Proposed, staged
    /// at a retained alternative's own id or linked to this marker by its
    /// provenance. An ApproveAndKeep approves and keeps only such a claim.
    pub(crate) fn staged_keep_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        staged: EntityId,
    ) -> Result<()> {
        let body = vault
            .get_claim_in_txn(txn, &staged)?
            .filter(|_| self.members.contains(&staged))
            .ok_or_else(|| {
                invalid_consolidation("the staged claim is not a member of the conflict")
            })?;
        let kept_here = KeptConflictLink::of_claim(&body)
            .is_some_and(|link| link.marker == self.marker)
            || retained_alternatives(&self.body.value)
                .iter()
                .any(|alternative| alternative.id == staged);
        if !kept_here
            || body.approval != ClaimApprovalStatus::Proposed
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            return Err(invalid_consolidation(
                "no Keep of this conflict waits in its review there",
            ));
        }
        Ok(())
    }
}
