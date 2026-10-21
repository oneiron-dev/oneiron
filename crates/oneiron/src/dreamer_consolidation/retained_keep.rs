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
//!
//! A staged Keep the owner declines there stays a member, but it stands for
//! nothing (FIX 7072): its alternative is keepable again unless another Keep
//! of it still waits or stands, and an explicit Keep stages it afresh, at a
//! fresh id. The declined claim never reopens and is never approved, and
//! nothing stages it again on its own: the Dreamer's ruling never offers it.

use super::retained_conflict::{RetainedAlternative, retained_alternatives};
use super::settle::{
    ConflictSettleReceipt, MATERIALIZED_KEY, OpenConflict, SettledConflict, marker_ids, string_at,
};
use super::support::invalid_consolidation;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, PREDICATE_CONFLICT_RESOLVED,
    claim_surfaceable,
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

/// What a conflict's earlier Keeps left of its retained alternatives, each
/// as (selector, claim).
#[derive(Debug, Default)]
pub(super) struct KeepHistory {
    /// The landings reverted settlements made, each retracted with its
    /// answer and no longer standing: a Keep after them lands afresh (FIX
    /// 5752).
    pub(super) landings: Vec<(EntityId, EntityId)>,
    /// The Keeps staged in their import's review, each linked to the marker
    /// by its provenance (FIX 6152): a member standing for its alternative.
    pub(super) staged: Vec<(EntityId, EntityId)>,
    /// Those of the staged Keeps the owner declined there (FIX 7072): still
    /// members, standing for nothing, so a Keep after them stages afresh.
    pub(super) declined: Vec<(EntityId, EntityId)>,
}

/// What the earlier Keeps of `marker`, on `subject`, left of its retained
/// alternatives. After a reverted settlement: each landing those
/// settlements made while it no longer stands, by the answers the owner
/// retracted that name one, and each Keep staged since that names the
/// marker. With none reverted, a Keep is staged at a fresh id only after the
/// owner declined one staged at its alternative's own id, which the marker
/// names among `named` (FIX 7072): only then are the subject's staged Keeps
/// read, and a subject that does not read leaves the history as it stood
/// before, the declined Keep still standing in for its alternative.
pub(super) fn keep_history_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    marker: EntityId,
    subject: EntityId,
    named: &[EntityId],
    reverted: bool,
) -> Result<KeepHistory> {
    if reverted {
        return subject_keeps_in_txn(vault, txn, marker, subject, true);
    }
    let mut declined_named = false;
    for id in named {
        if vault
            .get_claim_in_txn(txn, id)?
            .is_some_and(|claim| declined_keep_of(&claim, marker))
        {
            declined_named = true;
            break;
        }
    }
    if !declined_named {
        return Ok(KeepHistory::default());
    }
    Ok(
        subject_keeps_in_txn(vault, txn, marker, subject, false).unwrap_or_else(|error| {
            tracing::warn!(
                target: "oneiron::dreamer",
                kind = ?error.kind(),
                marker = %marker.to_hex(),
                "a declined Keep's history did not read; its alternative stays as it stood"
            );
            KeepHistory::default()
        }),
    )
}

/// Whether `claim` is a Keep of `marker`'s retained alternative, staged in
/// its import's review, that the owner declined there (FIX 7072).
fn declined_keep_of(claim: &ClaimBody, marker: EntityId) -> bool {
    claim.approval == ClaimApprovalStatus::Rejected
        && KeptConflictLink::of_claim(claim).is_some_and(|link| link.marker == marker)
}

/// The subject's claims read for [`keep_history_in_txn`]: each staged Keep
/// that names `marker`, declined or not, and, with `landings`, each landing
/// a reverted settlement of it made.
fn subject_keeps_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    marker: EntityId,
    subject: EntityId,
    landings: bool,
) -> Result<KeepHistory> {
    let mut kept = KeepHistory::default();
    for id in vault.claims_for_subject_in_txn(txn, &subject)? {
        let Some(claim) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if let Some(link) = KeptConflictLink::of_claim(&claim) {
            if link.marker == marker {
                kept.staged.push((link.selector, id));
                if claim.approval == ClaimApprovalStatus::Rejected {
                    kept.declined.push((link.selector, id));
                }
            }
            continue;
        }
        if !landings
            || claim.predicate != PREDICATE_CONFLICT_RESOLVED
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
/// reverted landings made of it and the staged Keeps of it the owner
/// declined. A declined Keep stays a member but stands in for nothing (FIX
/// 7072): its alternative is keepable again unless another Keep of it still
/// waits or stands.
pub(super) fn keepable(
    alternatives: Vec<RetainedAlternative>,
    members: &[EntityId],
    kept: &KeepHistory,
) -> Vec<RetainedAlternative> {
    let declined = |id: &EntityId| kept.declined.iter().any(|(_, claim)| claim == id);
    alternatives
        .into_iter()
        .filter(|alternative| {
            (!members.contains(&alternative.id) || declined(&alternative.id))
                && !kept
                    .staged
                    .iter()
                    .any(|(selector, staged)| *selector == alternative.id && !declined(staged))
        })
        .map(|mut alternative| {
            alternative.landings = of_selector(&kept.landings, alternative.id);
            alternative.declined = of_selector(&kept.declined, alternative.id);
            alternative
        })
        .collect()
}

/// The claims of `kept` made of the alternative `selector`.
fn of_selector(kept: &[(EntityId, EntityId)], selector: EntityId) -> Vec<EntityId> {
    kept.iter()
        .filter(|(of, _)| *of == selector)
        .map(|(_, claim)| *claim)
        .collect()
}

/// Keeps `alternative` of the conflict `marker` in the settlement's
/// transaction: lands it at its own id the first time, at a fresh id after
/// a revert took a landing of it back or the owner declined a Keep of it
/// staged in its import's review (FIX 7072), or stages it in its import's
/// review at that same id, linked to `marker` and the alternative so it
/// stays a member of the conflict (FIX 6152).
pub(super) fn keep_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    marker: EntityId,
    alternative: &RetainedAlternative,
    now: u64,
) -> Result<KeptAlternative> {
    let landing = if alternative.landings.is_empty() && alternative.declined.is_empty() {
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
