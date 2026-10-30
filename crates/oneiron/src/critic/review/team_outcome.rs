//! The critics of a settled team's work (OF-420, FIX 2970, FIX 12106). A
//! team's anchored outcome is the outcome of every critique a persisted
//! review gave of the work it judged: the deliverable claim the owner ruled
//! on, the team's bound deliverables a held-out outcome settles, a
//! tournament's winner. Every settlement names those critics on its outcome
//! the one way [`name_deliverable_critics_in_txn`] reads them, where the
//! TrustedCritic decision of the type tree reads them, and records each
//! critique's outcome against its own critic's reliability cell. Work no
//! critic reviewed records nothing new.
use super::outcomes::OutcomeWriter;
use super::*;
use crate::team::{TeamCritic, TeamOutcome};

/// Names on `outcome` the critics whose persisted reviews judged
/// `deliverables`, the work the outcome settles, and gives those reviews
/// back for [`record_deliverable_outcomes_in_txn`]. The critics come from
/// the store, never from the settler. `None` (and critics unknown) when the
/// reviews do not read: the settlement they ride never fails on them.
pub(crate) fn name_deliverable_critics_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    deliverables: &[EntityId],
    outcome: &mut TeamOutcome,
) -> Option<Vec<ReviewResult>> {
    let reviews = deliverable_reviews_in_txn(vault, txn, deliverables);
    outcome.critics = reviews.as_deref().map(deliverable_critics);
    reviews
}

/// The persisted reviews of `deliverables`: each trusted, active
/// `review.verdict` about one of them, with its stored critiques, once.
fn deliverable_reviews_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    deliverables: &[EntityId],
) -> Option<Vec<ReviewResult>> {
    let mut reviews = Vec::new();
    for deliverable in deliverables.iter().collect::<std::collections::BTreeSet<_>>() {
        match reviews_of_in_txn(vault, txn, deliverable) {
            Ok(of) => reviews.extend(of),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the reviews of a team's deliverable did not read; its outcome names no critic"
                );
                return None;
            }
        }
    }
    Some(reviews)
}

fn reviews_of_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    deliverable: &EntityId,
) -> Result<Vec<ReviewResult>> {
    let mut reviews = Vec::new();
    for id in vault.claims_for_subject_in_txn(txn, deliverable)? {
        let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if body.predicate != "review.verdict" {
            continue;
        }
        if let Some(review) = trusted_review_in_txn(vault, txn, &id, deliverable)? {
            reviews.push(review);
        }
    }
    Ok(reviews)
}

/// The critics `reviews` hold: one per in-scope critique, its lens skill and
/// executor as its reliability cell keys them. A critique whose cell names
/// no executor names no critic.
fn deliverable_critics(reviews: &[ReviewResult]) -> Vec<TeamCritic> {
    let mut critics = Vec::new();
    for review in reviews {
        for artifact in review.artifacts.iter().filter(|artifact| !artifact.out_of_scope) {
            let Some(executor) = artifact.calibration.executor.clone() else {
                continue;
            };
            critics.push(TeamCritic {
                review: review.verdict_claim,
                artifact_id: artifact.artifact_id.clone(),
                lens: artifact.calibration.subject,
                executor,
                verdict: artifact.verdict,
            });
        }
    }
    critics
}

/// Records `outcome` on the work `reviews` judged as the anchored outcome of
/// each in-scope critique, on that critic's own cell. A critique is upheld
/// when it accepted work that succeeded, or asked to revise or discard work
/// that failed. `owner` is the principal whose verdict the outcome is, the
/// actor of each record; with none, the review's own principal writes it.
/// An owner verdict scores as one, a held-out outcome as a held-out eval;
/// any other anchor names its critics and scores none. Each lands in its
/// own savepoint, so one that does not land never fails the settlement it
/// rides. A critique already scored by this outcome is scored once; one
/// another outcome scored is scored again, and this outcome supersedes that
/// one (FIX 12160). An outcome the write gate holds gets its evidence at the
/// measured-state sweep after its release (FIX 12159), and that sweep keeps
/// an overruled critique's dissent (FIX 12105).
pub(crate) fn record_deliverable_outcomes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    reviews: &[ReviewResult],
    outcome: &TeamOutcome,
    owner: Option<EntityId>,
) {
    let source = match outcome.anchor {
        crate::learning::Anchor::OwnerVerdict => ReliabilityOutcomeSource::OwnerVerdict,
        crate::learning::Anchor::HeldOut => ReliabilityOutcomeSource::HeldOutEval,
        _ => return,
    };
    let writer = owner.map_or(OutcomeWriter::Review, |owner| {
        OutcomeWriter::Owner(WriteActor::new(owner, crate::EdgeActorClass::Human))
    });
    for review in reviews {
        for artifact in review.artifacts.iter().filter(|artifact| !artifact.out_of_scope) {
            let upheld = (artifact.verdict == CritiqueVerdict::Accept) == outcome.success;
            let landed = vault
                .store
                .env
                .nested_write_txn(txn)
                .map_err(Error::from)
                .and_then(|mut savepoint| {
                    super::outcomes::record_review_outcome_in_txn(
                        vault,
                        &mut savepoint,
                        &review.verdict_claim,
                        writer,
                        &artifact.artifact_id,
                        source,
                        upheld,
                        outcome.at,
                    )?;
                    Ok(savepoint.commit()?)
                });
            if let Err(error) = landed {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a critique's outcome on a settled team did not land; the settlement stands"
                );
            }
        }
    }
}
