//! The critics of a settled team deliverable (OF-420, FIX 2970). The owner's
//! verdict on a team's bound deliverable claim is the anchored outcome of
//! every critique a persisted review gave of that exact claim. The team's
//! settlement names those critics on its outcome, where the TrustedCritic
//! decision of the type tree reads them, and records each critique's outcome
//! against its own critic's reliability cell. A deliverable no critic
//! reviewed records nothing new.
use super::*;
use crate::team::TeamCritic;

/// The persisted reviews of `deliverable`: each trusted, active
/// `review.verdict` about it, with its stored critiques. `None` when they do
/// not read: the settlement they ride never fails on them, and its outcome
/// then names no critic.
pub(crate) fn deliverable_reviews_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    deliverable: &EntityId,
) -> Option<Vec<ReviewResult>> {
    match reviews_of_in_txn(vault, txn, deliverable) {
        Ok(reviews) => Some(reviews),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "the reviews of a team's deliverable did not read; its outcome names no critic"
            );
            None
        }
    }
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
pub(crate) fn deliverable_critics(reviews: &[ReviewResult]) -> Vec<TeamCritic> {
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

/// Records `owner`'s verdict on the deliverable `reviews` judged as the
/// anchored outcome of each in-scope critique, on that critic's own cell. A
/// critique is upheld when it accepted a deliverable the owner accepted, or
/// asked to revise or discard one the owner rejected (`accepted` false).
/// Each lands in its own savepoint, so one that does not land never fails
/// the verdict it rides. An overruled critique's dissent is not kept here.
pub(crate) fn record_deliverable_outcomes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    reviews: &[ReviewResult],
    owner: EntityId,
    accepted: bool,
    at: u64,
) {
    let actor = WriteActor::new(owner, crate::EdgeActorClass::Human);
    for review in reviews {
        for artifact in review.artifacts.iter().filter(|artifact| !artifact.out_of_scope) {
            let upheld = (artifact.verdict == CritiqueVerdict::Accept) == accepted;
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
                        actor,
                        &artifact.artifact_id,
                        ReliabilityOutcomeSource::OwnerVerdict,
                        upheld,
                        at,
                    )?;
                    Ok(savepoint.commit()?)
                });
            if let Err(error) = landed {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a critique's outcome on a settled team did not land; the verdict stands"
                );
            }
        }
    }
}
