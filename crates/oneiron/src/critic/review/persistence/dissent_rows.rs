//! A review's dissent rows: the dissent each critique keeps so far, the
//! claim one caller holds while it authors that dissent (FIX 12161), and the
//! reviews whose dissent is kept or still owed (FIX 12105). Moved whole from
//! persistence.rs, which keeps the stored review itself.

use super::*;

/// Resume partial dissent retention without creating a second note or question: the
/// review's principal, the class it authenticated as when the review kept one, the
/// dissent so far and the triage verdict.
pub(in crate::critic::review) fn dissent_state(
    vault: &Vault,
    verdict: &EntityId,
    artifact: &str,
) -> Result<(
    EntityId,
    Option<crate::EdgeActorClass>,
    ReviewDissent,
    CritiqueVerdict,
)> {
    let txn = vault.store.env.read_txn()?;
    let body = vault
        .get_claim_in_txn(&txn, verdict)?
        .ok_or(Error::EntityNotFound)?;
    if !trusted_claim(vault, &txn, verdict, &body)? {
        return Err(invalid_critic_config(
            "dissent requires a producer-bound review",
        ));
    }
    let hash = result_hash(vault, &txn, verdict)?;
    let stored = RESULT
        .get(&vault.store, &txn, &hash)?
        .ok_or(Error::EntityNotFound)?;
    let state = dissent_of(&stored, artifact);
    let class = stored
        .principal_class
        .and_then(crate::EdgeActorClass::try_from_u8);
    Ok((stored.principal, class, state, stored.triage.verdict))
}

/// The dissent `stored` keeps for `artifact` so far.
fn dissent_of(stored: &StoredReview, artifact: &str) -> ReviewDissent {
    stored
        .dissent
        .get(artifact)
        .cloned()
        .unwrap_or_else(|| ReviewDissent {
            artifact_id: artifact.to_owned(),
            note: None,
            question: None,
            settled_fact: None,
        })
}

/// Claims the dissent of the critique `artifact` of the review `verdict` for
/// this process run before any of it is authored (FIX 12161). The check and
/// the claim are one write, so of two callers keeping one dissent at once,
/// the second finds it taken and authors nothing. Gives back the dissent so
/// far, or `None` when another caller in this run holds it; a dissent kept
/// in full is given back unclaimed. A claim an earlier run left, stopped by
/// a crash, is taken over.
pub(in crate::critic::review) fn claim_dissent(
    vault: &Vault,
    verdict: &EntityId,
    artifact: &str,
) -> Result<Option<ReviewDissent>> {
    vault.with_write_txn_grouped(|txn| {
        let hash = result_hash(vault, txn, verdict)?;
        let mut stored = RESULT
            .get(&vault.store, txn, &hash)?
            .ok_or(Error::EntityNotFound)?;
        let state = dissent_of(&stored, artifact);
        if state.note.is_some() && state.question.is_some() {
            return Ok(Some(state));
        }
        if stored.dissent_claims.get(artifact) == Some(&this_run()) {
            return Ok(None);
        }
        stored
            .dissent_claims
            .insert(artifact.to_owned(), this_run());
        RESULT.put(vault, txn, &hash, &stored)?;
        Ok(Some(state))
    })
}

/// Drops this run's claim on the dissent of `artifact` once its authoring
/// ends, kept or not.
pub(in crate::critic::review) fn release_dissent_claim(
    vault: &Vault,
    verdict: &EntityId,
    artifact: &str,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let hash = result_hash(vault, txn, verdict)?;
        let mut stored = RESULT
            .get(&vault.store, txn, &hash)?
            .ok_or(Error::EntityNotFound)?;
        if stored.dissent_claims.get(artifact) == Some(&this_run()) {
            stored.dissent_claims.remove(artifact);
            RESULT.put(vault, txn, &hash, &stored)?;
        }
        Ok(())
    })
}

/// This process run, the holder a dissent claim names: a claim that names
/// another run was left by a run that stopped.
fn this_run() -> EntityId {
    static RUN: std::sync::OnceLock<EntityId> = std::sync::OnceLock::new();
    *RUN.get_or_init(EntityId::now)
}

pub(in crate::critic::review) fn save_dissent(
    vault: &Vault,
    verdict: &EntityId,
    state: &ReviewDissent,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let hash = result_hash(vault, txn, verdict)?;
        let mut stored = RESULT
            .get(&vault.store, txn, &hash)?
            .ok_or(Error::EntityNotFound)?;
        stored
            .dissent
            .insert(state.artifact_id.clone(), state.clone());
        RESULT.put(vault, txn, &hash, &stored)
    })
}

pub(in crate::critic::review) fn reviews_with_dissent(vault: &Vault) -> Result<Vec<ReviewResult>> {
    let txn = vault.store.env.read_txn()?;
    RESULT
        .scan_from(&vault.store, &txn, &[])?
        .into_iter()
        .filter(|(_, stored)| {
            stored
                .dissent
                .values()
                .any(|state| state.question.is_some())
        })
        .map(|(_, stored)| stored_result(stored))
        .collect()
}

/// Each stored review with its in-scope critiques that carry a prediction
/// but keep no standing question yet: the dissent an overruling triage or
/// outcome may still owe (FIX 12105, 12161).
pub(in crate::critic::review) fn reviews_with_unkept_dissent(
    vault: &Vault,
) -> Result<Vec<(ReviewResult, Vec<String>)>> {
    let txn = vault.store.env.read_txn()?;
    let mut unkept = Vec::new();
    for (_, stored) in RESULT.scan_from(&vault.store, &txn, &[])? {
        let artifacts: Vec<String> = stored
            .artifacts
            .iter()
            .filter(|artifact| {
                !artifact.out_of_scope
                    && artifact.prediction.is_some()
                    && stored
                        .dissent
                        .get(&artifact.artifact_id)
                        .is_none_or(|state| state.question.is_none())
            })
            .map(|artifact| artifact.artifact_id.clone())
            .collect();
        if !artifacts.is_empty() {
            unkept.push((stored_result(stored)?, artifacts));
        }
    }
    Ok(unkept)
}
