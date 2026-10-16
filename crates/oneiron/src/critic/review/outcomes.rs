//! Anchored review outcomes feed the shared measured-state projector.
use super::*;
use crate::learning::{LearningEvidence, Observation};
use crate::ports::EntityStore;

/// Accept/dismiss a finding with an anchored outcome. Critic agreement never trains a cell.
pub fn record_review_outcome(
    vault: &Vault,
    result: &ReviewResult,
    actor: WriteActor,
    artifact_id: &str,
    source: ReliabilityOutcomeSource,
    accepted: bool,
    at: u64,
) -> Result<EntityId> {
    let anchor = source.anchor()?;
    let verdict = vault
        .get_claim(&result.verdict_claim)?
        .ok_or(Error::EntityNotFound)?;
    if verdict.predicate != "review.verdict" {
        return Err(invalid_critic_config("outcome requires review verdict"));
    }
    let session = EntityId::from_hex(
        verdict
            .session_tag
            .as_deref()
            .ok_or_else(|| invalid_critic_config("review has no session bundle"))?,
    )?;
    let artifact = persisted_artifact(vault, &result.verdict_claim, artifact_id)?;
    let stored = CritiqueArtifactStore::new(vault)
        .get(artifact.branch_attempt, artifact_id)?
        .ok_or(Error::EntityNotFound)?;
    if stored != artifact
        || candidate_evidence(&verdict) != Some(&Value::from(artifact.run_id.clone()))
    {
        return Err(invalid_critic_config(
            "outcome does not cite this persisted review",
        ));
    }
    let outcome_value = value_of(&(source, accepted))?;
    let outcome_key = format!("{}:{artifact_id}", result.verdict_claim.to_hex());
    let outcome = vault.with_write_txn_grouped(|txn| {
        let current = vault
            .get_claim_in_txn(txn, &result.verdict_claim)?
            .ok_or(Error::EntityNotFound)?;
        if current != verdict || !trusted_claim(vault, txn, &result.verdict_claim, &current)? {
            return Err(invalid_critic_config(
                "review changed during outcome admission",
            ));
        }
        if actor.actor_class() != crate::EdgeActorClass::Human
            || crate::memory::verify_owner_actor_binding_in_txn(vault, txn, actor.entity_ref())
                .is_err()
        {
            return Err(invalid_critic_config(
                "review outcome requires an active human owner",
            ));
        }
        let mut existing = None;
        for id in vault.claims_for_subject_in_txn(txn, &session)? {
            let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
                continue;
            };
            if crate::claim::claim_surfaceable(&body)
                && trusted_claim(vault, txn, &id, &body)?
                && body.predicate == "review.outcome"
                && candidate_evidence(&body) == Some(&Value::from(outcome_key.clone()))
            {
                if body.value != outcome_value {
                    return Err(invalid_critic_config("outcome already recorded"));
                }
                existing = Some(id);
                break;
            }
        }
        let id = if let Some(id) = existing {
            id
        } else {
            let id = EntityId::now();
            let mut body = ClaimBody::new(
                "review.outcome",
                ClaimSubject::Entity(session),
                outcome_value.clone(),
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )?;
            body.source = Some(ClaimSource::Observed);
            body.evidence = Some(Value::from(outcome_key.clone()));
            body.scope = Some(Value::from(super::findings::finding_key(&artifact)));
            body.session_tag = Some(session.to_hex());
            write_claim(vault, txn, &id, &body, actor, at)?;
            id
        };
        // A verdict still waiting for its owner's answer is not evidence.
        if crate::gate::claim_consolidation_eligible_in_txn(
            &vault.store,
            txn,
            &id,
            crate::gate::ConsolidationReader::CriticOutcome,
        )? {
            let evidence_at = vault
                .port_entity_get(txn, &id)?
                .ok_or(Error::EntityNotFound)?
                .occurred
                .start;
            crate::learning::record_evidence_in_txn(
                vault,
                txn,
                &artifact.calibration,
                &LearningEvidence::anchored(
                    calibration_receipt(&result.verdict_claim, artifact_id),
                    evidence_at,
                    anchor,
                    Observation::Success(accepted),
                ),
                at,
            )?;
        }
        Ok(id)
    })?;
    if !accepted {
        preserve_review_dissent(vault, result, artifact_id, at)?;
    }
    Ok(outcome)
}

pub(super) fn calibration_receipt(verdict: &EntityId, artifact: &str) -> String {
    format!("critic.review:{}:{artifact}", verdict.to_hex())
}

/// Repeated finding keys, with their anchored outcome count, for a session bundle.
pub fn recurring_findings(vault: &Vault, session: &EntityId) -> Result<Vec<(String, usize)>> {
    let mut counts = BTreeMap::<String, usize>::new();
    let txn = vault.store.env.read_txn()?;
    for id in vault.claims_for_subject_in_txn(&txn, session)? {
        let Some(body) = vault.get_claim_in_txn(&txn, &id)? else {
            continue;
        };
        if crate::claim::claim_surfaceable(&body)
            && trusted_claim(vault, &txn, &id, &body)?
            && body.predicate == "review.outcome"
            && let Some(key) = body.scope.as_ref().and_then(Value::as_str)
        {
            *counts.entry(key.to_owned()).or_default() += 1;
        }
    }
    Ok(counts.into_iter().filter(|(_, count)| *count > 1).collect())
}
