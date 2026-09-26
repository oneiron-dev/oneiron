//! Anchored outcomes, Beta updates and repeat-finding reads.
use super::*;

/// Accept/dismiss a finding with an anchored outcome. Automatic critic agreement is deliberately
/// not calibration evidence; only an owner verdict, held-out evaluation or BEAM outcome updates Beta.
pub fn record_review_outcome(
    vault: &Vault,
    result: &ReviewResult,
    actor: WriteActor,
    artifact_id: &str,
    source: ReliabilityOutcomeSource,
    accepted: bool,
    at: u64,
) -> Result<EntityId> {
    if !source.is_anchored() {
        return Err(invalid_critic_config("review outcome is not anchored"));
    }
    let verdict = vault
        .get_claim(&result.verdict_claim)?
        .ok_or(Error::EntityNotFound)?;
    if verdict.predicate != "review.verdict" {
        return Err(invalid_critic_config("outcome requires review verdict"));
    }
    {
        let txn = vault.store.env.read_txn()?;
        if !trusted_claim(vault, &txn, &result.verdict_claim, &verdict)? {
            return Err(invalid_critic_config(
                "outcome requires a producer-bound review verdict",
            ));
        }
    }
    let session = EntityId::from_hex(
        verdict
            .session_tag
            .as_deref()
            .ok_or_else(|| invalid_critic_config("review has no session bundle"))?,
    )?;
    let artifact = &persisted_artifact(vault, &result.verdict_claim, artifact_id)?;
    let stored = CritiqueArtifactStore::new(vault)
        .get(artifact.branch_attempt, artifact_id)?
        .ok_or(Error::EntityNotFound)?;
    if stored != *artifact || candidate_evidence(&verdict) != Some(&Value::from(stored.run_id)) {
        return Err(invalid_critic_config(
            "outcome does not cite this persisted review",
        ));
    }
    let outcome_value = value_of(&(source, accepted))?;
    let outcome_key = format!("{}:{artifact_id}", result.verdict_claim.to_hex());
    vault.with_write_txn(|txn| {
        let current = vault
            .get_claim_in_txn(txn, &result.verdict_claim)?
            .ok_or(Error::EntityNotFound)?;
        if current != verdict || !trusted_claim(vault, txn, &result.verdict_claim, &current)? {
            return Err(invalid_critic_config(
                "review changed during outcome admission",
            ));
        }
        {
            let fold = vault.authority_fold_readonly_in_txn(txn)?;
            if actor.actor_class() != crate::EdgeActorClass::Human
                || fold.vault_root_is_conflicted()
                || (fold.vault_id.is_some()
                    && !crate::authority::actor_binding_is_active(
                        &fold,
                        &actor.entity_ref(),
                        "human",
                    ))
            {
                return Err(invalid_critic_config(
                    "owner verdict requires an active human owner",
                ));
            }
        }
        let predicate = critic_reliability_predicate(&artifact.domain, &artifact.lens_id)?;
        let mut reliability = CriticReliability::prior(&artifact.lens_id, &artifact.domain)?;
        let mut old = Vec::new();
        for id in vault.claims_for_subject_in_txn(txn, &session)? {
            let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
                continue;
            };
            if !crate::claim::claim_surfaceable(&body) || !trusted_claim(vault, txn, &id, &body)? {
                continue;
            }
            if body.predicate == "review.outcome"
                && candidate_evidence(&body) == Some(&Value::from(outcome_key.clone()))
            {
                return if body.value == outcome_value {
                    Ok(id)
                } else {
                    Err(invalid_critic_config("outcome already recorded"))
                };
            }
            if body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active {
                reliability = reliability_from_body(&body, &artifact.lens_id, &artifact.domain)?;
                old.push(id);
            }
        }
        reliability.apply_outcome(ReliabilityOutcomeEvent::new(
            &artifact.lens_id,
            &artifact.domain,
            source,
            accepted,
            at,
        )?)?;
        let mut calibration = critic_reliability_claim_body(session, &reliability, 1.0)?;
        calibration.source = Some(ClaimSource::Observed);
        calibration.evidence = Some(Value::from(outcome_key.clone()));
        let calibration_id = EntityId::now();
        write_claim(vault, txn, &calibration_id, &calibration, actor, at)?;
        for id in old {
            vault.supersede_claim_in_txn(txn, &calibration_id, &id, at)?;
        }
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
        body.evidence = Some(Value::from(outcome_key));
        body.scope = Some(Value::from(super::findings::finding_key(artifact)));
        body.session_tag = Some(session.to_hex());
        write_claim(vault, txn, &id, &body, actor, at)?;
        Ok(id)
    })
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
