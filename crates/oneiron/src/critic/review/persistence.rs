//! Transactional review bundles. Every public claim goes through the write gate.
use super::*;

pub(super) fn persist_review(
    vault: &Vault,
    request: &ReviewRequest,
    triage: &CritiqueTriage,
    artifacts: &[CritiqueArtifact],
) -> Result<ReviewResult> {
    let value = value_of(&(
        request.kind,
        triage.verdict,
        triage.auto_resolved,
        &triage.findings,
    ))?;
    vault.with_write_txn(|txn| {
        if let Some(result) = cached_review(vault, txn, request)? {
            return Ok(result);
        }
        for artifact in artifacts {
            if artifact.out_of_scope {
                continue;
            }
            let key = critique_artifact_key(artifact.branch_attempt, &artifact.artifact_id)?;
            let encoded = rmp_serde::to_vec_named(artifact)
                .map_err(|_| invalid_critic_config("review artifact encode"))?;
            if let Some(held) = vault.store.vault_meta.get(txn, &key)?
                && held != encoded
            {
                return Err(invalid_critic_config("review artifact id already used"));
            }
            vault.store.vault_meta.put(txn, &key, &encoded)?;
        }
        let id = EntityId::now();
        let mut body = ClaimBody::new(
            "review.verdict",
            ClaimSubject::Entity(request.target),
            value.clone(),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.session_tag = Some(request.session.to_hex());
        body.evidence = Some(Value::from(request.run_id.clone()));
        write_claim(vault, txn, &id, &body, request.actor, request.at)?;
        for finding in triage
            .findings
            .iter()
            .filter(|finding| finding.auto_resolved)
        {
            let outcome_id = EntityId::now();
            let mut body = ClaimBody::new(
                "review.automatic_outcome",
                ClaimSubject::Entity(id),
                value_of(&(finding.verdict, finding.confidence))?,
                1.0,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            body.session_tag = Some(request.session.to_hex());
            body.evidence = Some(Value::from(finding.key.clone()));
            write_claim(vault, txn, &outcome_id, &body, request.actor, request.at)?;
        }
        let result = ReviewResult {
            verdict_claim: id,
            triage: triage.clone(),
            artifacts: artifacts.to_vec(),
        };
        let stored = StoredReview {
            verdict: id.to_hex(),
            triage: triage.clone(),
            artifacts: artifacts.to_vec(),
        };
        let bytes = rmp_serde::to_vec_named(&stored)
            .map_err(|_| invalid_critic_config("review result encode"))?;
        vault
            .store
            .vault_meta
            .put(txn, &review_key(request)?, &bytes)?;
        vault
            .store
            .vault_meta
            .put(txn, &result_id_key(&id), &review_key(request)?)?;
        Ok(result)
    })
}

pub(super) fn candidate_evidence(body: &ClaimBody) -> Option<&Value> {
    body.evidence
        .as_ref()?
        .as_map()?
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
        .map(|(_, value)| value)
}
pub(super) fn write_claim(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    actor: WriteActor,
    at: u64,
) -> Result<()> {
    let provenance = WriteProvenance::new(Value::from("critic.review"))?;
    let mut envelope = WriteEnvelope::new(actor, ClaimSource::Observed, provenance, body.approval);
    if let Some(tag) = &body.session_tag {
        envelope = envelope.with_session_tag(tag);
    }
    let mut candidate = ClaimCandidate::new(
        &body.predicate,
        body.subject,
        body.value.clone(),
        body.confidence,
    );
    if let Some(evidence) = &body.evidence {
        candidate = candidate.with_evidence(evidence.clone());
    }
    if let Some(scope) = &body.scope {
        candidate = candidate.with_scope(scope.clone());
    }
    vault
        .batch_in()
        .claim_candidate(
            id,
            candidate,
            &envelope,
            TimeRange { start: at, end: at },
            at,
        )
        .apply(txn)?;
    let stored = vault
        .get_claim_in_txn(txn, id)?
        .ok_or(Error::EntityNotFound)?;
    let digest = blake3::hash(&crate::claim::encode_claim_body(&stored)?);
    vault
        .store
        .vault_meta
        .put(txn, &trusted_key(id), digest.as_bytes())?;
    Ok(())
}

pub(super) fn read_reliabilities(
    vault: &Vault,
    session: &EntityId,
    catalog: &LensCatalog,
) -> Result<Vec<CriticReliability>> {
    let mut rows = BTreeMap::new();
    let rtxn = vault.store.env.read_txn()?;
    for id in vault.claims_for_subject_in_txn(&rtxn, session)? {
        let Some(body) = vault.get_claim_in_txn(&rtxn, &id)? else {
            continue;
        };
        if !crate::claim::claim_surfaceable(&body) || !trusted_claim(vault, &rtxn, &id, &body)? {
            continue;
        }
        for lens in &catalog.lenses {
            if body.predicate == critic_reliability_predicate(&lens.domain, &lens.id)? {
                rows.insert(
                    (lens.domain.clone(), lens.id.clone()),
                    reliability_from_body(&body, &lens.id, &lens.domain)?,
                );
            }
        }
    }
    Ok(rows.into_values().collect())
}
pub(super) fn reliability_from_body(
    body: &ClaimBody,
    lens: &str,
    domain: &str,
) -> Result<CriticReliability> {
    let Value::Map(fields) = &body.value else {
        return Err(invalid_critic_config("invalid critic posterior"));
    };
    let field = |key| {
        fields
            .iter()
            .find(|(k, _)| k.as_str() == Some(key))
            .map(|(_, v)| v)
    };
    CriticReliability::new(
        lens,
        domain,
        field("alpha")
            .and_then(Value::as_f64)
            .ok_or_else(|| invalid_critic_config("posterior alpha"))?,
        field("beta")
            .and_then(Value::as_f64)
            .ok_or_else(|| invalid_critic_config("posterior beta"))?,
        field("observations")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_critic_config("posterior observations"))?,
    )
}

#[derive(Serialize, Deserialize)]
struct StoredReview {
    verdict: String,
    triage: CritiqueTriage,
    artifacts: Vec<CritiqueArtifact>,
}
fn review_key(request: &ReviewRequest) -> Result<Vec<u8>> {
    let bytes = rmp_serde::to_vec_named(&(
        request.target.to_hex(),
        request.kind,
        request.session.to_hex(),
        &request.run_id,
        request.branch_attempt,
        request.actor.entity_ref().to_hex(),
        request.actor.actor_class() as u8,
        request.auto_resolve_threshold,
    ))
    .map_err(|_| invalid_critic_config("review identity encode"))?;
    let mut key = b"review:result:v1:".to_vec();
    key.extend_from_slice(blake3::hash(&bytes).as_bytes());
    Ok(key)
}
pub(super) fn cached_review(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &ReviewRequest,
) -> Result<Option<ReviewResult>> {
    let Some(raw) = vault.store.vault_meta.get(txn, &review_key(request)?)? else {
        return Ok(None);
    };
    let stored: StoredReview =
        rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex("review result"))?;
    let id = EntityId::from_hex(&stored.verdict)?;
    let body = vault
        .get_claim_in_txn(txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    if !trusted_claim(vault, txn, &id, &body)? {
        return Err(Error::CorruptedIndex(
            "review verdict changed outside its producer",
        ));
    }
    Ok(Some(ReviewResult {
        verdict_claim: id,
        triage: stored.triage,
        artifacts: stored.artifacts,
    }))
}
fn trusted_key(id: &EntityId) -> Vec<u8> {
    let mut key = b"review:claim:v1:".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}
/// Calibration is node-local derived state, like the private critic artifacts it folds.
/// A synced or raw claim is not a calibration event and cannot train this projector.
pub(super) fn trusted_claim(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<bool> {
    let Some(held) = vault.store.vault_meta.get(txn, &trusted_key(id))? else {
        return Ok(false);
    };
    Ok(held.as_ref() == blake3::hash(&crate::claim::encode_claim_body(body)?).as_bytes())
}

fn result_id_key(id: &EntityId) -> Vec<u8> {
    let mut key = b"review:result_id:v1:".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}
pub(super) fn persisted_artifact(
    vault: &Vault,
    verdict: &EntityId,
    artifact_id: &str,
) -> Result<CritiqueArtifact> {
    let txn = vault.store.env.read_txn()?;
    let key = vault
        .store
        .vault_meta
        .get(&txn, &result_id_key(verdict))?
        .ok_or(Error::EntityNotFound)?;
    let raw = vault
        .store
        .vault_meta
        .get(&txn, &key)?
        .ok_or(Error::EntityNotFound)?;
    let stored: StoredReview =
        rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex("review result"))?;
    if stored.verdict != verdict.to_hex() {
        return Err(Error::CorruptedIndex("review result identity"));
    }
    stored
        .artifacts
        .into_iter()
        .find(|artifact| artifact.artifact_id == artifact_id && !artifact.out_of_scope)
        .ok_or_else(|| invalid_critic_config("artifact is not a finding in this persisted review"))
}
