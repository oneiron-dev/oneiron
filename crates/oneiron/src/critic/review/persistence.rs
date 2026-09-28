//! Transactional review bundles. Every public claim goes through the write gate.
use super::*;
use crate::side_table::{self, Named, Raw, SideTable};

/// Cached review verdict/triage/artifacts for a review request, keyed by a hash of the request's
/// identity tuple. Key: hash32.
const RESULT: SideTable<[u8; 32], StoredReview, Named> =
    SideTable::new(&side_table::CRITIC_REVIEW_RESULT);

/// Index from a review verdict claim id back to its [`RESULT`] row key: the exact bytes
/// [`RESULT::key_bytes`](SideTable::key_bytes) gives for the hash, unchanged since before the
/// typed door. Key: id16.
const RESULT_ID: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::CRITIC_REVIEW_RESULT_ID);

/// Blake3 stamp of a written claim body, used to detect a review verdict claim edited outside its
/// producer. Key: id16.
const CLAIM_TRUST: SideTable<EntityId, [u8; 32], Raw> =
    SideTable::new(&side_table::CRITIC_REVIEW_CLAIM_TRUST);

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
            let key = CritiqueArtifactKey {
                branch_attempt: artifact.branch_attempt,
                artifact_id: artifact.artifact_id.clone(),
            };
            if let Some(held) = CRITIQUE_ARTIFACT.get(&vault.store, txn, &key)?
                && held != *artifact
            {
                return Err(invalid_critic_config("review artifact id already used"));
            }
            CRITIQUE_ARTIFACT.put(&vault.store, txn, &key, artifact)?;
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
        let hash = review_identity_hash(request)?;
        RESULT.put(&vault.store, txn, &hash, &stored)?;
        RESULT_ID.put(&vault.store, txn, &id, &RESULT.key_bytes(&hash))?;
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
    CLAIM_TRUST.put(&vault.store, txn, id, digest.as_bytes())?;
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
/// The [`RESULT`] table's key: a blake3 hash of the review request's identity tuple.
fn review_identity_hash(request: &ReviewRequest) -> Result<[u8; 32]> {
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
    Ok(*blake3::hash(&bytes).as_bytes())
}
pub(super) fn cached_review(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &ReviewRequest,
) -> Result<Option<ReviewResult>> {
    let Some(stored) = RESULT.get(&vault.store, txn, &review_identity_hash(request)?)? else {
        return Ok(None);
    };
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
/// Calibration is node-local derived state, like the private critic artifacts it folds.
/// A synced or raw claim is not a calibration event and cannot train this projector.
pub(super) fn trusted_claim(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<bool> {
    let Some(held) = CLAIM_TRUST.get(&vault.store, txn, id)? else {
        return Ok(false);
    };
    Ok(held == *blake3::hash(&crate::claim::encode_claim_body(body)?).as_bytes())
}

pub(super) fn persisted_artifact(
    vault: &Vault,
    verdict: &EntityId,
    artifact_id: &str,
) -> Result<CritiqueArtifact> {
    let txn = vault.store.env.read_txn()?;
    let pointer = RESULT_ID
        .get(&vault.store, &txn, verdict)?
        .ok_or(Error::EntityNotFound)?;
    let hash: [u8; 32] = pointer
        .strip_prefix(RESULT.decl().prefix)
        .and_then(|hash| hash.try_into().ok())
        .ok_or(Error::EntityNotFound)?;
    let stored = RESULT
        .get(&vault.store, &txn, &hash)?
        .ok_or(Error::EntityNotFound)?;
    if stored.verdict != verdict.to_hex() {
        return Err(Error::CorruptedIndex("review result identity"));
    }
    stored
        .artifacts
        .into_iter()
        .find(|artifact| artifact.artifact_id == artifact_id && !artifact.out_of_scope)
        .ok_or_else(|| invalid_critic_config("artifact is not a finding in this persisted review"))
}
