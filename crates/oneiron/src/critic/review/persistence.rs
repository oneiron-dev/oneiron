//! Transactional review bundles. Every public claim goes through the write gate.
use super::*;
use crate::batch::secret_scan::{admitted_from, named_tree};
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
    vault.with_write_txn_grouped(|txn| {
        if let Some(result) = cached_review(vault, txn, request)? {
            return Ok(result);
        }
        // OF-067: each artifact as the side-row wall keeps it, so its row, the cached review
        // and the result handed back carry the same handles. A held row stands for an artifact
        // it holds with handles where this one holds the secrets.
        let mut artifacts = artifacts.to_vec();
        for artifact in &mut artifacts {
            if artifact.out_of_scope {
                continue;
            }
            let key = CritiqueArtifactKey {
                branch_attempt: artifact.branch_attempt,
                artifact_id: artifact.artifact_id.clone(),
            };
            if let Some(held) = CRITIQUE_ARTIFACT.get(&vault.store, txn, &key)? {
                if held != *artifact && !admitted_from(&named_tree(&held)?, &named_tree(&*artifact)?)? {
                    return Err(invalid_critic_config("review artifact id already used"));
                }
                *artifact = held;
                continue;
            }
            CRITIQUE_ARTIFACT.admit(vault, txn, &key, artifact)?;
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
        )?;
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
            )?;
            body.session_tag = Some(request.session.to_hex());
            body.evidence = Some(Value::from(finding.key.clone()));
            write_claim(vault, txn, &outcome_id, &body, request.actor, request.at)?;
        }
        let result = ReviewResult {
            verdict_claim: id,
            triage: triage.clone(),
            artifacts: artifacts.clone(),
            receipts: Vec::new(),
        };
        let stored = StoredReview {
            principal: request.actor.entity_ref(),
            dissent: BTreeMap::new(),
            verdict: id.to_hex(),
            triage: triage.clone(),
            artifacts,
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
    artifacts: &[CritiqueArtifact],
) -> Result<Vec<CriticReliability>> {
    let mut rows = BTreeMap::new();
    for artifact in artifacts.iter().filter(|artifact| !artifact.out_of_scope) {
        let cell = &artifact.calibration;
        if rows.contains_key(&cell.digest()) {
            continue;
        }
        let estimate = crate::learning::read_learning(vault, cell, &[])?.estimate;
        rows.insert(
            cell.digest(),
            CriticReliability::new(cell.clone(), estimate)?,
        );
    }
    Ok(rows.into_values().collect())
}

#[derive(Serialize, Deserialize)]
struct StoredReview {
    principal: EntityId,
    dissent: BTreeMap<String, ReviewDissent>,
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
        &request.type_ref,
        &request.axis,
        request
            .critics
            .iter()
            .map(|critic| {
                (
                    &critic.lens_id,
                    critic.lens_ref,
                    critic.actor.entity_ref(),
                    critic.actor.actor_class() as u8,
                )
            })
            .collect::<Vec<_>>(),
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
        receipts: Vec::new(),
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

/// Resume partial dissent retention without creating a second note or question.
pub(super) fn dissent_state(
    vault: &Vault,
    verdict: &EntityId,
    artifact: &str,
) -> Result<(EntityId, ReviewDissent, CritiqueVerdict)> {
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
    let state = stored
        .dissent
        .get(artifact)
        .cloned()
        .unwrap_or_else(|| ReviewDissent {
            artifact_id: artifact.to_owned(),
            note: None,
            question: None,
            settled_fact: None,
        });
    Ok((stored.principal, state, stored.triage.verdict))
}

pub(super) fn save_dissent(vault: &Vault, verdict: &EntityId, state: &ReviewDissent) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        let hash = result_hash(vault, txn, verdict)?;
        let mut stored = RESULT
            .get(&vault.store, txn, &hash)?
            .ok_or(Error::EntityNotFound)?;
        stored
            .dissent
            .insert(state.artifact_id.clone(), state.clone());
        RESULT.put(&vault.store, txn, &hash, &stored)
    })
}

fn result_hash(vault: &Vault, txn: &heed::RoTxn<'_>, verdict: &EntityId) -> Result<[u8; 32]> {
    let pointer = RESULT_ID
        .get(&vault.store, txn, verdict)?
        .ok_or(Error::EntityNotFound)?;
    pointer
        .strip_prefix(RESULT.decl().prefix)
        .and_then(|hash| hash.try_into().ok())
        .ok_or(Error::CorruptedIndex("review result identity"))
}

pub(super) fn reviews_with_dissent(vault: &Vault) -> Result<Vec<ReviewResult>> {
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
        .map(|(_, stored)| {
            Ok(ReviewResult {
                verdict_claim: EntityId::from_hex(&stored.verdict)?,
                triage: stored.triage,
                artifacts: stored.artifacts,
                receipts: Vec::new(),
            })
        })
        .collect()
}
