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
                if held != *artifact
                    && !admitted_from(&named_tree(&held)?, &named_tree(&*artifact)?)?
                {
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
            spawn_attempt: request.spawn_attempt,
        };
        let stored = StoredReview {
            principal: request.actor.entity_ref(),
            principal_class: Some(request.actor.actor_class() as u8),
            dissent: BTreeMap::new(),
            verdict: id.to_hex(),
            triage: triage.clone(),
            artifacts,
            spawn_attempt: request.spawn_attempt,
        };
        let hash = review_identity_hash(request)?;
        RESULT.put(vault, txn, &hash, &stored)?;
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
    )
    .with_confidence_details(body.confidence_details());
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
    /// The class the review's actor authenticated as, the asker class of a dissent
    /// question it keeps (FIX 1588). None on a review stored before it was kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    principal_class: Option<u8>,
    dissent: BTreeMap<String, ReviewDissent>,
    verdict: String,
    triage: CritiqueTriage,
    artifacts: Vec<CritiqueArtifact>,
    /// The launched run the review was first declared for. A review declared
    /// for none stores none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spawn_attempt: Option<EntityId>,
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
    // A project's review keys apart (FIX 6038); a vault review keeps its key.
    let mut hasher = blake3::Hasher::new();
    hasher.update(&bytes);
    if let Some(project) = request.project {
        hasher.update(project.as_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
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
        spawn_attempt: stored.spawn_attempt,
    }))
}

/// Declares the review behind `verdict` for `spawn` when it is declared for
/// no run yet, and gives back the run it is declared for: a declared review
/// keeps its first run.
pub(super) fn declare_spawn(
    vault: &Vault,
    verdict: &EntityId,
    spawn: EntityId,
) -> Result<Option<EntityId>> {
    vault.with_write_txn_grouped(|txn| {
        let hash = result_hash(vault, txn, verdict)?;
        let mut stored = RESULT
            .get(&vault.store, txn, &hash)?
            .ok_or(Error::EntityNotFound)?;
        if stored.spawn_attempt.is_none() {
            stored.spawn_attempt = Some(spawn);
            RESULT.put(vault, txn, &hash, &stored)?;
        }
        Ok(stored.spawn_attempt)
    })
}

/// One in-scope critique of a stored review declared for a launched run,
/// beside that review's verdict claim (FIX 5252): the row the critique's
/// observation derives from, `None` when the stored ref does not read.
pub(crate) struct DeclaredCritique {
    pub(crate) verdict_ref: Option<EntityId>,
    pub(crate) artifact: CritiqueArtifact,
}

/// The in-scope critiques of every stored review declared for one of `runs`,
/// by run, read in the caller's snapshot for an observation (FIX 4470): one
/// pass over every stored review, each critique validated on its own as the
/// branch store validates it and kept beside its review's verdict claim, and
/// one line naming each review, verdict ref or critique that does not read.
/// A storage fault fails the pass.
pub(crate) fn declared_critiques_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    runs: &BTreeSet<EntityId>,
) -> Result<(BTreeMap<EntityId, Vec<DeclaredCritique>>, Vec<String>)> {
    let mut found: BTreeMap<EntityId, Vec<DeclaredCritique>> = BTreeMap::new();
    let mut unread = Vec::new();
    for row in RESULT.iter_raw_from(&vault.store, txn, &[])? {
        let (key, value) = row?;
        let stored = match RESULT.decode_value(&value) {
            Ok(stored) => stored,
            Err(error) => {
                let key = crate::entity_id::bytes_to_hex_lower(&key);
                unread.push(format!(
                    "stored review {key} does not read, so the run it was declared for is unknown: {error}"
                ));
                continue;
            }
        };
        let Some(run) = stored.spawn_attempt.filter(|run| runs.contains(run)) else {
            continue;
        };
        let verdict_ref = EntityId::from_hex(&stored.verdict).ok();
        if verdict_ref.is_none() {
            unread.push(format!(
                "review {} declared for run {} keeps a verdict ref that does not read",
                stored.verdict,
                run.to_hex()
            ));
        }
        for artifact in stored.artifacts {
            if artifact.out_of_scope {
                continue;
            }
            match validate_critique_artifact(&artifact) {
                Ok(()) => found.entry(run).or_default().push(DeclaredCritique {
                    verdict_ref,
                    artifact,
                }),
                Err(error) => unread.push(format!(
                    "critique {} of review {} declared for run {} does not read: {error}",
                    artifact.artifact_id,
                    stored.verdict,
                    run.to_hex()
                )),
            }
        }
    }
    Ok((found, unread))
}

/// The verdict claim of the stored review holding each in-scope critique,
/// keyed by the critique's branch and artifact id, read in the caller's
/// snapshot (FIX 6380): the way back from a critique found on its branch to
/// the review that wrote it. A critique two reviews hold names the first in
/// stored order. One line names each review whose verdict ref does not read;
/// a review that does not decode is skipped here, as
/// [`declared_critiques_in_txn`] names it. A storage fault fails the pass.
pub(crate) fn critique_review_refs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<(BTreeMap<([u8; 16], String), EntityId>, Vec<String>)> {
    let mut refs = BTreeMap::new();
    let mut unread = Vec::new();
    for row in RESULT.iter_raw_from(&vault.store, txn, &[])? {
        let (_, value) = row?;
        let Ok(stored) = RESULT.decode_value(&value) else {
            continue;
        };
        let Ok(verdict) = EntityId::from_hex(&stored.verdict) else {
            unread.push(format!(
                "review {} keeps a verdict ref that does not read, so its critiques name no review",
                stored.verdict
            ));
            continue;
        };
        for artifact in stored.artifacts {
            if !artifact.out_of_scope {
                refs.entry((*artifact.branch_attempt.as_bytes(), artifact.artifact_id))
                    .or_insert(verdict);
            }
        }
    }
    Ok((refs, unread))
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

/// Resume partial dissent retention without creating a second note or question: the
/// review's principal, the class it authenticated as when the review kept one, the
/// dissent so far and the triage verdict.
pub(super) fn dissent_state(
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
    let class = stored
        .principal_class
        .and_then(crate::EdgeActorClass::try_from_u8);
    Ok((stored.principal, class, state, stored.triage.verdict))
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
        RESULT.put(vault, txn, &hash, &stored)
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
                spawn_attempt: stored.spawn_attempt,
            })
        })
        .collect()
}

/// The persisted review `verdict` of `target`, read back through its
/// producer's own rows (FIX 6869, G4 PR1): the verdict claim must be the
/// trusted, active `review.verdict` about `target`, and its stored result
/// must name exactly that verdict. The saved triage and artifacts come
/// from the store, never from a caller. `None` when no stored review or
/// live claim names `verdict` about `target`; a stamp or identity that no
/// longer matches its producer is an error.
pub(crate) fn trusted_review_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    verdict: &EntityId,
    target: &EntityId,
) -> Result<Option<ReviewResult>> {
    let Some(pointer) = RESULT_ID.get(&vault.store, txn, verdict)? else {
        return Ok(None);
    };
    let hash: [u8; 32] = pointer
        .strip_prefix(RESULT.decl().prefix)
        .and_then(|hash| hash.try_into().ok())
        .ok_or(Error::CorruptedIndex("review result identity"))?;
    let stored = RESULT
        .get(&vault.store, txn, &hash)?
        .ok_or(Error::CorruptedIndex("review result identity"))?;
    if stored.verdict != verdict.to_hex() {
        return Err(Error::CorruptedIndex("review result identity"));
    }
    let Some(body) = vault.get_claim_in_txn(txn, verdict)? else {
        return Ok(None);
    };
    if !trusted_claim(vault, txn, verdict, &body)? {
        return Err(Error::CorruptedIndex(
            "review verdict changed outside its producer",
        ));
    }
    if body.predicate != "review.verdict"
        || body.subject != ClaimSubject::Entity(*target)
        || body.lifecycle != ClaimLifecycleStatus::Active
    {
        return Ok(None);
    }
    Ok(Some(ReviewResult {
        verdict_claim: *verdict,
        triage: stored.triage,
        artifacts: stored.artifacts,
        receipts: Vec::new(),
        spawn_attempt: stored.spawn_attempt,
    }))
}

/// Re-keys the session tag of every review verdict and automatic outcome naming erased
/// `entity` to one fresh opaque id (FIX 11363), its trust stamp with it. Gives back the
/// verdicts it touched, for their cached rows' move.
pub(crate) fn erase_review_session_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<Vec<EntityId>> {
    let named = entity.to_hex();
    let mut opaque = None;
    let mut verdicts = Vec::new();
    for predicate in ["review.verdict", "review.automatic_outcome"] {
        let mut ids = Vec::new();
        vault.for_each_claim_with_predicate_in_txn(wtxn, predicate, |id, body| {
            if body.session_tag.as_deref() == Some(named.as_str()) {
                ids.push(id);
            }
            Ok(())
        })?;
        for id in ids {
            let Some(mut body) = vault.get_claim_in_txn(wtxn, &id)? else {
                continue;
            };
            let opaque_id = match opaque {
                Some(opaque) => opaque,
                None => {
                    let id = vault.store.clock.entity_id()?;
                    opaque = Some(id);
                    id
                }
            };
            body.session_tag = Some(opaque_id.to_hex());
            rewrite_review_claim_in_txn(vault, wtxn, &id, &body)?;
            if predicate == "review.verdict" {
                verdicts.push(id);
            }
        }
    }
    Ok(verdicts)
}

/// Applies the erase's artifact rename map to every review verdict's findings (FIX
/// 11368): the claim value names each finding's artifact ids.
pub(crate) fn rewrite_verdict_artifact_ids_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    renamed: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    let mut ids = Vec::new();
    vault.for_each_claim_with_predicate_in_txn(wtxn, "review.verdict", |id, _| {
        ids.push(id);
        Ok(())
    })?;
    for id in ids {
        let Some(mut body) = vault.get_claim_in_txn(wtxn, &id)? else {
            continue;
        };
        let mut value = body.value.clone();
        rename_value_strings(&mut value, renamed);
        if value == body.value {
            continue;
        }
        body.value = value;
        rewrite_review_claim_in_txn(vault, wtxn, &id, &body)?;
    }
    Ok(())
}

/// Writes `body` over claim `id` in place, its header times kept, its trust stamp
/// re-hashed over the rewritten bytes.
fn rewrite_review_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &crate::claim::ClaimBody,
) -> Result<()> {
    let raw = vault
        .get_raw_in(wtxn, id)?
        .ok_or(Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("review claim header"))?;
    vault.put_reserved_claim_in_txn(
        wtxn,
        id,
        body,
        crate::temporal::TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        header.learned_at,
    )?;
    let digest = blake3::hash(&crate::claim::encode_claim_body(body)?);
    CLAIM_TRUST.put(&vault.store, wtxn, id, digest.as_bytes())?;
    Ok(())
}

/// Replaces every string in `value`, map keys included, that `renamed` maps.
fn rename_value_strings(
    value: &mut rmpv::Value,
    renamed: &std::collections::BTreeMap<String, String>,
) {
    match value {
        rmpv::Value::String(text) => {
            if let Some(new) = text.as_str().and_then(|text| renamed.get(text)) {
                *value = rmpv::Value::from(new.as_str());
            }
        }
        rmpv::Value::Array(items) => {
            for item in items {
                rename_value_strings(item, renamed);
            }
        }
        rmpv::Value::Map(entries) => {
            for (key, item) in entries {
                rename_value_strings(key, renamed);
                rename_value_strings(item, renamed);
            }
        }
        _ => {}
    }
}
