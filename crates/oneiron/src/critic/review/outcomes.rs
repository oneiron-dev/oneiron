//! Anchored review outcomes feed the shared measured-state projector.
use super::*;
use crate::learning::{LearningEvidence, Observation};
use crate::ports::EntityStore;
use crate::side_table::{self, Raw, SideTable};

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
    let outcome = vault.with_write_txn_grouped(|txn| {
        record_review_outcome_in_txn(
            vault,
            txn,
            &result.verdict_claim,
            OutcomeWriter::Owner(actor),
            artifact_id,
            source,
            accepted,
            at,
        )
    })?;
    if !accepted {
        preserve_review_dissent(vault, result, artifact_id, at)?;
    }
    Ok(outcome)
}

/// Who writes a critique's outcome claim.
#[derive(Debug, Clone, Copy)]
pub(super) enum OutcomeWriter {
    /// The owner's own act: an active human owner, checked here.
    Owner(WriteActor),
    /// An anchored settlement no owner decided, such as a held-out team
    /// outcome (FIX 12106): the review's own principal, the actor that wrote
    /// the review and its automatic outcomes.
    Review,
}

/// [`record_review_outcome`] in the caller's transaction, every check read in
/// its snapshot, for a caller whose own write settles the outcome (FIX 2970).
/// It keeps no dissent: an overruled critique's dissent opens writes of its
/// own, which [`record_review_outcome`] runs after its commit and the
/// measured-state sweep keeps for every other writer (FIX 12105).
#[allow(clippy::too_many_arguments)]
pub(super) fn record_review_outcome_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    verdict_claim: &EntityId,
    writer: OutcomeWriter,
    artifact_id: &str,
    source: ReliabilityOutcomeSource,
    accepted: bool,
    at: u64,
) -> Result<EntityId> {
    let anchor = source.anchor()?;
    let verdict = vault
        .get_claim_in_txn(txn, verdict_claim)?
        .ok_or(Error::EntityNotFound)?;
    if verdict.predicate != "review.verdict" {
        return Err(invalid_critic_config("outcome requires review verdict"));
    }
    if !trusted_claim(vault, txn, verdict_claim, &verdict)? {
        return Err(invalid_critic_config(
            "outcome requires a producer-bound review",
        ));
    }
    let session = EntityId::from_hex(
        verdict
            .session_tag
            .as_deref()
            .ok_or_else(|| invalid_critic_config("review has no session bundle"))?,
    )?;
    let artifact = persisted_artifact_in_txn(vault, txn, verdict_claim, artifact_id)?;
    let stored = CritiqueArtifactStore::new(vault)
        .get_in_txn(txn, artifact.branch_attempt, artifact_id)?
        .ok_or(Error::EntityNotFound)?;
    if stored != artifact
        || candidate_evidence(&verdict) != Some(&Value::from(artifact.run_id.clone()))
    {
        return Err(invalid_critic_config(
            "outcome does not cite this persisted review",
        ));
    }
    let actor = match writer {
        OutcomeWriter::Owner(actor) if active_owner(vault, txn, actor) => actor,
        OutcomeWriter::Owner(_) => {
            return Err(invalid_critic_config(
                "review outcome requires an active human owner",
            ));
        }
        OutcomeWriter::Review => review_actor_in_txn(vault, txn, verdict_claim)?,
    };
    let outcome_value = value_of(&(source, accepted))?;
    let outcome_key = format!("{}:{artifact_id}", verdict_claim.to_hex());
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
                calibration_receipt(verdict_claim, artifact_id),
                evidence_at,
                anchor,
                Observation::Success(accepted),
            ),
            at,
        )?;
    }
    Ok(id)
}

/// Whether `actor` is an active human owner of the vault.
fn active_owner(vault: &Vault, txn: &heed::RoTxn<'_>, actor: WriteActor) -> bool {
    actor.actor_class() == crate::EdgeActorClass::Human
        && crate::memory::verify_owner_actor_binding_in_txn(vault, txn, actor.entity_ref())
            .is_ok()
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

/// The trust stamp of a rewritten outcome claim, the same table its producer writes.
const OUTCOME_TRUST: SideTable<EntityId, [u8; 32], Raw> =
    SideTable::new(&side_table::CRITIC_REVIEW_CLAIM_TRUST);

/// Applies the erase's artifact rename map to every review outcome's evidence key and
/// to the learning rows citing those artifacts (FIX 11368): an outcome key cites its
/// artifact, and a calibration receipt cites it again in the evidence ledger and heads.
pub(crate) fn rewrite_outcome_artifact_ids_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    renamed: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    rewrite_outcome_keys_in_txn(vault, wtxn, renamed)?;
    rewrite_learning_receipts_in_txn(vault, wtxn, renamed)?;
    rewrite_learning_head_citations_in_txn(vault, wtxn, renamed)
}

/// Re-keys the artifact suffix of every `review.outcome` evidence key the map renames.
fn rewrite_outcome_keys_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    renamed: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    let mut ids = Vec::new();
    vault.for_each_claim_with_predicate_in_txn(wtxn, "review.outcome", |id, _| {
        ids.push(id);
        Ok(())
    })?;
    for id in ids {
        let Some(mut body) = vault.get_claim_in_txn(wtxn, &id)? else {
            continue;
        };
        let Some(rmpv::Value::Map(entries)) = body.evidence.as_mut() else {
            continue;
        };
        let mut changed = false;
        for (key, value) in entries.iter_mut() {
            if key.as_str() != Some("candidate_evidence") {
                continue;
            }
            let Some(text) = value.as_str().map(str::to_owned) else {
                continue;
            };
            let Some((verdict, artifact)) = text.rsplit_once(':') else {
                continue;
            };
            if let Some(new) = renamed.get(artifact) {
                *value = rmpv::Value::from(format!("{verdict}:{new}"));
                changed = true;
            }
        }
        if !changed {
            continue;
        }
        rewrite_outcome_claim_in_txn(vault, wtxn, &id, &body)?;
    }
    Ok(())
}

/// Writes `body` over outcome claim `id` in place, its header times kept, its trust
/// stamp re-hashed.
fn rewrite_outcome_claim_in_txn(
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
    OUTCOME_TRUST.put(&vault.store, wtxn, id, digest.as_bytes())?;
    Ok(())
}

/// Moves every learning evidence row whose receipt cites a renamed artifact to its
/// re-keyed receipt (FIX 11368): the receipt is the row's key suffix.
fn rewrite_learning_receipts_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    renamed: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    let table = crate::learning::evidence::EVIDENCE;
    for ((digest, receipt), row) in
        crate::skill_attribution::erase_scan_in_txn(vault, wtxn, table)?
    {
        let Some((prefix, artifact)) = receipt.rsplit_once(':') else {
            continue;
        };
        let Some(new) = renamed.get(artifact) else {
            continue;
        };
        let moved = (digest, format!("{prefix}:{new}"));
        table.delete(&vault.store, wtxn, &(digest, receipt))?;
        table.put(&vault.store, wtxn, &moved, &row)?;
    }
    Ok(())
}

/// Re-keys the artifact suffix of every learning head citation the map renames (FIX
/// 11368): heads cite each counted receipt, calibration receipts among them.
fn rewrite_learning_head_citations_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    renamed: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    for predicate in crate::learning::LEARNING_PREDICATES {
        let mut after = None;
        loop {
            let page = crate::claim::claim_ids_for_predicate_page_in_txn(
                &vault.store,
                wtxn,
                predicate,
                after,
                256,
            )?;
            let Some(last) = page.last().copied() else {
                break;
            };
            after = Some(last);
            for id in page {
                let Some(mut body) = vault.get_claim_in_txn(wtxn, &id)? else {
                    continue;
                };
                let Some(rmpv::Value::Array(cited)) = body.evidence.as_mut() else {
                    continue;
                };
                let mut changed = false;
                for receipt in cited.iter_mut() {
                    let Some(text) = receipt.as_str().map(str::to_owned) else {
                        continue;
                    };
                    let Some((prefix, artifact)) = text.rsplit_once(':') else {
                        continue;
                    };
                    if let Some(new) = renamed.get(artifact) {
                        *receipt = rmpv::Value::from(format!("{prefix}:{new}"));
                        changed = true;
                    }
                }
                if !changed {
                    continue;
                }
                let raw = vault
                    .get_raw_in(wtxn, &id)?
                    .ok_or(Error::EntityNotFound)?;
                let header = crate::batch::EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("learning head header"))?;
                vault.put_reserved_claim_in_txn(
                    wtxn,
                    &id,
                    &body,
                    crate::temporal::TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    header.learned_at,
                )?;
            }
        }
    }
    Ok(())
}
