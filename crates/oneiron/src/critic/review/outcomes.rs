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
