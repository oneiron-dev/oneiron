//! Anchored review outcomes feed the shared measured-state projector.
use super::*;
use crate::learning::{LearningEvidence, Observation};
use crate::ports::EntityStore;
use crate::side_table::{self, Raw, SideTable};

mod settled_actor;

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
    /// outcome (FIX 12106): the review's own actor, the one that wrote the
    /// review and its automatic outcomes, under the run attempt and
    /// authority frontier it carried (FIX 12188).
    Review,
}

/// [`record_review_outcome`] in the caller's transaction, every check read in
/// its snapshot, for a caller whose own write settles the outcome (FIX 2970).
/// A critique holds one standing outcome: a later outcome with another value,
/// such as a later settlement with another anchor or a replaced held-out
/// result, supersedes the one that stood (FIX 12160). Its calibration evidence
/// is kept under the critique's own receipt, so it reads the standing outcome
/// only, or the fact the critique's kept dissent settled, which outranks it
/// (FIX 12190). It keeps no dissent: an overruled critique's dissent opens writes of
/// its own, which [`record_review_outcome`] runs after its commit and the
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
    let standing = standing_outcome_in_txn(vault, txn, &session, verdict_claim, artifact_id)?;
    let (id, replaced) = match standing {
        Some((id, body)) if body.value == outcome_value => (id, false),
        standing => {
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
            body.evidence = Some(Value::from(outcome_key(verdict_claim, artifact_id)));
            body.scope = Some(Value::from(super::findings::finding_key(&artifact)));
            body.session_tag = Some(session.to_hex());
            let actor = match writer {
                OutcomeWriter::Owner(_) => {
                    write_claim(vault, txn, &id, &body, actor, at)?;
                    actor
                }
                OutcomeWriter::Review => settled_actor::write_settled_outcome_in_txn(
                    vault, txn, &id, &body, actor, at,
                )?,
            };
            if let Some((old, _)) = &standing {
                let old_start = vault
                    .port_entity_get(txn, old)?
                    .ok_or(Error::EntityNotFound)?
                    .occurred
                    .start;
                vault.supersede_claim_in_txn_as(txn, &id, old, at.max(old_start), Some(actor))?;
            }
            (id, standing.is_some())
        }
    };
    let outcome = StandingOutcome {
        id,
        anchor,
        accepted,
    };
    if !record_outcome_evidence_in_txn(vault, txn, verdict_claim, &artifact, &outcome, at)?
        && replaced
    {
        // A replacement the gate holds is not evidence yet, and the outcome
        // it closed stands no more (FIX 12160).
        crate::learning::evidence::withdraw_evidence_in_txn(
            vault,
            txn,
            &artifact.calibration,
            &calibration_receipt(verdict_claim, artifact_id),
            at,
        )?;
    }
    Ok(id)
}

/// A critique's standing outcome claim, as its calibration evidence records it.
struct StandingOutcome {
    id: EntityId,
    anchor: crate::learning::Anchor,
    accepted: bool,
}

/// The `review.outcome` key of `artifact`, a critique of the review `verdict`.
fn outcome_key(verdict: &EntityId, artifact: &str) -> String {
    format!("{}:{artifact}", verdict.to_hex())
}

/// The trusted, surfaceable `review.outcome` of the critique `artifact` of
/// the review `verdict` in `session`: the one that stands, since a later
/// outcome supersedes it (FIX 12160).
fn standing_outcome_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    session: &EntityId,
    verdict: &EntityId,
    artifact: &str,
) -> Result<Option<(EntityId, ClaimBody)>> {
    let key = Value::from(outcome_key(verdict, artifact));
    for id in vault.claims_for_subject_in_txn(txn, session)? {
        let Some(body) = vault.get_claim_in_txn(txn, &id)? else {
            continue;
        };
        if crate::claim::claim_surfaceable(&body)
            && trusted_claim(vault, txn, &id, &body)?
            && body.predicate == "review.outcome"
            && candidate_evidence(&body) == Some(&key)
        {
            return Ok(Some((id, body)));
        }
    }
    Ok(None)
}

/// Records `outcome` as the calibration evidence of the critique `artifact`
/// of the review `verdict`, on its critic's cell, under the critique's own
/// receipt, which replaces any outcome evidence it held. A fact the
/// critique's kept dissent settled outranks its outcome (FIX 12190): a
/// receipt holding that world-outcome evidence keeps it, and this gives back
/// true. A verdict still waiting for its owner's answer is not evidence:
/// then nothing is recorded, and it gives back false.
fn record_outcome_evidence_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    verdict: &EntityId,
    artifact: &CritiqueArtifact,
    outcome: &StandingOutcome,
    at: u64,
) -> Result<bool> {
    let receipt = calibration_receipt(verdict, &artifact.artifact_id);
    if crate::learning::evidence::EVIDENCE
        .get(
            &vault.store,
            txn,
            &(artifact.calibration.digest(), receipt.clone()),
        )?
        .is_some_and(|row| row.anchor == crate::learning::Anchor::WorldOutcome)
    {
        return Ok(true);
    }
    if !crate::gate::claim_consolidation_eligible_in_txn(
        &vault.store,
        txn,
        &outcome.id,
        crate::gate::ConsolidationReader::CriticOutcome,
    )? {
        return Ok(false);
    }
    let evidence_at = vault
        .port_entity_get(txn, &outcome.id)?
        .ok_or(Error::EntityNotFound)?
        .occurred
        .start;
    crate::learning::record_evidence_in_txn(
        vault,
        txn,
        &artifact.calibration,
        &LearningEvidence::anchored(
            receipt,
            evidence_at,
            outcome.anchor,
            Observation::Success(outcome.accepted),
        ),
        at,
    )?;
    Ok(true)
}

/// The standing `review.outcome` `id` when it owes its critique's
/// calibration evidence (FIX 12159): it is eligible now, and its critic's
/// cell holds no evidence under the critique's receipt. An outcome the write
/// gate held when it was recorded owes it once it is released. Gives back
/// the review's verdict, the critique and the outcome; `None` when the
/// outcome does not stand or owes nothing.
fn owed_outcome_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(EntityId, CritiqueArtifact, StandingOutcome)>> {
    let Some(body) = vault.get_claim_in_txn(txn, id)? else {
        return Ok(None);
    };
    if body.predicate != "review.outcome"
        || !crate::claim::claim_surfaceable(&body)
        || !trusted_claim(vault, txn, id, &body)?
    {
        return Ok(None);
    }
    let Some((verdict, artifact_id)) = candidate_evidence(&body)
        .and_then(Value::as_str)
        .and_then(|key| key.split_once(':'))
    else {
        return Ok(None);
    };
    let verdict = EntityId::from_hex(verdict)?;
    let artifact = persisted_artifact_in_txn(vault, txn, &verdict, artifact_id)?;
    let receipt = calibration_receipt(&verdict, artifact_id);
    if crate::learning::evidence::EVIDENCE
        .get(&vault.store, txn, &(artifact.calibration.digest(), receipt))?
        .is_some()
        || !crate::gate::claim_consolidation_eligible_in_txn(
            &vault.store,
            txn,
            id,
            crate::gate::ConsolidationReader::CriticOutcome,
        )?
    {
        return Ok(None);
    }
    let (source, accepted) = outcome_of(&body.value)?;
    let outcome = StandingOutcome {
        id: *id,
        anchor: source.anchor()?,
        accepted,
    };
    Ok(Some((verdict, artifact, outcome)))
}

/// The source and acceptance a `review.outcome` value records.
fn outcome_of(value: &Value) -> Result<(ReliabilityOutcomeSource, bool)> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| invalid_critic_config("review outcome value"))?;
    rmp_serde::from_slice(&bytes).map_err(|_| invalid_critic_config("review outcome value"))
}

/// Records the calibration evidence every standing critique outcome still
/// owes (FIX 12159), each in its own write: an outcome the write gate held
/// is finished at the measured-state sweep after its release. An outcome
/// that does not read or record warns, and the sweep goes on.
pub(super) fn finish_owed_outcomes(vault: &Vault, at: u64) -> Result<()> {
    let owed = {
        let txn = vault.store.env.read_txn()?;
        let outcomes =
            crate::claim::claim_ids_for_predicate_in_txn(&vault.store, &txn, "review.outcome")?;
        let mut owed = Vec::new();
        for id in outcomes {
            match owed_outcome_in_txn(vault, &txn, &id) {
                Ok(Some(_)) => owed.push(id),
                Ok(None) => {}
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    "a critique's outcome did not read; its evidence waits"
                ),
            }
        }
        owed
    };
    for id in owed {
        let recorded = vault.with_write_txn_grouped(|txn| {
            let Some((verdict, artifact, outcome)) = owed_outcome_in_txn(vault, txn, &id)? else {
                return Ok(false);
            };
            record_outcome_evidence_in_txn(vault, txn, &verdict, &artifact, &outcome, at)
        });
        if let Err(error) = recorded {
            tracing::warn!(
                kind = ?error.kind(),
                "a critique's outcome evidence was not recorded; the sweep goes on"
            );
        }
    }
    Ok(())
}

/// Withdraws the world-outcome evidence a settled fact gave the critique
/// `artifact` of the review `verdict`, once the fact's calibration pairs are
/// gone, and in the same write records the evidence the critique's standing
/// outcome owes in its place (FIX 12219). Calibration reads that outcome at
/// once, not only after the next sweep, and under the critique's one
/// receipt, so it is counted once. An outcome that does not read or record
/// warns, and the withdraw stands.
pub(super) fn withdraw_fact_evidence(
    vault: &Vault,
    verdict: &EntityId,
    artifact: &CritiqueArtifact,
    at: u64,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        crate::learning::evidence::withdraw_evidence_in_txn(
            vault,
            txn,
            &artifact.calibration,
            &calibration_receipt(verdict, &artifact.artifact_id),
            at,
        )?;
        let mut savepoint = vault.store.env.nested_write_txn(txn)?;
        match restore_outcome_evidence_in_txn(vault, &mut savepoint, verdict, artifact, at) {
            Ok(()) => savepoint.commit()?,
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "a critique's outcome evidence was not restored after its fact went; the next sweep records it"
            ),
        }
        Ok(())
    })
}

/// Records the evidence the standing outcome of the critique `artifact` of
/// the review `verdict` owes, as [`finish_owed_outcomes`] records it; a
/// critique with no standing outcome, or one that owes none, records nothing.
fn restore_outcome_evidence_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    verdict: &EntityId,
    artifact: &CritiqueArtifact,
    at: u64,
) -> Result<()> {
    let Some(body) = vault.get_claim_in_txn(txn, verdict)? else {
        return Ok(());
    };
    let Some(session) = body.session_tag.as_deref() else {
        return Ok(());
    };
    let session = EntityId::from_hex(session)?;
    let Some((id, _)) =
        standing_outcome_in_txn(vault, txn, &session, verdict, &artifact.artifact_id)?
    else {
        return Ok(());
    };
    let Some((verdict, artifact, outcome)) = owed_outcome_in_txn(vault, txn, &id)? else {
        return Ok(());
    };
    record_outcome_evidence_in_txn(vault, txn, &verdict, &artifact, &outcome, at)?;
    Ok(())
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
    let raw = vault.get_raw_in(wtxn, id)?.ok_or(Error::EntityNotFound)?;
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
    for ((digest, receipt), row) in crate::skill_attribution::erase_scan_in_txn(vault, wtxn, table)?
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
                let raw = vault.get_raw_in(wtxn, &id)?.ok_or(Error::EntityNotFound)?;
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
