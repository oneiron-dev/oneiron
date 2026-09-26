//! TASK-lane receipt pump: capture once, route, then resume both idempotent projections.

use super::codec::{decode_u64, evidence_after, validate_evidence};
use super::projector::record_evidence_in_txn;
use super::{
    AttemptOutcome, AttributionJudge, FollowedState, OutcomeEvidence, RuleAttributionJudge,
    attribution_judgments, read_attribution_cursor, run_attribution_projector_with_judge,
};
use crate::attempt_queue::ManifestEntry;
use crate::receipt::{ReceiptRecord, attempt_pack_receipt_page};
use crate::{EntityId, Error, Result, Vault};

const SCAN_CURSOR: &[u8] = b"skill_attribution:sweep_scan:v1";
const APPLIED_CURSOR: &[u8] = b"skill_attribution:sweep_applied:v1";
const CAPTURED_PREFIX: &[u8] = b"skill_attribution:sweep_receipt:v1:";

/// Facts that a receipt does not carry. Hosts must resolve real actor/skill IDs;
/// neither a lease-owner string nor listing a tier-1 skill proves contribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptAttributionFacts {
    pub actor: EntityId,
    pub skill: Option<EntityId>,
    pub followed_state: FollowedState,
    pub skill_covered_step: bool,
}

pub trait ReceiptAttributionSource {
    /// `None` means facts are not yet available, not an abstention to spend forever.
    fn facts(&self, receipt: &ReceiptRecord) -> Result<Option<Vec<ReceiptAttributionFacts>>>;
}

#[derive(Debug, Default)]
pub struct AttributionSweepReport {
    pub scanned: usize,
    pub captured_evidence: usize,
    pub judgments: usize,
    pub skills: Vec<EntityId>,
    pub actor_claims: Vec<EntityId>,
    pub deferred: Vec<String>,
    pub failures: Vec<(String, Error)>,
}

/// One bounded receipt page. The rule judge stays the default; fact resolution is
/// a host seam because execution/coverage facts cannot be invented from a failure.
pub fn run_task_attribution_sweep(
    vault: &Vault,
    limit: usize,
    source: &dyn ReceiptAttributionSource,
) -> Result<AttributionSweepReport> {
    run_task_attribution_sweep_with_judge(vault, limit, source, &RuleAttributionJudge)
}

pub fn run_task_attribution_sweep_with_judge(
    vault: &Vault,
    limit: usize,
    source: &dyn ReceiptAttributionSource,
    judge: &dyn AttributionJudge,
) -> Result<AttributionSweepReport> {
    let after = {
        let txn = vault.store.env.read_txn()?;
        vault
            .store
            .vault_meta
            .get(&txn, SCAN_CURSOR)?
            .map(|raw| {
                String::from_utf8(raw.to_vec())
                    .map_err(|_| Error::CorruptedIndex("attribution scan cursor"))
            })
            .transpose()?
    };
    let (receipts, complete) = attempt_pack_receipt_page(vault, after.as_deref(), limit)?;
    let mut report = AttributionSweepReport {
        scanned: receipts.len(),
        ..Default::default()
    };
    for receipt in &receipts {
        let outcome = match receipt.outcome.as_str() {
            "completed" => AttemptOutcome::Succeeded,
            "failed" => AttemptOutcome::Failed,
            _ => continue, // cancellation and abandonment are not evidence of blame
        };
        match capture_receipt(vault, receipt, outcome, source) {
            Ok(Some(count)) => report.captured_evidence += count,
            Ok(None) => report.deferred.push(receipt.receipt_id.clone()),
            Err(error) => report.failures.push((receipt.receipt_id.clone(), error)),
        }
    }
    // A crash before this cursor repeats captures safely. A full pass wraps, so
    // late terminal receipts and temporarily unknown facts are retried as well.
    vault.with_write_txn(|txn| {
        if complete {
            vault.store.vault_meta.delete(txn, SCAN_CURSOR)?;
        } else if let Some(last) = receipts.last() {
            vault
                .store
                .vault_meta
                .put(txn, SCAN_CURSOR, last.receipt_id.as_bytes())?;
        }
        Ok(())
    })?;
    let applied = {
        let txn = vault.store.env.read_txn()?;
        vault
            .store
            .vault_meta
            .get(&txn, APPLIED_CURSOR)?
            .map(|raw| decode_u64(&raw, "attribution applied cursor"))
            .transpose()?
            .unwrap_or(0)
    };
    run_attribution_projector_with_judge(vault, read_attribution_cursor(vault)?, judge)?;
    let routed = read_attribution_cursor(vault)?;
    let judgments: Vec<_> = attribution_judgments(vault)?
        .into_iter()
        .filter(|row| row.sequence > applied && row.sequence <= routed)
        .collect();
    report.judgments = judgments.len();
    report.skills = crate::skill_reliability::project_skill_reliability(vault, &judgments)?;
    report.actor_claims =
        crate::actor_claims::project_actor_claims_from_judgments(vault, &judgments)?;
    for (sequence, evidence) in evidence_after(vault, applied)? {
        if sequence <= routed
            && evidence.outcome == AttemptOutcome::Succeeded
            && (matches!(evidence.followed_state, Some(FollowedState::Followed))
                || evidence.followed_state.is_none() && evidence.followed_skill == Some(true))
            && let Some(skill) = evidence.skill
        {
            crate::skill_reliability::record_skill_contributing_win(
                vault,
                &skill,
                &evidence.receipt_ref,
                evidence.at,
            )?;
            crate::skill_reliability::project_skill_reliability_for(vault, &skill, evidence.at)?;
            if !report.skills.contains(&skill) {
                report.skills.push(skill);
            }
        }
    }
    // Separate from routing: an interrupted projector must be retried from durable
    // judgments, not silently skipped merely because the judge advanced its cursor.
    vault.with_write_txn(|txn| {
        let held = vault
            .store
            .vault_meta
            .get(txn, APPLIED_CURSOR)?
            .map(|raw| decode_u64(&raw, "attribution applied cursor"))
            .transpose()?
            .unwrap_or(0);
        vault
            .store
            .vault_meta
            .put(txn, APPLIED_CURSOR, &held.max(routed).to_be_bytes())?;
        Ok(())
    })?;
    Ok(report)
}

fn capture_receipt(
    vault: &Vault,
    receipt: &ReceiptRecord,
    outcome: AttemptOutcome,
    source: &dyn ReceiptAttributionSource,
) -> Result<Option<usize>> {
    let mut key = CAPTURED_PREFIX.to_vec();
    key.extend_from_slice(receipt.receipt_id.as_bytes());
    {
        let txn = vault.store.env.read_txn()?;
        if vault.store.vault_meta.get(&txn, &key)?.is_some() {
            return Ok(Some(0));
        }
    }
    let Some(facts) = source.facts(receipt)? else {
        return Ok(None);
    };
    if facts.len() > 64 {
        return Err(Error::InvalidConfig(
            "too many attribution facts for one receipt".to_owned(),
        ));
    }
    // A partial host answer must not mark this receipt captured forever. The
    // terminal manifest is the authority on which tier-2 skills were loaded.
    if let Some(manifest) = receipt.pack_manifest_skills() {
        let loaded = manifest
            .iter()
            .map(|wire| {
                ManifestEntry::parse_wire_form(wire)
                    .map(|(reference, _)| reference.to_owned())
                    .ok_or(Error::InvalidConfig(
                        "invalid skill manifest reference".to_owned(),
                    ))
            })
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        let named = facts
            .iter()
            .map(|fact| {
                let skill = fact.skill.ok_or(Error::InvalidConfig(
                    "attribution fact must name a loaded skill".to_owned(),
                ))?;
                vault
                    .get_skill_record(&skill)?
                    .map(|record| record.skill_id)
                    .ok_or(Error::InvalidConfig(
                        "attribution fact names an unknown skill".to_owned(),
                    ))
            })
            .collect::<Result<Vec<_>>>()?;
        let unique_named: std::collections::BTreeSet<_> = named.iter().cloned().collect();
        if unique_named != loaded || unique_named.len() != named.len() {
            return Err(Error::InvalidConfig(
                "attribution facts must cover every loaded skill exactly once".to_owned(),
            ));
        }
    }
    let mut unique = std::collections::BTreeSet::new();
    let mut evidence = Vec::new();
    for fact in facts {
        if !unique.insert((fact.actor, fact.skill)) {
            return Err(Error::InvalidConfig(
                "duplicate receipt attribution subject".to_owned(),
            ));
        }
        let mut row = OutcomeEvidence::new(
            &receipt.receipt_id,
            fact.actor,
            outcome,
            receipt.occurred_at,
        )
        .with_followed_state(fact.followed_state);
        row.skill_covered_step = Some(fact.skill_covered_step);
        row.skill = fact.skill;
        validate_evidence(vault, &row)?;
        evidence.push(row);
    }
    vault.with_write_txn(|txn| {
        if vault.store.vault_meta.get(txn, &key)?.is_some() {
            return Ok(Some(0));
        }
        for row in &evidence {
            record_evidence_in_txn(vault, txn, row)?;
        }
        vault.store.vault_meta.put(txn, &key, &[1])?;
        Ok(Some(evidence.len()))
    })
}
