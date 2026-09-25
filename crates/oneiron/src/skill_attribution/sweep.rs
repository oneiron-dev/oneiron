//! TASK-lane receipt pump: capture once, route, then resume both idempotent projections.

use super::codec::{evidence_after, validate_evidence};
use super::projector::record_evidence_in_txn;
use super::{
    AttemptOutcome, AttributionJudge, OutcomeEvidence, RuleAttributionJudge, attribution_judgments,
    read_attribution_cursor, run_attribution_projector_with_judge,
};
use crate::receipt::{ReceiptRecord, attempt_pack_receipt_page};
use crate::side_table::{self, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// Resume cursor for the in-progress task-attribution receipt-page scan. Key: ().
const SCAN_CURSOR: SideTable<(), String, side_table::Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_SWEEP_SCAN_CURSOR);

/// Highest judgment sequence the sweep has already applied. Key: ().
const APPLIED_CURSOR: SideTable<(), u64, side_table::Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_SWEEP_APPLIED_CURSOR);

/// Idempotency marker recording that a receipt's attribution evidence has
/// already been captured. Key: receipt id text.
const CAPTURED: SideTable<String, [u8; 1], side_table::Raw> =
    SideTable::new(&side_table::SKILL_ATTRIBUTION_SWEEP_RECEIPT_CAPTURED);

/// Facts that a receipt does not carry. Hosts must resolve real actor/skill IDs;
/// neither a lease-owner string nor listing a tier-1 skill proves contribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptAttributionFacts {
    pub actor: EntityId,
    pub skill: Option<EntityId>,
    pub followed_skill: bool,
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
        SCAN_CURSOR.get(&vault.store, &txn, &())?
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
            SCAN_CURSOR.delete(&vault.store, txn, &())?;
        } else if let Some(last) = receipts.last() {
            SCAN_CURSOR.put(&vault.store, txn, &(), &last.receipt_id)?;
        }
        Ok(())
    })?;
    let applied = {
        let txn = vault.store.env.read_txn()?;
        APPLIED_CURSOR.get(&vault.store, &txn, &())?.unwrap_or(0)
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
        let held = APPLIED_CURSOR.get(&vault.store, txn, &())?.unwrap_or(0);
        APPLIED_CURSOR.put(&vault.store, txn, &(), &held.max(routed))?;
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
    {
        let txn = vault.store.env.read_txn()?;
        if CAPTURED.contains(&vault.store, &txn, &receipt.receipt_id)? {
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
        .with_routing_facts(fact.followed_skill, fact.skill_covered_step);
        row.skill = fact.skill;
        validate_evidence(vault, &row)?;
        evidence.push(row);
    }
    vault.with_write_txn(|txn| {
        if CAPTURED.contains(&vault.store, txn, &receipt.receipt_id)? {
            return Ok(Some(0));
        }
        for row in &evidence {
            record_evidence_in_txn(vault, txn, row)?;
        }
        CAPTURED.put(&vault.store, txn, &receipt.receipt_id, &[1u8])?;
        Ok(Some(evidence.len()))
    })
}
