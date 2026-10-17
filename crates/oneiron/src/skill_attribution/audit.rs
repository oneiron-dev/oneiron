//! Held-out defect-injection audit: fixtures, the generic harness, and the pass-rate report.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

use super::calibration::{AuditBatch, AuditCase, record_unclear_floor_fit_in_txn};
use super::codec::{AUDIT, AuditRow, next_evidence_sequence_in_txn};
use super::judge::AttributionDecisions;
use super::split::{classify_split_traced, unclear_floor};
use super::types::{
    AttemptOutcome, AttributionLane, AttributionVerdict, JudgeRequest, OutcomeEvidence,
};

// ---------------------------------------------------------------------------
// Defect-injection audit (Blind Curator guard)
// ---------------------------------------------------------------------------

/// One held-out audit case: evidence whose correct answer is already known.
///
/// `expected: None` means ABSTENTION is the honest answer — the routing facts
/// do not settle the case, so a judge that names a verdict anyway is WRONG,
/// not merely unlucky. Without this arm the audit could only reward labelling,
/// which is the exact bias it exists to catch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFixture {
    pub evidence: OutcomeEvidence,
    pub expected: Option<AttributionVerdict>,
}

/// Aggregate result of one audit pass.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AttributionAuditReport {
    pub total: usize,
    /// Cases the judge answered correctly — including the cases where the
    /// correct answer was to abstain.
    pub passed: usize,
    /// Cases the judge abstained on, right or wrong. A judge that abstains on
    /// everything earns only the fixtures whose honest answer is abstention,
    /// so it can never score 100%.
    pub abstained: usize,
    pub at: u64,
}

impl AttributionAuditReport {
    /// Passed over total. An empty fixture set scores 0.0, never 1.0: "nothing
    /// was checked" is the worst evidence, not the best.
    #[must_use]
    pub fn pass_rate(&self) -> f32 {
        if self.total == 0 {
            return 0.0;
        }
        // Precision loss here is intended: this is a reported metric, not an
        // accumulator, and both counts are bounded by the fixture set.
        #[expect(
            clippy::cast_precision_loss,
            reason = "reported aggregate metric over a bounded fixture set"
        )]
        {
            self.passed as f32 / self.total as f32
        }
    }
}

/// One persisted audit run: the receipt reference its floor fit cites, its
/// aggregate report, and its batch kept whole.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributionAuditRecord {
    pub receipt: String,
    pub report: AttributionAuditReport,
    pub batch: AuditBatch,
}

/// The receipt reference of the attempt-lane audit row at `(at, sequence)`.
fn audit_receipt(at: u64, sequence: u64) -> String {
    format!("skill-attribution-audit:{at}:{sequence}")
}

/// Runs the built-in held-out audit against the deterministic tier, persists
/// the report, and returns the pass-rate.
///
/// A judge biased toward false passes moves this number, so the bias is
/// visible in an aggregate metric instead of hiding inside individual verdicts.
pub fn run_attribution_audit(vault: &Vault) -> Result<f32> {
    let fixtures = held_out_audit_fixtures();
    let report = run_attribution_audit_with_decisions(
        vault,
        &fixtures,
        None,
        vault.store.clock.now_recorded_at(),
    )?;
    Ok(report.pass_rate())
}

/// The generic audit harness: any fixture set, the host's decisions or (with
/// `None`) the rule tier.
///
/// `receipted` here = persisted audit rows at the audited prefix, NOT RS1
/// receipt rows (which are reified projections over the send ledger).
///
/// Deliberately not specialized to skill attribution — ED-03 reuses this shape
/// for amendment evidence, so the harness stays generic over the evidence class
/// by taking its fixtures as an argument.
///
/// The run keeps each case's raw answers, revision and id beside the report
/// (OF-542), and the floor they argue for is one held-out check on
/// `attribution_unclear_floor`, committed with the row.
pub fn run_attribution_audit_with_decisions(
    vault: &Vault,
    fixtures: &[AuditFixture],
    decisions: Option<&AttributionDecisions<'_>>,
    at: u64,
) -> Result<AttributionAuditReport> {
    let floor = unclear_floor(vault)?;
    let mut passed = 0;
    let mut abstained = 0;
    let mut cases = Vec::with_capacity(fixtures.len());
    for fixture in fixtures {
        // The audit asks through the same split path production routes
        // through, so a verdict the floor would hold scores as `unclear`:
        // no attribution, which is an abstention.
        let request = JudgeRequest {
            lane: AttributionLane::Attempt,
            evidence: &fixture.evidence,
            hunks: &[],
            floor,
        };
        let (split, trace) = classify_split_traced(decisions, &request, &[])?;
        let answer = split
            .and_then(|(split, _)| split.sole())
            .filter(|verdict| *verdict != AttributionVerdict::Unclear);
        if answer.is_none() {
            abstained += 1;
        }
        if answer == fixture.expected {
            passed += 1;
        }
        cases.push(AuditCase::new(
            &fixture.evidence.receipt_ref,
            fixture.expected,
            trace,
        ));
    }
    let report = AttributionAuditReport {
        total: fixtures.len(),
        passed,
        abstained,
        at,
    };
    let row = AuditRow::new(
        report,
        AuditBatch::fitted(AttributionLane::Attempt, floor, cases),
    );
    let now = vault.store.clock.now_recorded_at();

    vault.with_write_txn_grouped(|wtxn| {
        let sequence = next_evidence_sequence_in_txn(vault, wtxn)?;
        AUDIT.put(&vault.store, wtxn, &(at, sequence), &row)?;
        record_unclear_floor_fit_in_txn(
            vault,
            wtxn,
            &row.batch.fit,
            &audit_receipt(at, sequence),
            at,
            now,
        )
    })?;

    Ok(report)
}

/// Every persisted audit report, oldest first.
pub fn attribution_audit_reports(vault: &Vault) -> Result<Vec<AttributionAuditReport>> {
    Ok(attribution_audit_records(vault)?
        .into_iter()
        .map(|record| record.report)
        .collect())
}

/// Every persisted audit run with its batch and the receipt reference its
/// floor fit cites, oldest first.
pub fn attribution_audit_records(vault: &Vault) -> Result<Vec<AttributionAuditRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(AUDIT
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|((at, sequence), row)| AttributionAuditRecord {
            receipt: audit_receipt(at, sequence),
            report: row.report,
            batch: row.batch,
        })
        .collect())
}

/// The held-out set: one case per verdict, plus one whose honest answer is
/// ABSTENTION (the routing facts are unsettled).
///
/// The case ids are OPAQUE (`audit:case:N`) and carry no verdict wire string.
/// A fixture id like `audit:skill_defect` would let a judge score 100% by
/// reading the label instead of reasoning over the facts — which is precisely
/// the false-pass bias this audit exists to expose, so the audit must not
/// leak the answer key into its own inputs.
///
/// These ids are never resolved against the receipt ledger: fixtures go
/// straight to the judge, never through [`record_attribution_evidence`](crate::skill_attribution::record_attribution_evidence).
///
/// Subject ids are minted fresh per call. They are never written to the vault —
/// the routing table reasons over the outcome and the two routing facts, so the
/// identities are placeholders and a fixed seed would only risk aliasing a real
/// entity.
#[must_use]
pub fn held_out_audit_fixtures() -> Vec<AuditFixture> {
    let actor = EntityId::now();
    let skill = EntityId::now();
    let failed = |case: &str| OutcomeEvidence::new(case, actor, AttemptOutcome::Failed, 1);
    let routed = |case: &str, followed: bool, covered: bool| {
        failed(case)
            .with_skill(skill)
            .with_routing_facts(followed, covered)
    };
    vec![
        AuditFixture {
            evidence: routed("audit:case:1", true, true),
            expected: Some(AttributionVerdict::SkillDefect),
        },
        AuditFixture {
            evidence: routed("audit:case:2", false, true),
            expected: Some(AttributionVerdict::ExecutionLapse),
        },
        AuditFixture {
            evidence: routed("audit:case:3", false, false),
            expected: Some(AttributionVerdict::ExecutionLapse),
        },
        AuditFixture {
            evidence: routed("audit:case:4", true, false),
            expected: Some(AttributionVerdict::Discovery),
        },
        // The routing facts are unsettled, so the honest answer is to abstain.
        // A judge that names a verdict here is wrong, not unlucky.
        AuditFixture {
            evidence: failed("audit:case:5").with_skill(skill),
            expected: None,
        },
    ]
}
