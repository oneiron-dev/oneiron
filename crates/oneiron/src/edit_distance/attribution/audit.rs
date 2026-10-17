//! Held-out judge audit (Blind Curator guard).

use super::stored::{AUDIT, AUDIT_ROW_LABEL, ROW_VERSION, StoredAudit, next_audit_sequence_in_txn};
use super::taxonomy::{
    AmendmentCause, AmendmentClass, AmendmentEvidence, classify_amendment_traced,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill_attribution::{
    AttributionAuditReport, AttributionDecisions, AttributionLane, AttributionVerdict, AuditBatch,
    AuditCase, record_unclear_floor_fit_in_txn, unclear_floor,
};

// ---------------------------------------------------------------------------
// Defect-injection audit (Blind Curator guard)
// ---------------------------------------------------------------------------

/// One held-out audit case: an amendment whose correct class is already known.
///
/// `expected: None` means ABSTENTION is the honest answer — a judge that names
/// a class anyway is WRONG, not unlucky. Without that arm the audit could only
/// reward labelling, which is the bias it exists to catch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmendmentAuditFixture {
    pub evidence: AmendmentEvidence,
    pub expected: Option<AmendmentClass>,
}

/// One persisted amendment audit run: the receipt reference its floor fit
/// cites, its aggregate report, and its batch kept whole.
#[derive(Debug, Clone, PartialEq)]
pub struct AmendmentAuditRecord {
    pub receipt: String,
    pub report: AttributionAuditReport,
    pub batch: AuditBatch,
}

/// The receipt reference of the amendment-lane audit row at `(at, sequence)`.
fn audit_receipt(at: u64, sequence: u64) -> String {
    format!("edit-distance-judge-audit:{at}:{sequence}")
}

/// Runs the built-in held-out audit against the deterministic tier, persists
/// the report, and returns the pass-rate.
///
/// # Errors
///
/// Storage errors.
pub fn run_judge_audit(vault: &Vault) -> Result<f32> {
    let fixtures = held_out_amendment_fixtures();
    let report = run_judge_audit_with_decisions(
        vault,
        &fixtures,
        None,
        vault.store.clock.now_recorded_at(),
    )?;
    Ok(report.pass_rate())
}

/// The audit harness: any fixture set, the host's decisions or (with `None`)
/// the rule tier.
///
/// Reuses [`AttributionAuditReport`] rather than minting a second metric shape —
/// two evidence classes, one number ops reads. The rows land in this module's
/// own keyspace so the two ledgers stay tellable apart. Each run keeps its
/// cases' raw answers beside the report, and the floor they argue for is one
/// held-out check on `attribution_unclear_floor`, committed with the row
/// (OF-542).
///
/// # Errors
///
/// Storage errors, and whatever the decision path returns.
pub fn run_judge_audit_with_decisions(
    vault: &Vault,
    fixtures: &[AmendmentAuditFixture],
    decisions: Option<&AttributionDecisions<'_>>,
    at: u64,
) -> Result<AttributionAuditReport> {
    let floor = unclear_floor(vault)?;
    let mut passed = 0;
    let mut abstained = 0;
    let mut cases = Vec::with_capacity(fixtures.len());
    for fixture in fixtures {
        // A hunk the floor holds is `unclear`: no attribution, an abstention.
        let (split, trace) = classify_amendment_traced(&fixture.evidence, decisions, &[], floor)?;
        let answer = split
            .and_then(|split| split.sole())
            .filter(|class| *class != AttributionVerdict::Unclear);
        if answer.is_none() {
            abstained += 1;
        }
        if answer == fixture.expected {
            passed += 1;
        }
        cases.push(AuditCase::new(
            &fixture.evidence.receipt_id,
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
    let row = StoredAudit {
        v: ROW_VERSION,
        total: report.total as u64,
        passed: report.passed as u64,
        abstained: report.abstained as u64,
        at,
        batch: AuditBatch::fitted(AttributionLane::Amendment, floor, cases),
    };
    let now = vault.store.clock.now_recorded_at();
    vault.with_write_txn_grouped(|wtxn| {
        let sequence = next_audit_sequence_in_txn(vault, wtxn)?;
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
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn judge_audit_reports(vault: &Vault) -> Result<Vec<AttributionAuditReport>> {
    Ok(judge_audit_records(vault)?
        .into_iter()
        .map(|record| record.report)
        .collect())
}

/// Every persisted audit run with its batch and the receipt reference its
/// floor fit cites, oldest first.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn judge_audit_records(vault: &Vault) -> Result<Vec<AmendmentAuditRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for ((at, sequence), row) in AUDIT.scan(&vault.store, &rtxn)? {
        let count = |value: u64| -> Result<usize> {
            usize::try_from(value).map_err(|_| Error::CorruptedIndex(AUDIT_ROW_LABEL))
        };
        out.push(AmendmentAuditRecord {
            receipt: audit_receipt(at, sequence),
            report: AttributionAuditReport {
                total: count(row.total)?,
                passed: count(row.passed)?,
                abstained: count(row.abstained)?,
                at: row.at,
            },
            batch: row.batch,
        });
    }
    Ok(out)
}

/// The held-out set: one case per class the judge can reach, plus one whose
/// honest answer is ABSTENTION.
///
/// The case ids are OPAQUE and carry no class token. A fixture named
/// `audit:environment` would let a judge score full marks by reading the label
/// instead of the facts — precisely the bias this audit exists to expose, so
/// the answer key must not leak into its own inputs.
///
/// These ids are never resolved against any ledger: fixtures go straight to
/// [`classify_amendment`](super::taxonomy::classify_amendment), never through [`record_amendment_evidence`](crate::edit_distance::attribution::record_amendment_evidence). Subject
/// ids are minted fresh per call and never written — the table reasons over the
/// cause and the two routing facts, so a fixed seed would only risk aliasing a
/// real entity.
#[must_use]
pub fn held_out_amendment_fixtures() -> Vec<AmendmentAuditFixture> {
    let actor = EntityId::now();
    let skill = EntityId::now();
    let base = |case: &str| {
        AmendmentEvidence::new(case, actor, "audit")
            .at(1)
            .with_skill(skill)
    };
    let wrong = |case: &str, followed: bool, covered: bool| {
        base(case)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(followed, covered)
    };
    vec![
        AmendmentAuditFixture {
            evidence: wrong("audit:amendment:1", true, true),
            expected: Some(AmendmentClass::SkillDefect),
        },
        AmendmentAuditFixture {
            evidence: wrong("audit:amendment:2", false, true),
            expected: Some(AmendmentClass::ExecutionLapse),
        },
        AmendmentAuditFixture {
            evidence: wrong("audit:amendment:3", true, false),
            expected: Some(AmendmentClass::Discovery),
        },
        AmendmentAuditFixture {
            evidence: base("audit:amendment:4").with_cause(AmendmentCause::ExternalChange),
            expected: Some(AmendmentClass::Environment),
        },
        AmendmentAuditFixture {
            evidence: base("audit:amendment:5").with_cause(AmendmentCause::DeciderPreference),
            expected: Some(AmendmentClass::PreferenceShift),
        },
        // The cause is unsettled, so the honest answer is to abstain. A judge
        // that names a class here is wrong, not unlucky.
        AmendmentAuditFixture {
            evidence: base("audit:amendment:6").with_routing_facts(true, true),
            expected: None,
        },
    ]
}
