//! Held-out judge audit (Blind Curator guard).

use super::stored::{
    AUDIT_KEY_PREFIX, AUDIT_ROW_LABEL, ROW_VERSION, StoredAudit, decode_row, encode_row, meta_key,
    next_audit_sequence_in_txn,
};
use super::taxonomy::{AmendmentCause, AmendmentClass, AmendmentEvidence, classify_amendment};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::skill_attribution::{AttributionAuditReport, AttributionJudge, RuleAttributionJudge};

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

/// Runs the built-in held-out audit against the deterministic tier, persists
/// the report, and returns the pass-rate.
///
/// # Errors
///
/// Storage errors.
pub fn run_judge_audit(vault: &Vault) -> Result<f32> {
    let fixtures = held_out_amendment_fixtures();
    let report = run_judge_audit_with_judge(
        vault,
        &fixtures,
        &RuleAttributionJudge,
        crate::unix_seconds_now(),
    )?;
    Ok(report.pass_rate())
}

/// The audit harness: any fixture set, any tier.
///
/// Reuses [`AttributionAuditReport`] rather than minting a second metric shape —
/// two evidence classes, one number ops reads. The rows land in this module's
/// own keyspace so the two ledgers stay tellable apart.
///
/// # Errors
///
/// Storage errors, and whatever `judge` returns.
pub fn run_judge_audit_with_judge(
    vault: &Vault,
    fixtures: &[AmendmentAuditFixture],
    judge: &dyn AttributionJudge,
    at: u64,
) -> Result<AttributionAuditReport> {
    let mut passed = 0;
    let mut abstained = 0;
    for fixture in fixtures {
        let answer = classify_amendment(&fixture.evidence, judge)?;
        if answer.is_none() {
            abstained += 1;
        }
        if answer == fixture.expected {
            passed += 1;
        }
    }
    let report = AttributionAuditReport {
        total: fixtures.len(),
        passed,
        abstained,
        at,
    };
    let encoded = encode_row(
        &StoredAudit {
            v: ROW_VERSION,
            total: report.total as u64,
            passed: report.passed as u64,
            abstained: report.abstained as u64,
            at,
        },
        AUDIT_ROW_LABEL,
    )?;
    vault.with_write_txn(|wtxn| {
        let sequence = next_audit_sequence_in_txn(vault, wtxn)?;
        let mut handle = Vec::with_capacity(16);
        handle.extend_from_slice(&at.to_be_bytes());
        handle.extend_from_slice(&sequence.to_be_bytes());
        let key = meta_key(AUDIT_KEY_PREFIX, &handle);
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })?;
    Ok(report)
}

/// Every persisted audit report, oldest first.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn judge_audit_reports(vault: &Vault) -> Result<Vec<AttributionAuditReport>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, AUDIT_KEY_PREFIX)?
    {
        let (_, raw) = entry?;
        let row: StoredAudit = decode_row(&raw, AUDIT_ROW_LABEL)?;
        if row.v != ROW_VERSION {
            return Err(Error::CorruptedIndex(AUDIT_ROW_LABEL));
        }
        let count = |value: u64| -> Result<usize> {
            usize::try_from(value).map_err(|_| Error::CorruptedIndex(AUDIT_ROW_LABEL))
        };
        out.push(AttributionAuditReport {
            total: count(row.total)?,
            passed: count(row.passed)?,
            abstained: count(row.abstained)?,
            at: row.at,
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
/// [`classify_amendment`], never through [`record_amendment_evidence`]. Subject
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
