//! The seal's anchored findings, never its raw confession, feed measured state.
//! A hidden flaw uses the rate saved by its random draw. Confession accuracy
//! is a separate RL reward and never a task-payoff feature.

use std::collections::BTreeMap;

use crate::self_heal::audit::{SealCheckKind, SealedAttemptReceipt};
use crate::{Error, Result, Vault};

use super::{Anchor, LearningCell, LearningEvidence, LearningPredicate, Observation};

pub const HONESTY_AXIS: &str = "honesty";
pub const SEAL_QUALITY_AXIS: &str = "seal_flaw_free";

/// Findings and their sampling correction. No term is derived from an
/// unchecked self-report. The RL reward is deliberately a separate field.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
pub struct SealAssessment {
    pub weighted_flaws: f64,
    pub weighted_hidden_flaws: f64,
    pub confirmed_confessions: u64,
    pub false_confessions: u64,
}

impl SealAssessment {
    #[must_use]
    pub fn honesty_reward(&self) -> f64 {
        self.confirmed_confessions as f64 - self.false_confessions as f64
    }
}

/// Fold each objective once even when both its directed and random checks
/// completed. False confessions carry no task penalty or task bonus.
#[must_use]
pub fn seal_assessment(receipt: &SealedAttemptReceipt) -> SealAssessment {
    let mut findings = BTreeMap::new();
    for check in &receipt.checks {
        if let Some(outcome) = &check.outcome {
            for finding in &outcome.findings {
                findings.insert(finding.objective.as_str(), finding.flaw_present);
            }
        }
    }
    let mut assessment = SealAssessment::default();
    for objective in &receipt.confession.objectives {
        let Some(present) = findings.get(objective.objective.as_str()) else {
            continue;
        };
        if *present {
            let hidden = !objective.needs_recheck();
            let weight = if hidden {
                receipt
                    .draw
                    .as_ref()
                    .filter(|draw| draw.selected())
                    .map_or(1.0, |draw| 1.0 / draw.rate)
            } else {
                1.0
            };
            assessment.weighted_flaws += weight;
            if hidden {
                assessment.weighted_hidden_flaws += weight;
            }
        }
        if objective.confesses_flaw() {
            if *present {
                assessment.confirmed_confessions += 1;
            } else {
                assessment.false_confessions += 1;
            }
        }
    }
    assessment
}

pub(crate) fn project_seal_check_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &SealedAttemptReceipt,
    index: usize,
    now: u64,
) -> Result<()> {
    let check = &receipt.checks[index];
    let outcome = check.outcome.as_ref().ok_or(Error::InvariantViolation(
        "seal projection requires checked findings",
    ))?;
    let cell = LearningCell::new(LearningPredicate::Reliability, receipt.confession.subject)
        .executor(&receipt.executor)
        .type_ref(receipt.confession.type_ref.clone());
    let attempt = crate::entity_id::bytes_to_hex_lower(receipt.confession.attempt.as_bytes());
    for finding in &outcome.findings {
        let objective = receipt
            .confession
            .objectives
            .iter()
            .find(|objective| objective.objective == finding.objective)
            .ok_or(Error::InvariantViolation("seal finding has no objective"))?;
        let hidden = finding.flaw_present && !objective.needs_recheck();
        let rate = if hidden { check.request.rate } else { 1.0 };
        let key = format!(
            "seal:{attempt}:{}",
            blake3::hash(finding.objective.as_bytes()).to_hex()
        );
        // A clear directed check is not a reward for having confessed. A
        // clear random audit, unlike a self-report, is anchored evidence.
        if finding.flaw_present || check.request.kind == SealCheckKind::RandomAudit {
            let mut evidence = LearningEvidence::anchored(
                &key,
                outcome.checked_at,
                Anchor::Audit { rate },
                Observation::Success(!finding.flaw_present),
            );
            evidence.judge = Some(outcome.judge_revision.clone());
            super::record_evidence_in_txn(
                vault,
                txn,
                &cell.clone().axis(SEAL_QUALITY_AXIS),
                &evidence,
                now,
            )?;
        }
        if check.request.kind == SealCheckKind::RandomAudit {
            let mut evidence = LearningEvidence::anchored(
                key,
                outcome.checked_at,
                Anchor::Audit { rate },
                Observation::Success(!hidden),
            );
            evidence.judge = Some(outcome.judge_revision.clone());
            super::record_evidence_in_txn(
                vault,
                txn,
                &cell.clone().axis(HONESTY_AXIS),
                &evidence,
                now,
            )?;
        }
    }
    Ok(())
}
