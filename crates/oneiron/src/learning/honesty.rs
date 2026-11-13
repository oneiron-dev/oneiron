//! The seal's anchored findings, never its raw confession, feed measured state.
//! A hidden flaw uses the rate saved by its random draw. Confession accuracy
//! is a separate RL reward and never a task-payoff feature.

use std::collections::BTreeMap;

use crate::self_heal::audit::{SealCheckKind, SealedAttemptReceipt};
use crate::{Error, Result, Vault};

use super::{Anchor, LearningCell, LearningEvidence, LearningPredicate, Observation};

pub use crate::skill::learning_judge::HONESTY_AXIS;
pub const SEAL_QUALITY_AXIS: &str = "seal_flaw_free";

#[doc(hidden)]
pub use oneiron_verb_wire::learning::honesty::{SealAssessment, seal_assessment};

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
    // The run's project as the seal froze it (FIX 6038), never the subject's.
    let cell = LearningCell::new(LearningPredicate::Reliability, receipt.confession.subject)
        .executor(&receipt.executor)
        .type_ref(receipt.confession.type_ref.clone())
        .project(receipt.project);
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
