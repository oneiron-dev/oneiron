//! Case-bound human-escalation intent in the Coach's ordinary proposal write.

use crate::attempt_queue::AttemptQueue;
use crate::failure_ladder::{HealerCase, HealerRepairRoute};
use crate::{EntityId, Vault};

pub(super) fn repair_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    case: &HealerCase,
) -> Option<serde_json::Value> {
    let failed = AttemptQueue::new(vault)
        .get_in_write_txn(txn, case.failing_attempt_id)
        .ok()
        .flatten()?;
    crate::failure_ladder::require_healer_case_in_txn(vault, txn, case, failed.run_id.as_deref())
        .ok()?;
    let diagnosis = EntityId::from_hex(&case.evidence_ref).ok()?;
    let agent = EntityId::from_hex(&case.scope.agent_ref).ok()?;
    if diagnosis.to_hex() != case.evidence_ref || agent.to_hex() != case.scope.agent_ref {
        return None;
    }
    let route = HealerRepairRoute::EscalateWithDiagnosis {
        agent_ref: case.scope.agent_ref.clone(),
        diagnosis_ref: case.evidence_ref.clone(),
    };
    Some(serde_json::json!({ "route": route }))
}

pub(super) fn report_repair_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    receipt: &EntityId,
    issue: &crate::self_heal::blocked_reports::BlockedIssue,
) -> Option<serde_json::Value> {
    let current = crate::self_heal::blocked_reports::blocked_issue_in_txn(vault, txn, receipt)
        .ok()
        .flatten()?;
    if current != *issue {
        return None;
    }
    let run = issue.run?;
    if !crate::self_heal::blocked_reports::filed_by_run_in(vault, txn, run, *receipt).ok()? {
        return None;
    }
    let attempt = crate::attempt_queue::AttemptId::from_bytes(run.as_bytes()).ok()?;
    let record = AttemptQueue::new(vault)
        .get_in_write_txn(txn, attempt)
        .ok()
        .flatten()?;
    if crate::failure_ladder::dispatched_target_ref(&record) != Some(issue.reporter) {
        return None;
    }
    let route = HealerRepairRoute::EscalateWithDiagnosis {
        agent_ref: issue.reporter.to_hex(),
        diagnosis_ref: issue.diagnostic.to_hex(),
    };
    Some(serde_json::json!({ "route": route }))
}
