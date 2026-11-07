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
