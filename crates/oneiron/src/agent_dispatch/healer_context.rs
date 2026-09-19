//! Reference-only healer context validation, shared by dispatch and decoding.

use crate::failure_ladder::{HealerCase, failure_case_ref};
use crate::{EntityId, Error, Result};

pub(crate) fn validate(case: &HealerCase) -> Result<()> {
    if case.case_ref != failure_case_ref(case.failing_attempt_id)
        || case.blocked_reports.len() > 128
    {
        return Err(Error::InvalidConfig("invalid healer case binding".into()));
    }
    for reference in [
        &case.evidence_ref,
        &case.pre_fail_checkpoint_ref,
        &case.qa_thread_ref,
        &case.scope.agent_ref,
    ]
    .into_iter()
    .chain(case.scope.skill_ref.iter())
    .chain(case.task_ref.iter())
    .chain(case.blocked_reports.iter().map(|r| &r.receipt_ref))
    {
        let id = EntityId::from_hex(reference)?;
        if id.to_hex() != *reference {
            return Err(Error::InvalidConfig("noncanonical healer reference".into()));
        }
    }
    Ok(())
}
