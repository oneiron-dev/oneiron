//! Optional settled Coach diagnosis for an existing failure card.

use super::failure_card::SurfacedFailureCardInput;
use crate::claim::{
    ClaimApprovalStatus, ClaimLifecycleStatus, decode_claim_body, session_claim_producer,
};
use crate::dreamer_runner::authority::coach_actor_id;
use crate::dreamer_runner::maintenance::coach_heal::COACH_HEAL_PROPOSAL_PREDICATE;
use crate::entity_id::bytes_to_hex_lower;
use crate::failure_ladder::{HealerRepairRoute, failure_case_ref, healer_case_in_txn};
use crate::self_heal::blocked_reports::settled_in_txn;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{ClaimSource, ClaimSubject, EntityId, Vault};

pub(super) fn diagnosed_route(
    vault: &Vault,
    input: &SurfacedFailureCardInput,
) -> Option<HealerRepairRoute> {
    let txn = vault.store.env.read_txn().ok()?;
    let case_ref = failure_case_ref(input.failing_attempt_id);
    let case = healer_case_in_txn(vault, &txn, &case_ref).ok()??;
    if case.case_ref != case_ref
        || case.failing_attempt_id != input.failing_attempt_id
        || case.failure_class != input.failure_class
        || case.consecutive_transients != input.consecutive_transients
        || case.pre_fail_checkpoint_ref != input.pre_fail_checkpoint_ref.to_hex()
        || case.qa_thread_ref != input.qa.thread_ref
    {
        return None;
    }
    let key = EntityId::from_hex(&case_ref).ok()?;
    let settled = settled_in_txn(vault, &txn, &key).ok()??;
    let LiveEntityRow::Live { entity_type, body } =
        live_entity_row_in_txn(&vault.store, &txn, &settled.proposal).ok()?
    else {
        return None;
    };
    if entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return None;
    }
    let claim = decode_claim_body(&body, true).ok()?;
    let coach = coach_actor_id().ok()?;
    if claim.subject != ClaimSubject::Entity(coach)
        || claim.predicate != COACH_HEAL_PROPOSAL_PREDICATE
        || claim.source != Some(ClaimSource::Generated)
        || claim.lifecycle != ClaimLifecycleStatus::Active
        || claim.approval == ClaimApprovalStatus::Rejected
        || session_claim_producer(&claim) != Some(coach)
    {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(claim.value.as_str()?).ok()?;
    if value.get("case")?.as_str()? != case_ref
        || value.get("agent")?.as_str()? != case.scope.agent_ref
        || value.get("failing_attempt")?.as_str()?
            != bytes_to_hex_lower(case.failing_attempt_id.as_bytes())
        || value.get("evidence")?.as_str()? != case.evidence_ref
        || value.get("checkpoint")?.as_str()? != case.pre_fail_checkpoint_ref
        || value.get("qa_thread")?.as_str()? != case.qa_thread_ref
    {
        return None;
    }
    let route: HealerRepairRoute =
        serde_json::from_value(value.get("repair")?.get("route")?.clone()).ok()?;
    let (HealerRepairRoute::SkillEdit { diagnosis_ref, .. }
    | HealerRepairRoute::PromptInjectAndForkResume { diagnosis_ref, .. }
    | HealerRepairRoute::Environment { diagnosis_ref, .. }
    | HealerRepairRoute::EscalateWithDiagnosis { diagnosis_ref, .. }) = &route;
    (diagnosis_ref == &case.evidence_ref).then_some(route)
}
