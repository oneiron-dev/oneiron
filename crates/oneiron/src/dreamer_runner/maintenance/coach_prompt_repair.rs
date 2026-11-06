//! A case-backed prompt draft is data for owner review, never permission to
//! inject it or resume the failed run. The prompt artifact and the heal that
//! references it land in the same writer under the Coach's Proposed envelope.

use super::coach_heal::CoachHealAuthor;
use super::proposals;
use crate::attempt_queue::AttemptQueue;
use crate::error::ArtifactError;
use crate::failure_ladder::{HealerCase, HealerRepairRoute};
use crate::limit_ask::EngineLimit;
use crate::self_heal::HealEvidenceContext;
use crate::{EntityId, Error, Result, Vault, WriteEnvelope};
use serde_json::{Value, json};

/// The exact prompt and explanation a host author proposes for a failed case.
/// The engine supplies the agent, diagnosis and recorded pre-fail checkpoint;
/// an author supplies no references and grants no execution authority.
pub struct CoachPromptDraft {
    pub prompt: String,
    pub rationale: String,
}

/// The canonical Proposed claim predicate for a case's prompt artifact.
const PROMPT_REPAIR_PREDICATE: &str = "coach.prompt_repair";

pub(super) enum PromptRepair {
    Drafted {
        case: HealerCase,
        draft: CoachPromptDraft,
    },
    Skipped(&'static str),
}

/// Calls the host outside the writer. A decline or failed author leaves the
/// existing route-only heal; prompt bytes are neither trimmed nor rewritten.
pub(super) fn draft(
    case: &HealerCase,
    cause: &HealEvidenceContext,
    author: &dyn CoachHealAuthor,
) -> PromptRepair {
    match author.draft_prompt(case, cause) {
        Ok(Some(draft)) if !draft.prompt.trim().is_empty() => PromptRepair::Drafted {
            case: case.clone(),
            draft,
        },
        Ok(Some(_)) => PromptRepair::Skipped("unusable_draft"),
        Ok(None) => PromptRepair::Skipped("declined"),
        Err(_) => PromptRepair::Skipped("author_failed"),
    }
}

/// Rechecks the exact case and dispatched target before writing its prompt.
/// Stale context keeps the heal route-only, as a stale skill draft does.
pub(super) fn land_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    repair: &PromptRepair,
    evidence: &[EntityId],
    envelope: &WriteEnvelope,
    now: u64,
) -> Result<Value> {
    let skipped = |why| json!({ "skipped": why });
    let (case, draft) = match repair {
        PromptRepair::Drafted { case, draft } => (case, draft),
        PromptRepair::Skipped(why) => return Ok(skipped(*why)),
    };
    if crate::agent_dispatch::validate_healer_case(case).is_err() {
        return Ok(skipped("unbound_case"));
    }
    let checkpoint = EntityId::from_hex(&case.pre_fail_checkpoint_ref)?;
    if checkpoint.as_bytes() == case.failing_attempt_id.as_bytes() {
        return Ok(skipped("unbound_case"));
    }
    let Some(failing) =
        AttemptQueue::new(vault).get_in_write_txn(&*txn, case.failing_attempt_id)?
    else {
        return Ok(skipped("case_moved"));
    };
    match crate::failure_ladder::require_healer_case_in_txn(
        vault,
        txn,
        case,
        failing.run_id.as_deref(),
    ) {
        Ok(()) => {}
        Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(_))) => {
            return Ok(skipped("case_moved"));
        }
        Err(error) => return Err(error),
    }
    let _ = vault.measure_limit(
        EngineLimit::MaintenanceTextBytes,
        draft.prompt.len().max(draft.rationale.len()) as u64,
    );
    let value = json!({
        "case": case.case_ref,
        "failing_attempt": crate::entity_id::bytes_to_hex_lower(case.failing_attempt_id.as_bytes()),
        "agent": case.scope.agent_ref,
        "checkpoint": case.pre_fail_checkpoint_ref,
        "diagnosis": case.evidence_ref,
        "prompt": draft.prompt,
        "rationale": draft.rationale,
    });
    let prompt = proposals::emit_in_txn(
        vault,
        txn,
        envelope.actor().entity_ref(),
        PROMPT_REPAIR_PREDICATE,
        &value,
        evidence,
        envelope,
        now,
    )?;
    let route = HealerRepairRoute::PromptInjectAndForkResume {
        agent_ref: case.scope.agent_ref.clone(),
        prompt_ref: prompt.to_hex(),
        checkpoint_ref: case.pre_fail_checkpoint_ref.clone(),
        diagnosis_ref: case.evidence_ref.clone(),
    };
    Ok(json!({ "route": route }))
}
