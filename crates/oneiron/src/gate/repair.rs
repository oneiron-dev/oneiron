//! Pure, per-proposal consent recomputation. No diagnostic severity enters this boundary.

use crate::claim::UNSTAMPED_CLAIM_SENSITIVITY_BAND;
use crate::self_heal::{
    HealerInvocationStamp, RepairConsentRoute, RepairCriticality, RepairOperation, RepairProposal,
    validate_repair_proposal,
};

use super::ceiling::PolicyCriticality;
use super::constants::POLICY_SCHEMA_VERSION;
use super::decision::{GateDecision, GateOutcome};
use super::input::{GateActor, GateContentKind, GateEvaluatorInput, GateProvenanceHandles};
use super::resolution::PolicyManifestResolution;

/// Recompute from the repair's own target against the supplied CURRENT policy.
///
/// Invalid drafts cannot auto-route even at a direct adapter call. The runner
/// rejects them entirely. Code/schema/skill edits and unproven policy narrowing
/// have an unconditional review-only floor, independent of the named predicate.
pub(crate) fn repair_criticality(
    policy: &PolicyManifestResolution,
    invocation: &HealerInvocationStamp,
    proposal: &RepairProposal,
) -> RepairCriticality {
    let current = policy.criticality_for_predicate(&proposal.target_predicate);
    let review_only = matches!(
        proposal.operation,
        RepairOperation::NarrowPolicy { .. }
            | RepairOperation::SkillEdit { .. }
            | RepairOperation::DevPatch { .. }
            | RepairOperation::SchemaPatch { .. }
    );
    if current == PolicyCriticality::Critical
        || review_only
        || validate_repair_proposal(proposal, invocation.session_tag()).is_err()
    {
        RepairCriticality::Critical
    } else {
        RepairCriticality::Normal
    }
}

pub(super) fn repair_gate_input(
    policy: &PolicyManifestResolution,
    invocation: &HealerInvocationStamp,
    proposal: &RepairProposal,
) -> GateEvaluatorInput {
    let actor = invocation.actor();
    GateEvaluatorInput {
        actor: GateActor {
            actor_class: actor.actor_class.clone(),
            actor_ref: Some(actor.actor_ref.to_hex()),
            delegation_grant_ref: None,
        },
        source: Some(invocation.source()),
        content_kind: GateContentKind::Repair,
        // No healer-authored sensitivity or source-trust bypass is accepted.
        sensitivity_band: Some(UNSTAMPED_CLAIM_SENSITIVITY_BAND),
        criticality: match repair_criticality(policy, invocation, proposal) {
            RepairCriticality::Normal => PolicyCriticality::Normal,
            RepairCriticality::Critical => PolicyCriticality::Critical,
        },
        policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
        provenance: GateProvenanceHandles {
            actor_entity_ref: Some(actor.actor_ref),
            ..GateProvenanceHandles::default()
        },
        external_effect: None,
        agent_definition_ceiling: invocation.agent_definition_ceiling(),
        // No consent/grant supplied by a healer can dissolve the criticality floor.
        consent: None,
    }
}

/// Return routing advice and the ordinary three-axis Gate decision, without I/O.
///
/// Actor, source, and provenance come ONLY from the engine-minted invocation,
/// never proposal disclosure. There is deliberately no diagnostic parameter.
/// Even AutoEligible is only a proposal; this result is not an apply capability.
pub(crate) fn evaluate_repair_consent(
    policy: &PolicyManifestResolution,
    invocation: &HealerInvocationStamp,
    proposal: &RepairProposal,
) -> (RepairConsentRoute, GateDecision) {
    let input = repair_gate_input(policy, invocation, proposal);
    let decision = policy.evaluate_gate(&input);
    let route = match decision.outcome() {
        GateOutcome::Allow => RepairConsentRoute::AutoEligible,
        GateOutcome::Pending => RepairConsentRoute::HumanReview,
        GateOutcome::Deny => RepairConsentRoute::Denied,
    };
    (route, decision)
}
