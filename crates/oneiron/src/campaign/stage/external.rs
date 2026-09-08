//! External-evidence hook ingress with the owner-attestation proposal-boundary gate.

use super::ladder::{
    PromotionMode, StageEvidence, StageLadderDefinition, StageTransitionRule,
    proposal_boundary_index, stage_index, transition_rule, validate_ladder,
};
use super::projector::{
    StageProjectResult, StageProjectorInput, invalid, project_stage_transition, stage_position,
};
use crate::campaign::claims::{CrmStageValue, EvidenceBasis, StageKey};
use crate::{EntityId, Result, Vault};

/// A typed request from an evidence source CA-04 does not own.
///
/// Deposit, audit/delivery, desk, and renewal inputs enter ONLY through this
/// hook. Their source truth stays with the counterparty ledger (ONE-1542),
/// commitments, or TASK_LIST machinery; CA-04 stores the stage and the evidence
/// reference and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalStageEvidenceHook {
    /// PERSON the stage is about.
    pub party_ref: EntityId,
    /// Campaign the stage is scoped to.
    pub campaign_ref: EntityId,
    /// Stage the evidence claims to earn.
    pub target_stage: StageKey,
    /// The evidence itself.
    pub evidence: StageEvidence,
}

// ---------------------------------------------------------------------------
// External evidence hooks
// ---------------------------------------------------------------------------

/// Accepts evidence from a source CA-04 does not own, then routes a canonical
/// value through the stage projector.
///
/// Deposit, audit/delivery, desk, and renewal stages are EVIDENCE HOOKS only:
/// this writes the stage and its evidence reference, and never a payment,
/// commitment, renewal, or TASK_LIST record. Source truth stays with the
/// counterparty ledger (ONE-1542) and the other existing owners.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the hook carries no evidence references,
/// when its class disagrees with the configured transition, or when an
/// owner-attested basis is not admissible (see `require_owner_attestable`).
/// Projector and storage errors propagate.
pub fn apply_external_stage_evidence(
    vault: &Vault,
    definition: &StageLadderDefinition,
    hook: &ExternalStageEvidenceHook,
    mode: PromotionMode,
) -> Result<StageProjectResult> {
    validate_ladder(definition)?;
    if hook.evidence.evidence_refs.is_empty() {
        return Err(invalid("external stage evidence requires evidence refs"));
    }
    let (previous_stage_claim_ref, from) =
        stage_position(vault, &hook.party_ref, &hook.campaign_ref)?;
    let Some(rule) = transition_rule(definition, from.as_ref(), &hook.target_stage) else {
        return Ok(StageProjectResult::NoChange);
    };
    if hook.evidence.class != rule.evidence_class {
        return Err(invalid(
            "external stage evidence class does not match the transition",
        ));
    }
    if hook.evidence.basis == EvidenceBasis::OwnerAttested {
        require_owner_attestable(definition, rule)?;
    }
    project_stage_transition(
        vault,
        &StageProjectorInput {
            party_ref: hook.party_ref,
            previous_stage_claim_ref,
            value: CrmStageValue {
                campaign_ref: hook.campaign_ref,
                stage: hook.target_stage.clone(),
                evidence_class: hook.evidence.class,
                evidence_refs: hook.evidence.evidence_refs.clone(),
                basis: hook.evidence.basis,
                recorded_at: hook.evidence.recorded_at,
            },
        },
        mode,
    )
}

/// Enforces "stages past `proposal_sent` accept owner-attested basis" WITHOUT
/// spelling `proposal_sent`.
///
/// The boundary is read from the ladder itself: `proposal_sent` is definitionally
/// the stage a document artifact plus its send receipt earns, so the earliest
/// stage entered by a [`StageEvidenceClass::DocumentArtifactAndSendReceipt`]
/// transition IS the boundary, and "strictly after" is a position comparison in
/// the declared stage order. Consultancy stage names therefore stay in ONE-1779's
/// preset data, and a ladder that declares no such stage has nothing to attest
/// past.
///
/// The rule's own `owner_attested_allowed` flag is the second half: the ladder
/// may withhold attestation from a late stage, but it cannot grant it to an early
/// one.
fn require_owner_attestable(
    definition: &StageLadderDefinition,
    rule: &StageTransitionRule,
) -> Result<()> {
    if !rule.owner_attested_allowed {
        return Err(invalid("transition does not admit owner-attested evidence"));
    }
    let Some(boundary) = proposal_boundary_index(definition) else {
        return Err(invalid("ladder declares no proposal stage to attest past"));
    };
    let Some(target) = stage_index(definition, &rule.to) else {
        return Err(invalid("stage transition enters an undeclared stage"));
    };
    if target <= boundary {
        return Err(invalid(
            "owner-attested evidence is admissible only past the proposal stage",
        ));
    }
    Ok(())
}
