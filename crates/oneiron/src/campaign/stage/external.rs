//! External-evidence hook ingress with the owner-attestation proposal-boundary gate.

use super::ladder::{
    PromotionMode, StageEvidence, StageLadderDefinition, StageTransitionRule,
    proposal_boundary_index, stage_index, transition_rule, validate_ladder,
};
use super::projector::{
    StageProjectResult, StageProjectorInput, invalid, live_stage_head_in,
    project_stage_transition_in_txn,
};
use crate::calendar::claims::decode_event_outcome_value;
use crate::calendar::outcome::{EventOutcome, PREDICATE_CALENDAR_EVENT_OUTCOME};
use crate::campaign::claims::{CrmStageValue, EvidenceBasis, StageEvidenceClass, StageKey};
use crate::claim::claim_surfaceable;
use crate::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_MESSAGE};
use crate::{EntityId, Result, Vault};

pub use crate::write_envelope::cohort_claims::ladder::ExternalStageEvidenceHook;

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
/// [`Error::InvalidClaimBody`](crate::Error::InvalidClaimBody) when the hook carries no evidence references,
/// when its class disagrees with the configured transition, when an
/// owner-attested basis is not admissible (see `require_owner_attestable`), or
/// when the references do not re-read as the source their class names (see
/// `require_source_evidence`). Projector and storage errors propagate.
pub fn apply_external_stage_evidence(
    vault: &Vault,
    definition: &StageLadderDefinition,
    hook: &ExternalStageEvidenceHook,
    mode: PromotionMode,
) -> Result<StageProjectResult> {
    vault.with_write_txn_grouped(|txn| {
        apply_external_stage_evidence_in_txn(vault, txn, definition, hook, mode, None)
    })
}

/// The public evidence door shares this ingress with native projectors. The
/// current stage, transition rule and every write use the caller's snapshot.
pub(crate) fn apply_external_stage_evidence_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    definition: &StageLadderDefinition,
    hook: &ExternalStageEvidenceHook,
    mode: PromotionMode,
    envelope: Option<&crate::WriteEnvelope>,
) -> Result<StageProjectResult> {
    validate_ladder(definition)?;
    if hook.evidence.evidence_refs.is_empty() {
        return Err(invalid("external stage evidence requires evidence refs"));
    }
    let head = live_stage_head_in(vault, txn, &hook.party_ref, &hook.campaign_ref)?;
    let previous_stage_claim_ref = head.as_ref().map(|(id, _)| *id);
    let from = head.as_ref().map(|(_, value)| &value.stage);
    let Some(rule) = transition_rule(definition, from, &hook.target_stage) else {
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
    require_source_evidence(vault, txn, hook.evidence.class, &hook.evidence.evidence_refs)?;
    project_stage_transition_in_txn(
        vault,
        txn,
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
        envelope,
    )
}

/// Re-reads the source a vault-owned evidence class names, so declaring the
/// class and citing any reference cannot stand in for the evidence itself.
///
/// A meaningful reply is a MESSAGE, a booking is an EVENT (the row calendar
/// ingestion writes from its ICS source), and a held call is a live
/// `calendar.event_outcome` claim that says `held` — cited by the claim
/// itself or by its EVENT, as the outcome door cites it. Silence stays
/// silence: an EVENT with no held outcome earns no held stage here either.
///
/// The remaining classes name sources some other owner records — a document
/// and its send receipt, the counterparty ledger, a task list, a recurring
/// commitment — and their truth stays with that owner, so this ingress keeps
/// checking only that a reference is present for them.
fn require_source_evidence(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    class: StageEvidenceClass,
    evidence_refs: &[EntityId],
) -> Result<()> {
    match class {
        StageEvidenceClass::MeaningfulReply => {
            if evidence_has_entity_type(vault, txn, evidence_refs, ENTITY_TYPE_MESSAGE)? {
                Ok(())
            } else {
                Err(invalid(
                    "meaningful reply evidence requires a MESSAGE evidence ref",
                ))
            }
        }
        StageEvidenceClass::CalendarEvent => {
            if evidence_has_entity_type(vault, txn, evidence_refs, ENTITY_TYPE_EVENT)? {
                Ok(())
            } else {
                Err(invalid(
                    "calendar event evidence requires an EVENT evidence ref",
                ))
            }
        }
        StageEvidenceClass::CalendarEventOutcome => {
            if evidence_has_held_outcome(vault, txn, evidence_refs)? {
                Ok(())
            } else {
                Err(invalid(
                    "calendar event outcome evidence requires a held outcome",
                ))
            }
        }
        StageEvidenceClass::DocumentArtifactAndSendReceipt
        | StageEvidenceClass::CounterpartyLedger
        | StageEvidenceClass::TaskListProgress
        | StageEvidenceClass::RecurringCommitment => Ok(()),
    }
}

/// Whether any cited reference is a stored entity of `entity_type`.
fn evidence_has_entity_type(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    evidence_refs: &[EntityId],
    entity_type: u8,
) -> Result<bool> {
    for reference in evidence_refs {
        if vault.get_entity_type_in_txn(txn, reference)? == Some(entity_type) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether any cited reference carries a live `held` outcome: the outcome
/// claim itself, or an EVENT one of its claims is that claim.
fn evidence_has_held_outcome(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    evidence_refs: &[EntityId],
) -> Result<bool> {
    for reference in evidence_refs {
        if is_held_outcome_claim(vault, txn, reference)? {
            return Ok(true);
        }
        if vault.get_entity_type_in_txn(txn, reference)? != Some(ENTITY_TYPE_EVENT) {
            continue;
        }
        for claim_ref in vault.claims_for_subject_in_txn(txn, reference)? {
            if is_held_outcome_claim(vault, txn, &claim_ref)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Whether `claim_ref` is a live `calendar.event_outcome` claim that says
/// `held`, read as a reader about to act on it would read it.
fn is_held_outcome_claim(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim_ref: &EntityId,
) -> Result<bool> {
    let Some(body) = vault.get_claim_for_effect_in_txn(txn, claim_ref)? else {
        return Ok(false);
    };
    if body.predicate != PREDICATE_CALENDAR_EVENT_OUTCOME || !claim_surfaceable(&body) {
        return Ok(false);
    }
    Ok(decode_event_outcome_value(&body.value)?.outcome == EventOutcome::Held)
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
