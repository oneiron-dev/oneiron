//! Calendar-outcome ingress: held promotion, no-show recovery, silence-is-never-held.

use super::ladder::{
    NoShowRecoveryRule, PromotionMode, StageLadderDefinition, StageTransitionRule,
    evidence_class_rule, validate_ladder,
};
use super::projector::{
    StageProjectResult, StageProjectorInput, StageRoute, project_stage_transition, stage_position,
};
use crate::calendar::claims::decode_event_outcome_value;
use crate::calendar::outcome::{
    EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue, PREDICATE_CALENDAR_EVENT_OUTCOME,
    read_event_outcome,
};
use crate::campaign::claims::{CrmStageValue, EvidenceBasis, StageEvidenceClass};
use crate::claim::claim_surfaceable;
use crate::{EntityId, Result, Vault};

/// One leg of the ratified no-show recovery order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoShowRecoveryStep {
    /// Offer a same-day reschedule.
    SameDayReschedule,
    /// Bump after a delay.
    BumpAfter {
        /// The configured delay.
        delay_secs: u64,
    },
    /// Snooze the membership.
    Snooze,
}

/// The recovery plan a `no_show` outcome produces. It never writes `call_held`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoShowRecoveryPlan {
    /// The EVENT that did not happen.
    pub event_ref: EntityId,
    /// The `calendar.event_outcome` claim that says so.
    pub outcome_claim_ref: EntityId,
    /// Recovery legs, in the ratified order.
    pub steps: Vec<NoShowRecoveryStep>,
}

// ---------------------------------------------------------------------------
// Calendar outcomes - read side only
// ---------------------------------------------------------------------------

/// Consumes CAL-07's recorded outcome for one EVENT.
///
/// The whole point of this function is what it REFUSES to do. CAL-07's
/// `read_event_outcome` answers `None` for silence, and `None` projects to
/// Unknown — never to `Held`, whatever else the calendar, the thread, or the
/// elapsed clock might suggest. Only `Some(EventOutcome::Held)` can advance, and
/// only with the live outcome claim itself as evidence.
///
/// `no_show` returns the ratified recovery plan and never writes a held stage.
/// `cancelled_pre_start`, an explicit `unknown`, and silence all return
/// [`StageProjectResult::NoChange`].
///
/// The outcome VALUE and the outcome CLAIM the stage cites are bound to each
/// other by `live_event_outcome_claim`, so an outcome that changes between the
/// two reads cannot be decided on under one value and cited under another.
///
/// # Errors
///
/// Propagates [`validate_ladder`], CAL-07's reader, and the projector.
pub fn apply_event_outcome(
    vault: &Vault,
    definition: &StageLadderDefinition,
    party_ref: &EntityId,
    campaign_ref: &EntityId,
    event_ref: &EntityId,
    mode: PromotionMode,
) -> Result<StageProjectResult> {
    validate_ladder(definition)?;
    let Some(outcome) = read_event_outcome(vault, *event_ref)? else {
        return Ok(StageProjectResult::NoChange);
    };
    let Some(outcome_claim_ref) = live_event_outcome_claim(vault, event_ref, &outcome)? else {
        return Ok(StageProjectResult::NoChange);
    };
    match outcome.outcome {
        EventOutcome::Held => promote_on_held(
            vault,
            definition,
            party_ref,
            campaign_ref,
            &HeldOutcome {
                value: outcome,
                claim_ref: outcome_claim_ref,
            },
            mode,
        ),
        EventOutcome::NoShow => Ok(StageProjectResult::Routed(StageRoute::Reengage(
            NoShowRecoveryPlan {
                event_ref: *event_ref,
                outcome_claim_ref,
                steps: recovery_steps(&definition.no_show_recovery),
            },
        ))),
        EventOutcome::CancelledPreStart | EventOutcome::Unknown => Ok(StageProjectResult::NoChange),
    }
}

/// One `held` outcome as a promotion needs it: the value that was read and the
/// claim that carries it, resolved as ONE generation.
struct HeldOutcome {
    value: EventOutcomeClaimValue,
    claim_ref: EntityId,
}

fn promote_on_held(
    vault: &Vault,
    definition: &StageLadderDefinition,
    party_ref: &EntityId,
    campaign_ref: &EntityId,
    outcome: &HeldOutcome,
    mode: PromotionMode,
) -> Result<StageProjectResult> {
    let (previous_stage_claim_ref, from) = stage_position(vault, party_ref, campaign_ref)?;
    let Some(rule) = evidence_class_rule(
        definition,
        from.as_ref(),
        StageEvidenceClass::CalendarEventOutcome,
    ) else {
        return Ok(StageProjectResult::NoChange);
    };
    let Some(basis) = admissible_basis(outcome.value.basis, rule) else {
        return Ok(StageProjectResult::NoChange);
    };
    project_stage_transition(
        vault,
        &StageProjectorInput {
            party_ref: *party_ref,
            previous_stage_claim_ref,
            value: CrmStageValue {
                campaign_ref: *campaign_ref,
                stage: rule.to.clone(),
                evidence_class: rule.evidence_class,
                evidence_refs: vec![outcome.claim_ref],
                basis,
                recorded_at: outcome.value.recorded_at,
            },
        },
        mode,
    )
}

/// Carries CAL-07's basis onto the stage head, or refuses it.
///
/// An owner who answered the check-in is not a machine observation, and writing
/// one as the other would launder the attestation past the ladder's own dial and
/// out of the head a reader inspects. So the basis rides through, and a
/// transition that does not admit attestation declines the promotion instead of
/// relabelling it — a configuration statement, not an error.
///
/// The proposal-stage boundary [`require_owner_attestable`] applies is
/// deliberately NOT applied here: it governs the downstream evidence HOOKS,
/// whose truth lives in the counterparty ledger, whereas a calendar outcome is
/// CAL-07's own recorded fact and the owner check-in is its ratified
/// owner-attested producer. The per-transition dial is the whole gate on this
/// path.
fn admissible_basis(basis: EventOutcomeBasis, rule: &StageTransitionRule) -> Option<EvidenceBasis> {
    match basis {
        EventOutcomeBasis::Machine => Some(EvidenceBasis::Machine),
        EventOutcomeBasis::OwnerAttested => rule
            .owner_attested_allowed
            .then_some(EvidenceBasis::OwnerAttested),
    }
}

/// The ratified order: same-day reschedule, then the bump, then snooze. Each leg
/// is a dial the ladder can drop; their relative order is not.
fn recovery_steps(rule: &NoShowRecoveryRule) -> Vec<NoShowRecoveryStep> {
    let mut steps = Vec::with_capacity(3);
    if rule.same_day_reschedule {
        steps.push(NoShowRecoveryStep::SameDayReschedule);
    }
    steps.push(NoShowRecoveryStep::BumpAfter {
        delay_secs: rule.bump_after_secs,
    });
    if rule.snooze_after_failed_bump {
        steps.push(NoShowRecoveryStep::Snooze);
    }
    steps
}

/// The live `calendar.event_outcome` claim that CARRIES `outcome`.
///
/// CAL-07 answers the outcome VALUE and a stage head has to cite a CLAIM, so the
/// two reads are bound by the value itself rather than by a second guess at which
/// head is current: the claim returned here still says exactly what the decision
/// was made on. A supersession landing between the reads — the `no_show` that
/// replaced the `held` this call read — leaves nothing carrying that value, so
/// the caller changes nothing instead of writing `call_held` citing a claim that
/// says the call never happened.
///
/// Reader-visibility is CAL-07's rule too: a gate-pending head the read path
/// cannot see is not evidence a stage may cite. Ties are broken on the claim id
/// so the choice among identical values stays total.
fn live_event_outcome_claim(
    vault: &Vault,
    event_ref: &EntityId,
    outcome: &EventOutcomeClaimValue,
) -> Result<Option<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut carrying: Vec<EntityId> = Vec::new();
    for id in vault.claims_for_subject_in_txn(&rtxn, event_ref)? {
        let Some(body) = vault.get_claim_in_txn(&rtxn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CALENDAR_EVENT_OUTCOME || !claim_surfaceable(&body) {
            continue;
        }
        if decode_event_outcome_value(&body.value)? == *outcome {
            carrying.push(id);
        }
    }
    Ok(carrying.into_iter().max())
}
