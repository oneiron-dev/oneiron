//! Stage projection outcomes, wake/re-entry plans and their queued reference payload.

use crate::entity_id::EntityId;

/// The whole queue payload: three refs.
///
/// Resolving them is a CROSS-BINDING, not a lookup — the program must belong to
/// the event's campaign and the step must belong to that program, or execution
/// fails closed. Refs a caller can shuffle are refs a caller can misuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CampaignEnrollmentAttemptPayload {
    /// The persisted [`CampaignEnrollmentEvent`].
    pub membership_event_ref: EntityId,
    /// The persisted [`CampaignProgram`](crate::campaign::enrollment::CampaignProgram).
    pub campaign_program_ref: EntityId,
    /// The persisted [`CampaignProgramStep`].
    pub program_step_ref: EntityId,
}

/// When a paused membership wakes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeCondition {
    /// At a deadline.
    At(u64),
    /// When a new trigger arrives.
    NewTrigger,
    /// At the deadline OR on a new trigger, whichever comes first.
    AtOrNewTrigger {
        /// The deadline half.
        at: u64,
    },
}

/// One snooze-with-wake re-entry directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReentryPlan {
    /// PERSON being paused.
    pub party_ref: EntityId,
    /// Campaign the pause is scoped to.
    pub campaign_ref: EntityId,
    /// The wake condition written onto the `campaign.member` head.
    pub wake: WakeCondition,
    /// Always 0: restart at touch 1.
    pub restart_touch_index: u32,
    /// The NEW reason this re-entry exists. Retained, never inferred.
    pub reason_evidence_ref: EntityId,
    /// The CA-03 attempt this re-entry re-runs at touch 1, when the caller holds
    /// the program refs.
    ///
    /// `None` pauses without queueing: the wake condition still lands on the
    /// membership head, and a caller that later resolves the program enqueues
    /// through this same door. The three refs cannot be derived here — CA-03's
    /// enqueue takes `{membership_event_ref, campaign_program_ref,
    /// program_step_ref}` and no campaign-to-program index exists — so they ride
    /// the plan rather than being invented.
    pub reentry_attempt: Option<CampaignEnrollmentAttemptPayload>,
}

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

/// The recovery plan a `no_show` or `cancelled_pre_start` outcome produces.
/// It never writes `call_held`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoShowRecoveryPlan {
    /// The EVENT that did not happen.
    pub event_ref: EntityId,
    /// The `calendar.event_outcome` claim that says so.
    pub outcome_claim_ref: EntityId,
    /// Recovery legs, in the ratified order.
    pub steps: Vec<NoShowRecoveryStep>,
}

/// What one ladder call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageProjectResult {
    /// The stage head moved.
    Advanced {
        /// The new live `crm.stage` head.
        new_claim_ref: EntityId,
    },
    /// A proposed head landed for the existing approval machinery to rule on.
    Proposed {
        /// The proposed `crm.stage` claim.
        proposed_claim_ref: EntityId,
    },
    /// Something happened that is not a stage move.
    Routed(StageRoute),
    /// Nothing to do. Silence, an unrouted code, and an unconfigured transition
    /// all land here — none of them is an error.
    NoChange,
}

/// A non-promoting route the ladder took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageRoute {
    /// The membership is paused with a wake condition.
    Snoozed(ReentryPlan),
    /// A no-show earned a recovery plan.
    Reengage(NoShowRecoveryPlan),
    /// Referral routing owns the next step.
    Referral,
    /// The membership left the cohort.
    Exited,
    /// The membership is held out of the cohort.
    Suppressed,
}
