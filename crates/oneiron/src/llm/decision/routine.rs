//! Routine driver steps (the CUA-S1 pattern, OF-523): a small decider takes a driver's
//! routine choice behind the driver, under the same ladder, clock and receipts as every
//! typed decision. The driver and its loop stay the caller's; a planner writes the loop,
//! and that writing is generation, never a decision here.
//!
//! A routine Choice offers every one of the step's candidates and three reserved options:
//! NONE (no candidate fits), reobserve (look again before choosing) and "too
//! complicated, ask up" (the step goes back to the planner). Their count is no refusal; a
//! provider that cannot take them all is passed over for one that can (FIX 9908). A routine Box or Point finds
//! the step's target in a screenshot, presence first: the point, or the box's centre, is
//! where the driver acts, and a found absence is NONE. A ladder that gives no answer sends
//! the step up with its reason.
//! Every step of one subgoal reads the subgoal's one clock, so a reobserve or a retry
//! never restarts it.

use super::policy::{DecisionBandPolicy, Reversibility};
use super::types::invalid;
use super::{
    AnswerContract, DecisionDial, DecisionImage, DecisionLadder, DecisionQuestion, LocatedDecision,
    TypedDecision,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Result};
use serde_json::Value;

#[doc(hidden)]
pub use oneiron_records::llm::decision::routine::{
    ROUTINE_ASK_UP, ROUTINE_MISSES_BEFORE_SCREENSHOT, ROUTINE_NONE, ROUTINE_REOBSERVE,
    RoutineOutcome, RoutineTrail,
};

/// The three options every routine Choice reserves, in the order they close its list.
pub const ROUTINE_RESERVED: [&str; 3] = [ROUTINE_NONE, ROUTINE_REOBSERVE, ROUTINE_ASK_UP];
/// A routine step's Choice: `candidates` (each a driver target the caller can act on),
/// then the three reserved options. A candidate that spells a reserved option, in any
/// case, is refused, so an answer always says which it is.
pub fn routine_choice(candidates: &[String]) -> Result<AnswerContract> {
    if candidates.is_empty()
        || candidates.iter().any(|candidate| {
            ROUTINE_RESERVED
                .iter()
                .any(|reserved| candidate.trim().eq_ignore_ascii_case(reserved))
        })
    {
        return Err(invalid("invalid routine candidates"));
    }
    let mut options = candidates.to_vec();
    options.extend(ROUTINE_RESERVED.iter().map(|&reserved| reserved.to_owned()));
    let contract = AnswerContract::Choice { options };
    contract.validate()?;
    Ok(contract)
}

/// Whether `contract` is a routine step's: a Box or a Point, or a Choice closed by the
/// three reserved options.
pub fn is_routine(contract: &AnswerContract) -> bool {
    match contract {
        AnswerContract::Box | AnswerContract::Point => true,
        AnswerContract::Choice { options } => {
            options.len() > ROUTINE_RESERVED.len()
                && options[options.len() - ROUTINE_RESERVED.len()..]
                    .iter()
                    .zip(ROUTINE_RESERVED)
                    .all(|(option, reserved)| option == reserved)
        }
        AnswerContract::Noul | AnswerContract::Score { .. } => false,
    }
}

/// One routine step's answer: what the driver does, and the decision with its receipt.
#[derive(Debug, Clone, PartialEq)]
pub struct RoutineDecision {
    pub outcome: RoutineOutcome,
    /// The decision that stands: a located step's coordinates when they ran, else its
    /// presence step.
    pub decision: TypedDecision,
    /// A located step's presence decision, beside the coordinates it started.
    pub presence: Option<TypedDecision>,
}

impl DecisionLadder<'_> {
    /// One routine driver step: [`Self::run_images`] over a routine Choice
    /// ([`routine_choice`]), or [`Self::run_located`] over a Box or Point, read as a
    /// [`RoutineOutcome`]. `deadline` is the
    /// subgoal's one clock, borrowed: every step, reobserve and retry of the subgoal reads
    /// the same one. A step whose effect leaves the vault asks with
    /// [`Reversibility::OutboundEffect`], so at a cut it abstains and goes up.
    #[expect(
        clippy::too_many_arguments,
        reason = "the step's images, state and clock join the question, its scope, the dial and the policy"
    )]
    pub fn run_routine(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
        evidence: &[EntityId],
        images: &[DecisionImage],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<RoutineDecision> {
        if !is_routine(&question.contract) {
            return Err(invalid("not a routine step's question"));
        }
        if question.contract.locates() {
            let located: LocatedDecision = self.run_located(
                question,
                principal,
                evidence,
                images,
                state,
                dial,
                policy,
                reversibility,
                deadline,
            )?;
            let outcome = RoutineOutcome::of_located(&located)?;
            let (decision, presence) = located.split();
            return Ok(RoutineDecision {
                outcome,
                decision,
                presence,
            });
        }
        let decision = self.run_images(
            question,
            principal,
            evidence,
            images,
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )?;
        Ok(RoutineDecision {
            outcome: RoutineOutcome::of(&decision)?,
            decision,
            presence: None,
        })
    }
}
