//! Routine driver steps (the CUA-S1 pattern, OF-523): a small decider takes a driver's
//! routine choice behind the driver, under the same ladder, clock and receipts as every
//! typed decision. The driver and its loop stay the caller's; a planner writes the loop,
//! and that writing is generation, never a decision here.
//!
//! A routine Choice offers the step's candidates and three reserved options inside its
//! 64: NONE (no candidate fits), reobserve (look again before choosing) and "too
//! complicated, ask up" (the step goes back to the planner). A routine Box finds the
//! step's target in a screenshot: its centre is the point the driver acts at, and a found
//! absence is NONE. A ladder that gives no answer sends the step up with its reason.
//! Every step of one subgoal reads the subgoal's one clock, so a reobserve or a retry
//! never restarts it.

use super::policy::{DecisionBandPolicy, Reversibility};
use super::types::invalid;
use super::{
    AnswerContract, DecisionAnswer, DecisionDial, DecisionImage, DecisionLadder, DecisionQuestion,
    HumanAskReason, ImageBox, TypedDecision,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The reserved option a decider picks when no candidate fits.
pub const ROUTINE_NONE: &str = "NONE";
/// The reserved option a decider picks to look again before it chooses.
pub const ROUTINE_REOBSERVE: &str = "reobserve";
/// The reserved option a decider picks to hand the step back to the planner.
pub const ROUTINE_ASK_UP: &str = "too complicated, ask up";
/// The three options every routine Choice reserves, in the order they close its list.
pub const ROUTINE_RESERVED: [&str; 3] = [ROUTINE_NONE, ROUTINE_REOBSERVE, ROUTINE_ASK_UP];
/// Candidates one routine Choice may offer: the contract's 64 less the three reserved.
pub const MAX_ROUTINE_CANDIDATES: usize = 61;
/// NONE or reobserve answers in a row before the next observation takes a screenshot
/// (EIRI-ARCH-0002: "the decider returns NONE or reobserve twice").
pub const ROUTINE_MISSES_BEFORE_SCREENSHOT: u32 = 2;

/// A routine step's Choice: `candidates` (each a driver target the caller can act on),
/// then the three reserved options. A candidate that spells a reserved option, in any
/// case, is refused, so an answer always says which it is.
pub fn routine_choice(candidates: &[String]) -> Result<AnswerContract> {
    if candidates.is_empty()
        || candidates.len() > MAX_ROUTINE_CANDIDATES
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

/// Whether `contract` is a routine step's: a Box, or a Choice closed by the three
/// reserved options.
pub fn is_routine(contract: &AnswerContract) -> bool {
    match contract {
        AnswerContract::Box => true,
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

/// What the driver does with a routine step's answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum RoutineOutcome {
    /// The decider picked this candidate: the driver takes its step on it.
    Act { candidate: String },
    /// The step's target in the screenshot: the driver acts at `x`, `y` (fractions of
    /// the image from its top-left), the centre of `found`.
    Point { x: f64, y: f64, found: ImageBox },
    /// No candidate fits, or the target is not in the screenshot.
    None,
    /// Look again before choosing.
    Reobserve,
    /// The step goes back to the planner: the decider chose to ask up (no reason), or the
    /// ladder gave no answer (`reason` says why: uncertain, cut by the clock, no rung).
    AskUp { reason: Option<HumanAskReason> },
}

impl RoutineOutcome {
    /// The routine reading of `decision`, a typed decision over a routine contract.
    pub fn of(decision: &TypedDecision) -> Result<Self> {
        Ok(match &decision.answer {
            DecisionAnswer::Choice(choice) if choice == ROUTINE_NONE => Self::None,
            DecisionAnswer::Choice(choice) if choice == ROUTINE_REOBSERVE => Self::Reobserve,
            DecisionAnswer::Choice(choice) if choice == ROUTINE_ASK_UP => {
                Self::AskUp { reason: None }
            }
            DecisionAnswer::Choice(choice) => Self::Act {
                candidate: choice.clone(),
            },
            DecisionAnswer::Box(Some(found)) => {
                let (x, y) = found.centre();
                Self::Point {
                    x,
                    y,
                    found: *found,
                }
            }
            DecisionAnswer::Box(None) => Self::None,
            DecisionAnswer::Abstain => Self::AskUp {
                reason: decision.human_ask,
            },
            DecisionAnswer::Noul(_) | DecisionAnswer::Score(_) => {
                return Err(invalid("not a routine answer"));
            }
        })
    }

    /// Whether the step found nothing to act on yet: NONE or reobserve.
    pub fn misses(&self) -> bool {
        matches!(self, Self::None | Self::Reobserve)
    }
}

/// The NONE and reobserve answers one subgoal's steps gave in a row: after
/// [`ROUTINE_MISSES_BEFORE_SCREENSHOT`] of them the next observation takes a screenshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutineTrail {
    pub misses: u32,
}

impl RoutineTrail {
    /// Records `outcome`; true when the next observation takes a screenshot.
    pub fn record(&mut self, outcome: &RoutineOutcome) -> bool {
        self.misses = if outcome.misses() {
            self.misses.saturating_add(1)
        } else {
            0
        };
        self.misses >= ROUTINE_MISSES_BEFORE_SCREENSHOT
    }
}

/// One routine step's answer: what the driver does, and the decision with its receipt.
#[derive(Debug, Clone, PartialEq)]
pub struct RoutineDecision {
    pub outcome: RoutineOutcome,
    pub decision: TypedDecision,
}

impl DecisionLadder<'_> {
    /// One routine driver step: [`Self::run_images`] over a routine contract
    /// ([`routine_choice`] or a Box), read as a [`RoutineOutcome`]. `deadline` is the
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
        })
    }
}
