//! Opt-in, non-light typed-decision seat and its receipt boundary.

use super::ladder::millis;
use super::{
    AnswerContract, DecisionAnswer, DecisionAudio, DecisionDial, DecisionImage, DecisionQuestion,
    DecisionReceipt, DecisionRung, DecisionTime, HumanAskReason, ProviderPin, Reasoning, ReasoningCause,
    Reversibility, StopCause, TypedDecision,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{
    BudgetGuard, BudgetLease, EntityId, FatalLlmError, HostingPrivacyPosture, LlmResult, LlmUsage,
};
use serde_json::Value;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// The remote call is never admitted on a light query or synchronous relay path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatPhase {
    PreQuery,
    Background,
    Light,
}

#[derive(Debug, Clone)]
pub struct SeatRequest {
    pub question: DecisionQuestion,
    /// Only a bounded, caller-scoped object; never an implicit vault dump.
    pub state: Value,
    /// Images the question reads, each filling the state field of its name. The
    /// receipt keeps their evidence refs, never the pixels.
    pub images: Vec<DecisionImage>,
    /// Audio clips the question reads, each filling the state field of its name. The
    /// receipt keeps their evidence refs, never the samples.
    pub audio: Vec<DecisionAudio>,
    /// Caller-authored labels for score levels in ascending order (2 to 10).
    pub score_levels: Vec<String>,
    pub posture: HostingPrivacyPosture,
    pub remote_opt_in: bool,
    pub phase: SeatPhase,
}

impl SeatRequest {
    pub fn validate_remote(&self) -> LlmResult<()> {
        self.question
            .validate()
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        if !(self.posture == HostingPrivacyPosture::Hosted || self.remote_opt_in)
            || self.posture == HostingPrivacyPosture::Relay
            || self.phase == SeatPhase::Light
            || !self.state.is_object()
            || serde_json::to_vec(&self.state)
                .map_err(|_| FatalLlmError::InvalidRequest)?
                .len()
                > 65_536
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        DecisionImage::check_call(
            &self.images,
            &self.state,
            matches!(self.question.contract, AnswerContract::Box),
        )?;
        DecisionAudio::check_call(&self.audio, &self.images, &self.state)?;
        match &self.question.contract {
            AnswerContract::Score { .. } if !(2..=10).contains(&self.score_levels.len()) => {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            AnswerContract::Score { .. } => {
                if self
                    .score_levels
                    .iter()
                    .any(|s| s.trim().is_empty() || s.len() > 256)
                {
                    return Err(FatalLlmError::InvalidRequest.into());
                }
            }
            _ if !self.score_levels.is_empty() => return Err(FatalLlmError::InvalidRequest.into()),
            _ => {}
        }
        Ok(())
    }
}

/// Noul probability is P(yes); choice/score probability is the selected answer's confidence.
#[derive(Debug, Clone, PartialEq)]
pub struct SeatAnswer {
    pub answer: DecisionAnswer,
    pub probability: f64,
    /// Tokens reported by this measurement; settled against its own lease.
    pub usage: LlmUsage,
}

pub type SeatFuture<'a> = Pin<Box<dyn Future<Output = LlmResult<SeatAnswer>> + Send + 'a>>;

/// A provider-specific seat behind the shared typed-decision boundary.
/// Hosts select providers; this trait never selects an egress route itself.
/// `time_left` is the call's work time left: a seat with a native deadline gets it,
/// and its client waits no longer.
pub trait DecisionSeat: Send + Sync {
    fn pin(&self) -> ProviderPin;
    fn ask<'a>(
        &'a self,
        request: SeatRequest,
        lease: &'a BudgetLease,
        time_left: Duration,
    ) -> SeatFuture<'a>;
}

/// One off-hot remote rung under the call's one clock, `deadline`. The caller owns
/// access-scoped state and subsequent escalation; uncertainty or disagreement is a
/// hold, never an accepted verdict. No measurement starts once the work time is spent.
/// A reply after the answer's time, or a failure once the work time is spent, is the
/// cut. A late reply is charged the usage it reports; a failed one is charged its
/// lease's reservation, since the provider may still bill. At the cut a reversible
/// step takes the answer it holds and an irreversible one abstains; with no answer
/// the call abstains.
#[expect(
    clippy::too_many_arguments,
    reason = "the call's clock and its step's reversibility join the seat's request"
)]
pub async fn decide_at_remote_seat(
    seat: &dyn DecisionSeat,
    request: SeatRequest,
    principal: EntityId,
    evidence: Vec<EntityId>,
    dial: DecisionDial,
    guard: &BudgetGuard,
    reversibility: Reversibility,
    deadline: &RetrievalDeadline,
) -> LlmResult<TypedDecision> {
    request.validate_remote()?;
    dial.band
        .validate()
        .map_err(|_| FatalLlmError::InvalidRequest)?;
    if dial.first > DecisionRung::SystemOne || dial.ceiling < DecisionRung::SystemOne {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let pin = seat.pin();
    if pin.rung != DecisionRung::SystemOne
        || pin.model.trim().is_empty()
        || pin.version.trim().is_empty()
    {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let mut providers = Vec::new();
    let mut stop = StopCause::Done;
    let mut reasoning = Reasoning::NotNeeded;
    let mut answer = DecisionAnswer::Abstain;
    let mut probability = None;
    let mut human_ask = Some(HumanAskReason::Deadline);
    // Each measurement is admitted and settled as its own call. A retry cannot
    // silently reuse the first terminal lease or exceed the caller's budget.
    let first = if deadline.decision_may_start() {
        let first_lease = guard.admit()?.lease;
        providers.push(pin.clone());
        let first = seat
            .ask(request.clone(), &first_lease, deadline.decision_time_left())
            .await;
        match first {
            Ok(first) => {
                guard.settle_per_call(&first_lease, &first.usage)?;
                (!deadline.answer_due()).then_some(first)
            }
            Err(error) => {
                guard.settle_reserved(&first_lease)?;
                if deadline.decision_may_start() {
                    return Err(error);
                }
                None
            }
        }
    } else {
        None
    };
    match first {
        None => stop = StopCause::Deadline,
        Some(first) => {
            check_answer(&request, &first)?;
            answer = first.answer.clone();
            probability = Some(first.probability);
            human_ask = None;
            // A negative accept-type Noul requires a fresh admitted measurement.
            if request.question.accept_type
                && matches!(request.question.contract, AnswerContract::Noul)
                && answer == DecisionAnswer::Noul(false)
                && first.probability < dial.band.low
            {
                let cause = ReasoningCause::SecondMeasurement;
                if !deadline.decision_may_start() {
                    stop = StopCause::Deadline;
                    reasoning = Reasoning::Skipped(cause);
                } else {
                    match guard.admit() {
                        Ok(admission) => {
                            reasoning = Reasoning::Ran(cause);
                            providers.push(pin);
                            let second = seat
                                .ask(
                                    request.clone(),
                                    &admission.lease,
                                    deadline.decision_time_left(),
                                )
                                .await;
                            match second {
                                Ok(second) => {
                                    guard.settle_per_call(&admission.lease, &second.usage)?;
                                    if deadline.answer_due() {
                                        stop = StopCause::Deadline;
                                        reasoning = Reasoning::Cut(cause);
                                    } else if check_answer(&request, &second).is_err() {
                                        answer = DecisionAnswer::Abstain;
                                        probability = None;
                                        human_ask = Some(HumanAskReason::ProviderUnavailable);
                                        stop = StopCause::ProviderFailure;
                                    } else if second.answer != DecisionAnswer::Noul(false)
                                        || second.probability >= dial.band.low
                                    {
                                        answer = DecisionAnswer::Abstain;
                                        probability = None;
                                        human_ask = Some(HumanAskReason::Disagreement);
                                    } else {
                                        probability = Some(second.probability);
                                    }
                                }
                                Err(_) => {
                                    guard.settle_reserved(&admission.lease)?;
                                    if deadline.decision_may_start() {
                                        answer = DecisionAnswer::Abstain;
                                        probability = None;
                                        human_ask = Some(HumanAskReason::ProviderUnavailable);
                                        stop = StopCause::ProviderFailure;
                                    } else {
                                        stop = StopCause::Deadline;
                                        reasoning = Reasoning::Cut(cause);
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            reasoning = Reasoning::Skipped(cause);
                            answer = DecisionAnswer::Abstain;
                            probability = None;
                            human_ask = Some(HumanAskReason::ProviderUnavailable);
                            stop = StopCause::ProviderFailure;
                        }
                    }
                }
                // The second measurement did not finish: an irreversible step never
                // takes the unfinished negative.
                if stop == StopCause::Deadline && reversibility == Reversibility::OutboundEffect {
                    answer = DecisionAnswer::Abstain;
                    probability = None;
                    human_ask = Some(HumanAskReason::Deadline);
                }
            }
        }
    }
    let in_band = probability.is_some_and(|p| match request.question.contract {
        AnswerContract::Noul => dial.band.contains(p),
        // Choice/score/box report the selected answer's confidence, not P(yes).
        // None has a 'confident no' below the lower bound.
        AnswerContract::Choice { .. } | AnswerContract::Score { .. } | AnswerContract::Box => {
            p < dial.band.high
        }
    });
    if in_band {
        answer = DecisionAnswer::Abstain;
        human_ask = Some(HumanAskReason::Uncertain);
    }
    let answered = (answer != DecisionAnswer::Abstain).then_some(DecisionRung::SystemOne);
    let evidence_versions = request
        .images
        .iter()
        .map(|image| image.evidence.clone())
        .chain(request.audio.iter().map(|clip| clip.evidence.clone()))
        .collect();
    Ok(TypedDecision {
        answer,
        probability,
        evidence,
        in_band,
        receipt: DecisionReceipt {
            question: request.question.id,
            question_version: request.question.version,
            principal,
            providers,
            band: dial.band,
            band_version: 0,
            evidence_versions,
            cost_per_thousand: None,
            paired: Vec::new(),
            person: Vec::new(),
            time: Some(DecisionTime {
                budget_ms: millis(deadline.budget()),
                used_ms: millis(deadline.used()),
                stop,
                answered,
                reasoning,
            }),
        },
        human_ask,
    })
}

fn check_answer(request: &SeatRequest, response: &SeatAnswer) -> LlmResult<()> {
    if !response.probability.is_finite()
        || !(0.0..=1.0).contains(&response.probability)
        || !request.question.contract.accepts(&response.answer)
        || response.answer == DecisionAnswer::Abstain
        || matches!(response.answer, DecisionAnswer::Noul(true)) && response.probability < 0.5
        || matches!(response.answer, DecisionAnswer::Noul(false)) && response.probability >= 0.5
    {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
