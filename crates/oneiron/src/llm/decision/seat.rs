//! Opt-in, non-light typed-decision seat and its receipt boundary.

use super::{
    AnswerContract, DecisionAnswer, DecisionDial, DecisionQuestion, DecisionReceipt, DecisionRung,
    HumanAskReason, ProviderPin, TypedDecision,
};
use crate::{
    BudgetGuard, BudgetLease, EntityId, FatalLlmError, HostingPrivacyPosture, LlmResult, LlmUsage,
};
use serde_json::Value;
use std::future::Future;
use std::pin::Pin;

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
pub trait DecisionSeat: Send + Sync {
    fn pin(&self) -> ProviderPin;
    fn ask<'a>(&'a self, request: SeatRequest, lease: &'a BudgetLease) -> SeatFuture<'a>;
}

/// One off-hot remote rung. The caller owns access-scoped state and subsequent
/// escalation; uncertainty or disagreement is a hold, never an accepted verdict.
pub async fn decide_at_remote_seat(
    seat: &dyn DecisionSeat,
    request: SeatRequest,
    principal: EntityId,
    evidence: Vec<EntityId>,
    dial: DecisionDial,
    guard: &BudgetGuard,
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
    // Each measurement is admitted and settled as its own call. A retry cannot
    // silently reuse the first terminal lease or exceed the caller's budget.
    let first_lease = guard.admit()?.lease;
    let first = seat.ask(request.clone(), &first_lease).await;
    let first = match first {
        Ok(first) => {
            guard.settle_per_call(&first_lease, &first.usage)?;
            first
        }
        Err(error) => {
            guard.settle_reserved(&first_lease)?;
            return Err(error);
        }
    };
    check_answer(&request, &first)?;
    let mut providers = vec![pin.clone()];
    let mut answer = first.answer.clone();
    let mut probability = Some(first.probability);
    let mut human_ask = None;
    // A negative accept-type Noul requires a fresh admitted measurement.
    if request.question.accept_type
        && matches!(request.question.contract, AnswerContract::Noul)
        && answer == DecisionAnswer::Noul(false)
        && first.probability < dial.band.low
    {
        match guard.admit() {
            Ok(admission) => {
                providers.push(pin);
                let second = seat.ask(request.clone(), &admission.lease).await;
                match second {
                    Ok(second) => {
                        guard.settle_per_call(&admission.lease, &second.usage)?;
                        if check_answer(&request, &second).is_err() {
                            answer = DecisionAnswer::Abstain;
                            probability = None;
                            human_ask = Some(HumanAskReason::ProviderUnavailable);
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
                        answer = DecisionAnswer::Abstain;
                        probability = None;
                        human_ask = Some(HumanAskReason::ProviderUnavailable);
                    }
                }
            }
            Err(_) => {
                answer = DecisionAnswer::Abstain;
                probability = None;
                human_ask = Some(HumanAskReason::ProviderUnavailable);
            }
        }
    }
    let in_band = probability.is_some_and(|p| match request.question.contract {
        AnswerContract::Noul => dial.band.contains(p),
        // Choice/score report the selected answer's confidence, not P(yes).
        // Neither has a 'confident no' below the lower bound.
        AnswerContract::Choice { .. } | AnswerContract::Score { .. } => p < dial.band.high,
    });
    if in_band {
        answer = DecisionAnswer::Abstain;
        human_ask = Some(HumanAskReason::Uncertain);
    }
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
            evidence_versions: Vec::new(),
            cost_per_thousand: None,
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
