//! A durable attempt's offer under the state every call shares (FIX 9510).
//! The attempt reads the offer's rests and probation before it is admitted,
//! and its end writes them as any call's does: an answer counts toward a
//! recovery, a limit refusal rests the offer, a down provider rests it for
//! its health. An attempt that meets its offer parked is not admitted and
//! goes nowhere else; its retry owner gets the refusal in the providers' one
//! vocabulary, with when the offer is back, and keeps the work. A spent window
//! or spent credit asks the owner the offer's quota question; only the
//! owner's answer pays, tops up or names another model.
//! Entry: `OfferLadder::step_offer_availability`.
use super::*;
use crate::models::cooldown::ResetSource;

/// What the offer's shared state says of one durable attempt before it is
/// admitted.
pub(super) enum StepOfferAvailability {
    /// Nothing another call met holds the offer: the attempt goes out.
    Open,
    /// The offer rests for a limit or its health, or its one probation
    /// request is out: the attempt is not admitted, and its retry owner gets
    /// this refusal.
    Parked(LlmError),
}

impl OfferLadder {
    /// The offer of this one-rung ladder as a durable attempt finds it now.
    pub(super) fn step_offer_availability(
        &self,
        call: Call<'_>,
        walk: &mut Walk,
    ) -> StepOfferAvailability {
        if !self.passes_over(call, 0, walk) {
            return StepOfferAvailability::Open;
        }
        StepOfferAvailability::Parked(self.parked_refusal(call, std::mem::take(walk)))
    }

    /// The refusal a durable attempt that did not answer ends with, once its
    /// failure is kept on the offer (the walk's [`Self::failed`] rested it):
    /// the provider's own error, after the owner is asked about a spent
    /// window or credit; or, for an attempt held unsent, the offer's park.
    pub(super) fn record_step_offer_result(&self, call: Call<'_>, mut walk: Walk) -> LlmError {
        match walk.last.take() {
            Some(error) => {
                self.ask_parked(&walk, call.needs, call.run.principal());
                error
            }
            None => self.parked_refusal(call, walk),
        }
    }

    /// Why the attempt's offer is parked: a spent window with its reset, or
    /// spent credit, which only the owner brings back, each after the owner
    /// is asked; else the walk's own end, a rate limit with when the offer
    /// is back or an outage.
    fn parked_refusal(&self, call: Call<'_>, walk: Walk) -> LlmError {
        let spent = walk
            .parked(self.rungs.len())
            .and_then(|parked| parked.first().map(|(_, rest)| *rest))
            .and_then(|rest| Some((rest, rest.spent?)));
        let Some(((rest, kind), now)) = spent.zip(self.rests.now()) else {
            return self.unanswered(call, walk);
        };
        self.ask_parked(&walk, call.needs, call.run.principal());
        let (retry_after, resets_at) = match rest.source {
            ResetSource::Parked => (None, Vec::new()),
            _ => (Some(rest.until.saturating_sub(now)), vec![rest.until]),
        };
        RetryableLlmError::QuotaSpent {
            kind,
            retry_after,
            resets_at,
        }
        .into()
    }
}
