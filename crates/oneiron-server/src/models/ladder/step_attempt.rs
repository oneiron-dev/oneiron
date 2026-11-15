//! The durable step executor owns retries; this door sends one gated attempt.
use super::step_quota::StepOfferAvailability;
use super::*;

impl OfferLadder {
    /// One exact-model attempt for the durable step executor. Its retry
    /// policy owns the backoff: no ladder walk, cooldown wait or owner model
    /// fallback can multiply that count. The attempt still meets its offer
    /// as every call does (FIX 9510): an offer that rests, or whose one
    /// probation request is out, parks the attempt unsent with when it is
    /// back, and the attempt's end is kept on the offer
    /// ([`Self::step_offer_availability`]). Every send takes this run's
    /// ordinary admission, gate, one-use permit and settlement.
    pub(crate) async fn generate_step_attempt(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
    ) -> LlmResult<LlmResponse> {
        self.generate_step_attempt_while(run, request, &|| true)
            .await
    }

    /// [`Self::generate_step_attempt`] that asks `may_send` before each
    /// physical admission and again before its send, as the walks do: a
    /// `false` ends the attempt with nothing more sent.
    pub(crate) async fn generate_step_attempt_while(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        may_send: &(dyn Fn() -> bool + Sync),
    ) -> LlmResult<LlmResponse> {
        self.admits(&request)?;
        if !self.picked || self.rungs.len() != 1 {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let routes = self.rests.world_routes(&request);
        let call = Call {
            run,
            request: &request,
            selector: None,
            needs: Needs::Chat {
                request: &request,
                stream: false,
            },
            routes: &routes,
            // The executor's own retry policy bounds the attempt.
            deadline: CallDeadline::Open,
        };
        let mut walk = Walk::default();
        if let StepOfferAvailability::Parked(refusal) =
            self.step_offer_availability(call, &mut walk)
        {
            return Err(refusal);
        }
        // A managed worker's lease is held through settlement (FIX 8315),
        // and the offer's probation slot through the request.
        match self
            .send(
                call,
                0,
                may_send,
                None,
                None,
                false,
                RungPrompt::Configured,
                &mut walk,
            )
            .await?
        {
            Sent::Answer(response, _) => Ok(response),
            Sent::Failed | Sent::Held | Sent::Stopped => {
                Err(self.record_step_offer_result(call, walk))
            }
        }
    }

    /// How long, in all, a durable step waits unsent for this ladder's offer
    /// back from a health rest before it hands the rest to its caller (FIX
    /// 11226): the vault's longest wait for an offer back, as any call's.
    pub(crate) fn step_rest_wait(&self) -> Duration {
        Duration::from_secs(self.rests.max_wait_secs())
    }
}
