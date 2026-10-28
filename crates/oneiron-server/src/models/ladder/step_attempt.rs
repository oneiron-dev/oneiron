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
        self.admits(&request)?;
        if !self.picked || self.rungs.len() != 1 {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let call = Call {
            run,
            request: &request,
            selector: None,
            needs: Needs::Chat {
                request: &request,
                stream: false,
            },
        };
        let mut walk = Walk::default();
        if let StepOfferAvailability::Parked(refusal) =
            self.step_offer_availability(call, &mut walk)
        {
            return Err(refusal);
        }
        // A managed worker's lease is held through settlement (FIX 8315),
        // and the offer's probation slot through the request.
        match self.send(call, 0, &|| true, None, &mut walk).await? {
            Sent::Answer(response) => Ok(response),
            Sent::Failed | Sent::Held | Sent::Stopped => {
                Err(self.record_step_offer_result(call, walk))
            }
        }
    }
}
