//! The durable step executor owns retries; this door sends one gated attempt.
use super::*;

impl OfferLadder {
    /// One exact-model attempt for the durable step executor. Its retry
    /// policy owns the backoff: no ladder walk, cooldown retry or owner model
    /// fallback can multiply that count. Every send still takes this run's
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
        let rung = &self.rungs[0];
        let (bound, permit) = self.admit(run, rung, &request, None, false)?;
        let gate = run.gate(Arc::clone(&rung.offer.backend), &rung.offer.binding);
        let warmth = super::cache_warmth::Sending::of(rung, &bound);
        match gate.generate(bound, permit.lease()).await {
            Ok(mut response) => {
                warmth.answered(&self.rests);
                permit.settle(CallOutcome::Answered(&response.usage))?;
                response.usage = self.answered(0, &Walk::default(), response.usage);
                rung.note_answered(&request);
                Ok(response)
            }
            Err(error) => {
                settle_failed(permit);
                Err(error)
            }
        }
    }
}
