//! A step replay's route prompt (FIX 6255): a replay sends the route prompt
//! its capsule's body holds, each secret in it its custody handle, on the
//! one picked rung of the captured model, by the same exact walk and the
//! same bind as any call: one picked rung, no fallback, the prompt put first
//! once, the cache boundaries and the host segments shifted for it. The
//! prompt is the call's own. No shared ladder or rung changes; the answer's
//! binding names the rung as configured; and the answer is noted for no
//! capture, so the stored prompt reaches no model-call record, capsule or
//! pin. Before the stored prompt takes the rung's place, the caller checks
//! the route configured now against the prompt as first sent, by its digest
//! ([`OfferLadder::exact_prompt_digest`], FIX 6356), never by its text.
use super::*;

/// The route prompt a call's rung puts first.
#[derive(Clone, Copy)]
pub(super) enum RungPrompt<'a> {
    /// The rung's configured prompt. The rung that answers names itself
    /// for a capture waiting on this thread.
    Configured,
    /// A step replay's stored prompt, `None` for a captured call whose rung
    /// put none. The answer is noted for no capture.
    Replayed(Option<&'a str>),
}

impl RungPrompt<'_> {
    /// `rung` as this call sends on it: a copy for this call alone, which
    /// puts a replay's prompt first in place of the configured one.
    pub(super) fn rung(self, rung: &LadderRung) -> LadderRung {
        let mut rung = rung.clone();
        if let Self::Replayed(prompt) = self {
            rung.prompt = prompt.map(str::to_owned);
        }
        rung
    }

    /// Whether the rung that answers names itself for a capture waiting on
    /// this thread (FIX 3028): never for a replay, whose stored prompt no
    /// capsule takes.
    pub(super) const fn noted(self) -> bool {
        matches!(self, Self::Configured)
    }
}

impl OfferLadder {
    /// The route prompt digest of this ladder's one picked rung as
    /// configured (FIX 6356, [`oneiron::code_run::route_prompt_digest`]):
    /// what a replay compares with its capsule's digest of the prompt as
    /// first sent before it sends the stored prompt. `None` for any other
    /// ladder.
    #[must_use]
    pub(crate) fn exact_prompt_digest(&self) -> Option<[u8; 32]> {
        self.exact_prompt()
            .map(oneiron::code_run::route_prompt_digest)
    }

    /// [`Self::generate_exact_within`], the one picked rung putting `prompt`
    /// first in place of its configured prompt (FIX 6255): a step replay's
    /// stored route prompt, `None` for a captured call whose rung put none.
    /// The prompt goes through the rung's one bind, once; preflight, the
    /// request-digest admission and the send all see the same bound call.
    /// Only a ladder that is one picked model takes the call, and no owner's
    /// fallback does. The answer is noted for no capture.
    pub(crate) async fn generate_exact_masked_within(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        prompt: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        wait_budget: Duration,
    ) -> LlmResult<LlmResponse> {
        if !self.picked || self.rungs.len() != 1 {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let deadline = CallDeadline::waits_within(wait_budget);
        let prompt = RungPrompt::Replayed(prompt);
        self.walk_generate(
            run, request, selector, may_send, deadline, false, None, prompt,
        )
        .await
        .map(|(response, _)| response)
    }
}
