//! A step replay's call (FIX 6255): the one replay path. The admitted
//! one-model ladder is selected for the capsule's call by the rung that
//! answered it, as it is configured now ([`OfferLadder::for_replay_binding`]):
//! the captured model, its offer that model's, served where the call ran.
//! The call sends the route prompt the capsule's body holds, each secret in
//! it its custody handle, by the same exact walk and the same bind as any
//! call: one picked rung, no fallback, the prompt put first once, the cache
//! boundaries and the host segments shifted for it. The prompt is the
//! call's own. No shared ladder or rung changes; the answer's binding names
//! the rung as configured; and the answer is noted for no capture, so the
//! stored prompt reaches no model-call record, capsule or pin. Before the
//! stored prompt takes the rung's place, the caller checks the selected
//! rung's configured prompt against the prompt as first sent, by its digest
//! ([`ReplayLadder::exact_prompt_digest`], FIX 6356), never by its text.
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

/// An admitted one-model ladder selected for a step replay: its one picked
/// rung is the rung that answered the capsule's call. Nothing of the ladder
/// changes; the capsule's stored route prompt goes on its call alone.
pub(crate) struct ReplayLadder<'a> {
    ladder: &'a OfferLadder,
    rung: &'a LadderRung,
}

impl OfferLadder {
    /// This admitted ladder as the replay of a capsule call that `model`
    /// answered at `locality`: only when it is one picked model, its one
    /// rung and that rung's offer are that model, and the offer serves
    /// where the call ran. `None` for any other ladder: no exact rung.
    pub(crate) fn for_replay_binding(
        &self,
        model: &ModelId,
        locality: ModelLocality,
    ) -> Option<ReplayLadder<'_>> {
        let [rung] = self.rungs.as_slice() else {
            return None;
        };
        if !self.picked
            || self.name != *model
            || rung.model != *model
            || rung.offer.binding.model != *model
            || rung.offer.binding.locality != locality
        {
            return None;
        }
        Some(ReplayLadder { ladder: self, rung })
    }

    /// The one-rung ladder of this ladder's first rung that serves at its own server, with
    /// that rung's own model (HOUSE-SCHEMA-CHECK; REVIEW-10538 rounds 1 and 2): a seat with
    /// a fallback after its house rung, such as EXL3 on its own server and then llama.cpp,
    /// still lends the answer-schema check that rung alone, and a route named by its
    /// synthetic `seat/<role>@<digest>` id finds it all the same, since the rung is chosen by
    /// where it serves, never by the route's name. The copy is picked, named for the rung's
    /// model, keeps the rung's configured prompt and place and this ladder's rests and scope,
    /// so [`Self::for_replay_binding`] selects it for that model and no fallback takes a call.
    /// It comes with where the rung's offer sends a call now, the destination the check judges
    /// each capture for. `None` when no rung serves at its own server. The shared ladder is
    /// never changed.
    pub(crate) fn house_rung_ladder(&self) -> Option<HouseRung> {
        let rung = self
            .rungs
            .iter()
            .find(|rung| rung.offer.binding.locality == ModelLocality::OwnServer)?;
        let model = rung.model.clone();
        let destination = rung.offer.destination();
        let ladder = Arc::new(Self {
            name: model.clone(),
            rungs: vec![rung.clone()],
            picked: true,
            rests: Arc::clone(&self.rests),
            scope: self.scope,
            prefix: ReceiptPrefix::default(),
            listed: self.listed.clone(),
        });
        Some(HouseRung {
            ladder,
            model,
            destination,
        })
    }
}

/// The house rung lent alone (HOUSE-SCHEMA-CHECK): its picked one-rung ladder, the rung's own
/// model, and where its offer sends a call now.
pub(crate) struct HouseRung {
    pub(crate) ladder: Arc<OfferLadder>,
    pub(crate) model: ModelId,
    pub(crate) destination: oneiron::settings::ReadDestination,
}

impl ReplayLadder<'_> {
    /// The route prompt digest of the selected rung as configured now (FIX
    /// 6356, [`oneiron::code_run::route_prompt_digest`]): what a replay
    /// compares with its capsule's digest of the prompt as first sent before
    /// it sends the stored prompt.
    #[must_use]
    pub(crate) fn exact_prompt_digest(&self) -> [u8; 32] {
        oneiron::code_run::route_prompt_digest(self.rung.prompt.as_deref())
    }

    /// [`OfferLadder::generate_exact_within`] on the selected rung, which
    /// puts `prompt` first in place of its configured prompt (FIX 6255): the
    /// capsule's stored route prompt, `None` for a captured call whose rung
    /// put none. The prompt goes through the rung's one bind, once;
    /// preflight, the request-digest admission and the send all see the same
    /// bound call. No owner's fallback takes the call. The answer is noted
    /// for no capture.
    pub(crate) async fn generate_exact_within(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        selector: Option<&str>,
        prompt: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        wait_budget: Duration,
    ) -> LlmResult<LlmResponse> {
        let deadline = CallDeadline::waits_within(wait_budget);
        let prompt = RungPrompt::Replayed(prompt);
        self.ladder
            .walk_generate(
                run, request, selector, may_send, deadline, false, None, None, false, prompt,
            )
            .await
            .map(|(response, _)| response)
    }

    /// [`Self::generate_exact_within`] for a call whose request carries sources the rung's
    /// destination must be admitted to (FIX 8714; REVIEW-10538 round 2): the picked rung is
    /// sent only while `sources` admits where its offer sends, judged before the rung is
    /// admitted and again right before each physical send, as any rung is on
    /// [`OfferLadder::generate_admitted`]. No owner's fallback takes the call.
    pub(crate) async fn generate_exact_admitted_within(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
        prompt: Option<&str>,
        may_send: &(dyn Fn() -> bool + Sync),
        sources: &dyn SourceAdmission,
        wait_budget: Duration,
    ) -> LlmResult<LlmResponse> {
        let deadline = CallDeadline::waits_within(wait_budget);
        let prompt = RungPrompt::Replayed(prompt);
        self.ladder
            .walk_generate(
                run,
                request,
                None,
                may_send,
                deadline,
                false,
                Some(sources),
                None,
                false,
                prompt,
            )
            .await
            .map(|(response, _)| response)
    }
}
