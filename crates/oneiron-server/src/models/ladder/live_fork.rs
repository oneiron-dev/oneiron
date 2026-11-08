//! The live fork's rung (FIX 4465 C): the one rung a run's live request is
//! bound to at a compaction breakpoint, and the one-rung ladder its fork is
//! sent on. The fork keeps the run's own permit path: its own admission,
//! the run's gate for the rung's offer, a one-use permit and its settlement.
//! It never takes an owner's fallback or another model. The bound rung is
//! the one that answered the run's latest completed call (FIX 4933), never
//! the one a walk would take now.
use oneiron::code_run::LiveForkRung;

use super::*;

impl LadderRung {
    /// This rung as a live fork names it (FIX 4933): its provider, its
    /// place in the configured ladder, its wire model and its offer.
    pub(super) fn live_fork_rung(&self) -> LiveForkRung {
        LiveForkRung {
            provider: self.provider.clone(),
            position: self.position,
            wire_model: self.wire_model.clone(),
            offer: self.offer.binding.clone(),
        }
    }
}

impl OfferLadder {
    /// Whether this ladder's walk would take `request` on `answered`, the
    /// rung that answered the run's latest completed call, now (FIX 4933):
    /// a rung here at its offer and wire model that the walk does not pass
    /// over (one that rests, has its probation request out, its order
    /// refuses, or would take the work off the device as a fallback). An
    /// owner's fallback's rung is on no ladder here, so it takes none.
    pub(crate) fn takes_answering_rung(
        &self,
        answered: &LiveForkRung,
        request: &LlmRequest,
    ) -> bool {
        if self.admits(request).is_err() {
            return false;
        }
        let routes = self.rests.world_routes(request);
        (0..self.rungs.len()).any(|index| {
            let rung = &self.rungs[index];
            rung.offer.binding == answered.offer
                && rung.wire_model == answered.wire_model
                && self.takes_now(index, request, &routes)
        })
    }

    /// Whether the walk would send `request` to the rung at `index` now.
    fn takes_now(&self, index: usize, request: &LlmRequest, routes: &WorldModelRoutes) -> bool {
        let rung = &self.rungs[index];
        self.route_admitted(routes, index)
            && self.kept_on_device(index, request).is_none()
            && self
                .rests
                .resting(&rung.offer.binding, &rung.wire_model)
                .is_none()
            && self
                .rests
                .probing(&rung.offer.binding, &rung.wire_model)
                .is_none()
    }

    /// The rung a kept chat breakpoint names by ref (FIX 4465 D): this
    /// ladder's rung whose wire model and offer digest are the kept ones,
    /// under the kept provider and place, when its walk would take `request`
    /// now. `None` when no rung here matches or the matching one rests or
    /// is held: the breakpoint is not admitted again.
    pub(crate) fn live_rung_by_ref(
        &self,
        provider: &str,
        position: usize,
        wire_model: &str,
        offer_digest: &str,
        request: &LlmRequest,
    ) -> Option<LiveForkRung> {
        let index = (0..self.rungs.len()).find(|index| {
            let rung = &self.rungs[*index];
            rung.wire_model == wire_model
                && oneiron::code_run::live_fork_offer_digest(&rung.offer.binding).as_deref()
                    == Some(offer_digest)
        })?;
        let routes = self.rests.world_routes(request);
        if !self.takes_now(index, request, &routes) {
            return None;
        }
        let rung = &self.rungs[index];
        Some(LiveForkRung {
            provider: provider.to_owned(),
            position,
            wire_model: rung.wire_model.clone(),
            offer: rung.offer.binding.clone(),
        })
    }

    /// The one-rung ladder a captured live fork is sent on: this ladder's
    /// rung at the captured offer and wire model, under the captured place
    /// in its ladder. It carries no prompt of its own, since the captured
    /// request already holds its rung's prompt first, so the prompt is never
    /// put in twice. `None` when no rung here matches the capture.
    pub(crate) fn live_fork_ladder(&self, captured: &LiveForkRung) -> Option<Self> {
        let served = self.rungs.iter().find(|rung| {
            rung.offer.binding == captured.offer && rung.wire_model == captured.wire_model
        })?;
        Some(Self {
            name: served.model.clone(),
            rungs: vec![LadderRung {
                provider: captured.provider.clone(),
                position: captured.position,
                prompt: None,
                ..served.clone()
            }],
            picked: true,
            rests: Arc::clone(&self.rests),
            scope: self.scope,
            prefix: ReceiptPrefix::default(),
            listed: self.listed.clone(),
        })
    }
}
