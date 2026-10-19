//! The live fork's rung (FIX 4465 C): the one rung a run's live request is
//! bound to at a compaction breakpoint, and the one-rung ladder its fork is
//! sent on. The fork keeps the run's own permit path: its own admission,
//! the run's gate for the rung's offer, a one-use permit and its settlement.
//! It never takes an owner's fallback or another model.
use oneiron::code_run::LiveForkRung;

use super::*;

impl OfferLadder {
    /// The rung `request`'s walk would send it to now, and the request as
    /// that rung sends it, its prompt first: the first rung the walk does
    /// not pass over (one that rests, has its probation request out, or
    /// would take the work off the device as a fallback). `None` when no
    /// rung can take it now: no rung is guessed.
    pub(crate) fn live_rung(&self, request: &LlmRequest) -> Option<(LiveForkRung, LlmRequest)> {
        self.admits(request).ok()?;
        let index = (0..self.rungs.len()).find(|index| self.takes_now(*index, request))?;
        let rung = &self.rungs[index];
        let captured = LiveForkRung {
            provider: rung.provider.clone(),
            position: rung.position,
            wire_model: rung.wire_model.clone(),
            offer: rung.offer.binding.clone(),
        };
        Some((captured, rung.bind(request.clone())))
    }

    /// Whether the walk would send `request` to the rung at `index` now.
    fn takes_now(&self, index: usize, request: &LlmRequest) -> bool {
        let rung = &self.rungs[index];
        !self.kept_on_device(index, request)
            && self
                .rests
                .resting(&rung.offer.binding, &rung.wire_model)
                .is_none()
            && self
                .rests
                .probing(&rung.offer.binding, &rung.wire_model)
                .is_none()
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
            receipt: true,
            picked: true,
            rests: Arc::clone(&self.rests),
            scope: self.scope,
            prefix: ReceiptPrefix::default(),
        })
    }
}
