//! A decision call whose question's posture keeps its unit text on the host
//! (FIX 9525): it goes down only the rungs whose offer keeps the text there,
//! and an owner's fallback reaches it only when every rung of that fallback
//! does too. The rungs that would send it off are passed as the posture's
//! own filter passes a slot: the call goes on to the next rung its ladder
//! already has.
use super::*;

/// Whether a decision call whose posture keeps its text on the host may be
/// sent to `offer`: an offer on the device or on the owner's own server, never
/// a third party's.
fn decision_offer_allowed(offer: &oneiron::llm::run_admission::OfferBinding) -> bool {
    !leaves_device(offer)
}

impl OfferLadder {
    /// This ladder for one decision call whose posture keeps its text on the
    /// host: a call-local copy of the rungs whose offer may take it, in order
    /// and at their configured positions, under this ladder's name and rests,
    /// scoped so that no owner's fallback that would take the work
    /// off the device is reachable ([`Self::can_serve`]). Every ladder stamps
    /// its receipt. The shared ladder is never changed. `None` when no rung
    /// may take the call.
    pub(crate) fn kept_on_host(&self) -> Option<Arc<Self>> {
        let rungs: Vec<LadderRung> = self
            .rungs
            .iter()
            .filter(|rung| decision_offer_allowed(&rung.offer.binding))
            .cloned()
            .collect();
        if rungs.is_empty() {
            return None;
        }
        Some(Arc::new(Self {
            name: self.name.clone(),
            rungs,
            picked: self.picked,
            rests: Arc::clone(&self.rests),
            scope: SeatScope {
                stays_on_device: true,
                ..self.scope
            },
            prefix: self.prefix.clone(),
        }))
    }
}
