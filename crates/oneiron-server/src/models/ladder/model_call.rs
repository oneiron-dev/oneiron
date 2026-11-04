//! The rung that answered one generate call (FIX 12743).
//!
//! A generate call settles on exactly one rung: the one whose `Sent::Answer`
//! the walk returns, on the owner's fallback ladder when it fell back there.
//! That rung's binding travels with the answer, so a capture site stamps the
//! rung that answered instead of re-deriving one from the served model on the
//! requested ladder, which a fallback answer never sat on. A call whose
//! answering rung the site cannot name (streams) keeps the explicit unknown
//! below, never a false pin.
use oneiron::code_run::{CapsuleRungBinding, ReplayRoutePin};
use oneiron::{ModelId, ModelLocality};

use super::shadow_capture;
use super::{LadderRung, OfferLadder};

/// The rung that answered one generate call: its model-call rung and the
/// route it went out on, pinned as it answered.
#[derive(Clone, Debug)]
pub(crate) struct ModelCallBinding {
    pub(crate) rung: CapsuleRungBinding,
    pub(crate) route: Option<ReplayRoutePin>,
}

impl ModelCallBinding {
    /// The binding of the rung that answered: its model, where it ran, the
    /// prompt it put first, and its answering route pin.
    pub(super) fn for_rung(rung: &LadderRung) -> Self {
        Self {
            rung: CapsuleRungBinding {
                model: rung.model.clone(),
                locality: rung.offer.binding.locality,
                prompt: rung.prompt.clone(),
            },
            route: shadow_capture::route_pin(rung),
        }
    }
}

impl OfferLadder {
    /// The answering rung, when the caller names the served model, and its
    /// exact route pin for the model-call record (FIX 12516). The pin is the
    /// capsule-canonical one (adapter@origin, offer, catalog revision, wire
    /// model), never rebuilt from today's catalog; it is `Some` only when
    /// the served model is this ladder's one picked rung. A fallback answer,
    /// or a call whose served model the site cannot name (streams), leaves
    /// the route unknown instead of naming the first rung falsely. The rung
    /// model is the served model; its locality is the answering rung's when
    /// that rung is on this ladder, else the requested first rung's (a
    /// generate call's exact answering binding is FIX 12743, threaded with
    /// its answer; this lookup stays for calls that cannot name one).
    pub(crate) fn model_call_binding(
        &self,
        served: Option<&ModelId>,
    ) -> (CapsuleRungBinding, Option<ReplayRoutePin>) {
        let prompt = self.exact_prompt().flatten().map(str::to_owned);
        let answered = served.and_then(|model| self.rungs.iter().find(|rung| rung.model == *model));
        let rung = answered.or(self.rungs.first());
        let binding = CapsuleRungBinding {
            model: served.cloned().unwrap_or_else(|| self.name.clone()),
            locality: rung.map_or(ModelLocality::OnDevice, |rung| rung.offer.binding.locality),
            prompt: prompt.clone(),
        };
        let route = if self.exact_prompt().is_some() {
            answered.and_then(shadow_capture::route_pin)
        } else {
            None
        };
        (binding, route)
    }
}
