//! The route a step replay capsule's answering rung went out on (PR-S1):
//! noted beside the rung itself when a rung answers ([`note_answered`]),
//! and read back off a one-picked-rung ladder for a strict replay
//! (`exact_replay_route_pin`). Best effort: a capture that takes no pin
//! leaves the capsule without one, and nothing the live call does changes.
//! A pin is the route as it answered, never rebuilt from today's catalog.
//! Its prompt digest is the one the capsule's stored rung keeps too
//! ([`oneiron::code_run::route_prompt_digest`], FIX 6356): the configured
//! prompt's, never a replay's stored prompt's (FIX 6255).
use oneiron::code_run::ReplayRoutePin;

use super::*;

/// Notes the route `rung` went out on for the capsule a capture on this
/// thread waits to finalize, beside the rung itself.
pub(super) fn note_answered(rung: &LadderRung, request: &LlmRequest) {
    oneiron::code_run::note_answering_route_pin(request, &route_pin(rung));
}

/// The route `rung` sends its calls on, as a capsule pins it: its route
/// (`adapter@origin`), its offer, the catalog revision the offer was bound
/// at, its wire model and the digest of its route prompt.
pub(super) fn route_pin(rung: &LadderRung) -> ReplayRoutePin {
    let binding = &rung.offer.binding;
    ReplayRoutePin {
        route_id: format!("{}@{}", binding.route.adapter(), binding.route.origin()),
        offer_id: binding.offer.clone(),
        catalog_revision: binding.catalog_revision.clone(),
        wire_model: rung.wire_model.clone(),
        route_prompt_digest: oneiron::code_run::route_prompt_digest(rung.prompt.as_deref()),
    }
}

impl OfferLadder {
    /// The route this ladder's one picked rung sends on, as a capsule pins
    /// it: what a strict replay compares with the route its capsule's call
    /// was answered on. `None` for any other ladder: a seat's walk names no
    /// one route.
    pub(crate) fn exact_replay_route_pin(&self) -> Option<ReplayRoutePin> {
        match self.rungs.as_slice() {
            [rung] if self.picked => Some(route_pin(rung)),
            _ => None,
        }
    }

    /// How long a strict replay's call waits for its offer back, in all:
    /// the vault's longest wait, as an exact call waits.
    pub(crate) fn exact_replay_wait(&self) -> Duration {
        Duration::from_secs(self.rests.max_wait_secs())
    }
}
