//! The route a step replay capsule's answering rung went out on (PR-S1):
//! noted beside the rung itself when a rung answers ([`note_answered`]),
//! and read back off a one-picked-rung ladder for a strict replay
//! (`exact_replay_route_pin`). Best effort: a rung whose pin is not taken
//! leaves the capsule without one, and nothing the live call does changes.
//! A pin is the route as it answered, never rebuilt from today's catalog.
use oneiron::code_run::ReplayRoutePin;

use super::*;

/// Notes the route `rung` went out on for the capsule a capture on this
/// thread waits to finalize, beside the rung itself.
pub(super) fn note_answered(rung: &LadderRung, request: &LlmRequest) {
    match route_pin(rung) {
        Some(pin) => oneiron::code_run::note_answering_route_pin(request, &pin),
        None => tracing::debug!("an answering rung's route pin was not taken"),
    }
}

/// The route `rung` sends its calls on, as a capsule pins it: its route
/// (`adapter@origin`), its offer, the catalog revision the offer was bound
/// at, its wire model and the digest of its route prompt.
fn route_pin(rung: &LadderRung) -> Option<ReplayRoutePin> {
    let binding = &rung.offer.binding;
    Some(ReplayRoutePin {
        route_id: format!("{}@{}", binding.route.adapter(), binding.route.origin()),
        offer_id: binding.offer.clone(),
        catalog_revision: binding.catalog_revision.clone(),
        wire_model: rung.wire_model.clone(),
        route_prompt_digest: route_prompt_digest(rung.prompt.as_deref())?,
    })
}

/// The digest a route prompt is pinned by (CALLS "route prompt digest"):
/// BLAKE3 of the prompt as JSON, `null` for a rung that puts none, so no
/// prompt and an empty one differ.
fn route_prompt_digest(prompt: Option<&str>) -> Option<[u8; 32]> {
    let bytes = serde_json::to_vec(&prompt).ok()?;
    Some(*blake3::hash(&bytes).as_bytes())
}

impl OfferLadder {
    /// The route this ladder's one picked rung sends on, as a capsule pins
    /// it: what a strict replay compares with the route its capsule's call
    /// was answered on. `None` for any other ladder: a seat's walk names no
    /// one route.
    pub(crate) fn exact_replay_route_pin(&self) -> Option<ReplayRoutePin> {
        match self.rungs.as_slice() {
            [rung] if self.picked => route_pin(rung),
            _ => None,
        }
    }

    /// How long a strict replay's call waits for its offer back, in all:
    /// the vault's longest wait, as an exact call waits.
    pub(crate) fn exact_replay_wait(&self) -> Duration {
        Duration::from_secs(self.rests.max_wait_secs())
    }
}
