//! Whether a fallback may take a call's world where the offer it falls back
//! to sends it, and why not (FIX 4938, 4939).

use oneiron::LlmRequest;
use oneiron::settings::{ReadDestination, ReleaseHold};

impl super::OfferCooldowns {
    /// Why a fallback to an offer whose calls go to `endpoint` keeps
    /// `request` on this device (world privacy, "Models": no silent fallback
    /// to a cloud model), or `None` while its world may go there. A call
    /// that names its world goes where the world settings' one judge lets
    /// that world go, and only for a world this vault holds; one that names
    /// none may carry any world's text, so it goes only while no world stays
    /// on the device. The endpoint is the offer's own (`ServedOffer::
    /// destination`), never the requester's proof: the model is a recipient
    /// of its own. The reason is content-free and judged in the verdict's
    /// snapshot. A call nobody can judge here stays, as an integrity hold;
    /// with no vault, no world's text is here to keep.
    pub(in crate::models) fn world_hold(
        &self,
        request: &LlmRequest,
        endpoint: &ReadDestination,
    ) -> Option<&'static str> {
        let world = request.envelope.scope.world;
        let Some(vault) = &self.vault else {
            return world.map(|_| ReleaseHold::Placement.reason());
        };
        match vault.model_call_hold_for(world, endpoint) {
            Ok(hold) => hold.map(ReleaseHold::reason),
            Err(_) => Some(ReleaseHold::Placement.reason()),
        }
    }
}
