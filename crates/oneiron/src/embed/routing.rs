//! Which embedder a leased row goes to, by the verdict of the reconciler's
//! rung on it (FIX 10009). One verdict serves both roles: a rung beside an
//! on-device primary sends what it allows off this device and embeds the
//! rest at home; a rung that is the primary itself sends what it allows and
//! leaves the rest pending.

use super::{
    EgressDecision, EmbedRoute, LeaseBatch, PendingEmbeddingInput, PendingEmbeddingReconciler,
};

/// What a reconciler's rung stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RungRole {
    /// A model off this device beside an on-device primary
    /// ([`PendingEmbeddingReconciler::with_remote_rung`]): a row the owner's
    /// predicate does not allow embeds on the primary.
    Fallback,
    /// The primary itself, off this device
    /// ([`PendingEmbeddingReconciler::with_primary_rung`]): a row the owner's
    /// predicate does not allow stays pending, unleased and unsent.
    Primary,
}

impl PendingEmbeddingReconciler {
    /// The route and lease window `input` takes by the rung's verdict on it,
    /// each `Deny` and `NoVerdict` counted in `batch`; `None` leaves it
    /// pending, unleased and unsent, for a later pass. With no rung, or for a
    /// row a device-local world keeps, it takes the primary as before.
    pub(super) fn rung_route(
        &self,
        input: &PendingEmbeddingInput,
        device_local: bool,
        batch: &mut LeaseBatch,
    ) -> Option<(EmbedRoute, u64)> {
        let primary = (EmbedRoute::Local, self.lease_duration_ms);
        let Some(rung) = &self.remote_rung else {
            return Some(primary);
        };
        if device_local {
            return Some(primary);
        }
        let decision = rung.predicate.decide(input);
        match decision {
            EgressDecision::Allow => {}
            EgressDecision::Deny => batch.egress_denied += 1,
            EgressDecision::NoVerdict => batch.egress_no_verdict += 1,
        }
        match (self.rung_role, decision) {
            (RungRole::Fallback, EgressDecision::Allow) => {
                Some((EmbedRoute::Remote, rung.lease_duration_ms))
            }
            (RungRole::Fallback, _) | (RungRole::Primary, EgressDecision::Allow) => Some(primary),
            (RungRole::Primary, EgressDecision::Deny | EgressDecision::NoVerdict) => None,
        }
    }
}
