//! Grant activation under the folded pact states. The pact vocabulary is defined in
//! `oneiron-authority`; this read stays here with the fold it reads.

use crate::entity_id::EntityId;
use crate::error::Result;

use super::{AuthorityFold, FederationGrantActivation, FederationPactStatus, invalid_authority};

impl AuthorityFold {
    /// The pact a delivery under `grant` came through, and that pact's
    /// consent epoch (FIX 321): the map key of the grant's ONE binding, which
    /// must be operative and Active. No binding (an unpacted grant), several
    /// bindings, a superseded binding or a non-Active pact refuse; a
    /// convenient id is never picked.
    pub fn active_pact_delivery_context(&self, grant: &EntityId) -> Result<([u8; 32], u64)> {
        let mut bindings = self
            .federation_grant_bindings
            .get(grant)
            .into_iter()
            .flatten();
        let (Some(pact_id), None) = (bindings.next(), bindings.next()) else {
            return Err(invalid_authority());
        };
        match self.federation_pacts.get(pact_id) {
            Some(state)
                if state.status == FederationPactStatus::Active && state.grant_ref == *grant =>
            {
                Ok((*pact_id, state.pact_epoch))
            }
            _ => Err(invalid_authority()),
        }
    }
}

/// Activation of `grant_ref` under the fold's pact states.
///
/// Grants without lifecycle entries stay `Unpacted` (legacy-allow). For
/// pact-bound grants the activation folds over EVERY pact the grant was ever
/// bound to (via [`AuthorityFold::federation_grant_bindings`], a superset of
/// the live pact states' operative `grant_ref`s) — never just the first live
/// pact naming it: a grant bound to any suspended or terminal pact is
/// `Inactive` regardless of another of its pacts being `Active`. `Active`
/// requires the grant to be the OPERATIVE binding of every pact it was ever
/// bound to, with all of them `Active`; a binding superseded by a
/// divergent-binding merge or an epoch bump therefore reports `Inactive`
/// (carrying the most restrictive live status, possibly `Active`) and never
/// returns to `Unpacted` or `Active`.
#[must_use]
pub fn federation_grant_activation(
    fold: &AuthorityFold,
    grant_ref: &EntityId,
) -> FederationGrantActivation {
    let Some(pact_ids) = fold.federation_grant_bindings.get(grant_ref) else {
        return FederationGrantActivation::Unpacted;
    };
    let mut every_binding_operative_active = true;
    let mut most_restrictive: Option<FederationPactStatus> = None;
    for pact_id in pact_ids {
        // The fold never registers a binding without its pact state; a
        // missing state fails closed as a suspended, non-operative binding.
        let (status, operative) = match fold.federation_pacts.get(pact_id) {
            Some(state) => (state.status, state.grant_ref == *grant_ref),
            None => (FederationPactStatus::Suspended, false),
        };
        if status != FederationPactStatus::Active || !operative {
            every_binding_operative_active = false;
        }
        most_restrictive = Some(most_restrictive.map_or(status, |worst| worst.max(status)));
    }
    match most_restrictive {
        Some(_) if every_binding_operative_active => FederationGrantActivation::Active,
        Some(status) => FederationGrantActivation::Inactive(status),
        // Registered binding sets are never empty; fail closed if one is.
        None => FederationGrantActivation::Inactive(FederationPactStatus::Suspended),
    }
}
