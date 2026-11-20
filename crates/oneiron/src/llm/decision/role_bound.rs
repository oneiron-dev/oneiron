//! A decision role's rung held to the vault's model manifest (DECIDE-SWITCHOVER = A: each
//! decision role is a backend inside decide(); ruling L9-27-ROLEBIND = A).
//!
//! The host fills the head, precision and escalation rungs from its own `[models]`. A vault
//! manifest may bind the `decision_head`, `decision_band` and `decision_escalation` roles,
//! and a binding names the one model its rung may answer with, at the slot's effective
//! route: a vault's route may narrow, never silently widen, the rule every served role
//! follows. A rung whose model is not the bound one, or whose calls may go wider than that
//! route (a remote seat under an on-device pin), is held: it abstains before any call,
//! unspent, so the ladder takes the question on to the next rung that can, and the
//! receipt's pins name the rung that abstained. The three roles are optional: a role the
//! manifest leaves unbound, or a vault with no manifest, keeps the host's rung.
//! Entry: ManifestBoundRung.

use std::sync::Arc;

use super::ladder::{
    DecisionCall, DecisionPack, DecisionProvider, ProviderCapability, ProviderDecision, abstained,
};
use super::types::invalid;
use super::{DecisionRung, HostRuleRef, ProviderPin};
use crate::llm::manifest::ModelRole;
use crate::llm::{ModelId, ModelLocality};
use crate::{Result, Vault};
use oneiron_verb_wire::llm::manifest::route_rank;

/// The rung `role` fills (`cross/models.md#oneiron-roles`): the hot-path head the System
/// One rung, the precision band the Precision rung, the escalation read the Escalation
/// rung. `None` for a role that fills no decision rung.
const fn decision_role_rung(role: ModelRole) -> Option<DecisionRung> {
    match role {
        ModelRole::DecisionHead => Some(DecisionRung::SystemOne),
        ModelRole::DecisionBand => Some(DecisionRung::Precision),
        ModelRole::DecisionEscalation => Some(DecisionRung::Escalation),
        _ => None,
    }
}

/// The model a rung's pin names: its `model` when that is a whole `provider/name@revision`
/// id (the house read's pin, whose version is its recipe's revision), else its `model` at
/// its `version` (a System One seat's pin). `None` when neither is a model id.
fn pinned_model(pin: &ProviderPin) -> Option<ModelId> {
    pin.model
        .parse()
        .ok()
        .or_else(|| format!("{}@{}", pin.model, pin.version).parse().ok())
}

/// The widest route a call `provider` answers may take: on this device when it says every
/// call is computed here, a third party when a call may leave the host (a remote seat, whose
/// endpoint the host cannot place), else the owner's own server (a model this host reaches
/// over HTTP).
fn provider_route(provider: &dyn DecisionProvider) -> ModelLocality {
    if provider.leaves_host() {
        ModelLocality::ThirdParty
    } else if provider.runs_on_device() {
        ModelLocality::OnDevice
    } else {
        ModelLocality::OwnServer
    }
}

/// A decision role's rung that answers only while the vault's manifest leaves the role
/// unbound, or binds it to the model the rung serves on a route its calls stay within.
pub struct ManifestBoundRung {
    vault: Arc<Vault>,
    role: ModelRole,
    inner: Arc<dyn DecisionProvider>,
}

impl ManifestBoundRung {
    /// `inner`, on the rung `role` fills, held to `vault`'s binding for `role`. Fails for a
    /// role that fills no decision rung, and for an `inner` pinned on another rung.
    pub fn new(
        vault: Arc<Vault>,
        role: ModelRole,
        inner: Arc<dyn DecisionProvider>,
    ) -> Result<Self> {
        if decision_role_rung(role) != Some(inner.pin().rung) {
            return Err(invalid("decision role fills another rung"));
        }
        Ok(Self { vault, role, inner })
    }

    /// Whether the vault's manifest holds this rung: it binds the role to a model other
    /// than the one this rung serves, or to a route narrower than the one its calls may
    /// take. The model and the route are read in one snapshot. A pin that names no model id
    /// is never the bound model.
    fn holds(&self) -> Result<bool> {
        let Some((bound, route)) = self.vault.bound_model_for_role(self.role)? else {
            return Ok(false);
        };
        Ok(pinned_model(&self.inner.pin()).as_ref() != Some(&bound)
            || route_rank(provider_route(self.inner.as_ref())) > route_rank(route))
    }
}

impl DecisionProvider for ManifestBoundRung {
    fn pin(&self) -> ProviderPin {
        self.inner.pin()
    }

    fn capability(&self) -> ProviderCapability {
        self.inner.capability()
    }

    fn reads_images(&self) -> bool {
        self.inner.reads_images()
    }

    fn image_edge(&self) -> Option<u32> {
        self.inner.image_edge()
    }

    fn reads_audio(&self) -> bool {
        self.inner.reads_audio()
    }

    fn leaves_host(&self) -> bool {
        self.inner.leaves_host()
    }

    fn runs_on_device(&self) -> bool {
        self.inner.runs_on_device()
    }

    fn cost_per_thousand(&self) -> Option<f64> {
        self.inner.cost_per_thousand()
    }

    fn state_budget_bytes(&self) -> Option<usize> {
        self.inner.state_budget_bytes()
    }

    /// The ladder asks this before each read and sends a held rung nothing.
    fn held(&self) -> Result<bool> {
        self.holds()
    }

    /// A held rung abstains here too, for a caller that asks it outside the ladder.
    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        if self.holds()? {
            return Ok(abstained());
        }
        self.inner.decide(call)
    }

    fn decide_pack(&self, pack: &DecisionPack<'_>) -> Result<Vec<ProviderDecision>> {
        if self.holds()? {
            return Ok(pack.questions.iter().map(|_| abstained()).collect());
        }
        self.inner.decide_pack(pack)
    }

    fn rule_row(
        &self,
        call: &DecisionCall<'_>,
        decision: &ProviderDecision,
    ) -> Option<HostRuleRef> {
        self.inner.rule_row(call, decision)
    }
}
