//! A decision role's rung held to the vault's model manifest (DECIDE-SWITCHOVER = A: each
//! decision role is a backend inside decide(); ruling L9-27-ROLEBIND = A).
//!
//! The host fills the head, precision and escalation rungs from its own `[models]`. A vault
//! manifest may bind the `decision_head`, `decision_band` and `decision_escalation` roles,
//! and a binding names the one model its rung may answer with, at the slot's effective
//! route: a vault's route may narrow, never silently widen, the rule every served role
//! follows. A rung whose model is not the bound one abstains before any call, unspent, so
//! the ladder takes the question on to the next rung that can, and the receipt's pins name
//! the rung that abstained. The three roles are optional: a role the manifest leaves
//! unbound, or a vault with no manifest, keeps the host's rung.
//! Entry: ManifestBoundRung.

use std::sync::Arc;

use super::ladder::{
    DecisionCall, DecisionPack, DecisionProvider, ProviderCapability, ProviderDecision, abstained,
};
use super::types::invalid;
use super::{DecisionRung, HostRuleRef, ProviderPin};
use crate::llm::ModelId;
use crate::llm::manifest::ModelRole;
use crate::{Result, Vault};

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

/// A decision role's rung that answers only while the vault's manifest leaves the role
/// unbound or binds it to the model the rung serves.
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

    /// Whether the vault's manifest binds the role to a model other than the one this rung
    /// serves. A pin that names no model id is never the bound model.
    fn bound_elsewhere(&self) -> Result<bool> {
        let Some(bound) = self.vault.bound_model_for_role(self.role)? else {
            return Ok(false);
        };
        Ok(pinned_model(&self.inner.pin()).as_ref() != Some(&bound))
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

    fn cost_per_thousand(&self) -> Option<f64> {
        self.inner.cost_per_thousand()
    }

    fn state_budget_bytes(&self) -> Option<usize> {
        self.inner.state_budget_bytes()
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        if self.bound_elsewhere()? {
            return Ok(abstained());
        }
        self.inner.decide(call)
    }

    fn decide_pack(&self, pack: &DecisionPack<'_>) -> Result<Vec<ProviderDecision>> {
        if self.bound_elsewhere()? {
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
