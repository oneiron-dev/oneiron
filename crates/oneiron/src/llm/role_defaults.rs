//! Per-role model defaults with optional overrides. The role vocabulary is defined in
//! `oneiron-model`; this type stays here because it reads routing hints from a vault.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{LlmRole, ModelId};
use crate::Vault;
use crate::edit_distance::routing::{RoutingScopeKey, WeightHint, routing_weight_hint};
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleModelDefaults {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub overrides: BTreeMap<LlmRole, ModelId>,
}

impl Default for RoleModelDefaults {
    fn default() -> Self {
        Self::new()
    }
}

impl RoleModelDefaults {
    #[must_use]
    pub fn new() -> Self {
        Self {
            overrides: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_override(mut self, role: LlmRole, model: ModelId) -> Self {
        let _ = self.set_override(role, model);
        self
    }

    pub fn set_override(&mut self, role: LlmRole, model: ModelId) -> Option<ModelId> {
        self.overrides.insert(role, model)
    }

    #[must_use]
    pub fn override_for(&self, role: LlmRole) -> Option<&ModelId> {
        self.overrides.get(&role)
    }

    #[must_use]
    pub fn resolve(&self, role: LlmRole) -> ModelId {
        self.override_for(role)
            .cloned()
            .unwrap_or_else(|| role.default_model_id())
    }

    /// [`Self::resolve`], plus what ED-07's routing loop
    /// ([`crate::edit_distance::routing`]) knows about that model in
    /// `task_class`.
    ///
    /// The hint never changes the model returned. This door resolves exactly
    /// what [`Self::resolve`] resolves and hands the routing signal back
    /// beside it — the projection informs how a router WEIGHTS a candidate it
    /// is already willing to use, and there is no shape of hint that takes a
    /// role's model out of play.
    ///
    /// `None` is the default answer: a task class starts on
    /// [`RolloutRung::Shadow`] and stays there until an owner promotes it, so
    /// an engine that never touches the ladder routes exactly as it did before
    /// this door existed.
    ///
    /// [`RolloutRung::Shadow`]: crate::edit_distance::routing::RolloutRung::Shadow
    ///
    /// # Errors
    ///
    /// Storage errors reading the routing projection.
    pub fn resolve_with_routing_hint(
        &self,
        vault: &Vault,
        role: LlmRole,
        task_class: &str,
    ) -> Result<(ModelId, Option<WeightHint>)> {
        let model = self.resolve(role);
        let hint = routing_weight_hint(vault, &RoutingScopeKey::for_model(&model, task_class))?;
        Ok((model, hint))
    }
}
