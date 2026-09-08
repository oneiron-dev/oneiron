//! Per-role default targets, explicitness tracking, and the full override-merge cluster.
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{RuntimeMode, RuntimeProviderKind, RuntimeRole};

/// Configured model target for one runtime role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeRoleTarget {
    /// Runtime mode selected for this role.
    pub mode: RuntimeMode,
    /// Provider class used by this role.
    pub provider_kind: RuntimeProviderKind,
    /// Provider-specific model identifier or local model name.
    pub model: String,
}

impl RuntimeRoleTarget {
    pub(super) fn for_role_mode(role: RuntimeRole, mode: RuntimeMode) -> Self {
        let prefix = match mode {
            RuntimeMode::LocalFree => "local",
            RuntimeMode::ByoCloudKey => "byo",
            RuntimeMode::OneironCloud => "oneiron-cloud",
        };

        Self {
            mode,
            provider_kind: mode.provider_kind(),
            model: format!("{prefix}-{}-default", role.as_str()),
        }
    }

    fn apply_override(&mut self, role: RuntimeRole, value: RuntimeRoleTargetOverride) -> bool {
        let mut mode_changed = false;
        if let Some(mode) = value.mode
            && self.mode != mode
        {
            *self = Self::for_role_mode(role, mode);
            mode_changed = true;
        }
        if let Some(provider_kind) = value.provider_kind {
            self.provider_kind = provider_kind;
        }
        if let Some(model) = value.model {
            self.model = model;
        }
        mode_changed
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RuntimeRoleTargetExplicitFields {
    mode: bool,
    provider_kind: bool,
    model: bool,
}

impl RuntimeRoleTargetExplicitFields {
    fn apply_override(&mut self, value: &RuntimeRoleTargetOverride, mode_changed: bool) {
        if value.mode.is_some() {
            self.mode = true;
            if mode_changed {
                self.provider_kind = false;
                self.model = false;
            }
        }
        if value.provider_kind.is_some() {
            self.provider_kind = true;
        }
        if value.model.is_some() {
            self.model = true;
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct RuntimeRoleDefaultExplicitFields {
    orchestrator: RuntimeRoleTargetExplicitFields,
    subagent: RuntimeRoleTargetExplicitFields,
    summarizer: RuntimeRoleTargetExplicitFields,
}

impl RuntimeRoleDefaultExplicitFields {
    fn target(&self, role: RuntimeRole) -> RuntimeRoleTargetExplicitFields {
        match role {
            RuntimeRole::Orchestrator => self.orchestrator,
            RuntimeRole::Subagent => self.subagent,
            RuntimeRole::Summarizer => self.summarizer,
        }
    }

    fn target_mut(&mut self, role: RuntimeRole) -> &mut RuntimeRoleTargetExplicitFields {
        match role {
            RuntimeRole::Orchestrator => &mut self.orchestrator,
            RuntimeRole::Subagent => &mut self.subagent,
            RuntimeRole::Summarizer => &mut self.summarizer,
        }
    }
}

/// Per-role runtime defaults after preset and config overrides are resolved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeRoleDefaults {
    /// Default route for orchestrator work.
    pub orchestrator: RuntimeRoleTarget,
    /// Default route for subagent work.
    pub subagent: RuntimeRoleTarget,
    /// Default route for summarization work.
    pub summarizer: RuntimeRoleTarget,
}

impl RuntimeRoleDefaults {
    pub fn for_mode(mode: RuntimeMode) -> Self {
        Self {
            orchestrator: RuntimeRoleTarget::for_role_mode(RuntimeRole::Orchestrator, mode),
            subagent: RuntimeRoleTarget::for_role_mode(RuntimeRole::Subagent, mode),
            summarizer: RuntimeRoleTarget::for_role_mode(RuntimeRole::Summarizer, mode),
        }
    }

    pub fn target(&self, role: RuntimeRole) -> &RuntimeRoleTarget {
        match role {
            RuntimeRole::Orchestrator => &self.orchestrator,
            RuntimeRole::Subagent => &self.subagent,
            RuntimeRole::Summarizer => &self.summarizer,
        }
    }

    fn target_mut(&mut self, role: RuntimeRole) -> &mut RuntimeRoleTarget {
        match role {
            RuntimeRole::Orchestrator => &mut self.orchestrator,
            RuntimeRole::Subagent => &mut self.subagent,
            RuntimeRole::Summarizer => &mut self.summarizer,
        }
    }

    pub(super) fn apply_overrides(
        &mut self,
        overrides: RuntimeRoleDefaultOverrides,
        explicit_fields: &mut RuntimeRoleDefaultExplicitFields,
    ) {
        if let Some(value) = overrides.orchestrator {
            let mode_changed = self
                .target_mut(RuntimeRole::Orchestrator)
                .apply_override(RuntimeRole::Orchestrator, value.clone());
            explicit_fields
                .target_mut(RuntimeRole::Orchestrator)
                .apply_override(&value, mode_changed);
        }
        if let Some(value) = overrides.subagent {
            let mode_changed = self
                .target_mut(RuntimeRole::Subagent)
                .apply_override(RuntimeRole::Subagent, value.clone());
            explicit_fields
                .target_mut(RuntimeRole::Subagent)
                .apply_override(&value, mode_changed);
        }
        if let Some(value) = overrides.summarizer {
            let mode_changed = self
                .target_mut(RuntimeRole::Summarizer)
                .apply_override(RuntimeRole::Summarizer, value.clone());
            explicit_fields
                .target_mut(RuntimeRole::Summarizer)
                .apply_override(&value, mode_changed);
        }
    }

    pub(super) fn apply_default_mode_change(
        &mut self,
        previous_mode: RuntimeMode,
        next_mode: RuntimeMode,
        explicit_fields: &RuntimeRoleDefaultExplicitFields,
    ) {
        let previous_defaults = Self::for_mode(previous_mode);
        let next_defaults = Self::for_mode(next_mode);

        for role in RuntimeRole::ALL {
            let target = self.target_mut(role);
            let previous_default = previous_defaults.target(role);
            let next_default = next_defaults.target(role);
            let explicit = explicit_fields.target(role);

            if explicit.mode {
                continue;
            }
            if target.mode == previous_default.mode {
                target.mode = next_default.mode;
            }
            if !explicit.provider_kind && target.provider_kind == previous_default.provider_kind {
                target.provider_kind = next_default.provider_kind;
            }
            if !explicit.model && target.model == previous_default.model {
                target.model.clone_from(&next_default.model);
            }
        }
    }

    pub(super) fn contains_mode(&self, mode: RuntimeMode) -> bool {
        RuntimeRole::ALL
            .into_iter()
            .any(|role| self.target(role).mode == mode)
    }
}

/// Partial runtime config accepted from config files, env, and CLI flags.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfigOverride {
    pub mode: Option<RuntimeMode>,
    pub byo_key_env: Option<String>,
    pub role_defaults: Option<RuntimeRoleDefaultOverrides>,
}

impl RuntimeConfigOverride {
    pub fn mode(mode: RuntimeMode) -> Self {
        Self {
            mode: Some(mode),
            ..Default::default()
        }
    }

    pub fn with_byo_key_env(byo_key_env: Option<String>) -> Self {
        Self {
            byo_key_env,
            ..Default::default()
        }
    }

    pub fn with_role_override(role: RuntimeRole, target: RuntimeRoleTargetOverride) -> Self {
        Self {
            role_defaults: Some(RuntimeRoleDefaultOverrides::with_role(role, target)),
            ..Default::default()
        }
    }

    pub fn merge(&mut self, other: Self) {
        if other.mode.is_some() {
            self.mode = other.mode;
        }
        if other.byo_key_env.is_some() {
            self.byo_key_env = other.byo_key_env;
        }
        if let Some(other_defaults) = other.role_defaults {
            self.role_defaults
                .get_or_insert_with(RuntimeRoleDefaultOverrides::default)
                .merge(other_defaults);
        }
    }
}

/// Partial role-default overrides.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeRoleDefaultOverrides {
    pub orchestrator: Option<RuntimeRoleTargetOverride>,
    pub subagent: Option<RuntimeRoleTargetOverride>,
    pub summarizer: Option<RuntimeRoleTargetOverride>,
}

impl RuntimeRoleDefaultOverrides {
    pub fn with_role(role: RuntimeRole, target: RuntimeRoleTargetOverride) -> Self {
        let mut value = Self::default();
        *value.target_mut(role) = Some(target);
        value
    }

    fn target_mut(&mut self, role: RuntimeRole) -> &mut Option<RuntimeRoleTargetOverride> {
        match role {
            RuntimeRole::Orchestrator => &mut self.orchestrator,
            RuntimeRole::Subagent => &mut self.subagent,
            RuntimeRole::Summarizer => &mut self.summarizer,
        }
    }

    pub(super) fn merge(&mut self, other: Self) {
        for role in RuntimeRole::ALL {
            let Some(incoming) = other.target(role) else {
                continue;
            };
            let target = self.target_mut(role);
            if let Some(current) = target.as_mut() {
                current.merge(incoming.clone());
            } else {
                *target = Some(incoming.clone());
            }
        }
    }

    fn target(&self, role: RuntimeRole) -> Option<&RuntimeRoleTargetOverride> {
        match role {
            RuntimeRole::Orchestrator => self.orchestrator.as_ref(),
            RuntimeRole::Subagent => self.subagent.as_ref(),
            RuntimeRole::Summarizer => self.summarizer.as_ref(),
        }
    }
}

/// Partial target override for one role.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeRoleTargetOverride {
    pub mode: Option<RuntimeMode>,
    pub provider_kind: Option<RuntimeProviderKind>,
    pub model: Option<String>,
}

impl RuntimeRoleTargetOverride {
    pub fn mode(mode: RuntimeMode) -> Self {
        Self {
            mode: Some(mode),
            ..Default::default()
        }
    }

    pub fn provider_kind(provider_kind: RuntimeProviderKind) -> Self {
        Self {
            provider_kind: Some(provider_kind),
            ..Default::default()
        }
    }

    pub fn model(model: impl Into<String>) -> Self {
        Self {
            model: Some(model.into()),
            ..Default::default()
        }
    }

    pub fn target(provider_kind: RuntimeProviderKind, model: impl Into<String>) -> Self {
        Self {
            mode: None,
            provider_kind: Some(provider_kind),
            model: Some(model.into()),
        }
    }

    fn merge(&mut self, other: Self) {
        if other.mode.is_some() {
            self.mode = other.mode;
        }
        if other.provider_kind.is_some() {
            self.provider_kind = other.provider_kind;
        }
        if other.model.is_some() {
            self.model = other.model;
        }
    }
}
