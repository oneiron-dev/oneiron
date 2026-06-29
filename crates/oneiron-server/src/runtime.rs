use std::ffi::{OsStr, OsString};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::usage::UsageMode;

const DEFAULT_BYO_KEY_ENV: &str = "ONEIRON_BYO_PROVIDER_API_KEY";

/// Runtime execution mode selected for model routing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    /// Free local runtime. Never meters Oneiron Cloud spend.
    #[default]
    #[serde(alias = "local")]
    LocalFree,
    /// User-owned cloud provider key. Never meters Oneiron Cloud spend.
    #[serde(alias = "byo", alias = "byo_cloud", alias = "bring_your_own")]
    ByoCloudKey,
    /// Oneiron-hosted runtime. This is the only metered Oneiron spend mode.
    #[serde(alias = "cloud", alias = "oneiron-cloud")]
    OneironCloud,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalFree => "local_free",
            Self::ByoCloudKey => "byo_cloud_key",
            Self::OneironCloud => "oneiron_cloud",
        }
    }

    pub fn oneiron_spend_metered(self) -> bool {
        matches!(self, Self::OneironCloud)
    }

    pub fn usage_mode(self) -> UsageMode {
        match self {
            Self::LocalFree => UsageMode::Local,
            Self::ByoCloudKey => UsageMode::Byo,
            Self::OneironCloud => UsageMode::OneironCloud,
        }
    }

    fn provider_kind(self) -> RuntimeProviderKind {
        match self {
            Self::LocalFree => RuntimeProviderKind::Local,
            Self::ByoCloudKey => RuntimeProviderKind::ByoCloud,
            Self::OneironCloud => RuntimeProviderKind::OneironCloud,
        }
    }

    fn allows_provider(self, provider_kind: RuntimeProviderKind) -> bool {
        self.provider_kind() == provider_kind
    }
}

impl From<UsageMode> for RuntimeMode {
    fn from(value: UsageMode) -> Self {
        match value {
            UsageMode::Local => Self::LocalFree,
            UsageMode::Byo => Self::ByoCloudKey,
            UsageMode::OneironCloud => Self::OneironCloud,
        }
    }
}

impl fmt::Display for RuntimeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RuntimeMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match normalized_key(value).as_str() {
            "local" | "localfree" => Ok(Self::LocalFree),
            "byo" | "byocloud" | "byocloudkey" | "bringyourown" => Ok(Self::ByoCloudKey),
            "cloud" | "oneironcloud" => Ok(Self::OneironCloud),
            _ => Err(format!(
                "expected one of local_free, byo_cloud_key, oneiron_cloud; got {value:?}"
            )),
        }
    }
}

/// Provider class used by a runtime route.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProviderKind {
    /// Local runtime/provider owned by the user process.
    #[default]
    Local,
    /// Cloud provider reached with a user-owned API key.
    #[serde(alias = "byo", alias = "bring_your_own")]
    ByoCloud,
    /// Oneiron-hosted provider.
    #[serde(alias = "cloud", alias = "oneiron-cloud")]
    OneironCloud,
}

impl RuntimeProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::ByoCloud => "byo_cloud",
            Self::OneironCloud => "oneiron_cloud",
        }
    }
}

impl fmt::Display for RuntimeProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RuntimeProviderKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match normalized_key(value).as_str() {
            "local" => Ok(Self::Local),
            "byo" | "byocloud" | "bringyourown" => Ok(Self::ByoCloud),
            "cloud" | "oneironcloud" => Ok(Self::OneironCloud),
            _ => Err(format!(
                "expected one of local, byo_cloud, oneiron_cloud; got {value:?}"
            )),
        }
    }
}

/// Role whose model route is being resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRole {
    /// Planner/coordinator model route.
    Orchestrator,
    /// Worker/subagent model route.
    Subagent,
    /// Summarization model route.
    Summarizer,
}

impl RuntimeRole {
    pub const ALL: [Self; 3] = [Self::Orchestrator, Self::Subagent, Self::Summarizer];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Orchestrator => "orchestrator",
            Self::Subagent => "subagent",
            Self::Summarizer => "summarizer",
        }
    }
}

impl fmt::Display for RuntimeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RuntimeRole {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match normalized_key(value).as_str() {
            "orchestrator" => Ok(Self::Orchestrator),
            "subagent" | "subagents" => Ok(Self::Subagent),
            "summarizer" | "summariser" => Ok(Self::Summarizer),
            _ => Err(format!(
                "expected one of orchestrator, subagent, summarizer; got {value:?}"
            )),
        }
    }
}

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
    fn for_role_mode(role: RuntimeRole, mode: RuntimeMode) -> Self {
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

    fn apply_override(&mut self, role: RuntimeRole, value: RuntimeRoleTargetOverride) {
        if let Some(mode) = value.mode {
            *self = Self::for_role_mode(role, mode);
        }
        if let Some(provider_kind) = value.provider_kind {
            self.provider_kind = provider_kind;
        }
        if let Some(model) = value.model {
            self.model = model;
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

    fn apply_overrides(&mut self, overrides: RuntimeRoleDefaultOverrides) {
        if let Some(value) = overrides.orchestrator {
            self.target_mut(RuntimeRole::Orchestrator)
                .apply_override(RuntimeRole::Orchestrator, value);
        }
        if let Some(value) = overrides.subagent {
            self.target_mut(RuntimeRole::Subagent)
                .apply_override(RuntimeRole::Subagent, value);
        }
        if let Some(value) = overrides.summarizer {
            self.target_mut(RuntimeRole::Summarizer)
                .apply_override(RuntimeRole::Summarizer, value);
        }
    }

    fn apply_default_mode_change(&mut self, previous_mode: RuntimeMode, next_mode: RuntimeMode) {
        let previous_defaults = Self::for_mode(previous_mode);
        let next_defaults = Self::for_mode(next_mode);

        for role in RuntimeRole::ALL {
            let target = self.target_mut(role);
            if target == previous_defaults.target(role) {
                *target = next_defaults.target(role).clone();
            }
        }
    }

    fn contains_mode(&self, mode: RuntimeMode) -> bool {
        RuntimeRole::ALL
            .into_iter()
            .any(|role| self.target(role).mode == mode)
    }
}

/// Fully resolved runtime routing configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConfig {
    /// Explicit runtime mode.
    pub mode: RuntimeMode,
    /// Environment variable name that must contain a BYO provider key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byo_key_env: Option<String>,
    /// Per-role default route targets.
    pub role_defaults: RuntimeRoleDefaults,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::for_mode(RuntimeMode::default())
    }
}

impl RuntimeConfig {
    pub fn for_mode(mode: RuntimeMode) -> Self {
        let byo_key_env = match mode {
            RuntimeMode::ByoCloudKey => Some(DEFAULT_BYO_KEY_ENV.to_owned()),
            RuntimeMode::LocalFree | RuntimeMode::OneironCloud => None,
        };
        Self {
            mode,
            byo_key_env,
            role_defaults: RuntimeRoleDefaults::for_mode(mode),
        }
    }

    pub fn apply_override(&mut self, value: RuntimeConfigOverride) {
        if let Some(mode) = value.mode {
            let previous_mode = self.mode;
            self.mode = mode;
            self.role_defaults
                .apply_default_mode_change(previous_mode, mode);
            if self.byo_key_env.is_none() && mode == RuntimeMode::ByoCloudKey {
                self.byo_key_env = Some(DEFAULT_BYO_KEY_ENV.to_owned());
            }
        }
        if let Some(byo_key_env) = value.byo_key_env {
            self.byo_key_env = if byo_key_env.trim().is_empty() {
                None
            } else {
                Some(byo_key_env)
            };
        }
        if let Some(role_defaults) = value.role_defaults {
            self.role_defaults.apply_overrides(role_defaults);
        }
        if self.byo_key_env.is_none() && self.role_defaults.contains_mode(RuntimeMode::ByoCloudKey)
        {
            self.byo_key_env = Some(DEFAULT_BYO_KEY_ENV.to_owned());
        }
    }

    pub fn route_for_role(&self, role: RuntimeRole) -> RuntimeRoute {
        self.route_for_role_with_key_lookup(role, |key| std::env::var_os(key))
    }

    pub fn usage_mode_for_model(&self, model: Option<&str>) -> Option<UsageMode> {
        let model = model.map(str::trim).filter(|model| !model.is_empty())?;
        let mut matched_usage_mode = None;

        for role in RuntimeRole::ALL {
            let target = self.role_defaults.target(role);
            if target.model != model {
                continue;
            }

            let usage_mode = target.mode.usage_mode();
            if usage_mode.debits_usage() {
                return Some(usage_mode);
            }
            matched_usage_mode = Some(usage_mode);
        }

        matched_usage_mode
    }

    pub fn route_for_role_with_key_lookup(
        &self,
        role: RuntimeRole,
        mut key_lookup: impl FnMut(&str) -> Option<OsString>,
    ) -> RuntimeRoute {
        let target = self.role_defaults.target(role).clone();
        let preset_target = RuntimeRoleTarget::for_role_mode(role, target.mode);
        let source = if target.mode == self.mode && target == preset_target {
            RuntimeRouteSource::ModePreset
        } else {
            RuntimeRouteSource::ConfigOverride
        };

        let (state, reason) = if target.model.trim().is_empty() {
            (
                RuntimeRouteState::Unavailable,
                RuntimeRouteReason::MissingModel,
            )
        } else if !target.mode.allows_provider(target.provider_kind) {
            (
                RuntimeRouteState::Unavailable,
                RuntimeRouteReason::ProviderModeMismatch,
            )
        } else if target.mode == RuntimeMode::ByoCloudKey
            && !self
                .byo_key_env
                .as_deref()
                .and_then(&mut key_lookup)
                .as_deref()
                .is_some_and(byo_key_value_available)
        {
            (
                RuntimeRouteState::Unavailable,
                RuntimeRouteReason::MissingByoKey,
            )
        } else {
            (RuntimeRouteState::Available, RuntimeRouteReason::Ready)
        };

        RuntimeRoute {
            role,
            mode: target.mode,
            provider_kind: target.provider_kind,
            model: target.model,
            state,
            reason,
            provenance: RuntimeRouteProvenance {
                role_default: role,
                source,
            },
            oneiron_spend_metered: target.mode.oneiron_spend_metered(),
        }
    }
}

fn byo_key_value_available(value: &OsStr) -> bool {
    !value.to_string_lossy().trim().is_empty()
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

    fn merge(&mut self, other: Self) {
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

/// Runtime routing status advertised by health and discovery responses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    /// Default runtime mode used when a role does not override it.
    pub mode: RuntimeMode,
    /// Whether any configured route can meter Oneiron Cloud spend.
    pub oneiron_spend_metered: bool,
    /// Route decision for each supported runtime role.
    pub routes: Vec<RuntimeRoute>,
}

impl RuntimeStatus {
    pub fn from_config(config: &RuntimeConfig) -> Self {
        let routes = RuntimeRole::ALL
            .into_iter()
            .map(|role| config.route_for_role(role))
            .collect::<Vec<_>>();
        let oneiron_spend_metered = routes.iter().any(|route| route.oneiron_spend_metered);

        Self {
            mode: config.mode,
            oneiron_spend_metered,
            routes,
        }
    }
}

/// Redacted runtime availability advertised by unauthenticated health.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeHealthStatus {
    /// Default runtime mode used when a role does not override it.
    pub mode: RuntimeMode,
    /// Whether any configured route can meter Oneiron Cloud spend.
    pub oneiron_spend_metered: bool,
    /// Aggregate route availability with per-role details redacted.
    pub state: RuntimeRouteState,
}

impl RuntimeHealthStatus {
    pub fn from_config(config: &RuntimeConfig) -> Self {
        let status = RuntimeStatus::from_config(config);
        let routes = status.routes;
        let state = if routes
            .iter()
            .any(|route| route.state == RuntimeRouteState::Unavailable)
        {
            RuntimeRouteState::Unavailable
        } else if routes
            .iter()
            .any(|route| route.state == RuntimeRouteState::Degraded)
        {
            RuntimeRouteState::Degraded
        } else {
            RuntimeRouteState::Available
        };

        Self {
            mode: config.mode,
            oneiron_spend_metered: status.oneiron_spend_metered,
            state,
        }
    }
}

/// Resolved route decision for one runtime role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeRoute {
    /// Role resolved by this route.
    pub role: RuntimeRole,
    /// Runtime mode that constrained the route.
    pub mode: RuntimeMode,
    /// Provider class selected for the role.
    pub provider_kind: RuntimeProviderKind,
    /// Provider-specific model identifier or local model name.
    pub model: String,
    /// Typed route availability state.
    pub state: RuntimeRouteState,
    /// Typed reason for the route state.
    pub reason: RuntimeRouteReason,
    /// How this role route was selected.
    pub provenance: RuntimeRouteProvenance,
    /// Whether this route can be metered as Oneiron Cloud spend.
    pub oneiron_spend_metered: bool,
}

/// Typed route availability state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRouteState {
    /// Route is usable.
    Available,
    /// Route is usable only with degraded confidence in its configuration.
    Degraded,
    /// Route is not usable.
    Unavailable,
}

/// Typed reason for a route state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRouteReason {
    /// Route is ready.
    Ready,
    /// BYO mode is selected but the configured provider-key environment
    /// variable is not present.
    MissingByoKey,
    /// Route provider kind does not match the selected runtime mode.
    ProviderModeMismatch,
    /// Route has no model id.
    MissingModel,
}

/// Provenance for a resolved role route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeRouteProvenance {
    /// Role default used for this selection.
    pub role_default: RuntimeRole,
    /// Whether the route came from a mode preset or config override.
    pub source: RuntimeRouteSource,
}

/// Source of a resolved route target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRouteSource {
    /// Route came from the selected mode preset.
    ModePreset,
    /// Route came from explicit runtime config.
    ConfigOverride,
}

fn normalized_key(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['-', '_'], "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_presets_route_each_role_with_expected_provider_and_spend_boundary() {
        for (mode, provider_kind, spend_metered) in [
            (RuntimeMode::LocalFree, RuntimeProviderKind::Local, false),
            (
                RuntimeMode::ByoCloudKey,
                RuntimeProviderKind::ByoCloud,
                false,
            ),
            (
                RuntimeMode::OneironCloud,
                RuntimeProviderKind::OneironCloud,
                true,
            ),
        ] {
            let config = RuntimeConfig::for_mode(mode);

            for role in RuntimeRole::ALL {
                let route = config.route_for_role_with_key_lookup(role, |_| Some("key".into()));

                assert_eq!(route.mode, mode);
                assert_eq!(route.provider_kind, provider_kind);
                assert_eq!(route.provenance.source, RuntimeRouteSource::ModePreset);
                assert_eq!(route.oneiron_spend_metered, spend_metered);
            }
        }
    }

    #[test]
    fn role_override_falls_back_to_mode_preset_for_missing_roles() {
        let mut config = RuntimeConfig::for_mode(RuntimeMode::ByoCloudKey);
        config.apply_override(RuntimeConfigOverride::with_role_override(
            RuntimeRole::Orchestrator,
            RuntimeRoleTargetOverride::target(RuntimeProviderKind::ByoCloud, "custom-orchestrator"),
        ));

        let orchestrator = config
            .route_for_role_with_key_lookup(RuntimeRole::Orchestrator, |_| Some("key".into()));
        let subagent =
            config.route_for_role_with_key_lookup(RuntimeRole::Subagent, |_| Some("key".into()));

        assert_eq!(orchestrator.model, "custom-orchestrator");
        assert_eq!(orchestrator.mode, RuntimeMode::ByoCloudKey);
        assert_eq!(
            orchestrator.provenance.source,
            RuntimeRouteSource::ConfigOverride
        );
        assert_eq!(subagent.mode, RuntimeMode::ByoCloudKey);
        assert_eq!(subagent.provider_kind, RuntimeProviderKind::ByoCloud);
        assert_eq!(subagent.provenance.source, RuntimeRouteSource::ModePreset);
    }

    #[test]
    fn per_role_modes_select_mode_defaults_for_each_role() {
        let mut config = RuntimeConfig::for_mode(RuntimeMode::LocalFree);
        let mut overrides = RuntimeRoleDefaultOverrides::default();
        overrides.merge(RuntimeRoleDefaultOverrides::with_role(
            RuntimeRole::Orchestrator,
            RuntimeRoleTargetOverride::mode(RuntimeMode::ByoCloudKey),
        ));
        overrides.merge(RuntimeRoleDefaultOverrides::with_role(
            RuntimeRole::Subagent,
            RuntimeRoleTargetOverride::mode(RuntimeMode::OneironCloud),
        ));
        overrides.merge(RuntimeRoleDefaultOverrides::with_role(
            RuntimeRole::Summarizer,
            RuntimeRoleTargetOverride::mode(RuntimeMode::LocalFree),
        ));
        config.apply_override(RuntimeConfigOverride {
            role_defaults: Some(overrides),
            ..Default::default()
        });

        let orchestrator = config
            .route_for_role_with_key_lookup(RuntimeRole::Orchestrator, |_| Some("key".into()));
        let subagent =
            config.route_for_role_with_key_lookup(RuntimeRole::Subagent, |_| Some("key".into()));
        let summarizer =
            config.route_for_role_with_key_lookup(RuntimeRole::Summarizer, |_| Some("key".into()));

        assert_eq!(
            (
                orchestrator.mode,
                orchestrator.provider_kind,
                orchestrator.model.as_str(),
                orchestrator.oneiron_spend_metered,
            ),
            (
                RuntimeMode::ByoCloudKey,
                RuntimeProviderKind::ByoCloud,
                "byo-orchestrator-default",
                false,
            )
        );
        assert_eq!(
            (
                subagent.mode,
                subagent.provider_kind,
                subagent.model.as_str(),
                subagent.oneiron_spend_metered,
            ),
            (
                RuntimeMode::OneironCloud,
                RuntimeProviderKind::OneironCloud,
                "oneiron-cloud-subagent-default",
                true,
            )
        );
        assert_eq!(
            (
                summarizer.mode,
                summarizer.provider_kind,
                summarizer.model.as_str(),
                summarizer.oneiron_spend_metered,
            ),
            (
                RuntimeMode::LocalFree,
                RuntimeProviderKind::Local,
                "local-summarizer-default",
                false,
            )
        );
    }

    #[test]
    fn per_role_byo_and_local_modes_stay_unmetered_under_metered_default() {
        let mut config = RuntimeConfig::for_mode(RuntimeMode::OneironCloud);
        let mut overrides = RuntimeRoleDefaultOverrides::default();
        overrides.merge(RuntimeRoleDefaultOverrides::with_role(
            RuntimeRole::Orchestrator,
            RuntimeRoleTargetOverride::mode(RuntimeMode::ByoCloudKey),
        ));
        overrides.merge(RuntimeRoleDefaultOverrides::with_role(
            RuntimeRole::Subagent,
            RuntimeRoleTargetOverride::mode(RuntimeMode::LocalFree),
        ));
        config.apply_override(RuntimeConfigOverride {
            role_defaults: Some(overrides),
            ..Default::default()
        });

        let status = RuntimeStatus::from_config(&config);
        let orchestrator = status
            .routes
            .iter()
            .find(|route| route.role == RuntimeRole::Orchestrator)
            .unwrap();
        let subagent = status
            .routes
            .iter()
            .find(|route| route.role == RuntimeRole::Subagent)
            .unwrap();
        let summarizer = status
            .routes
            .iter()
            .find(|route| route.role == RuntimeRole::Summarizer)
            .unwrap();

        assert_eq!(orchestrator.mode, RuntimeMode::ByoCloudKey);
        assert!(!orchestrator.oneiron_spend_metered);
        assert_eq!(subagent.mode, RuntimeMode::LocalFree);
        assert!(!subagent.oneiron_spend_metered);
        assert_eq!(summarizer.mode, RuntimeMode::OneironCloud);
        assert!(summarizer.oneiron_spend_metered);
        assert!(status.oneiron_spend_metered);
    }

    #[test]
    fn routing_returns_typed_unavailable_states() {
        let byo = RuntimeConfig::for_mode(RuntimeMode::ByoCloudKey);
        let missing_key = byo.route_for_role_with_key_lookup(RuntimeRole::Subagent, |_| None);
        assert_eq!(missing_key.state, RuntimeRouteState::Unavailable);
        assert_eq!(missing_key.reason, RuntimeRouteReason::MissingByoKey);

        let mut local = RuntimeConfig::for_mode(RuntimeMode::LocalFree);
        local.apply_override(RuntimeConfigOverride::with_role_override(
            RuntimeRole::Summarizer,
            RuntimeRoleTargetOverride::target(RuntimeProviderKind::OneironCloud, "cloud-model"),
        ));
        let mismatch =
            local.route_for_role_with_key_lookup(RuntimeRole::Summarizer, |_| Some("key".into()));
        assert_eq!(mismatch.state, RuntimeRouteState::Unavailable);
        assert_eq!(mismatch.reason, RuntimeRouteReason::ProviderModeMismatch);
        assert_eq!(mismatch.provider_kind, RuntimeProviderKind::OneironCloud);
        assert!(!mismatch.oneiron_spend_metered);
    }

    #[test]
    fn byo_key_env_requires_non_whitespace_value() {
        let config = RuntimeConfig::for_mode(RuntimeMode::ByoCloudKey);

        for key_value in [None, Some(""), Some(" \t\n")] {
            let route = config.route_for_role_with_key_lookup(RuntimeRole::Orchestrator, |_| {
                key_value.map(OsString::from)
            });

            assert_eq!(route.state, RuntimeRouteState::Unavailable);
            assert_eq!(route.reason, RuntimeRouteReason::MissingByoKey);
        }

        let available = config
            .route_for_role_with_key_lookup(RuntimeRole::Orchestrator, |_| Some("key".into()));
        assert_eq!(available.state, RuntimeRouteState::Available);
        assert_eq!(available.reason, RuntimeRouteReason::Ready);
    }

    #[test]
    fn provider_mode_mismatch_is_fail_closed_for_local_and_byo() {
        for mode in [RuntimeMode::LocalFree, RuntimeMode::ByoCloudKey] {
            let mut config = RuntimeConfig::for_mode(mode);
            config.apply_override(RuntimeConfigOverride::with_role_override(
                RuntimeRole::Orchestrator,
                RuntimeRoleTargetOverride::target(
                    RuntimeProviderKind::OneironCloud,
                    "hosted-model",
                ),
            ));

            let route = config
                .route_for_role_with_key_lookup(RuntimeRole::Orchestrator, |_| Some("key".into()));
            assert_eq!(route.provider_kind, RuntimeProviderKind::OneironCloud);
            assert_eq!(route.state, RuntimeRouteState::Unavailable);
            assert_eq!(route.reason, RuntimeRouteReason::ProviderModeMismatch);
            assert!(!route.oneiron_spend_metered);
        }
    }

    #[test]
    fn runtime_mode_usage_mapping_keeps_byo_and_local_unmetered() {
        assert!(!RuntimeMode::LocalFree.usage_mode().debits_usage());
        assert!(!RuntimeMode::ByoCloudKey.usage_mode().debits_usage());
        assert!(RuntimeMode::OneironCloud.usage_mode().debits_usage());
    }
}
