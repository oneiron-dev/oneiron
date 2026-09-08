//! Resolved runtime config including the 163-line resolution impl.
use std::ffi::{OsStr, OsString};
use std::fmt;

use serde::Serialize;
use utoipa::ToSchema;

use crate::usage::UsageMode;

use super::defaults::RuntimeRoleDefaultExplicitFields;
use super::{
    RuntimeConfigOverride, RuntimeMode, RuntimeRole, RuntimeRoleDefaults, RuntimeRoleTarget,
    RuntimeRoute, RuntimeRouteProvenance, RuntimeRouteReason, RuntimeRouteSource,
    RuntimeRouteState,
};

pub(super) const DEFAULT_BYO_KEY_ENV: &str = "ONEIRON_BYO_PROVIDER_API_KEY";

/// Fully resolved runtime routing configuration.
#[derive(Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeConfig {
    /// Explicit runtime mode.
    pub mode: RuntimeMode,
    /// Environment variable name that must contain a BYO provider key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byo_key_env: Option<String>,
    /// Per-role default route targets.
    pub role_defaults: RuntimeRoleDefaults,
    #[serde(skip)]
    #[schema(ignore)]
    role_default_explicit_fields: RuntimeRoleDefaultExplicitFields,
}

impl PartialEq for RuntimeConfig {
    fn eq(&self, other: &Self) -> bool {
        self.mode == other.mode
            && self.byo_key_env == other.byo_key_env
            && self.role_defaults == other.role_defaults
    }
}

impl Eq for RuntimeConfig {}

impl fmt::Debug for RuntimeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeConfig")
            .field("mode", &self.mode)
            .field("byo_key_env", &self.byo_key_env)
            .field("role_defaults", &self.role_defaults)
            .finish()
    }
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
            role_default_explicit_fields: RuntimeRoleDefaultExplicitFields::default(),
        }
    }

    pub fn apply_override(&mut self, value: RuntimeConfigOverride) {
        if let Some(mode) = value.mode {
            let previous_mode = self.mode;
            self.mode = mode;
            self.role_defaults.apply_default_mode_change(
                previous_mode,
                mode,
                &self.role_default_explicit_fields,
            );
            if self.byo_key_env.is_none() && mode == RuntimeMode::ByoCloudKey {
                self.byo_key_env = Some(DEFAULT_BYO_KEY_ENV.to_owned());
            }
        }
        if let Some(byo_key_env) = value.byo_key_env {
            self.byo_key_env = if byo_key_env.trim().is_empty() {
                Some(String::new())
            } else {
                Some(byo_key_env)
            };
        }
        if let Some(role_defaults) = value.role_defaults {
            self.role_defaults
                .apply_overrides(role_defaults, &mut self.role_default_explicit_fields);
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
        let mut matched_debits = None;

        for role in RuntimeRole::ALL {
            let route = self.route_for_role(role);
            if route.model != model || route.state != RuntimeRouteState::Available {
                continue;
            }

            let usage_mode = route.mode.usage_mode();
            let debits = usage_mode.debits_usage();
            if matched_debits.is_some_and(|matched| matched != debits) {
                return None;
            }
            matched_debits = Some(debits);
            matched_usage_mode.get_or_insert(usage_mode);
        }

        matched_usage_mode
    }

    pub fn has_model_route_match(&self, model: Option<&str>) -> bool {
        let Some(model) = model.map(str::trim).filter(|model| !model.is_empty()) else {
            return false;
        };

        RuntimeRole::ALL
            .into_iter()
            .any(|role| self.role_defaults.target(role).model == model)
    }

    pub fn usage_mode_without_model(&self) -> Option<UsageMode> {
        let first_route = self.route_for_role(RuntimeRole::Orchestrator);
        let first = first_route.mode.usage_mode();
        let first_debits = first.debits_usage();
        if first_debits && first_route.state != RuntimeRouteState::Available {
            return None;
        }

        for role in RuntimeRole::ALL.into_iter().skip(1) {
            let route = self.route_for_role(role);
            let usage_mode = route.mode.usage_mode();
            if usage_mode.debits_usage() != first_debits {
                return None;
            }
            if first_debits && route.state != RuntimeRouteState::Available {
                return None;
            }
        }

        Some(if first_debits {
            UsageMode::OneironCloud
        } else {
            first
        })
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
                .filter(|key| !key.trim().is_empty())
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
            oneiron_spend_metered: state == RuntimeRouteState::Available
                && target.mode.oneiron_spend_metered(),
        }
    }
}

fn byo_key_value_available(value: &OsStr) -> bool {
    !value.to_string_lossy().trim().is_empty()
}
