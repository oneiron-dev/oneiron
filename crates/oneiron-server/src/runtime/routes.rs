//! Resolved route decisions and redacted/full status views for health and discovery.
use oneiron::Vault;
use oneiron::agent_dispatch::AgentDispatchTarget;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{RuntimeConfig, RuntimeMode, RuntimeProviderKind, RuntimeRole};

/// Resolves a workspace roster route from STORED row state.
///
/// `None` means absorb into the primary agent: an unknown logical id or a
/// disabled row is a routing miss, not an error. An EXPLICIT engine dispatch
/// to a disabled row stays a typed engine error — only server route selection
/// absorbs. Stored-row decode failures propagate.
///
/// ONE-1832/RUNTIME owner note: the pre-1890 turn-text absorb classifier
/// (intimacy/erotic/repair phrases) was deleted with the branded roster. It
/// had zero production callers and its policy input is orthogonal to
/// row-state routing; any turn-content routing guard is a product decision
/// ONE-1832 owns, not preserved here.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "row routing lands with 1890; ONE-1832/RUNTIME wires the production caller \
                  (the deleted predecessors were equally test-only)"
    )
)]
pub(crate) fn resolve_agent_route(
    vault: &Vault,
    logical_id: &str,
) -> oneiron::Result<Option<AgentDispatchTarget>> {
    match vault.get_seeded_agent_definition_by_logical_id(logical_id) {
        Ok(Some((id, definition))) if definition.enabled => {
            Ok(Some(AgentDispatchTarget::Custom(id)))
        }
        Ok(Some(_)) | Ok(None) => Ok(None),
        Err(error) => Err(error),
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
