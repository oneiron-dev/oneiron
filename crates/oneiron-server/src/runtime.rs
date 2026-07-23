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

/// Eiri sub-agent lanes controlled by the Base Eiri dispatcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EiriSubagent {
    Scout,
    Keeper,
    Creative,
    Herald,
    Guide,
}

impl EiriSubagent {
    pub const ALL: [Self; 5] = [
        Self::Scout,
        Self::Keeper,
        Self::Creative,
        Self::Herald,
        Self::Guide,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scout => "scout",
            Self::Keeper => "keeper",
            Self::Creative => "creative",
            Self::Herald => "herald",
            Self::Guide => "guide",
        }
    }
}

/// Final Eiri dispatch target after Base Eiri absorb guards run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EiriDispatchTarget {
    BaseEiri,
    Subagent(EiriSubagent),
}

impl EiriDispatchTarget {
    pub fn runtime_role(self) -> RuntimeRole {
        match self {
            Self::BaseEiri => RuntimeRole::Orchestrator,
            Self::Subagent(_) => RuntimeRole::Subagent,
        }
    }
}

// Direct or contextual phrases absorb inside a longer turn; ambiguous bare terms and
// idioms below only absorb as complete short turns so technical work still routes.
const EIRI_ABSORB_CONTAINS_PHRASES: &[&str] = &[
    "i love you",
    "love you",
    "i miss you",
    "miss you",
    "i need comfort",
    "i feel safe with you",
    "im scared",
    "i am scared",
    "i feel alone",
    "i feel hurt",
    "you hurt me",
    "im sorry",
    "i am sorry",
    "are you mad at me",
    "repair this between us",
    "repair with me",
    "make this right between us",
    "kiss me",
    "cuddle me",
    "make love",
    "touch me",
    "you turn me on",
    "im aroused",
    "i am aroused",
    "feel aroused",
    "feeling aroused",
    "sexually aroused",
    "be intimate",
    "get intimate",
    "intimate with me",
    "intimate with you",
    "intimate together",
    "sexual feelings",
    "sexual thoughts",
    "sexual with me",
    "sexual with you",
    "sext me",
    "sexting me",
    "send a sext",
    "send me a sext",
    "send nudes",
    "send nude",
    "nude photo",
    "nude photos",
    "naked photo",
    "naked photos",
    "get naked",
    "be naked",
    "see me naked",
    "want me naked",
];

const EIRI_ABSORB_SHORT_TURN_PHRASES: &[&str] = &[
    "stay with me",
    "hold me",
    "comfort me",
    "forgive me",
    "relationship repair",
    "erotic",
    "aroused",
    "turn me on",
    "sexual",
    "sext",
    "nude",
    "naked",
    "intimate",
];

/// Bright-line absorb predicate for Eiri intimacy, erotic, emotional, and repair turns.
pub fn should_absorb(turn_text: &str) -> bool {
    let normalized_turn = normalize_absorb_text(turn_text);
    if normalized_turn.is_empty() {
        return false;
    }

    let padded_turn = format!(" {normalized_turn} ");
    EIRI_ABSORB_CONTAINS_PHRASES.iter().any(|phrase| {
        let normalized_phrase = normalize_absorb_text(phrase);
        let padded_phrase = format!(" {normalized_phrase} ");
        padded_turn.contains(&padded_phrase)
    }) || EIRI_ABSORB_SHORT_TURN_PHRASES
        .iter()
        .any(|phrase| matches_short_absorb_turn(&normalized_turn, phrase))
}

/// Resolves a requested Eiri sub-agent lane, forcing absorb-classified turns to Base Eiri.
pub fn resolve_eiri_dispatch(requested: EiriSubagent, turn_text: &str) -> EiriDispatchTarget {
    if should_absorb(turn_text) {
        EiriDispatchTarget::BaseEiri
    } else {
        EiriDispatchTarget::Subagent(requested)
    }
}

fn normalize_absorb_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut previous_was_space = true;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            previous_was_space = false;
        } else if matches!(ch, '\'' | '’' | '‘') {
            continue;
        } else if !previous_was_space {
            out.push(' ');
            previous_was_space = true;
        }
    }

    out.trim_end().to_owned()
}

fn matches_short_absorb_turn(normalized_turn: &str, phrase: &str) -> bool {
    let normalized_phrase = normalize_absorb_text(phrase);
    let without_leading_please = normalized_turn
        .strip_prefix("please ")
        .unwrap_or(normalized_turn);
    let short_turn = without_leading_please
        .strip_suffix(" please")
        .unwrap_or(without_leading_please);

    short_turn == normalized_phrase
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
struct RuntimeRoleDefaultExplicitFields {
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

    fn apply_overrides(
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

    fn apply_default_mode_change(
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

    fn contains_mode(&self, mode: RuntimeMode) -> bool {
        RuntimeRole::ALL
            .into_iter()
            .any(|role| self.target(role).mode == mode)
    }
}

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

    pub fn route_for_eiri_turn(&self, requested: EiriSubagent, turn_text: &str) -> RuntimeRoute {
        self.route_for_eiri_turn_with_key_lookup(requested, turn_text, |key| std::env::var_os(key))
    }

    pub fn route_for_eiri_turn_with_key_lookup(
        &self,
        requested: EiriSubagent,
        turn_text: &str,
        key_lookup: impl FnMut(&str) -> Option<OsString>,
    ) -> RuntimeRoute {
        self.route_for_role_with_key_lookup(
            resolve_eiri_dispatch(requested, turn_text).runtime_role(),
            key_lookup,
        )
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
mod tests;
