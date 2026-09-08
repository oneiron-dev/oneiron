//! Runtime mode, provider-kind, and role taxonomies with string conversions.
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::usage::UsageMode;

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

    pub(super) fn provider_kind(self) -> RuntimeProviderKind {
        match self {
            Self::LocalFree => RuntimeProviderKind::Local,
            Self::ByoCloudKey => RuntimeProviderKind::ByoCloud,
            Self::OneironCloud => RuntimeProviderKind::OneironCloud,
        }
    }

    pub(super) fn allows_provider(self, provider_kind: RuntimeProviderKind) -> bool {
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

fn normalized_key(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['-', '_'], "")
}
