//! Web provider selection and content-free usage vocabulary.
use oneiron_base::error::{Error, Result};
use serde::{Deserialize, Serialize};

pub mod provider;
pub use provider::{FetchRoute, ResultRetention, WebProvider, WebProviderProfile};

/// The connector name a `connector.call` names to reach this connector.
pub const WEB_CONNECTOR_NAME: &str = "web";

/// The connector's two tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebTool {
    Search,
    Fetch,
}

impl WebTool {
    /// The tool a `connector.call` names, if it is one of the two.
    #[must_use]
    pub fn parse(tool: &str) -> Option<Self> {
        match tool {
            "search" => Some(Self::Search),
            "fetch" => Some(Self::Fetch),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Search => "search",
            Self::Fetch => "fetch",
        }
    }
}

/// Whose key pays for a provider's calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WebProviderKey {
    /// The deploy's backend key, only for a provider whose profile allows it.
    Backend,
    /// The user's own key: the custody secret by this name, bound to the
    /// `connector:web` effector. Its value is read only at the custody door.
    Secret { name: String },
    /// An installed hub connector that serves the same `search` and `fetch`
    /// tools on its own key, under its own grant and gate.
    Hub { connector: String },
}

/// Which provider serves the vault's web calls, on whose key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebConnectorSetting {
    pub provider: WebProvider,
    pub key: WebProviderKey,
}

impl Default for WebConnectorSetting {
    /// The ruled default (CONN-1 A): Tavily basic on the deploy's backend key.
    fn default() -> Self {
        Self {
            provider: WebProvider::Tavily,
            key: WebProviderKey::Backend,
        }
    }
}

impl WebConnectorSetting {
    /// Refuses a backend key for a provider whose terms keep it on the user's
    /// own key, and a key that names nothing.
    pub fn validate(&self) -> Result<()> {
        match &self.key {
            WebProviderKey::Backend if !self.provider.profile().backend_key => {
                Err(Error::InvalidConfig(format!(
                    "web connector: {} runs only on the user's own key or through the hub",
                    self.provider.as_str()
                )))
            }
            WebProviderKey::Secret { name } if name.trim().is_empty() => Err(Error::InvalidConfig(
                "web connector: a secret key names its custody record".into(),
            )),
            WebProviderKey::Hub { connector }
                if connector.trim().is_empty() || connector == WEB_CONNECTOR_NAME =>
            {
                Err(Error::InvalidConfig(
                    "web connector: a hub key names another installed connector".into(),
                ))
            }
            _ => Ok(()),
        }
    }
}

/// Rows one read returns when its caller names no count.
pub const USAGE_READ_DEFAULT_LIMIT: u32 = 100;
/// The most rows one read returns.
pub const USAGE_READ_MAX_LIMIT: u32 = 1_000;

/// Whose key a call ran on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebKeySource {
    /// The deploy's backend key: our cash.
    Backend,
    /// The user's own key, from custody.
    User,
    /// A hub connector's key.
    Hub,
}

/// Where a row's cost came from (Engine call on FIX 8689, 10-26 22:19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebCostBasis {
    /// The provider reported it in its response.
    Actual,
    /// The provider's declared price for the tool.
    Estimated,
    /// No price is known: measured and shown, never refused.
    Unpriced,
}

/// How a call ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WebCallOutcome {
    /// Answered, with this many results (1 for a fetched page).
    Ok { results: u32 },
    /// Failed, with its reason code.
    Failed { reason: String },
    /// A hub connector's call that waits (held, pending delivery or awaiting
    /// input); its own row in the connector-call ledger settles it.
    Waiting { reason: String },
}

/// One web call's usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WebConnectorUsage {
    pub at_ms: u64,
    pub tool: WebTool,
    pub provider: WebProvider,
    pub key: WebKeySource,
    /// The installed connector a hub key forwarded the call to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub_connector: Option<String>,
    pub latency_ms: u64,
    /// `None` when unpriced.
    pub cost_micro_usd: Option<u64>,
    pub cost_basis: WebCostBasis,
    /// The provider's own id for the request, when its response names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_request_id: Option<String>,
    pub outcome: WebCallOutcome,
}

/// `vault.connectors.web.usage`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebConnectorUsageRead {
    /// Only rows at or after this time (ms).
    #[serde(default)]
    pub since_ms: Option<u64>,
    /// At most [`USAGE_READ_MAX_LIMIT`]; [`USAGE_READ_DEFAULT_LIMIT`] when absent.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// The rows a usage read returns, newest first, with their summed known cost.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WebConnectorUsagePage {
    pub rows: Vec<WebConnectorUsage>,
    /// The summed cost of the returned rows that carry one.
    pub total_cost_micro_usd: u64,
    /// How many returned rows are unpriced.
    pub unpriced: u32,
}
