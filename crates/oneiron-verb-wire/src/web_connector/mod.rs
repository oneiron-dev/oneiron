//! Moved from `crates/oneiron/src/web_connector/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::settings::web_connector::FetchRoute;
pub use oneiron_store::settings::web_connector::ResultRetention;
pub use oneiron_store::settings::web_connector::USAGE_READ_DEFAULT_LIMIT;
pub use oneiron_store::settings::web_connector::USAGE_READ_MAX_LIMIT;
pub use oneiron_store::settings::web_connector::WEB_CONNECTOR_NAME;
pub use oneiron_store::settings::web_connector::WebCallOutcome;
pub use oneiron_store::settings::web_connector::WebConnectorSetting;
pub use oneiron_store::settings::web_connector::WebConnectorUsage;
pub use oneiron_store::settings::web_connector::WebConnectorUsagePage;
pub use oneiron_store::settings::web_connector::WebConnectorUsageRead;
pub use oneiron_store::settings::web_connector::WebCostBasis;
pub use oneiron_store::settings::web_connector::WebKeySource;
pub use oneiron_store::settings::web_connector::WebProvider;
pub use oneiron_store::settings::web_connector::WebProviderKey;
pub use oneiron_store::settings::web_connector::WebProviderProfile;
pub use oneiron_store::settings::web_connector::WebTool;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// Results a search returns when its caller names no count.
pub const DEFAULT_MAX_RESULTS: u32 = 5;

/// The most results one search returns.
pub const MAX_RESULTS_CAP: u32 = 10;

/// `search`'s input: a bare query string, or this object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebSearchInput {
    pub query: String,
    /// At most [`MAX_RESULTS_CAP`]; [`DEFAULT_MAX_RESULTS`] when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_results: Option<u32>,
}

impl WebSearchInput {
    /// A call's arguments read as a search: a bare string is the query. `None`
    /// when they name no query.
    #[must_use]
    pub fn from_arguments(arguments: &Value) -> Option<Self> {
        let input = match arguments {
            Value::String(query) => Self {
                query: query.clone(),
                max_results: None,
            },
            other => serde_json::from_value(other.clone()).ok()?,
        };
        (!input.query.trim().is_empty()).then_some(input)
    }

    /// The result count this search asks for, within the cap.
    #[must_use]
    pub fn result_count(&self) -> u32 {
        self.max_results
            .unwrap_or(DEFAULT_MAX_RESULTS)
            .clamp(1, MAX_RESULTS_CAP)
    }
}

/// `fetch`'s input: a bare URL string, or this object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebFetchInput {
    pub url: String,
}

impl WebFetchInput {
    /// A call's arguments read as a fetch: a bare string is the URL. `None`
    /// unless they name an `http` or `https` URL.
    #[must_use]
    pub fn from_arguments(arguments: &Value) -> Option<Self> {
        let input = match arguments {
            Value::String(url) => Self { url: url.clone() },
            other => serde_json::from_value(other.clone()).ok()?,
        };
        let url = input.url.trim();
        (url.starts_with("https://") || url.starts_with("http://")).then(|| Self {
            url: url.to_owned(),
        })
    }
}

/// One search result, as Afterglow's `search_web` returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WebSearchHit {
    pub title: String,
    pub url: String,
    /// At most [`SNIPPET_MAX_CHARS`] characters.
    pub snippet: String,
}

/// `search`'s output, as Afterglow's `search_web` returns it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WebSearchOutput {
    pub provider: String,
    pub results: Vec<WebSearchHit>,
    pub latency_ms: u64,
    /// `None` when the call is unpriced.
    pub cost_usd: Option<f64>,
}

/// `fetch`'s output: one page's readable text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WebFetchOutput {
    pub provider: String,
    pub url: String,
    pub title: Option<String>,
    /// At most [`FETCH_CONTENT_MAX_CHARS`] characters.
    pub content: String,
    pub latency_ms: u64,
    /// `None` when the call is unpriced.
    pub cost_usd: Option<f64>,
}
