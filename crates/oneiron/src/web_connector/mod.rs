//! The built-in `web` connector (FIX 11598, CONN-1 A): `connector.web.search(query)`
//! and `connector.web.fetch(url)` over one provider registry.
//!
//! The server answers both tools before the MCP driver: the connector is
//! first-party, so it has no catalogued key, MCP schema or protocol pin. Which
//! provider serves a call, and whose key pays for it, is the vault's one switch
//! ([`WebConnectorSetting`]); unset, Tavily basic serves it on the deploy's
//! backend key. Every call leaves one [`WebConnectorUsage`] row: provider, tool,
//! key source, latency and cost, never the query, the URL or the results. The
//! result shapes are Afterglow's `search_web` tool's, so it can move in later.
mod provider;
mod setting;
mod usage;

pub use provider::{FetchRoute, ResultRetention, WebProvider, WebProviderProfile};
pub use setting::{WebConnectorSetting, WebProviderKey};
pub use usage::{
    USAGE_READ_DEFAULT_LIMIT, USAGE_READ_MAX_LIMIT, WebCallOutcome, WebConnectorUsage,
    WebConnectorUsagePage, WebConnectorUsageRead, WebCostBasis, WebKeySource,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The connector name a `connector.call` names to reach this connector.
pub const WEB_CONNECTOR_NAME: &str = "web";
/// The effector a user's own provider key is bound to in custody.
pub const WEB_CONNECTOR_EFFECTOR: &str = "connector:web";
/// The environment variable that holds the deploy's backend Tavily key. The
/// deploy sets it (from skate `tavily-api` for ours); the engine never logs it.
pub const BACKEND_KEY_ENV: &str = "TAVILY_API_KEY";
/// Results a search returns when its caller names no count.
pub const DEFAULT_MAX_RESULTS: u32 = 5;
/// The most results one search returns.
pub const MAX_RESULTS_CAP: u32 = 10;
/// A result snippet's length cap in characters, as Afterglow's `search_web` cuts it.
pub const SNIPPET_MAX_CHARS: usize = 300;
/// A fetched page's text cap in characters.
pub const FETCH_CONTENT_MAX_CHARS: usize = 50_000;

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

/// `text` cut to at most `max` characters, on a character boundary.
#[must_use]
pub fn cut_chars(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((end, _)) => text[..end].to_owned(),
        None => text.to_owned(),
    }
}

/// `micro_usd` as the USD amount a reply shows.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn micro_usd_to_usd(micro_usd: u64) -> f64 {
    micro_usd as f64 / 1_000_000.0
}
