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
pub(crate) mod tables;
mod usage;

pub use provider::{FetchRoute, ResultRetention, WebProvider, WebProviderProfile};
pub use setting::{WebConnectorSetting, WebProviderKey};
pub use usage::{
    USAGE_READ_DEFAULT_LIMIT, USAGE_READ_MAX_LIMIT, WebCallOutcome, WebConnectorUsage,
    WebConnectorUsagePage, WebConnectorUsageRead, WebCostBasis, WebKeySource,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::settings::web_connector::WEB_CONNECTOR_NAME;
/// The effector a user's own provider key is bound to in custody.
pub const WEB_CONNECTOR_EFFECTOR: &str = "connector:web";
/// The environment variable that holds the deploy's backend Tavily key. The
/// deploy sets it (from skate `tavily-api` for ours); the engine never logs it.
pub const BACKEND_KEY_ENV: &str = "TAVILY_API_KEY";
#[doc(hidden)]
pub use oneiron_verb_wire::web_connector::{
    DEFAULT_MAX_RESULTS, MAX_RESULTS_CAP, WebFetchInput, WebFetchOutput, WebSearchHit,
    WebSearchInput, WebSearchOutput,
};

/// A result snippet's length cap in characters, as Afterglow's `search_web` cuts it.
pub const SNIPPET_MAX_CHARS: usize = 300;
/// A fetched page's text cap in characters.
pub const FETCH_CONTENT_MAX_CHARS: usize = 50_000;

pub use crate::settings::web_connector::WebTool;

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
