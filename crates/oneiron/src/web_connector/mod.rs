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
pub(crate) mod setting_keys;
pub(crate) mod tables;
mod usage;

pub use provider::{FetchRoute, ResultRetention, WebProvider, WebProviderProfile};
pub use setting::{WebConnectorSetting, WebProviderKey};
pub use usage::{
    USAGE_READ_DEFAULT_LIMIT, USAGE_READ_MAX_LIMIT, WebCallOutcome, WebConnectorUsage,
    WebConnectorUsagePage, WebConnectorUsageRead, WebCostBasis, WebKeySource,
};

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

/// A result snippet's shipped length cap in characters, as Afterglow's `search_web` cuts it: the
/// default of the key `connectors.web.snippet_max_chars`.
pub const SNIPPET_MAX_CHARS: usize = 300;
/// A fetched page's shipped text cap in characters: the default of the key
/// `connectors.web.fetch_max_chars`.
pub const FETCH_CONTENT_MAX_CHARS: usize = 50_000;

pub use crate::settings::web_connector::WebTool;

/// The vault's caps on a web call's results, as [`crate::Vault::web_result_limits`] reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebResultLimits {
    /// The most characters of one search hit's snippet (`connectors.web.snippet_max_chars`,
    /// default [`SNIPPET_MAX_CHARS`]).
    pub snippet_max_chars: usize,
    /// The most characters of one fetched page's text (`connectors.web.fetch_max_chars`, default
    /// [`FETCH_CONTENT_MAX_CHARS`]); a provider that reads the page itself is asked for at most
    /// as many.
    pub fetch_max_chars: usize,
}

impl WebResultLimits {
    /// The shipped caps, which a vault with no row of either key reads.
    pub const SHIPPED: Self = Self {
        snippet_max_chars: SNIPPET_MAX_CHARS,
        fetch_max_chars: FETCH_CONTENT_MAX_CHARS,
    };

    /// `hit` with its snippet cut to the snippet cap.
    #[must_use]
    pub fn cut_hit(&self, hit: WebSearchHit) -> WebSearchHit {
        WebSearchHit {
            snippet: cut_chars(&hit.snippet, self.snippet_max_chars),
            ..hit
        }
    }

    /// A fetched page's `content` cut to the page cap.
    #[must_use]
    pub fn cut_page(&self, content: &str) -> String {
        cut_chars(content, self.fetch_max_chars)
    }
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
