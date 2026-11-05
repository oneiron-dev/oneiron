//! The provider registry: which providers may serve a web call, on whose key,
//! at what declared price, and how long their results may be kept.
use serde::{Deserialize, Serialize};

/// One provider of web search and page reading.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WebProvider {
    Tavily,
    Exa,
    Brave,
    Tinyfish,
    ContextDev,
    Octen,
}

/// How a provider's `fetch` reads a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchRoute {
    /// Its own page-reading endpoint, on the same key as its search.
    Provider,
    /// Our own guarded reader (`web_fetch`): no key and no fee.
    Direct,
}

/// How long a provider's results may be kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultRetention {
    /// The provider's terms set no limit.
    Unrestricted,
    /// Brave's standard grant: results are shown, never kept.
    Transient,
    /// octen.ai §4.6: cached 24 h at most, never stored.
    Cache24h,
}

/// What the registry knows of one provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebProviderProfile {
    pub provider: WebProvider,
    /// Whether the deploy's backend key may serve it. Only Tavily (CONN-1 A):
    /// Exa §4.2, TinyFish's internal-use terms and octen.ai §4.3 keep the
    /// others on the user's own key or the hub.
    pub backend_key: bool,
    /// The declared price of one search call in micro-USD, `None` when unpriced.
    pub search_price_micro_usd: Option<u64>,
    /// The declared price of one fetch call in micro-USD, `None` when unpriced.
    pub fetch_price_micro_usd: Option<u64>,
    pub fetch: FetchRoute,
    pub retention: ResultRetention,
}

/// Declared prices as published on 29 Oct 2026 (research-1120 and the
/// providers' price pages). A provider-reported cost replaces them per call.
const TAVILY: WebProviderProfile = WebProviderProfile {
    provider: WebProvider::Tavily,
    backend_key: true,
    // Basic search: 1 credit at $0.008 PAYG.
    search_price_micro_usd: Some(8_000),
    // Basic extraction: 1 credit per 5 successful URLs, $0.0016 a URL.
    fetch_price_micro_usd: Some(1_600),
    fetch: FetchRoute::Provider,
    retention: ResultRetention::Unrestricted,
};
const EXA: WebProviderProfile = WebProviderProfile {
    provider: WebProvider::Exa,
    backend_key: false,
    // Auto search, up to 10 results: $7 per 1,000 requests.
    search_price_micro_usd: Some(7_000),
    // Contents, one content type: $1 per 1,000 pages.
    fetch_price_micro_usd: Some(1_000),
    fetch: FetchRoute::Provider,
    retention: ResultRetention::Unrestricted,
};
const BRAVE: WebProviderProfile = WebProviderProfile {
    provider: WebProvider::Brave,
    backend_key: false,
    // Search plan: $5 per 1,000 requests.
    search_price_micro_usd: Some(5_000),
    fetch_price_micro_usd: Some(0),
    fetch: FetchRoute::Direct,
    retention: ResultRetention::Transient,
};
const TINYFISH: WebProviderProfile = WebProviderProfile {
    provider: WebProvider::Tinyfish,
    backend_key: false,
    // TinySearch and TinyFetch are free within their daily allowances.
    search_price_micro_usd: Some(0),
    fetch_price_micro_usd: Some(0),
    fetch: FetchRoute::Provider,
    retention: ResultRetention::Unrestricted,
};
const CONTEXT_DEV: WebProviderProfile = WebProviderProfile {
    provider: WebProvider::ContextDev,
    backend_key: false,
    // One credit (up to 10 results, or one scrape), at most $0.003 on Developer overage.
    search_price_micro_usd: Some(3_000),
    fetch_price_micro_usd: Some(3_000),
    fetch: FetchRoute::Provider,
    retention: ResultRetention::Unrestricted,
};
const OCTEN: WebProviderProfile = WebProviderProfile {
    provider: WebProvider::Octen,
    backend_key: false,
    // Web search: $1 per 1,000 calls.
    search_price_micro_usd: Some(1_000),
    // Standard extract: $1 per 1,000 successful URLs.
    fetch_price_micro_usd: Some(1_000),
    fetch: FetchRoute::Provider,
    retention: ResultRetention::Cache24h,
};

impl WebProvider {
    pub const ALL: [Self; 6] = [
        Self::Tavily,
        Self::Exa,
        Self::Brave,
        Self::Tinyfish,
        Self::ContextDev,
        Self::Octen,
    ];

    /// The provider's name in replies and usage rows.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tavily => "tavily",
            Self::Exa => "exa",
            Self::Brave => "brave",
            Self::Tinyfish => "tinyfish",
            Self::ContextDev => "context_dev",
            Self::Octen => "octen",
        }
    }

    #[must_use]
    pub fn profile(self) -> &'static WebProviderProfile {
        match self {
            Self::Tavily => &TAVILY,
            Self::Exa => &EXA,
            Self::Brave => &BRAVE,
            Self::Tinyfish => &TINYFISH,
            Self::ContextDev => &CONTEXT_DEV,
            Self::Octen => &OCTEN,
        }
    }
}

impl WebProviderProfile {
    /// The declared price of one call of `tool`, `None` when unpriced.
    #[must_use]
    pub fn declared_price_micro_usd(&self, tool: super::WebTool) -> Option<u64> {
        match tool {
            super::WebTool::Search => self.search_price_micro_usd,
            super::WebTool::Fetch => self.fetch_price_micro_usd,
        }
    }
}
