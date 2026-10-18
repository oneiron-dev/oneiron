//! Typed inputs for the two acquisition doors. Acquisition time is host-stamped.
use serde::{Deserialize, Serialize};

use super::{CrawlPageBudget, CrawlRequest, CrawlScope, WebFetchResult};

/// `fetch` acquires exactly one page. It has no crawl controls.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebFetchRequest {
    pub url: String,
}

/// `crawl` requires an explicit attempted-page budget; no hidden default.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebCrawlRequest {
    pub seed_url: String,
    #[schemars(range(min = 1))]
    pub page_budget: usize,
    #[serde(default)]
    pub scope: CrawlScope,
}

impl WebCrawlRequest {
    /// Validates the same nonzero budget the engine's crawler accepts.
    pub fn into_request(self, fetched_at: u64) -> WebFetchResult<CrawlRequest> {
        Ok(CrawlRequest {
            seed_url: self.seed_url,
            fetched_at,
            page_budget: CrawlPageBudget::new(self.page_budget)?,
            scope: self.scope,
        })
    }
}
