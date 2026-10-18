//! The host owns renderer configuration; acquisition itself stays in the engine.
use std::sync::Arc;

use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::web_fetch::{NativeReadabilityRenderer, WebFetcher};

use super::SyncServer;

impl SyncServer {
    /// Supplies the host's fixed renderer ladder, including any isolated
    /// headless or self-hosted Firecrawl adapters. No caller controls it.
    #[must_use]
    pub fn with_web_fetcher(mut self, fetcher: WebFetcher) -> Self {
        self.web_fetcher = std::sync::OnceLock::from(Arc::new(fetcher));
        self
    }

    /// Called off the async runtime. The default rung is a credential-free
    /// native GET; a host that supplies a ladder keeps that exact ladder.
    pub(crate) fn web_fetcher(&self) -> MemoryResult<Arc<WebFetcher>> {
        if let Some(fetcher) = self.web_fetcher.get() {
            return Ok(Arc::clone(fetcher));
        }
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .map_err(|_| MemoryError::new("WEB_FETCH_FAILED", "web HTTP client unavailable", &[]))?;
        let fetcher = WebFetcher::new(Arc::new(NativeReadabilityRenderer::new(client)))
            .map_err(|error| MemoryError::new("WEB_FETCH_FAILED", error.to_string(), &[]))?;
        Ok(Arc::clone(self.web_fetcher.get_or_init(|| Arc::new(fetcher))))
    }
}
