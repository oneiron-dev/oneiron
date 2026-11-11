//! OF-444 web acquisition primitive: one HTTP(S) URL in, one fixed six-field
//! [`FetchResult`] out, produced by a fixed three-rung renderer ladder.
//!
//! This module is acquisition only. It reads the web and returns a value. It
//! opens no database, writes no row, performs no import-pipeline work, and
//! routes through no outbound send path. The later import wiring and the later
//! fetch-safety layer are separate tickets that *consume* this primitive; they
//! are deliberately not present here.
//!
//! Three rungs run in exactly this order, and only when the preceding rung
//! fails or extracts too little content: native readability, native headless,
//! self-hosted Firecrawl. Once a rung succeeds, lower rungs never run. Hosted
//! search/scrape services stay outside the ladder entirely.
//!
//! The acquisition timestamp is always supplied by the caller. Nothing in this
//! module reads a host clock.

use std::num::NonZeroUsize;
use std::sync::Arc;

use crate::web_acquisition::content_hash;
pub use crate::web_acquisition::{
    CROSS_SITE_REDIRECT_REASON, CrawlCompletion, CrawlPageBudget, CrawlPageFailure, CrawlRequest,
    CrawlResult, CrawlScope, DEFAULT_MIN_EXTRACTED_CONTENT_BYTES, FetchResult,
    MinExtractedContentBytes, RendererAttemptFailure, RendererError, RendererErrorKind,
    RendererKind, RendererResult, WEB_FETCH_CONTENT_HASH_DOMAIN, WebFetchError, WebFetchResult,
};
use reqwest::Url;

mod client;
mod context;
mod door;
mod egress;
mod ladder;

pub use client::{SingleHopClient, build_single_hop_client, hosted_dns_resolver};
pub use context::{AcquisitionMode, PinnedOrigin, RenderContext};
pub use door::{WebCrawlRequest, WebFetchRequest};
pub use egress::{
    HOSTED_INFRASTRUCTURE_REASON, HOSTED_PRIVATE_NETWORK_REASON, HostedEgressGuard,
    HostedEgressRefusal, HostedPrivateOrigin,
};
mod render;
mod rungs;

use self::ladder::{CrawlWalk, crawl_failure_reason, require_renderer_slot};
use self::render::{parse_web_url, redact_url_credentials, validated_web_url};

/// How many characters of a peer-declared charset label a diagnostic may quote.
const MAX_REPORTED_CHARSET_LABEL_CHARS: usize = 32;

/// Default ceiling on the response bytes one rung will buffer: generous for
/// article HTML and for a scrape envelope, and far below "whatever the peer
/// decides to send". Per-renderer overrides exist so a caller — and a test —
/// can pin a tighter ceiling.
const DEFAULT_MAX_RESPONSE_BYTES: NonZeroUsize = match NonZeroUsize::new(8 * 1024 * 1024) {
    Some(ceiling) => ceiling,
    // A non-zero literal cannot land here.
    None => NonZeroUsize::MIN,
};

/// Fixed prefix of the rendered [`WebFetchError::AllRenderersFailed`] reason
/// recorded against a non-seed crawl page.
const ALL_RENDERERS_FAILED_REASON_PREFIX: &str = "all web fetch renderers failed: ";

/// Target status assumed when a Firecrawl envelope reports none. Silence is not
/// evidence of failure, and an unreported status still has to clear the
/// Markdown floor like any other rung's output.
const FIRECRAWL_UNREPORTED_STATUS: u16 = 200;

/// Internal renderer output. Carries the crawl-relevant fields that the closed
/// six-field public result deliberately does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedPage {
    pub markdown: String,
    pub title: String,
    /// Renderer-resolved metadata identity; emitted only as `FetchResult::canonical_url`.
    pub canonical_url: String,
    /// Independently witnessed navigation/transport-final URL. A renderer may
    /// leave this absent for single-page acquisition, but a containment-sensitive
    /// crawl refuses that rung rather than treating a request echo as evidence.
    pub final_url: Option<String>,
    pub discovered_links: Vec<String>,
}

/// One rung of the fixed ladder.
pub trait Renderer: Send + Sync {
    fn kind(&self) -> RendererKind;

    /// Renders `url` in `context`, the page's [`RenderContext`]. A rung that
    /// reaches the network holds every URL it contacts (the page, each
    /// redirect hop, each navigation) to the context's pinned origin before
    /// it resolves or sends it, failing one outside with
    /// [`RendererError::cross_site_redirect`] (FIX 4734); and on a managed
    /// (hosted) node checks every hop and address it reaches with the
    /// context's egress guard, failing a refused one with
    /// [`RendererError::hosted`] (SCAN C447, FIX 6101). A rung that cannot
    /// do both for the work it is given refuses it before any network
    /// activity. The ladder still checks the requested URL before and the
    /// navigation-final URL the rung hands back after.
    fn render(&self, url: &str, context: &RenderContext) -> RendererResult<RenderedPage>;
}

/// What a host browser returns for one navigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadlessDocument {
    pub html: String,
    /// Browser-final URL after navigation and redirects.
    pub final_url: String,
    /// Target page status observed by the browser navigation.
    pub status: u16,
}

/// Host-injected browser boundary. The engine owns no browser process or crate.
pub trait HeadlessRenderer: Send + Sync {
    /// Navigates to `url` in `context`, the page's [`RenderContext`]. The
    /// browser holds each navigation it makes (the page's load, each
    /// redirect hop, a script's or a meta refresh's move) to the context's
    /// pinned origin before it is sent, failing one outside with
    /// [`RendererError::cross_site_redirect`] (FIX 4734), and refuses an
    /// in-page frame's document outside it unsent while the page renders on;
    /// and on a managed (hosted) node checks every navigation, redirect and
    /// request it makes by the address it connects to
    /// ([`HostedEgressGuard::check_request`])
    /// with the context's egress guard, failing a refused one with
    /// [`RendererError::hosted`] (SCAN C447, FIX 6101). A browser that cannot
    /// do both refuses the work before it navigates.
    fn render_html(&self, url: &str, context: &RenderContext) -> RendererResult<HeadlessDocument>;
}

// ---------------------------------------------------------------------------
// Rung adapters (their `Renderer` impls, guarded paths included, are in
// `rungs`)
// ---------------------------------------------------------------------------

/// Rung 1: one blocking GET, each redirect hop followed by the rung itself,
/// plus native readability extraction.
///
/// The client follows no redirect ([`SingleHopClient`]), so every hop is
/// checked here before it is sent (FIX 4734). This adapter holds no
/// credential.
#[derive(Clone)]
pub struct NativeReadabilityRenderer {
    client: SingleHopClient,
    max_response_bytes: NonZeroUsize,
}

impl NativeReadabilityRenderer {
    /// A host builds `client` with [`build_single_hop_client`]: with a
    /// managed (hosted) node's guard, every name it connects to resolves
    /// through that guard (FIX 7123), and this rung checks every hop it
    /// follows with the guard and a same-site crawl's pin before it sends it.
    #[must_use]
    pub fn new(client: SingleHopClient) -> Self {
        Self {
            client,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// Overrides how many response body bytes this rung will buffer before it
    /// fails closed.
    #[must_use]
    pub fn with_max_response_bytes(mut self, max_response_bytes: NonZeroUsize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }
}

/// Rung 2: a host-provided browser navigation fed through the same extraction.
pub struct NativeHeadlessRenderer {
    headless: Arc<dyn HeadlessRenderer>,
    max_response_bytes: NonZeroUsize,
}

impl NativeHeadlessRenderer {
    #[must_use]
    pub fn new(headless: Arc<dyn HeadlessRenderer>) -> Self {
        Self {
            headless,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// Overrides how many rendered HTML bytes this rung will pass into the DOM
    /// extractor before it fails closed.
    #[must_use]
    pub fn with_max_response_bytes(mut self, max_response_bytes: NonZeroUsize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }
}

/// Rung 3: a self-hosted Firecrawl scrape endpoint.
///
/// The endpoint is complete caller configuration — no hosted default, no
/// inferred API-version prefix — and any deployment-local authentication lives
/// on the injected client, never in this struct.
#[derive(Clone)]
pub struct FirecrawlRenderer {
    client: reqwest::blocking::Client,
    scrape_endpoint: Url,
    max_response_bytes: NonZeroUsize,
}

impl FirecrawlRenderer {
    /// # Errors
    /// Returns [`WebFetchError::InvalidUrl`] when `scrape_endpoint` is not a
    /// credential-free absolute HTTP(S) URL. The endpoint is a URL, so no
    /// renderer or transport error variant fits. Deployment-local
    /// authentication belongs on the injected client, never in the endpoint.
    pub fn new(client: reqwest::blocking::Client, scrape_endpoint: &str) -> WebFetchResult<Self> {
        let endpoint =
            validated_web_url(scrape_endpoint).ok_or_else(|| WebFetchError::InvalidUrl {
                url: redact_url_credentials(scrape_endpoint),
            })?;
        Ok(Self {
            client,
            scrape_endpoint: endpoint,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        })
    }

    /// Overrides how many response body bytes this rung will buffer before it
    /// fails closed.
    #[must_use]
    pub fn with_max_response_bytes(mut self, max_response_bytes: NonZeroUsize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }
}

// ---------------------------------------------------------------------------
// The ladder driver
// ---------------------------------------------------------------------------

/// Drives the fixed ladder for one page ([`WebFetcher::fetch`]) or for a
/// budgeted breadth-first walk ([`WebFetcher::crawl`]).
pub struct WebFetcher {
    /// The required rung. It is an `Option` only so that the ladder driver can
    /// hold every slot uniformly and state the required/optional distinction in
    /// one place; the constructor always fills it, and an empty required slot
    /// fails closed instead of being stepped over.
    readability: Option<Arc<dyn Renderer>>,
    headless: Option<Arc<dyn Renderer>>,
    firecrawl: Option<Arc<dyn Renderer>>,
    minimum_content: MinExtractedContentBytes,
    /// A managed node's egress guard (SCAN C447), installed by its host,
    /// which may be at first use; empty on a self-hosted one.
    egress: std::sync::OnceLock<Arc<HostedEgressGuard>>,
}

impl WebFetcher {
    /// The readability rung is always present. Optional fallbacks stay visible
    /// as `Unavailable` attempt records when escalation reaches them. A host
    /// that supplies this ladder on a managed node builds the readability
    /// rung's client with [`build_single_hop_client`] (see
    /// [`NativeReadabilityRenderer::new`]).
    ///
    /// # Errors
    /// Returns [`WebFetchError::InvalidRendererSlot`] when the renderer does not
    /// report [`RendererKind::Readability`].
    pub fn new(readability: Arc<dyn Renderer>) -> WebFetchResult<Self> {
        require_renderer_slot(RendererKind::Readability, readability.as_ref())?;
        Ok(Self {
            readability: Some(readability),
            headless: None,
            firecrawl: None,
            minimum_content: MinExtractedContentBytes::default(),
            egress: std::sync::OnceLock::new(),
        })
    }

    /// # Errors
    /// Returns [`WebFetchError::InvalidRendererSlot`] when the renderer does not
    /// report [`RendererKind::Headless`].
    pub fn with_headless(mut self, headless: Arc<dyn Renderer>) -> WebFetchResult<Self> {
        require_renderer_slot(RendererKind::Headless, headless.as_ref())?;
        self.headless = Some(headless);
        Ok(self)
    }

    /// # Errors
    /// Returns [`WebFetchError::InvalidRendererSlot`] when the renderer does not
    /// report [`RendererKind::Firecrawl`].
    pub fn with_firecrawl(mut self, firecrawl: Arc<dyn Renderer>) -> WebFetchResult<Self> {
        require_renderer_slot(RendererKind::Firecrawl, firecrawl.as_ref())?;
        self.firecrawl = Some(firecrawl);
        Ok(self)
    }

    #[must_use]
    pub const fn with_minimum_content(mut self, minimum_content: MinExtractedContentBytes) -> Self {
        self.minimum_content = minimum_content;
        self
    }

    /// Acquires one page.
    ///
    /// # Errors
    /// Returns [`WebFetchError::InvalidUrl`], [`WebFetchError::UnsupportedScheme`],
    /// or [`WebFetchError::CredentialsInUrl`] for a URL this module will not
    /// fetch; [`WebFetchError::MissingRequiredRenderer`] when a required rung is
    /// unconfigured; [`WebFetchError::HostedInfrastructure`] or
    /// [`WebFetchError::HostedPrivateNetwork`] when a managed node's guard
    /// refused the page, a hop or an address a rung reached; and
    /// [`WebFetchError::AllRenderersFailed`] carrying the ordered ladder trace
    /// when no rung produced content.
    pub fn fetch(&self, url: &str, fetched_at: u64) -> WebFetchResult<FetchResult> {
        let parsed = parse_web_url(url)?;
        let (result, _links, _final_url) =
            self.fetch_page(&parsed, fetched_at, RenderContext::single_page())?;
        Ok(result)
    }

    /// Walks a site breadth-first under an explicit page budget.
    ///
    /// The budget counts *attempted* page fetches, not successes: a seed failure
    /// is a typed `Err`, and every non-seed failure consumes its unit, lands in
    /// [`CrawlResult::failed`], and the walk continues.
    ///
    /// A same-site walk holds every page after its seed to the seed's
    /// navigation-final origin ([`PinnedOrigin`]) before any rung contacts
    /// anything of it: a page, redirect hop or navigation outside it is
    /// refused unsent, and the page is recorded as
    /// [`CROSS_SITE_REDIRECT_REASON`] (FIX 4734). The seed is fetched with no
    /// pin, so its own redirects are not held to an origin. A rung whose
    /// redirects run on a remote service (Firecrawl) is used for no page of a
    /// same-site walk, its seed's included.
    ///
    /// # Errors
    /// Returns [`WebFetchError::InvalidUrl`], [`WebFetchError::UnsupportedScheme`],
    /// or [`WebFetchError::CredentialsInUrl`] for an unusable seed URL, and
    /// propagates the seed page's typed ladder failure because there is no
    /// successful final URL from which to pin the walk.
    pub fn crawl(&self, request: CrawlRequest) -> WebFetchResult<CrawlResult> {
        let seed = parse_web_url(&request.seed_url)?;
        let mut walk = CrawlWalk::new(seed, request.page_budget.get());

        while let Some(current) = walk.pop_frontier() {
            let requested = current.to_string();
            // Dequeue-time seen-set skip: an earlier page already navigated here.
            // Not an attempt, so it charges no budget.
            if walk.visited.contains(&requested) {
                continue;
            }
            if walk.remaining_budget == 0 {
                walk.restore_front(current);
                return Ok(walk.into_budget_exhausted());
            }
            walk.remaining_budget -= 1;
            walk.visited.insert(requested.clone());

            let is_seed = walk.pinned_origin.is_none();
            let context = RenderContext::crawl_page(request.scope, walk.pinned_origin.clone());
            match self.fetch_page(&current, request.fetched_at, context) {
                Ok((page, links, final_url)) => {
                    // A URL reached through a redirect is skipped when it is
                    // later dequeued. This set also carries requested URLs
                    // inserted before their own fetch, so its insertion result
                    // is deliberately not the duplicate signal: that decision
                    // belongs to completed navigation-final identity alone.
                    walk.visited.insert(final_url.to_string());
                    walk.absorb_success(requested, page, &links, &final_url, request.scope);
                }
                Err(error) if is_seed => return Err(error),
                Err(error) => walk.failed.push(CrawlPageFailure {
                    url: requested,
                    reason: crawl_failure_reason(&error),
                }),
            }
        }

        Ok(CrawlResult {
            pages: walk.pages,
            failed: walk.failed,
            completion: CrawlCompletion::Complete,
        })
    }
}

impl crate::web_acquisition::WebAcquisition for WebFetcher {
    fn fetch(&self, url: &str, fetched_at: u64) -> WebFetchResult<FetchResult> {
        WebFetcher::fetch(self, url, fetched_at)
    }

    fn crawl(&self, request: CrawlRequest) -> WebFetchResult<CrawlResult> {
        WebFetcher::crawl(self, request)
    }
}

#[cfg(test)]
mod tests;
