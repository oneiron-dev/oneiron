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

use reqwest::Url;
use serde::{Deserialize, Serialize};

mod client;
mod door;
mod egress;
mod ladder;

pub use client::{build_single_hop_client, build_web_fetch_client};
pub use door::{WebCrawlRequest, WebFetchRequest};
pub use egress::{HOSTED_INFRASTRUCTURE_REASON, HostedEgressGuard, HostedInfrastructureRefusal};
mod render;
mod rungs;

use self::ladder::{CrawlWalk, FetchResultWire, crawl_failure_reason, require_renderer_slot};
use self::render::{parse_web_url, redact_url_credentials, validated_web_url};

/// Domain prefix for the OF-444 content identity.
pub const WEB_FETCH_CONTENT_HASH_DOMAIN: &[u8] = b"oneiron.web_fetch.content.v1\0";

/// Engine default for deciding that a renderer extracted real page content.
/// This is a test-injectable mechanism dial, not a safety or quality verdict.
pub const DEFAULT_MIN_EXTRACTED_CONTENT_BYTES: usize = 256;

/// What replaces the userinfo of any URL this module reports.
const REDACTED_USERINFO: &str = "REDACTED";

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

/// Ceiling on how many raw link entries one page may make the engine inspect.
///
/// This is separate from the normalized-link ceiling below. Duplicate, invalid,
/// and non-HTTP entries still cost parse and join work, and a compact Firecrawl
/// JSON array can otherwise expand into far more allocations than its wire bytes.
const MAX_RAW_LINKS_PER_PAGE: usize = 16_384;

/// Ceiling on how many distinct normalized links one page may contribute.
///
/// The normalized set is bounded while it is built. It never grows to the
/// peer-controlled size and gets measured afterward.
const MAX_DISCOVERED_LINKS_PER_PAGE: usize = 8192;

/// The exact reason literal recorded when a same-site walk lands on a foreign
/// host through a post-fetch redirect.
const CROSS_SITE_REDIRECT_REASON: &str = "cross_site_redirect";

/// Fixed prefix of the rendered [`WebFetchError::AllRenderersFailed`] reason
/// recorded against a non-seed crawl page.
const ALL_RENDERERS_FAILED_REASON_PREFIX: &str = "all web fetch renderers failed: ";

/// Target status assumed when a Firecrawl envelope reports none. Silence is not
/// evidence of failure, and an unreported status still has to clear the
/// Markdown floor like any other rung's output.
const FIRECRAWL_UNREPORTED_STATUS: u16 = 200;

/// Which rung of the fixed ladder produced a result.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RendererKind {
    Readability,
    Headless,
    Firecrawl,
}

impl RendererKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Readability => "readability",
            Self::Headless => "headless",
            Self::Firecrawl => "firecrawl",
        }
    }
}

/// The complete and only public shape produced by a successful single-page fetch.
///
/// Six fields, closed. Status codes, raw HTML, provider payloads, discovered
/// links, and downstream references are deliberately absent: they belong to
/// internal renderer output, to errors, or to later consumers.
///
/// The closure is enforced in both directions: serialization emits exactly the
/// six keys, and `deny_unknown_fields` makes decoding reject a seventh instead
/// of silently dropping it. A value that round-trips through this type is
/// therefore evidence about the whole payload, not just about the six fields
/// that happened to be recognized.
///
/// Decoding is closed on identity as well as on shape: it runs through a private
/// wire form that repeats the field closure and re-derives `content_hash` from
/// the `markdown` beside it, so a decoded value carries the identity documented
/// below rather than whichever identity the payload asserted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, try_from = "FetchResultWire")]
pub struct FetchResult {
    markdown: String,
    title: String,
    canonical_url: String,
    /// Caller-supplied Unix timestamp in seconds, copied verbatim. This module
    /// never reads a host clock.
    fetched_at: u64,
    /// Lowercase 64-character BLAKE3 hex over
    /// [`WEB_FETCH_CONTENT_HASH_DOMAIN`] followed by the exact `markdown` bytes.
    content_hash: String,
    renderer: RendererKind,
}

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

/// Machine-stable classification of a renderer failure. Callers branch on this
/// and on [`RendererKind`]; the accompanying message is a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendererErrorKind {
    Transport,
    Extraction,
    InvalidResponse,
    /// A managed node's egress guard refused a hop, an address or a landing
    /// the rung reached (SCAN C447, FIX 6101). The ladder ends on it typed.
    HostedInfrastructure,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{kind:?}: {message}")]
pub struct RendererError {
    pub kind: RendererErrorKind,
    pub message: String,
}

impl RendererError {
    #[must_use]
    pub fn transport(message: impl Into<String>) -> Self {
        Self {
            kind: RendererErrorKind::Transport,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn extraction(message: impl Into<String>) -> Self {
        Self {
            kind: RendererErrorKind::Extraction,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn invalid_response(message: impl Into<String>) -> Self {
        Self {
            kind: RendererErrorKind::InvalidResponse,
            message: message.into(),
        }
    }
}

pub type RendererResult<T> = std::result::Result<T, RendererError>;

/// One rung of the fixed ladder.
pub trait Renderer: Send + Sync {
    fn kind(&self) -> RendererKind;
    fn render(&self, url: &str) -> RendererResult<RenderedPage>;

    /// [`Self::render`] on a managed (hosted) node, which hands the rung its
    /// egress guard (SCAN C447, FIX 6101): a rung that reaches the network
    /// checks every hop and address it reaches with it, failing a refused one
    /// with [`RendererError::hosted_infrastructure`]. The default renders
    /// unchecked; the ladder still checks the requested URL before and the
    /// navigation-final URL the rung hands back after.
    fn render_guarded(
        &self,
        url: &str,
        _guard: &HostedEgressGuard,
    ) -> RendererResult<RenderedPage> {
        self.render(url)
    }
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
    fn render_html(&self, url: &str) -> RendererResult<HeadlessDocument>;

    /// [`Self::render_html`] on a managed (hosted) node (SCAN C447,
    /// FIX 6101): a browser that sees its own traffic checks every
    /// navigation, redirect and request it makes, by the address it connects
    /// to ([`HostedEgressGuard::check_request`]), and fails a refused one with
    /// [`RendererError::hosted_infrastructure`]; a host that performs each
    /// request itself can send it with [`build_single_hop_client`]. The
    /// default navigates unchecked; the engine then checks only the requested
    /// URL and the browser-final URL.
    fn render_html_guarded(
        &self,
        url: &str,
        _guard: &HostedEgressGuard,
    ) -> RendererResult<HeadlessDocument> {
        self.render_html(url)
    }
}

/// One rung's outcome when it did not win. Absent configuration, a typed
/// renderer error, and a below-threshold extraction stay distinguishable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RendererAttemptFailure {
    Unavailable {
        renderer: RendererKind,
    },
    Error {
        renderer: RendererKind,
        error: RendererError,
    },
    EmptyExtraction {
        renderer: RendererKind,
        extracted_bytes: usize,
        minimum_bytes: usize,
    },
}

impl RendererAttemptFailure {
    /// Renders one attempt as `{renderer}: {detail}` for the crawl failure trace.
    fn render_reason(&self) -> String {
        match self {
            Self::Unavailable { renderer } => {
                format!("{}: renderer unavailable", renderer.as_str())
            }
            Self::Error { renderer, error } => {
                format!("{}: {error}", renderer.as_str())
            }
            Self::EmptyExtraction {
                renderer,
                extracted_bytes,
                minimum_bytes,
            } => format!(
                "{}: empty extraction ({extracted_bytes} bytes < {minimum_bytes} minimum)",
                renderer.as_str()
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WebFetchError {
    /// The reported URL is always credential-redacted.
    #[error("invalid web fetch URL: {url}")]
    InvalidUrl { url: String },

    #[error("web fetch supports only http and https, not {scheme}")]
    UnsupportedScheme { scheme: String },

    /// Embedded `user:pass@host` userinfo is refused at the boundary rather
    /// than carried into a request, a provider payload, or a diagnostic. The
    /// reported URL has already had its userinfo replaced.
    #[error("web fetch URL must not carry embedded credentials: {url}")]
    CredentialsInUrl { url: String },

    #[error("renderer slot expected {expected:?}, got {actual:?}")]
    InvalidRendererSlot {
        expected: RendererKind,
        actual: RendererKind,
    },

    /// A required rung has no renderer. This is an engine misconfiguration, not
    /// a ladder outcome, so it is never recorded as one more `Unavailable`
    /// attempt and stepped over.
    #[error("required {} renderer rung is not configured", .renderer.as_str())]
    MissingRequiredRenderer { renderer: RendererKind },

    #[error("minimum extracted content bytes must be greater than zero")]
    InvalidMinimumContentBytes,

    #[error("crawl page budget must be greater than zero")]
    InvalidPageBudget,

    #[error("all web fetch renderers failed for {url}")]
    AllRenderersFailed {
        url: String,
        attempts: Vec<RendererAttemptFailure>,
    },

    /// A managed (hosted) node's fetcher refused a destination that reaches
    /// the infrastructure it runs on (SCAN C447): the requested page before
    /// any rung ran, or a redirect hop, a re-resolved address or a landing a
    /// rung reached (FIX 6101), which ends the ladder. The message names
    /// [`HOSTED_INFRASTRUCTURE_REASON`]; `url` is the requested page,
    /// credential-redacted.
    #[error(
        "web fetch refused (hosted_infrastructure): on a hosted node, {url} resolves or redirects to the hosting infrastructure (loopback, link-local, this node's own address or a cloud metadata endpoint); a self-hosted node fetches it"
    )]
    HostedInfrastructure { url: String },
}

pub type WebFetchResult<T> = std::result::Result<T, WebFetchError>;

/// Minimum trimmed Markdown byte count that counts as a real extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinExtractedContentBytes(usize);

impl MinExtractedContentBytes {
    /// # Errors
    /// Returns [`WebFetchError::InvalidMinimumContentBytes`] when `value` is zero.
    pub fn new(value: usize) -> WebFetchResult<Self> {
        if value == 0 {
            return Err(WebFetchError::InvalidMinimumContentBytes);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl Default for MinExtractedContentBytes {
    fn default() -> Self {
        Self(DEFAULT_MIN_EXTRACTED_CONTENT_BYTES)
    }
}

/// Explicit number of page fetches one crawl may attempt. There is deliberately
/// no default: a hidden crawl multiplier is the design bug this type removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(try_from = "usize")]
pub struct CrawlPageBudget(usize);

impl CrawlPageBudget {
    /// # Errors
    /// Returns [`WebFetchError::InvalidPageBudget`] when `value` is zero.
    pub fn new(value: usize) -> WebFetchResult<Self> {
        if value == 0 {
            return Err(WebFetchError::InvalidPageBudget);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl TryFrom<usize> for CrawlPageBudget {
    type Error = WebFetchError;

    fn try_from(value: usize) -> std::result::Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Same-site containment is the default; leaving the seed's origin is an
/// affirmative caller choice.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CrawlScope {
    #[default]
    SameSite,
    CrossSite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CrawlRequest {
    pub seed_url: String,
    pub fetched_at: u64,
    pub page_budget: CrawlPageBudget,
    #[serde(default)]
    pub scope: CrawlScope,
}

impl CrawlRequest {
    /// Constructs the canonical same-site crawl request.
    #[must_use]
    pub fn same_site(
        seed_url: impl Into<String>,
        fetched_at: u64,
        page_budget: CrawlPageBudget,
    ) -> Self {
        Self {
            seed_url: seed_url.into(),
            fetched_at,
            page_budget,
            scope: CrawlScope::SameSite,
        }
    }

    /// Cross-site walking is an affirmative caller choice.
    #[must_use]
    pub const fn with_scope(mut self, scope: CrawlScope) -> Self {
        self.scope = scope;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CrawlCompletion {
    Complete,
    BudgetExhausted {
        /// The normalized breadth-first frontier not visited because the explicit
        /// page budget was consumed. The list is never silently truncated.
        unvisited_urls: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CrawlPageFailure {
    pub url: String,
    /// `AllRenderersFailed` renders as `"all web fetch renderers failed: "` plus
    /// each attempt as `{renderer}: {detail}` joined by `"; "` in ladder order.
    /// A cross-site redirect is the exact literal `cross_site_redirect`, and a
    /// page whose links would overflow the walk's frontier ceiling is the exact
    /// literal `frontier_link_budget_exceeded`; other reasons are diagnostic and
    /// are matched by substring.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CrawlResult {
    /// Successful fetches in breadth-first attempt order, beginning with the seed page.
    pub pages: Vec<FetchResult>,
    /// Non-seed failures in breadth-first attempt order.
    pub failed: Vec<CrawlPageFailure>,
    pub completion: CrawlCompletion,
}

// ---------------------------------------------------------------------------
// URL and hash helpers (private)
// ---------------------------------------------------------------------------

fn content_hash(markdown: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(WEB_FETCH_CONTENT_HASH_DOMAIN);
    hasher.update(markdown.as_bytes());
    hasher.finalize().to_hex().to_string()
}

// ---------------------------------------------------------------------------
// Rung adapters (their `Renderer` impls, guarded paths included, are in
// `rungs`)
// ---------------------------------------------------------------------------

/// Rung 1: one blocking GET plus native readability extraction.
///
/// The caller owns the client, and therefore owns timeout, redirect, proxy, and
/// header policy. This adapter adds none of its own and holds no credential.
#[derive(Clone)]
pub struct NativeReadabilityRenderer {
    client: reqwest::blocking::Client,
    max_response_bytes: NonZeroUsize,
}

impl NativeReadabilityRenderer {
    /// On a managed (hosted) node, a host that builds its own ladder builds
    /// `client` with [`build_web_fetch_client`]`(Some(guard))`, so every
    /// redirect hop it follows is checked too (FIX 7123). A client built
    /// otherwise is used as handed in: this rung does not rebuild it.
    #[must_use]
    pub fn new(client: reqwest::blocking::Client) -> Self {
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
    /// rung's client with [`build_web_fetch_client`] (see
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
    /// unconfigured; [`WebFetchError::HostedInfrastructure`] when a managed
    /// node's guard refused the page, a hop or an address a rung reached; and
    /// [`WebFetchError::AllRenderersFailed`] carrying the ordered ladder trace
    /// when no rung produced content.
    pub fn fetch(&self, url: &str, fetched_at: u64) -> WebFetchResult<FetchResult> {
        let parsed = parse_web_url(url)?;
        let (result, _links, _final_url) = self.fetch_page(&parsed, fetched_at, false)?;
        Ok(result)
    }

    /// Walks a site breadth-first under an explicit page budget.
    ///
    /// The budget counts *attempted* page fetches, not successes: a seed failure
    /// is a typed `Err`, and every non-seed failure consumes its unit, lands in
    /// [`CrawlResult::failed`], and the walk continues.
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
            match self.fetch_page(&current, request.fetched_at, true) {
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

#[cfg(test)]
mod tests;
