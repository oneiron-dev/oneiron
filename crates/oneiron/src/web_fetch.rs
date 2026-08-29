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

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

use dom_smoothie::{Config, Readability, TextMode};
use reqwest::Url;
use serde::{Deserialize, Serialize};

/// Domain prefix for the OF-444 content identity.
pub const WEB_FETCH_CONTENT_HASH_DOMAIN: &[u8] = b"oneiron.web_fetch.content.v1\0";

/// Engine default for deciding that a renderer extracted real page content.
/// This is a test-injectable mechanism dial, not a safety or quality verdict.
pub const DEFAULT_MIN_EXTRACTED_CONTENT_BYTES: usize = 256;

/// The exact reason literal recorded when a same-site walk lands on a foreign
/// host through a post-fetch redirect.
const CROSS_SITE_REDIRECT_REASON: &str = "cross_site_redirect";

/// Fixed prefix of the rendered [`WebFetchError::AllRenderersFailed`] reason
/// recorded against a non-seed crawl page.
const ALL_RENDERERS_FAILED_REASON_PREFIX: &str = "all web fetch renderers failed: ";

/// Which rung of the fixed ladder produced a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchResult {
    pub markdown: String,
    pub title: String,
    pub canonical_url: String,
    /// Caller-supplied Unix timestamp in seconds, copied verbatim. This module
    /// never reads a host clock.
    pub fetched_at: u64,
    /// Lowercase 64-character BLAKE3 hex over
    /// [`WEB_FETCH_CONTENT_HASH_DOMAIN`] followed by the exact `markdown` bytes.
    pub content_hash: String,
    pub renderer: RendererKind,
}

/// Internal renderer output. Carries the crawl-relevant fields that the closed
/// six-field public result deliberately does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedPage {
    pub markdown: String,
    pub title: String,
    /// Renderer-resolved metadata identity; emitted only as `FetchResult::canonical_url`.
    pub canonical_url: String,
    /// Navigation/transport-final URL used for containment and seen-set identity.
    pub final_url: String,
    pub discovered_links: Vec<String>,
}

/// Machine-stable classification of a renderer failure. Callers branch on this
/// and on [`RendererKind`]; the accompanying message is a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendererErrorKind {
    Transport,
    Extraction,
    InvalidResponse,
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
}

/// What a host browser returns for one navigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadlessDocument {
    pub html: String,
    /// Browser-final URL after navigation and redirects.
    pub final_url: String,
}

/// Host-injected browser boundary. The engine owns no browser process or crate.
pub trait HeadlessRenderer: Send + Sync {
    fn render_html(&self, url: &str) -> RendererResult<HeadlessDocument>;
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
    #[error("invalid web fetch URL: {url}")]
    InvalidUrl { url: String },

    #[error("web fetch supports only http and https, not {scheme}")]
    UnsupportedScheme { scheme: String },

    #[error("renderer slot expected {expected:?}, got {actual:?}")]
    InvalidRendererSlot {
        expected: RendererKind,
        actual: RendererKind,
    },

    #[error("minimum extracted content bytes must be greater than zero")]
    InvalidMinimumContentBytes,

    #[error("crawl page budget must be greater than zero")]
    InvalidPageBudget,

    #[error("all web fetch renderers failed for {url}")]
    AllRenderersFailed {
        url: String,
        attempts: Vec<RendererAttemptFailure>,
    },
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Same-site containment is the default; leaving the seed's host is an
/// affirmative caller choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CrawlScope {
    #[default]
    SameSite,
    CrossSite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CrawlCompletion {
    Complete,
    BudgetExhausted {
        /// The normalized breadth-first frontier not visited because the explicit
        /// page budget was consumed. The list is never silently truncated.
        unvisited_urls: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawlPageFailure {
    pub url: String,
    /// `AllRenderersFailed` renders as `"all web fetch renderers failed: "` plus
    /// each attempt as `{renderer}: {detail}` joined by `"; "` in ladder order.
    /// A cross-site redirect is the exact literal `cross_site_redirect`; other
    /// reasons are diagnostic and are matched by substring.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// The single normalization step: drop the fragment and keep whatever the URL
/// parser already canonicalized (host lowercasing, default-port elision,
/// dot-segment resolution). No trailing-slash rewriting, query reordering, or
/// IDN transformation is added on top.
fn normalize_url(url: &Url) -> Url {
    let mut normalized = url.clone();
    normalized.set_fragment(None);
    normalized
}

/// Absolute HTTP(S) with a non-empty host is the only transport this module speaks.
fn is_web_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https") && url.host_str().is_some_and(|host| !host.is_empty())
}

/// Parses a caller-supplied URL into its normalized form.
fn parse_web_url(raw: &str) -> WebFetchResult<Url> {
    let parsed = Url::parse(raw).map_err(|_| WebFetchError::InvalidUrl {
        url: raw.to_string(),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(WebFetchError::UnsupportedScheme {
            scheme: parsed.scheme().to_string(),
        });
    }
    if !is_web_url(&parsed) {
        return Err(WebFetchError::InvalidUrl {
            url: raw.to_string(),
        });
    }
    Ok(normalize_url(&parsed))
}

/// Validates a renderer-reported navigation/transport-final URL.
fn renderer_final_url(raw: &str) -> RendererResult<Url> {
    Url::parse(raw)
        .ok()
        .filter(is_web_url)
        .map(|url| normalize_url(&url))
        .ok_or_else(|| {
            RendererError::invalid_response(format!(
                "renderer returned a final URL that is not absolute http(s): {raw}"
            ))
        })
}

fn content_hash(markdown: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(WEB_FETCH_CONTENT_HASH_DOMAIN);
    hasher.update(markdown.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Normalizes, filters to HTTP(S), sorts bytewise, and deduplicates a raw link list.
fn normalize_link_list<I, S>(links: I, base: &Url) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut normalized = BTreeSet::new();
    for raw in links {
        let Ok(joined) = base.join(raw.as_ref().trim()) else {
            continue;
        };
        let candidate = normalize_url(&joined);
        if is_web_url(&candidate) {
            normalized.insert(candidate.to_string());
        }
    }
    normalized.into_iter().collect()
}

fn resolve_canonical_url(final_url: &Url, candidate: Option<&str>) -> String {
    let resolved = candidate
        .and_then(|raw| final_url.join(raw.trim()).ok())
        .map(|joined| normalize_url(&joined))
        .filter(is_web_url);
    match resolved {
        Some(url) => url.to_string(),
        None => final_url.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Native readability extraction (private, shared by the readability and
// headless rungs)
// ---------------------------------------------------------------------------

/// Collects `a[href]` targets from the document *before* `parse()` mutates it.
/// Relative hrefs resolve against the document `<base href>` when one is
/// present and otherwise against the response-final URL.
fn collect_document_links(readability: &Readability, final_url: &Url) -> Vec<String> {
    let base = readability
        .doc
        .select("base[href]")
        .nodes()
        .first()
        .and_then(|node| node.attr("href"))
        .and_then(|href| final_url.join(href.trim()).ok())
        .unwrap_or_else(|| final_url.clone());

    let anchors = readability.doc.select("a[href]");
    let mut hrefs: Vec<String> = Vec::new();
    for node in anchors.nodes() {
        if let Some(href) = node.attr("href") {
            hrefs.push(href.to_string());
        }
    }
    normalize_link_list(hrefs, &base)
}

/// The one extraction path. Both the native readability rung and the headless
/// rung run this, so headless is a rendering rung rather than a second
/// extraction algorithm.
fn extract_readable_page(html: &str, final_url: &Url) -> RendererResult<RenderedPage> {
    let normalized_final = normalize_url(final_url);
    let final_url_text = normalized_final.to_string();
    let config = Config {
        text_mode: TextMode::Markdown,
        ..Config::default()
    };
    let mut readability = Readability::new(html, Some(final_url_text.as_str()), Some(config))
        .map_err(|error| {
            RendererError::extraction(format!("readability construction failed: {error}"))
        })?;

    let discovered_links = collect_document_links(&readability, &normalized_final);

    let article = readability.parse().map_err(|error| {
        RendererError::extraction(format!("readability extraction failed: {error}"))
    })?;

    let canonical_url = resolve_canonical_url(&normalized_final, article.url.as_deref());
    Ok(RenderedPage {
        markdown: article.text_content.to_string(),
        title: article.title.trim().to_string(),
        canonical_url,
        final_url: final_url_text,
        discovered_links,
    })
}

// ---------------------------------------------------------------------------
// Rung adapters
// ---------------------------------------------------------------------------

/// Rung 1: one blocking GET plus native readability extraction.
///
/// The caller owns the client, and therefore owns timeout, redirect, proxy, and
/// header policy. This adapter adds none of its own and holds no credential.
#[derive(Clone)]
pub struct NativeReadabilityRenderer {
    client: reqwest::blocking::Client,
}

impl NativeReadabilityRenderer {
    #[must_use]
    pub fn new(client: reqwest::blocking::Client) -> Self {
        Self { client }
    }
}

impl Renderer for NativeReadabilityRenderer {
    fn kind(&self) -> RendererKind {
        RendererKind::Readability
    }

    fn render(&self, url: &str) -> RendererResult<RenderedPage> {
        let response = self
            .client
            .get(url)
            .send()
            .map_err(|error| RendererError::transport(format!("web fetch GET failed: {error}")))?
            .error_for_status()
            .map_err(|error| {
                RendererError::transport(format!("web fetch GET returned an error status: {error}"))
            })?;
        let final_url = renderer_final_url(response.url().as_str())?;
        let html = response.text().map_err(|error| {
            RendererError::transport(format!("web fetch response body was unreadable: {error}"))
        })?;
        extract_readable_page(&html, &final_url)
    }
}

/// Rung 2: a host-provided browser navigation fed through the same extraction.
pub struct NativeHeadlessRenderer {
    headless: Arc<dyn HeadlessRenderer>,
}

impl NativeHeadlessRenderer {
    #[must_use]
    pub fn new(headless: Arc<dyn HeadlessRenderer>) -> Self {
        Self { headless }
    }
}

impl Renderer for NativeHeadlessRenderer {
    fn kind(&self) -> RendererKind {
        RendererKind::Headless
    }

    fn render(&self, url: &str) -> RendererResult<RenderedPage> {
        let document = self.headless.render_html(url)?;
        let final_url = renderer_final_url(&document.final_url)?;
        extract_readable_page(&document.html, &final_url)
    }
}

#[derive(Debug, Serialize)]
struct FirecrawlScrapeRequest {
    url: String,
    formats: [&'static str; 2],
    #[serde(rename = "onlyMainContent")]
    only_main_content: bool,
}

#[derive(Debug, Deserialize)]
struct FirecrawlScrapeEnvelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    data: Option<FirecrawlScrapeData>,
}

#[derive(Debug, Deserialize)]
struct FirecrawlScrapeData {
    #[serde(default)]
    markdown: Option<String>,
    #[serde(default)]
    links: Vec<String>,
    #[serde(default)]
    metadata: Option<FirecrawlScrapeMetadata>,
}

#[derive(Debug, Default, Deserialize)]
struct FirecrawlScrapeMetadata {
    #[serde(default)]
    title: Option<String>,
    #[serde(default, rename = "sourceURL")]
    source_url: Option<String>,
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
}

impl FirecrawlRenderer {
    /// # Errors
    /// Returns [`WebFetchError::InvalidUrl`] when `scrape_endpoint` is not an
    /// absolute HTTP(S) URL. The endpoint is a URL, so no renderer or transport
    /// error variant fits.
    pub fn new(client: reqwest::blocking::Client, scrape_endpoint: &str) -> WebFetchResult<Self> {
        let endpoint = Url::parse(scrape_endpoint)
            .ok()
            .filter(is_web_url)
            .ok_or_else(|| WebFetchError::InvalidUrl {
                url: scrape_endpoint.to_string(),
            })?;
        Ok(Self {
            client,
            scrape_endpoint: endpoint,
        })
    }
}

impl Renderer for FirecrawlRenderer {
    fn kind(&self) -> RendererKind {
        RendererKind::Firecrawl
    }

    fn render(&self, url: &str) -> RendererResult<RenderedPage> {
        let payload = FirecrawlScrapeRequest {
            url: url.to_string(),
            formats: ["markdown", "links"],
            only_main_content: true,
        };
        let response = self
            .client
            .post(self.scrape_endpoint.clone())
            .json(&payload)
            .send()
            .map_err(|error| {
                RendererError::transport(format!("firecrawl scrape request failed: {error}"))
            })?
            .error_for_status()
            .map_err(|error| {
                RendererError::transport(format!(
                    "firecrawl scrape returned an error status: {error}"
                ))
            })?;
        let envelope: FirecrawlScrapeEnvelope = response.json().map_err(|error| {
            RendererError::invalid_response(format!(
                "firecrawl scrape envelope was undecodable: {error}"
            ))
        })?;
        Self::map_envelope(envelope)
    }
}

impl FirecrawlRenderer {
    fn map_envelope(envelope: FirecrawlScrapeEnvelope) -> RendererResult<RenderedPage> {
        if !envelope.success {
            return Err(RendererError::invalid_response(
                "firecrawl scrape envelope did not report success",
            ));
        }
        let data = envelope.data.ok_or_else(|| {
            RendererError::invalid_response("firecrawl scrape envelope carried no data object")
        })?;
        let markdown = data.markdown.ok_or_else(|| {
            RendererError::invalid_response("firecrawl scrape envelope carried no markdown")
        })?;
        let metadata = data.metadata.unwrap_or_default();
        let source_url = metadata.source_url.ok_or_else(|| {
            RendererError::invalid_response(
                "firecrawl scrape envelope carried no data.metadata.sourceURL",
            )
        })?;
        let final_url = Url::parse(&source_url)
            .ok()
            .filter(is_web_url)
            .map(|url| normalize_url(&url))
            .ok_or_else(|| {
                RendererError::invalid_response(format!(
                    "firecrawl sourceURL is not absolute http(s): {source_url}"
                ))
            })?;
        let final_url_text = final_url.to_string();
        let discovered_links = normalize_link_list(&data.links, &final_url);
        Ok(RenderedPage {
            markdown,
            title: metadata.title.unwrap_or_default().trim().to_string(),
            // The pinned envelope carries no separate canonical field, so the
            // source URL supplies both. Only `final_url` ever participates in
            // containment or the seen set.
            canonical_url: final_url_text.clone(),
            final_url: final_url_text,
            discovered_links,
        })
    }
}

// ---------------------------------------------------------------------------
// The ladder driver
// ---------------------------------------------------------------------------

/// Drives the fixed ladder for one page ([`WebFetcher::fetch`]) or for a
/// budgeted breadth-first walk ([`WebFetcher::crawl`]).
pub struct WebFetcher {
    readability: Arc<dyn Renderer>,
    headless: Option<Arc<dyn Renderer>>,
    firecrawl: Option<Arc<dyn Renderer>>,
    minimum_content: MinExtractedContentBytes,
}

fn require_renderer_slot(expected: RendererKind, renderer: &dyn Renderer) -> WebFetchResult<()> {
    let actual = renderer.kind();
    if actual == expected {
        Ok(())
    } else {
        Err(WebFetchError::InvalidRendererSlot { expected, actual })
    }
}

impl WebFetcher {
    /// The readability rung is always present. Optional fallbacks stay visible
    /// as `Unavailable` attempt records when escalation reaches them.
    ///
    /// # Errors
    /// Returns [`WebFetchError::InvalidRendererSlot`] when the renderer does not
    /// report [`RendererKind::Readability`].
    pub fn new(readability: Arc<dyn Renderer>) -> WebFetchResult<Self> {
        require_renderer_slot(RendererKind::Readability, readability.as_ref())?;
        Ok(Self {
            readability,
            headless: None,
            firecrawl: None,
            minimum_content: MinExtractedContentBytes::default(),
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
    /// Returns [`WebFetchError::InvalidUrl`] or [`WebFetchError::UnsupportedScheme`]
    /// for a URL this module cannot fetch, and [`WebFetchError::AllRenderersFailed`]
    /// carrying the ordered ladder trace when no rung produced content.
    pub fn fetch(&self, url: &str, fetched_at: u64) -> WebFetchResult<FetchResult> {
        let parsed = parse_web_url(url)?;
        let (result, _links, _final_url) = self.fetch_page(&parsed, fetched_at)?;
        Ok(result)
    }

    /// Runs one rung. `Err` is the attempt record, not a terminal failure.
    fn try_rung(
        &self,
        kind: RendererKind,
        renderer: &dyn Renderer,
        url: &str,
        fetched_at: u64,
    ) -> std::result::Result<(FetchResult, Vec<String>, Url), RendererAttemptFailure> {
        let page = renderer
            .render(url)
            .map_err(|error| RendererAttemptFailure::Error {
                renderer: kind,
                error,
            })?;

        // `str::len` is a byte count: the threshold compares trimmed Markdown
        // bytes, never characters, and never the untrimmed bytes that are
        // returned and hashed.
        let extracted_bytes = page.markdown.trim().len();
        let minimum_bytes = self.minimum_content.get();
        if extracted_bytes < minimum_bytes {
            return Err(RendererAttemptFailure::EmptyExtraction {
                renderer: kind,
                extracted_bytes,
                minimum_bytes,
            });
        }

        let final_url =
            renderer_final_url(&page.final_url).map_err(|error| RendererAttemptFailure::Error {
                renderer: kind,
                error,
            })?;

        let result = FetchResult {
            content_hash: content_hash(&page.markdown),
            markdown: page.markdown,
            title: page.title,
            canonical_url: page.canonical_url,
            fetched_at,
            renderer: kind,
        };
        Ok((result, page.discovered_links, final_url))
    }

    /// The fixed ladder. Sequential, never speculative, never parallel; a rung
    /// advances only on a typed renderer error, an absent rung, or a
    /// below-threshold extraction. Once a rung succeeds, lower rungs never run.
    fn fetch_page(
        &self,
        url: &Url,
        fetched_at: u64,
    ) -> WebFetchResult<(FetchResult, Vec<String>, Url)> {
        let requested = url.to_string();
        let mut attempts = Vec::new();
        for (kind, slot) in [
            (RendererKind::Readability, Some(&self.readability)),
            (RendererKind::Headless, self.headless.as_ref()),
            (RendererKind::Firecrawl, self.firecrawl.as_ref()),
        ] {
            let Some(renderer) = slot else {
                attempts.push(RendererAttemptFailure::Unavailable { renderer: kind });
                continue;
            };
            match self.try_rung(kind, renderer.as_ref(), &requested, fetched_at) {
                Ok(success) => return Ok(success),
                Err(failure) => attempts.push(failure),
            }
        }
        Err(WebFetchError::AllRenderersFailed {
            url: requested,
            attempts,
        })
    }

    /// Walks a site breadth-first under an explicit page budget.
    ///
    /// The budget counts *attempted* page fetches, not successes: a seed failure
    /// is a typed `Err`, and every non-seed failure consumes its unit, lands in
    /// [`CrawlResult::failed`], and the walk continues.
    ///
    /// # Errors
    /// Returns [`WebFetchError::InvalidUrl`] or [`WebFetchError::UnsupportedScheme`]
    /// for an unusable seed URL, and propagates the seed page's typed ladder
    /// failure because there is no successful final URL from which to pin the walk.
    pub fn crawl(&self, request: CrawlRequest) -> WebFetchResult<CrawlResult> {
        let seed = parse_web_url(&request.seed_url)?;
        let mut walk = CrawlWalk::new(seed, request.page_budget.get());

        while let Some(current) = walk.frontier.pop_front() {
            let requested = current.to_string();
            // Dequeue-time seen-set skip: an earlier page already navigated here.
            // Not an attempt, so it charges no budget.
            if walk.visited.contains(&requested) {
                continue;
            }
            if walk.remaining_budget == 0 {
                walk.frontier.push_front(current);
                return Ok(walk.into_budget_exhausted());
            }
            walk.remaining_budget -= 1;
            walk.visited.insert(requested.clone());

            let is_seed = walk.pinned_host.is_none();
            match self.fetch_page(&current, request.fetched_at) {
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

/// Mutable state of one breadth-first walk.
struct CrawlWalk {
    frontier: VecDeque<Url>,
    /// Frontier identity at enqueue time. Kills duplicate (diamond) enqueues.
    enqueued: BTreeSet<String>,
    /// Dequeue-time skip identity: requested URLs already attempted plus
    /// response-final URLs already reached. A requested URL enters this set
    /// before its own fetch, so membership is not evidence that a page for that
    /// identity was admitted.
    visited: BTreeSet<String>,
    /// Navigation-final identity of every page already admitted to `pages`.
    /// This is the completion record, and the only basis for suppressing a
    /// later alias that redirects onto an identity already acquired.
    completed_finals: BTreeSet<String>,
    pages: Vec<FetchResult>,
    failed: Vec<CrawlPageFailure>,
    /// Host of the seed page's response-final URL, pinned after the seed succeeds.
    pinned_host: Option<String>,
    remaining_budget: usize,
}

impl CrawlWalk {
    fn new(seed: Url, page_budget: usize) -> Self {
        let mut enqueued = BTreeSet::new();
        enqueued.insert(seed.to_string());
        let mut frontier = VecDeque::new();
        frontier.push_back(seed);
        Self {
            frontier,
            enqueued,
            visited: BTreeSet::new(),
            completed_finals: BTreeSet::new(),
            pages: Vec::new(),
            failed: Vec::new(),
            pinned_host: None,
            remaining_budget: page_budget,
        }
    }

    fn absorb_success(
        &mut self,
        requested: String,
        page: FetchResult,
        links: &[String],
        final_url: &Url,
        scope: CrawlScope,
    ) {
        let final_host = final_url.host_str().unwrap_or_default().to_string();
        let Some(pinned_host) = self.pinned_host.clone() else {
            // Seed success pins containment to the seed page's own final host.
            // A cross-host metadata canonical cannot move it.
            self.pinned_host = Some(final_host.clone());
            self.admit_page(page, links, final_url, scope, &final_host);
            return;
        };

        if scope == CrawlScope::SameSite && final_host != pinned_host {
            // A same-host link that redirected onto a foreign host. The attempt
            // is already counted; the page and every link it carries are not
            // admitted.
            self.failed.push(CrawlPageFailure {
                url: requested,
                reason: CROSS_SITE_REDIRECT_REASON.to_string(),
            });
            return;
        }

        if self.completed_finals.contains(final_url.as_str()) {
            // A later alias that navigated onto an identity this walk has
            // already acquired. The attempt and its budget unit are spent, but
            // the second copy of the same page is not a page, and the links it
            // carries are the already-admitted page's links, so re-enqueueing
            // them would widen the frontier on a duplicate. Requested identity
            // is deliberately not consulted: an ordinary page whose final URL
            // is its own requested URL is still its own first completion.
            return;
        }

        self.admit_page(page, links, final_url, scope, &pinned_host);
    }

    /// The single admission point: one page, its completed navigation-final
    /// identity, and its links enter together, so no admitted page can leave
    /// its final identity unrecorded.
    fn admit_page(
        &mut self,
        page: FetchResult,
        links: &[String],
        final_url: &Url,
        scope: CrawlScope,
        pinned_host: &str,
    ) {
        self.pages.push(page);
        self.completed_finals.insert(final_url.to_string());
        self.enqueue_links(links, scope, pinned_host);
    }

    fn enqueue_links(&mut self, links: &[String], scope: CrawlScope, pinned_host: &str) {
        for raw in links {
            let Ok(parsed) = Url::parse(raw) else {
                continue;
            };
            let normalized = normalize_url(&parsed);
            if !is_web_url(&normalized) {
                continue;
            }
            // Exact host equality. Sibling subdomains are a different site.
            if scope == CrawlScope::SameSite && normalized.host_str() != Some(pinned_host) {
                continue;
            }
            if self.enqueued.insert(normalized.to_string()) {
                self.frontier.push_back(normalized);
            }
        }
    }

    fn into_budget_exhausted(self) -> CrawlResult {
        let unvisited_urls = self
            .frontier
            .iter()
            .map(Url::to_string)
            .filter(|url| !self.visited.contains(url))
            .collect();
        CrawlResult {
            pages: self.pages,
            failed: self.failed,
            completion: CrawlCompletion::BudgetExhausted { unvisited_urls },
        }
    }
}

/// Renders a non-seed page failure without flattening the ladder trace into the
/// last transport error.
fn crawl_failure_reason(error: &WebFetchError) -> String {
    match error {
        WebFetchError::AllRenderersFailed { attempts, .. } => {
            let rendered: Vec<String> = attempts
                .iter()
                .map(RendererAttemptFailure::render_reason)
                .collect();
            format!(
                "{ALL_RENDERERS_FAILED_REASON_PREFIX}{}",
                rendered.join("; ")
            )
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests;
