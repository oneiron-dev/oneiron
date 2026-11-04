//! Web acquisition values and the host-supplied acquisition port.
use serde::{Deserialize, Serialize};

mod door;
mod refusal;
mod result;
mod url;
pub use door::{WebCrawlRequest, WebFetchRequest};
pub use refusal::{
    HOSTED_INFRASTRUCTURE_REASON, HOSTED_PRIVATE_NETWORK_REASON, HostedEgressRefusal,
};
use result::FetchResultWire;
pub(crate) use url::*;

/// Domain prefix for the OF-444 content identity.
pub const WEB_FETCH_CONTENT_HASH_DOMAIN: &[u8] = b"oneiron.web_fetch.content.v1\0";

/// Engine default for deciding that a renderer extracted real page content.
/// This is a test-injectable mechanism dial, not a safety or quality verdict.
pub const DEFAULT_MIN_EXTRACTED_CONTENT_BYTES: usize = 256;

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
    pub(crate) markdown: String,
    pub(crate) title: String,
    pub(crate) canonical_url: String,
    /// Caller-supplied Unix timestamp in seconds, copied verbatim. This module
    /// never reads a host clock.
    pub(crate) fetched_at: u64,
    /// Lowercase 64-character BLAKE3 hex over
    /// [`WEB_FETCH_CONTENT_HASH_DOMAIN`] followed by the exact `markdown` bytes.
    pub(crate) content_hash: String,
    pub(crate) renderer: RendererKind,
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
    /// A managed node's egress guard refused a private-network address no
    /// operator origin admits (FIX 7657). The ladder ends on it typed.
    HostedPrivateNetwork,
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
    pub(crate) fn render_reason(&self) -> String {
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

    /// A managed (hosted) node's fetcher refused a destination that reaches
    /// a private network (RFC1918, CGNAT, ULA) at no origin the hosting
    /// operator allows (FIX 7657), as [`Self::HostedInfrastructure`] is
    /// refused. The message names [`HOSTED_PRIVATE_NETWORK_REASON`]; `url` is
    /// the requested page, credential-redacted.
    #[error(
        "web fetch refused (hosted_private_network): on a hosted node, {url} resolves or redirects to a private-network address outside the hosting operator's allowed origins, and hosted nodes refuse private-network addresses (RFC1918, CGNAT 100.64.0.0/10, IPv6 ULA fc00::/7); a self-hosted node fetches it, or the hosting operator can allow its named private origin"
    )]
    HostedPrivateNetwork { url: String },
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
    /// A cross-site redirect is the exact literal `cross_site_redirect`; other
    /// reasons are diagnostic and are matched by substring.
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

pub(crate) fn content_hash(markdown: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(WEB_FETCH_CONTENT_HASH_DOMAIN);
    hasher.update(markdown.as_bytes());
    hasher.finalize().to_hex().to_string()
}

/// Acquisition used by actor-bound import. Each method is one ladder operation.
pub trait WebAcquisition {
    fn fetch(&self, url: &str, fetched_at: u64) -> WebFetchResult<FetchResult>;
    fn crawl(&self, request: CrawlRequest) -> WebFetchResult<CrawlResult>;
}
