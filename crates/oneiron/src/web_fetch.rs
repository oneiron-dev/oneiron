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
use std::io::Read;
use std::num::NonZeroUsize;
use std::sync::Arc;

use dom_smoothie::{Config, Readability, TextMode};
use reqwest::Url;
use serde::{Deserialize, Serialize};

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
///
/// The closure is enforced in both directions: serialization emits exactly the
/// six keys, and `deny_unknown_fields` makes decoding reject a seventh instead
/// of silently dropping it. A value that round-trips through this type is
/// therefore evidence about the whole payload, not just about the six fields
/// that happened to be recognized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Absolute HTTP(S), a non-empty host, and no embedded credentials: the only
/// transport this module speaks.
///
/// Userinfo is refused by the same predicate that decides "is this fetchable",
/// rather than stripped somewhere downstream. One predicate therefore keeps
/// `user:pass@host` out of every request this module sends, every provider
/// payload it builds, every URL it publishes, and every frontier it walks.
fn is_web_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some_and(|host| !host.is_empty())
        && !has_userinfo(url)
}

/// Whether a parsed URL carries a username or a password.
fn has_userinfo(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

/// Replaces the userinfo of a URL-shaped string with [`REDACTED_USERINFO`].
///
/// Every diagnostic this module emits is public: errors cross the crate
/// boundary, and a crawl failure reason is a stored string. Redaction is
/// therefore parse-first rather than textual, because a textual scan does not
/// recognize the spellings WHATWG parsing still accepts as credentialed:
/// `http:a:b@host` carries no `//` at all, `http:/a:b@host` carries one slash,
/// `http:\\a:b@host` carries backslashes, and ASCII tab or newline inside the
/// credential is stripped before the authority is read. Each of those parses to
/// an HTTP URL with a username and a password, so each is redacted on the
/// parsed [`Url`] and re-serialized in its canonical spelling — one sanitizer,
/// no spelling-dependent hole.
///
/// A credential-free URL is reported exactly as supplied. A string the parser
/// rejects has no [`Url`] to ask, so it falls back to a fail-closed textual
/// scan rather than being echoed raw.
fn redact_url_credentials(raw: &str) -> String {
    let Ok(parsed) = Url::parse(raw) else {
        return redact_userinfo_text(raw);
    };
    if !has_userinfo(&parsed) {
        return raw.to_string();
    }
    let mut sanitized = parsed;
    // Both setters refuse only a host-less URL, which cannot carry userinfo in
    // the first place; the textual scan stays the fail-closed answer anyway.
    if sanitized.set_password(None).is_err() || sanitized.set_username(REDACTED_USERINFO).is_err() {
        return redact_userinfo_text(raw);
    }
    sanitized.to_string()
}

/// The fail-closed textual half of [`redact_url_credentials`], reached only for
/// input the URL parser rejected outright.
///
/// It skips the same run of `/` and `\` between scheme and authority that the
/// parser skips, so an unparseable *and* credential-looking string — an empty
/// host behind a real credential, say — still loses its userinfo.
fn redact_userinfo_text(raw: &str) -> String {
    let Some(scheme_end) = raw.find(':') else {
        return raw.to_string();
    };
    let scheme = &raw[..scheme_end];
    let is_scheme_shaped = scheme.starts_with(|first: char| first.is_ascii_alphabetic())
        && scheme.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        });
    if !is_scheme_shaped {
        return raw.to_string();
    }
    let after_scheme = &raw[scheme_end + 1..];
    let authority_start = after_scheme
        .find(|character: char| character != '/' && character != '\\')
        .map_or(raw.len(), |offset| scheme_end + 1 + offset);
    let authority_end = raw[authority_start..]
        .find(['/', '\\', '?', '#'])
        .map_or(raw.len(), |offset| authority_start + offset);
    // The last `@` wins: a password may itself contain one.
    match raw[authority_start..authority_end].rfind('@') {
        Some(offset) => format!(
            "{}{REDACTED_USERINFO}{}",
            &raw[..authority_start],
            &raw[authority_start + offset..]
        ),
        None => raw.to_string(),
    }
}

/// The one parse-normalize-validate step behind every URL this module accepts,
/// whoever supplied it: a caller, a renderer, a provider envelope, or a link.
fn validated_web_url(raw: &str) -> Option<Url> {
    Url::parse(raw)
        .ok()
        .filter(is_web_url)
        .map(|url| normalize_url(&url))
}

/// Parses a caller-supplied URL into its normalized form.
fn parse_web_url(raw: &str) -> WebFetchResult<Url> {
    let parsed = Url::parse(raw).map_err(|_| WebFetchError::InvalidUrl {
        url: redact_url_credentials(raw),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(WebFetchError::UnsupportedScheme {
            scheme: parsed.scheme().to_string(),
        });
    }
    // Named before the general check so the caller learns the actual reason,
    // and reported redacted so learning it costs no credential.
    if has_userinfo(&parsed) {
        return Err(WebFetchError::CredentialsInUrl {
            url: redact_url_credentials(raw),
        });
    }
    if !is_web_url(&parsed) {
        return Err(WebFetchError::InvalidUrl {
            url: redact_url_credentials(raw),
        });
    }
    Ok(normalize_url(&parsed))
}

/// Validates a renderer-reported navigation/transport-final URL.
fn renderer_final_url(raw: &str) -> RendererResult<Url> {
    validated_web_url(raw).ok_or_else(|| {
        RendererError::invalid_response(format!(
            "renderer returned a final URL that is not credential-free absolute http(s): {}",
            redact_url_credentials(raw)
        ))
    })
}

/// Validates a renderer-reported canonical identity.
///
/// Every rung's canonical URL passes through here, including one produced by a
/// host-supplied custom [`Renderer`], so nothing unvalidated and nothing
/// carrying credentials can reach the closed public `FetchResult`.
fn renderer_canonical_url(raw: &str) -> RendererResult<Url> {
    validated_web_url(raw).ok_or_else(|| {
        RendererError::invalid_response(format!(
            "renderer returned a canonical URL that is not credential-free absolute http(s): {}",
            redact_url_credentials(raw)
        ))
    })
}

/// The one pre-transport check for a URL this module is about to put on the
/// wire or into a provider request body. Nothing reaches a network boundary
/// without passing it.
fn renderer_request_url(raw: &str) -> RendererResult<String> {
    let Some(url) = validated_web_url(raw) else {
        return Err(RendererError::transport(format!(
            "refusing to request a URL that is not credential-free absolute http(s): {}",
            redact_url_credentials(raw)
        )));
    };
    Ok(url.to_string())
}

/// Reads at most `limit` bytes of a response body, and fails closed when the
/// peer sends more.
///
/// The ceiling is applied while the bytes are still streaming, so an oversized
/// or endless body is a typed failure rather than memory growth. Exactly one
/// byte past the ceiling is read, purely to tell "at the ceiling" apart from
/// "over it".
fn read_capped_body(source: impl Read, limit: NonZeroUsize) -> RendererResult<Vec<u8>> {
    let limit = limit.get();
    let ceiling = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut body = Vec::new();
    let read = source
        .take(ceiling)
        .read_to_end(&mut body)
        .map_err(|error| {
            RendererError::transport(format!("web fetch response body was unreadable: {error}"))
        })?;
    if read > limit {
        return Err(RendererError::invalid_response(format!(
            "web fetch response body exceeded the {limit} byte ceiling"
        )));
    }
    Ok(body)
}

/// Reads the `charset` parameter of a `Content-Type` header value.
///
/// Parameter boundaries are scanned rather than split blindly, because a MIME
/// quoted-string value may legally contain `;`. Only a `;` outside a quoted
/// string ends a parameter, and inside one a backslash escapes the next
/// character, so an escaped quote does not end the value either. That is what
/// keeps `text/html; note="x;charset=windows-1252"; charset=utf-8` reading as
/// two parameters whose only real charset is `utf-8`: the decoy text sits
/// inside `note`'s value and is never a parameter of its own.
fn declared_charset_label(content_type: &str) -> Option<String> {
    let mut quoted = false;
    let mut escaped = false;
    content_type
        .split(move |character| match (escaped, character) {
            (true, _) => {
                escaped = false;
                false
            }
            (false, '\\') if quoted => {
                escaped = true;
                false
            }
            (false, '"') => {
                quoted = !quoted;
                false
            }
            (false, ';') => !quoted,
            _ => false,
        })
        .skip(1)
        .find_map(|parameter| {
            let (name, value) = parameter.split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("charset")
                .then(|| unquoted_parameter_value(value.trim()))
        })
}

/// Unwraps one MIME parameter value: a quoted string loses its surrounding
/// quotes and its backslash escapes, and any other value is taken as written.
fn unquoted_parameter_value(value: &str) -> String {
    let Some(quoted) = value.strip_prefix('"') else {
        return value.to_string();
    };
    let mut unquoted = String::new();
    let mut characters = quoted.chars();
    while let Some(character) = characters.next() {
        match character {
            '"' => break,
            '\\' => {
                if let Some(escaped) = characters.next() {
                    unquoted.push(escaped);
                }
            }
            _ => unquoted.push(character),
        }
    }
    unquoted
}

/// Decodes an already-bounded response body into text.
///
/// The ceiling is applied first and separately: this decodes the bytes
/// [`read_capped_body`] admitted and never reads more. Precedence is the text
/// contract's — a BOM outranks the header, a declared charset outranks the
/// default, and UTF-8 is the default when nothing is declared. In-document
/// `<meta charset>` is deliberately not consulted: the transport's own
/// statement is the one this boundary trusts.
///
/// Decoding is closed. An unsupported declared encoding and a malformed byte
/// sequence are both typed rung failures, so no page is ever admitted with
/// replacement characters standing in for content the peer actually sent.
fn decode_response_body(body: &[u8], content_type: Option<&str>) -> RendererResult<String> {
    let (encoding, bytes) = match encoding_rs::Encoding::for_bom(body) {
        Some((encoding, bom_length)) => (encoding, &body[bom_length..]),
        None => match content_type.and_then(declared_charset_label) {
            Some(label) => {
                let encoding = encoding_rs::Encoding::for_label_no_replacement(label.as_bytes())
                    .ok_or_else(|| {
                        RendererError::invalid_response(format!(
                            "web fetch response declared an unsupported charset: {}",
                            reported_charset_label(&label)
                        ))
                    })?;
                (encoding, body)
            }
            None => (encoding_rs::UTF_8, body),
        },
    };
    encoding
        .decode_without_bom_handling_and_without_replacement(bytes)
        .map(std::borrow::Cow::into_owned)
        .ok_or_else(|| {
            RendererError::invalid_response(format!(
                "web fetch response body was not valid {}",
                encoding.name()
            ))
        })
}

/// Bounds how much of a peer-supplied charset label a public diagnostic repeats,
/// so an unusable header cannot push arbitrary remote text into a stored crawl
/// reason.
fn reported_charset_label(label: &str) -> String {
    label
        .chars()
        .take(MAX_REPORTED_CHARSET_LABEL_CHARS)
        .collect()
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
    max_response_bytes: NonZeroUsize,
}

impl NativeReadabilityRenderer {
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

impl Renderer for NativeReadabilityRenderer {
    fn kind(&self) -> RendererKind {
        RendererKind::Readability
    }

    fn render(&self, url: &str) -> RendererResult<RenderedPage> {
        let target = renderer_request_url(url)?;
        let response = self
            .client
            .get(target)
            .send()
            .map_err(|error| RendererError::transport(format!("web fetch GET failed: {error}")))?
            .error_for_status()
            .map_err(|error| {
                RendererError::transport(format!("web fetch GET returned an error status: {error}"))
            })?;
        let final_url = renderer_final_url(response.url().as_str())?;
        // The transport's charset statement has to be taken here: reading the
        // body consumes the response, and the header is what decides how the
        // bytes below the ceiling are decoded.
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        // Read under an explicit ceiling instead of `Response::text`, which
        // buffers the whole body first and so cannot be bounded. Decoding is a
        // separate closed step over exactly those bounded bytes.
        let body = read_capped_body(response, self.max_response_bytes)?;
        let html = decode_response_body(&body, content_type.as_deref())?;
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
        // The host browser is a network boundary like any other, so the same
        // pre-transport check applies before a URL is handed to it.
        let target = renderer_request_url(url)?;
        let document = self.headless.render_html(&target)?;
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

/// The pinned self-hosted scrape metadata.
///
/// `url` is where the scraper actually landed, and is the only identity this
/// module accepts as navigation-final. The envelope's `sourceURL` echoes the
/// request and is deliberately not read: a request echo cannot witness a
/// redirect, so trusting it would silently make every redirect invisible to
/// containment and to the crawl seen set.
///
/// `statusCode` is the *target page's* status, which is the reason a perfectly
/// well-formed success envelope can still describe a page that failed.
#[derive(Debug, Default, Deserialize)]
struct FirecrawlScrapeMetadata {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default, rename = "statusCode")]
    status_code: Option<u16>,
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

impl Renderer for FirecrawlRenderer {
    fn kind(&self) -> RendererKind {
        RendererKind::Firecrawl
    }

    fn render(&self, url: &str) -> RendererResult<RenderedPage> {
        let payload = FirecrawlScrapeRequest {
            // No credential reaches the provider: the URL is checked before it
            // is written into the request body.
            url: renderer_request_url(url)?,
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
            })?;
        let transport_status = response.status();
        let body = read_capped_body(response, self.max_response_bytes)?;
        // The target's outcome lives in the envelope, so the envelope is
        // decoded and interpreted before the transport status is allowed to
        // speak. `error_for_status` ahead of this point would discard a
        // structured scrape error and report a generic status instead. The
        // transport status only decides how an *undecodable* body is reported.
        let envelope = match serde_json::from_slice::<FirecrawlScrapeEnvelope>(&body) {
            Ok(envelope) => envelope,
            // With no decodable envelope there is no target verdict to honor,
            // so a non-2xx transport status becomes the remaining evidence.
            Err(_) if !transport_status.is_success() => {
                return Err(RendererError::transport(format!(
                    "firecrawl scrape returned an error status: {transport_status}"
                )));
            }
            Err(error) => {
                return Err(RendererError::invalid_response(format!(
                    "firecrawl scrape envelope was undecodable: {error}"
                )));
            }
        };
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
        let metadata = data.metadata.unwrap_or_default();
        // The target page's own status, read before any of its content is
        // trusted: a scrape of a 404 arrives inside a well-formed 2xx envelope,
        // and the error page it carries can clear the Markdown floor.
        let target_status = metadata.status_code.unwrap_or(FIRECRAWL_UNREPORTED_STATUS);
        if !(200..300).contains(&target_status) {
            return Err(RendererError::transport(format!(
                "firecrawl scrape target returned status {target_status}"
            )));
        }
        let markdown = data.markdown.ok_or_else(|| {
            RendererError::invalid_response("firecrawl scrape envelope carried no markdown")
        })?;
        // Navigation-final identity, taken from the response contract. The
        // request-echoing `sourceURL` is never consulted for it.
        let Some(reported_final) = metadata.url else {
            return Err(RendererError::invalid_response(
                "firecrawl scrape envelope carried no data.metadata.url",
            ));
        };
        let final_url = validated_web_url(&reported_final).ok_or_else(|| {
            RendererError::invalid_response(format!(
                "firecrawl final URL is not credential-free absolute http(s): {}",
                redact_url_credentials(&reported_final)
            ))
        })?;
        let final_url_text = final_url.to_string();
        let discovered_links = normalize_link_list(&data.links, &final_url);
        Ok(RenderedPage {
            markdown,
            title: metadata.title.unwrap_or_default().trim().to_string(),
            // The pinned envelope carries no separate canonical field, so the
            // navigation-final identity supplies both. Only `final_url` ever
            // participates in containment or the seen set.
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
    /// The required rung. It is an `Option` only so that the ladder driver can
    /// hold every slot uniformly and state the required/optional distinction in
    /// one place; the constructor always fills it, and an empty required slot
    /// fails closed instead of being stepped over.
    readability: Option<Arc<dyn Renderer>>,
    headless: Option<Arc<dyn Renderer>>,
    firecrawl: Option<Arc<dyn Renderer>>,
    minimum_content: MinExtractedContentBytes,
}

/// Whether an absent ladder slot is an ordinary trace record or a fail-closed
/// engine error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RungRequirement {
    Required,
    Optional,
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
            readability: Some(readability),
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
    /// Returns [`WebFetchError::InvalidUrl`], [`WebFetchError::UnsupportedScheme`],
    /// or [`WebFetchError::CredentialsInUrl`] for a URL this module will not
    /// fetch; [`WebFetchError::MissingRequiredRenderer`] when a required rung is
    /// unconfigured; and [`WebFetchError::AllRenderersFailed`] carrying the
    /// ordered ladder trace when no rung produced content.
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
        // The one spelling of "this rung failed" used by every check below, so
        // no boundary check can accidentally become a terminal failure.
        let as_attempt = |error| RendererAttemptFailure::Error {
            renderer: kind,
            error,
        };
        let page = renderer.render(url).map_err(as_attempt)?;

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

        let final_url = renderer_final_url(&page.final_url).map_err(as_attempt)?;
        // A rung's canonical identity passes the same central check as its
        // final URL. The built-in rungs already resolve a valid one, so this is
        // the guard for a host-supplied custom [`Renderer`], whose output would
        // otherwise reach the closed public result unvalidated.
        let canonical_url = renderer_canonical_url(&page.canonical_url).map_err(as_attempt)?;

        // Every rung's link set leaves through the one normalization seam,
        // resolved against the validated navigation-final URL. The built-in
        // rungs already normalize, so this is the guard for a host-supplied
        // custom [`Renderer`]: without it a relative link would be silently
        // dropped downstream, and renderer order would decide which pages a
        // finite budget reaches. Sorted, deduplicated, fragment-free HTTP(S) is
        // the only shape the walk ever sees.
        let discovered_links = normalize_link_list(page.discovered_links, &final_url);

        let result = FetchResult {
            content_hash: content_hash(&page.markdown),
            markdown: page.markdown,
            title: page.title,
            canonical_url: canonical_url.to_string(),
            fetched_at,
            renderer: kind,
        };
        Ok((result, discovered_links, final_url))
    }

    /// The fixed ladder. Sequential, never speculative, never parallel; a rung
    /// advances only on a typed renderer error, an absent *optional* rung, or a
    /// below-threshold extraction. Once a rung succeeds, lower rungs never run.
    ///
    /// # Errors
    /// Returns [`WebFetchError::MissingRequiredRenderer`] when a required rung
    /// has no renderer, and [`WebFetchError::AllRenderersFailed`] with the
    /// ordered trace when every rung was tried and none produced content.
    fn fetch_page(
        &self,
        url: &Url,
        fetched_at: u64,
    ) -> WebFetchResult<(FetchResult, Vec<String>, Url)> {
        let requested = url.to_string();
        let mut attempts = Vec::new();
        for (kind, requirement, slot) in [
            (
                RendererKind::Readability,
                RungRequirement::Required,
                self.readability.as_ref(),
            ),
            (
                RendererKind::Headless,
                RungRequirement::Optional,
                self.headless.as_ref(),
            ),
            (
                RendererKind::Firecrawl,
                RungRequirement::Optional,
                self.firecrawl.as_ref(),
            ),
        ] {
            let Some(renderer) = slot else {
                // Only a genuinely optional rung may be recorded and stepped
                // over. A missing required rung is an engine misconfiguration
                // rather than a ladder outcome, so it fails closed instead of
                // becoming one more `Unavailable` line that lets the walk
                // continue as though the required rung had been consulted.
                if requirement == RungRequirement::Required {
                    return Err(WebFetchError::MissingRequiredRenderer { renderer: kind });
                }
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
    /// Returns [`WebFetchError::InvalidUrl`], [`WebFetchError::UnsupportedScheme`],
    /// or [`WebFetchError::CredentialsInUrl`] for an unusable seed URL, and
    /// propagates the seed page's typed ladder failure because there is no
    /// successful final URL from which to pin the walk.
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
