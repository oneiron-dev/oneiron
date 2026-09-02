//! Private rendering support for the OF-444 ladder: URL parsing,
//! normalization, validation, and credential redaction; credential-safe
//! transport and read diagnostics; the response byte ceiling and closed
//! decoding; native readability extraction; and the pinned self-hosted
//! Firecrawl scrape records with their envelope mapping.
//!
//! Nothing here is public surface. The parent module owns every exported type,
//! constant, trait, and rung adapter, and reaches these units through
//! `pub(super)`.

use std::collections::BTreeSet;
use std::io::Read;
use std::num::NonZeroUsize;

use dom_smoothie::{Config, Readability, TextMode};
use reqwest::Url;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::{
    FIRECRAWL_UNREPORTED_STATUS, FirecrawlRenderer, MAX_DISCOVERED_LINKS_PER_PAGE,
    MAX_RAW_LINKS_PER_PAGE, MAX_REPORTED_CHARSET_LABEL_CHARS, REDACTED_USERINFO, RenderedPage,
    RendererError, RendererResult, WebFetchError, WebFetchResult,
};

/// The single normalization step: drop the fragment and keep whatever the URL
/// parser already canonicalized (host lowercasing, default-port elision,
/// dot-segment resolution). No trailing-slash rewriting, query reordering, or
/// IDN transformation is added on top.
pub(super) fn normalize_url(url: &Url) -> Url {
    let mut normalized = url.clone();
    normalized.set_fragment(None);
    normalized
}

/// Normalizes, filters to HTTP(S), sorts bytewise, and deduplicates one raw
/// link list under both work ceilings.
///
/// Raw entries are counted before parsing or joining, so duplicates and invalid
/// spellings cannot buy unbounded CPU work. Distinct normalized entries are
/// checked before insertion, so the set itself never grows past its ceiling.
/// Either overflow is a typed rung failure; no shortened link list is admitted.
pub(super) fn normalize_link_list<I, S>(links: I, base: &Url) -> RendererResult<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut raw_count = 0_usize;
    let mut normalized = BTreeSet::new();
    for raw in links {
        raw_count = raw_count.saturating_add(1);
        if raw_count > MAX_RAW_LINKS_PER_PAGE {
            return Err(RendererError::invalid_response(format!(
                "web fetch page exceeded the {MAX_RAW_LINKS_PER_PAGE} raw-link ceiling"
            )));
        }
        let Ok(joined) = base.join(raw.as_ref().trim()) else {
            continue;
        };
        let candidate = normalize_url(&joined);
        if !is_web_url(&candidate) {
            continue;
        }
        let identity = candidate.to_string();
        if normalized.contains(&identity) {
            continue;
        }
        if normalized.len() == MAX_DISCOVERED_LINKS_PER_PAGE {
            return Err(RendererError::invalid_response(format!(
                "web fetch page exceeded the {MAX_DISCOVERED_LINKS_PER_PAGE} discovered-link ceiling"
            )));
        }
        normalized.insert(identity);
    }
    Ok(normalized.into_iter().collect())
}

/// Absolute HTTP(S), a non-empty host, and no embedded credentials: the only
/// transport this module speaks.
///
/// Userinfo is refused by the same predicate that decides "is this fetchable",
/// rather than stripped somewhere downstream. One predicate therefore keeps
/// `user:pass@host` out of every request this module sends, every provider
/// payload it builds, every URL it publishes, and every frontier it walks.
pub(super) fn is_web_url(url: &Url) -> bool {
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
pub(super) fn redact_url_credentials(raw: &str) -> String {
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
pub(super) fn validated_web_url(raw: &str) -> Option<Url> {
    Url::parse(raw)
        .ok()
        .filter(is_web_url)
        .map(|url| normalize_url(&url))
}

/// Parses a caller-supplied URL into its normalized form.
pub(super) fn parse_web_url(raw: &str) -> WebFetchResult<Url> {
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
pub(super) fn renderer_final_url(raw: &str) -> RendererResult<Url> {
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
/// host-supplied custom [`Renderer`](super::Renderer), so nothing unvalidated
/// and nothing carrying credentials can reach the closed public `FetchResult`.
pub(super) fn renderer_canonical_url(raw: &str) -> RendererResult<Url> {
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
pub(super) fn renderer_request_url(raw: &str) -> RendererResult<String> {
    let Some(url) = validated_web_url(raw) else {
        return Err(RendererError::transport(format!(
            "refusing to request a URL that is not credential-free absolute http(s): {}",
            redact_url_credentials(raw)
        )));
    };
    Ok(url.to_string())
}

/// Renders one `reqwest` failure into a credential-safe diagnostic.
///
/// A transport error is hostile URL-bearing input, not a safe display string.
/// `reqwest` keeps the URL of the request that failed and prints it verbatim,
/// and once the client has followed a redirect that URL is the *peer's*
/// `Location` rather than the target [`renderer_request_url`] admitted — so it
/// may carry `user:pass@host` even though nothing this module accepted did.
///
/// The URL is therefore read structurally, redacted through the one parse-first
/// sanitizer, and removed from the error *before* anything formats it. Because
/// the URL is in hand, the credentials it carried are known exactly, so the
/// remaining text is scrubbed of those exact secrets rather than trusted to be
/// free of them. An empty username or password is not a secret and is never
/// substituted for.
pub(super) fn redacted_transport_detail(error: reqwest::Error) -> String {
    let Some(url) = error.url().cloned() else {
        // No URL was ever attached, so there is none to disclose.
        return error.to_string();
    };
    let target = redact_url_credentials(url.as_str());
    // `without_url` is a structural removal, not a hope that the upstream
    // `Display` will keep the URL to itself.
    let mut detail = error.without_url().to_string();
    for secret in [url.username(), url.password().unwrap_or_default()] {
        if !secret.is_empty() {
            detail = detail.replace(secret, REDACTED_USERINFO);
        }
    }
    format!("{detail} (target {target})")
}

/// Renders one response-body read failure into a credential-safe diagnostic.
///
/// A blocking `reqwest` body read reaches this module as [`std::io::Error`]
/// carrying the transport's own error inside it, and that inner error is
/// URL-bearing exactly like the ones the request path produces — after a
/// redirect, with the peer's `Location`. It is therefore recovered structurally
/// and sent through the same seam. Anything else is reported by its
/// [`std::io::ErrorKind`], a fixed enum that can carry no URL at all, rather
/// than by a nested message this module cannot vouch for.
fn redacted_read_detail(error: std::io::Error) -> String {
    let kind = format!("{:?}", error.kind());
    let Some(source) = error.into_inner() else {
        return kind;
    };
    match source.downcast::<reqwest::Error>() {
        Ok(transport) => redacted_transport_detail(*transport),
        Err(_) => kind,
    }
}

/// Reads at most `limit` bytes of a response body, and fails closed when the
/// peer sends more.
///
/// The ceiling is applied while the bytes are still streaming, so an oversized
/// or endless body is a typed failure rather than memory growth. Exactly one
/// byte past the ceiling is read, purely to tell "at the ceiling" apart from
/// "over it".
pub(super) fn read_capped_body(source: impl Read, limit: NonZeroUsize) -> RendererResult<Vec<u8>> {
    let limit = limit.get();
    let ceiling = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut body = Vec::new();
    let read = source
        .take(ceiling)
        .read_to_end(&mut body)
        .map_err(|error| {
            RendererError::transport(format!(
                "web fetch response body was unreadable: {}",
                redacted_read_detail(error)
            ))
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
pub(super) fn decode_response_body(
    body: &[u8],
    content_type: Option<&str>,
) -> RendererResult<String> {
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
fn collect_document_links(
    readability: &Readability,
    final_url: &Url,
) -> RendererResult<Vec<String>> {
    let base = readability
        .doc
        .select("base[href]")
        .nodes()
        .first()
        .and_then(|node| node.attr("href"))
        .and_then(|href| final_url.join(href.trim()).ok())
        .unwrap_or_else(|| final_url.clone());

    // Collect only under the raw-entry ceiling. The DOM is already present, but
    // an anchor-dense document must not create an unbounded second vector before
    // normalization gets its turn.
    let anchors = readability.doc.select("a[href]");
    let mut hrefs = Vec::new();
    for node in anchors.nodes() {
        if let Some(href) = node.attr("href") {
            if hrefs.len() == MAX_RAW_LINKS_PER_PAGE {
                return Err(RendererError::invalid_response(format!(
                    "web fetch page exceeded the {MAX_RAW_LINKS_PER_PAGE} raw-link ceiling"
                )));
            }
            hrefs.push(href.to_string());
        }
    }
    normalize_link_list(hrefs, &base)
}

/// The one extraction path. Both the native readability rung and the headless
/// rung run this, so headless is a rendering rung rather than a second
/// extraction algorithm.
pub(super) fn extract_readable_page(html: &str, final_url: &Url) -> RendererResult<RenderedPage> {
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

    let discovered_links = collect_document_links(&readability, &normalized_final)?;

    let article = readability.parse().map_err(|error| {
        RendererError::extraction(format!("readability extraction failed: {error}"))
    })?;

    let canonical_url = resolve_canonical_url(&normalized_final, article.url.as_deref());
    Ok(RenderedPage {
        markdown: article.text_content.to_string(),
        title: article.title.trim().to_string(),
        canonical_url,
        final_url: Some(final_url_text),
        discovered_links,
    })
}

// ---------------------------------------------------------------------------
// Self-hosted Firecrawl scrape records and envelope mapping (private)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(super) struct FirecrawlScrapeRequest {
    pub(super) url: String,
    pub(super) formats: [&'static str; 2],
    #[serde(rename = "onlyMainContent")]
    pub(super) only_main_content: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct FirecrawlScrapeEnvelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    data: Option<FirecrawlScrapeData>,
}

#[derive(Debug, Deserialize)]
struct FirecrawlScrapeData {
    #[serde(default)]
    markdown: Option<String>,
    #[serde(default, deserialize_with = "deserialize_bounded_links")]
    links: Vec<String>,
    #[serde(default)]
    metadata: Option<FirecrawlScrapeMetadata>,
}

/// Decodes Firecrawl's link array without first expanding the whole peer-chosen
/// sequence into a `Vec<String>`. The visitor stops at the first entry beyond
/// the raw ceiling, so even an array of tiny duplicates has bounded allocation
/// and bounded decode work.
fn deserialize_bounded_links<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedLinksVisitor;

    impl<'de> Visitor<'de> for BoundedLinksVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {MAX_RAW_LINKS_PER_PAGE} Firecrawl link strings"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|length| length > MAX_RAW_LINKS_PER_PAGE)
            {
                return Err(de::Error::custom(format!(
                    "firecrawl links exceeded the {MAX_RAW_LINKS_PER_PAGE} raw-link ceiling"
                )));
            }
            let capacity = sequence
                .size_hint()
                .unwrap_or_default()
                .min(MAX_RAW_LINKS_PER_PAGE);
            let mut links = Vec::with_capacity(capacity);
            while let Some(link) = sequence.next_element::<String>()? {
                if links.len() == MAX_RAW_LINKS_PER_PAGE {
                    return Err(de::Error::custom(format!(
                        "firecrawl links exceeded the {MAX_RAW_LINKS_PER_PAGE} raw-link ceiling"
                    )));
                }
                links.push(link);
            }
            Ok(links)
        }
    }

    deserializer.deserialize_seq(BoundedLinksVisitor)
}

/// The pinned self-hosted scrape metadata.
///
/// Firecrawl's canonical page identity is `sourceURL`. Some v1 deployments
/// additionally report a post-navigation `url`; it is decoded separately and
/// is the only Firecrawl field this engine accepts as redirect-final evidence.
/// When it is absent, single-page acquisition remains usable but a crawl must
/// reject the rung rather than pretending the request echo witnessed a landing.
///
/// `statusCode` is the *target page's* status, which is the reason a perfectly
/// well-formed success envelope can still describe a page that failed.
#[derive(Debug, Default, Deserialize)]
struct FirecrawlScrapeMetadata {
    #[serde(default)]
    title: Option<String>,
    #[serde(default, rename = "sourceURL")]
    source_url: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default, rename = "statusCode")]
    status_code: Option<u16>,
}

impl FirecrawlRenderer {
    pub(super) fn map_envelope(envelope: FirecrawlScrapeEnvelope) -> RendererResult<RenderedPage> {
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
        // Firecrawl's actual canonical field. It is intentionally not treated
        // as redirect-final evidence: `sourceURL` can echo the requested page.
        let Some(reported_url) = metadata.source_url else {
            return Err(RendererError::invalid_response(
                "firecrawl scrape envelope carried no data.metadata.sourceURL",
            ));
        };
        let canonical_url = validated_web_url(&reported_url).ok_or_else(|| {
            RendererError::invalid_response(format!(
                "firecrawl sourceURL is not credential-free absolute http(s): {}",
                redact_url_credentials(&reported_url)
            ))
        })?;
        let final_url = metadata
            .url
            .map(|reported_final| {
                validated_web_url(&reported_final).ok_or_else(|| {
                    RendererError::invalid_response(format!(
                        "firecrawl url is not credential-free absolute http(s): {}",
                        redact_url_credentials(&reported_final)
                    ))
                })
            })
            .transpose()?;
        // Relative links resolve against a witnessed landing when supplied and
        // otherwise against the canonical identity. The latter links can serve
        // callers inspecting one page, but the crawl door below rejects this
        // unwitnessed result before any link reaches its frontier.
        let link_base = final_url.as_ref().unwrap_or(&canonical_url);
        let discovered_links = normalize_link_list(&data.links, link_base)?;
        Ok(RenderedPage {
            markdown,
            title: metadata.title.unwrap_or_default().trim().to_string(),
            canonical_url: canonical_url.to_string(),
            final_url: final_url.map(|url| url.to_string()),
            discovered_links,
        })
    }
}
