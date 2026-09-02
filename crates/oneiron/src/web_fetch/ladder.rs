//! Private ladder-driver internals: the rung-slot requirement and check, the
//! per-rung and per-page implementation behind [`WebFetcher::fetch`] and
//! [`WebFetcher::crawl`], the two peer-controlled link ceilings, the
//! breadth-first walk state, the crawl failure reason renderer, and the closed
//! wire form every decoded [`FetchResult`] passes through.
//!
//! Nothing here is public surface. The parent module owns [`WebFetcher`], every
//! public constructor and method on it, and every exported type these units
//! move; they are reached through `pub(super)`.

use std::collections::{BTreeSet, VecDeque};

use reqwest::Url;
use serde::Deserialize;

use super::render::{
    is_web_url, normalize_link_list, normalize_url, renderer_canonical_url, renderer_final_url,
    validated_web_url,
};
use super::{
    ALL_RENDERERS_FAILED_REASON_PREFIX, CROSS_SITE_REDIRECT_REASON, CrawlCompletion,
    CrawlPageFailure, CrawlResult, CrawlScope, FetchResult, Renderer, RendererAttemptFailure,
    RendererKind, RendererResult, WebFetchError, WebFetchResult, WebFetcher, content_hash,
};

/// Ceiling on how many distinct URLs one walk's frontier may hold.
///
/// The per-page ceiling alone still leaves `page budget × per-page ceiling`, and
/// the page budget is the caller's number, so the frontier carries its own
/// bound. Both ceilings are engine constants: neither is a caller dial.
pub(super) const MAX_CRAWL_FRONTIER_URLS: usize = 65536;

/// The exact reason literal recorded when admitting a page's links would push
/// the walk's frontier past [`MAX_CRAWL_FRONTIER_URLS`].
pub(super) const FRONTIER_LINK_BUDGET_EXCEEDED_REASON: &str = "frontier_link_budget_exceeded";

/// The one seam a rung's discovered links reach the walk through.
///
/// An over-ceiling page is an ordinary typed rung failure, so it consumes its
/// attempt and admits neither page nor links, and a seed that does it stays a
/// typed seed error. Nothing here ever hands back a shortened link list.
fn bounded_link_list(links: Vec<String>, base: &Url) -> RendererResult<Vec<String>> {
    normalize_link_list(links, base)
}

/// Whether an absent ladder slot is an ordinary trace record or a fail-closed
/// engine error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RungRequirement {
    Required,
    Optional,
}

pub(super) fn require_renderer_slot(
    expected: RendererKind,
    renderer: &dyn Renderer,
) -> WebFetchResult<()> {
    let actual = renderer.kind();
    if actual == expected {
        Ok(())
    } else {
        Err(WebFetchError::InvalidRendererSlot { expected, actual })
    }
}

impl WebFetcher {
    /// Runs one rung. `Err` is the attempt record, not a terminal failure.
    pub(super) fn try_rung(
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
        // finite budget reaches. Sorted, deduplicated, fragment-free HTTP(S)
        // under the per-page ceiling is the only shape the walk ever sees.
        let discovered_links =
            bounded_link_list(page.discovered_links, &final_url).map_err(as_attempt)?;

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
    pub(super) fn fetch_page(
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
}

/// Mutable state of one breadth-first walk.
pub(super) struct CrawlWalk {
    pub(super) frontier: VecDeque<Url>,
    /// Identities held by `frontier` right now. It kills duplicate (diamond)
    /// enqueues without retaining every URL that was ever queued.
    queued: BTreeSet<String>,
    /// Dequeue-time skip identity: requested URLs already attempted plus
    /// response-final URLs already reached. A requested URL enters this set
    /// before its own fetch, so membership is not evidence that a page for that
    /// identity was admitted.
    pub(super) visited: BTreeSet<String>,
    /// Navigation-final identity of every page already admitted to `pages`.
    /// This is the completion record, and the only basis for suppressing a
    /// later alias that redirects onto an identity already acquired.
    completed_finals: BTreeSet<String>,
    pub(super) pages: Vec<FetchResult>,
    pub(super) failed: Vec<CrawlPageFailure>,
    /// Host of the seed page's response-final URL, pinned after the seed succeeds.
    pub(super) pinned_host: Option<String>,
    pub(super) remaining_budget: usize,
}

impl CrawlWalk {
    pub(super) fn new(seed: Url, page_budget: usize) -> Self {
        let mut queued = BTreeSet::new();
        queued.insert(seed.to_string());
        let mut frontier = VecDeque::new();
        frontier.push_back(seed);
        Self {
            frontier,
            queued,
            visited: BTreeSet::new(),
            completed_finals: BTreeSet::new(),
            pages: Vec::new(),
            failed: Vec::new(),
            pinned_host: None,
            remaining_budget: page_budget,
        }
    }

    /// Removes one live frontier entry and its queue identity together.
    pub(super) fn pop_frontier(&mut self) -> Option<Url> {
        let current = self.frontier.pop_front()?;
        self.queued.remove(current.as_str());
        Some(current)
    }

    /// Restores a page that was popped only to discover the explicit page budget
    /// was already exhausted.
    pub(super) fn restore_front(&mut self, current: Url) {
        self.queued.insert(current.to_string());
        self.frontier.push_front(current);
    }

    pub(super) fn absorb_success(
        &mut self,
        requested: String,
        page: FetchResult,
        links: &[String],
        final_url: &Url,
        scope: CrawlScope,
    ) {
        let final_host = final_url.host_str().unwrap_or_default().to_string();
        // Seed success pins containment to the seed page's own final host. A
        // cross-host metadata canonical cannot move it.
        let is_seed = self.pinned_host.is_none();
        let pinned_host = self.pinned_host.as_ref().unwrap_or(&final_host).clone();

        if !is_seed {
            if scope == CrawlScope::SameSite && final_host != pinned_host {
                // A same-host link that redirected onto a foreign host. The
                // attempt is already counted; the page and every link it
                // carries are not admitted.
                self.failed.push(CrawlPageFailure {
                    url: requested,
                    reason: CROSS_SITE_REDIRECT_REASON.to_string(),
                });
                return;
            }

            if self.completed_finals.contains(final_url.as_str()) {
                // A later alias that navigated onto an identity this walk has
                // already acquired. The attempt and its budget unit are spent,
                // but the second copy of the same page is not a page, and the
                // links it carries are the already-admitted page's links, so
                // re-enqueueing them would widen the frontier on a duplicate.
                // Requested identity is deliberately not consulted: an ordinary
                // page whose final URL is its own requested URL is still its own
                // first completion.
                return;
            }
        }

        let fresh = self.fresh_links(links, scope, &pinned_host);
        if self.frontier.len().saturating_add(fresh.len()) > MAX_CRAWL_FRONTIER_URLS {
            // The bound is over URLs still held in memory, not every URL the
            // walk ever queued. A long one-link chain therefore remains a
            // one-entry frontier, while a genuinely wide page is refused. The
            // attempt is already counted, and neither the page nor one link of
            // it is admitted. Dropping only the overflowing tail would make
            // `unvisited_urls` a quiet lie about what remained in front of us.
            self.failed.push(CrawlPageFailure {
                url: requested,
                reason: FRONTIER_LINK_BUDGET_EXCEEDED_REASON.to_string(),
            });
            return;
        }

        if is_seed {
            self.pinned_host = Some(final_host);
        }
        self.admit_page(page, fresh, final_url);
    }

    /// This page's links that admission would newly add to the frontier: in link
    /// order, deduplicated, and filtered exactly as admission filters.
    ///
    /// Measuring the ceiling against this — rather than against raw peer text —
    /// is what keeps the bound about frontier growth instead of about how
    /// verbosely a page spells links the walk would discard anyway.
    fn fresh_links(&self, links: &[String], scope: CrawlScope, pinned_host: &str) -> Vec<Url> {
        let mut seen = BTreeSet::new();
        let mut fresh = Vec::new();
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
            let identity = normalized.to_string();
            if !self.queued.contains(&identity)
                && !self.visited.contains(&identity)
                && seen.insert(identity)
            {
                fresh.push(normalized);
            }
        }
        fresh
    }

    /// The single admission point: one page, its completed navigation-final
    /// identity, and its links enter together, so no admitted page can leave
    /// its final identity unrecorded.
    fn admit_page(&mut self, page: FetchResult, fresh: Vec<Url>, final_url: &Url) {
        self.pages.push(page);
        self.completed_finals.insert(final_url.to_string());
        for link in fresh {
            if self.queued.insert(link.to_string()) {
                self.frontier.push_back(link);
            }
        }
    }

    pub(super) fn into_budget_exhausted(self) -> CrawlResult {
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
pub(super) fn crawl_failure_reason(error: &WebFetchError) -> String {
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

// ---------------------------------------------------------------------------
// The closed decode door for the public six-field result
// ---------------------------------------------------------------------------

/// How many lowercase hex characters a BLAKE3 content identity is written in.
const CONTENT_HASH_HEX_CHARS: usize = 64;

/// Whether a decoded `content_hash` has the only shape this door accepts:
/// exactly [`CONTENT_HASH_HEX_CHARS`] lowercase ASCII hex characters. Uppercase
/// is refused rather than folded, because the writer emits one spelling and two
/// spellings of one identity is how a later dedup seam starts missing matches.
fn is_content_hash_shaped(hex: &str) -> bool {
    let is_lower_hex = |byte: u8| matches!(byte, b'0'..=b'9' | b'a'..=b'f');
    hex.len() == CONTENT_HASH_HEX_CHARS && hex.bytes().all(is_lower_hex)
}

/// The decode-side form of [`FetchResult`]: the same six fields, the same names,
/// and the same closure, plus the one check a derived door cannot make.
///
/// [`FetchResult`] documents `content_hash` as the identity of the `markdown`
/// beside it, and [`WebFetcher::try_rung`] always writes exactly that. A payload
/// arriving from anywhere else only asserts it, so this door re-derives the
/// identity through the one private [`content_hash`] over the exact markdown
/// bytes and refuses any pair that disagrees.
///
/// The re-derived value never replaces the supplied one. A door that quietly
/// substituted would turn a stale or forged pair into a well-formed-looking one,
/// which is the opposite of what a rematerialization door is for.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FetchResultWire {
    markdown: String,
    title: String,
    canonical_url: String,
    fetched_at: u64,
    content_hash: String,
    renderer: RendererKind,
}

impl TryFrom<FetchResultWire> for FetchResult {
    /// A decode-door diagnostic, not a typed engine error: serde renders it
    /// through `de::Error::custom`, and no caller branches on it.
    type Error = String;

    fn try_from(wire: FetchResultWire) -> std::result::Result<Self, Self::Error> {
        // Shape first, so a malformed, short, long, or uppercase value is
        // refused as what it is rather than reported as a stale identity.
        if !is_content_hash_shaped(&wire.content_hash) {
            return Err(format!(
                "content_hash must be {CONTENT_HASH_HEX_CHARS} lowercase hex characters"
            ));
        }
        if wire.content_hash != content_hash(&wire.markdown) {
            return Err("content_hash does not match the markdown it arrived with".to_string());
        }
        let canonical_url = validated_web_url(&wire.canonical_url).ok_or_else(|| {
            "canonical_url must be a credential-free absolute http(s) URL".to_string()
        })?;
        Ok(Self {
            markdown: wire.markdown,
            title: wire.title,
            canonical_url: canonical_url.to_string(),
            fetched_at: wire.fetched_at,
            content_hash: wire.content_hash,
            renderer: wire.renderer,
        })
    }
}
