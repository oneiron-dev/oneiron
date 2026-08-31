//! Private ladder-driver internals: the rung-slot requirement and check, the
//! per-rung and per-page implementation behind [`WebFetcher::fetch`] and
//! [`WebFetcher::crawl`], the breadth-first walk state, and the crawl failure
//! reason renderer.
//!
//! Nothing here is public surface. The parent module owns [`WebFetcher`], every
//! public constructor and method on it, and every exported type these units
//! move; they are reached through `pub(super)`.

use std::collections::{BTreeSet, VecDeque};

use reqwest::Url;

use super::render::{is_web_url, normalize_url, renderer_canonical_url, renderer_final_url};
use super::{
    ALL_RENDERERS_FAILED_REASON_PREFIX, CROSS_SITE_REDIRECT_REASON, CrawlCompletion,
    CrawlPageFailure, CrawlResult, CrawlScope, FetchResult, Renderer, RendererAttemptFailure,
    RendererKind, WebFetchError, WebFetchResult, WebFetcher, content_hash, normalize_link_list,
};

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
    /// Frontier identity at enqueue time. Kills duplicate (diamond) enqueues.
    enqueued: BTreeSet<String>,
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

    pub(super) fn absorb_success(
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
