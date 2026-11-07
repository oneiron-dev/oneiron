//! The context one page's render runs in (FIX 4734): how the page is
//! acquired, the origin a same-site crawl holds it to, and a managed node's
//! egress guard. The ladder builds one per page and hands the same one to
//! every rung, and each rung hands it on to whatever reaches the network for
//! it (a host browser among them). Nothing keeps it past the page: the
//! fetcher holds no crawl state of its own.

use std::sync::Arc;

use reqwest::Url;

use super::render::redact_url_credentials;
use super::{CrawlScope, HostedEgressGuard, RendererError, RendererResult};

/// The exact origin a same-site crawl is held to: the serialized origin
/// (`Url::origin().ascii_serialization()`: scheme, host and effective port)
/// of the seed's witnessed navigation-final URL. A subdomain, another port
/// or another scheme is another origin; no registrable-domain rule applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedOrigin(String);

impl PinnedOrigin {
    /// The origin of `url`. An opaque origin, which no web URL has, admits
    /// nothing.
    #[must_use]
    pub fn of(url: &Url) -> Self {
        Self(url.origin().ascii_serialization())
    }

    /// Whether `url` is at this origin. It is the one check behind a
    /// same-site crawl's link filtering, its landing check and each hop a
    /// rung admits.
    #[must_use]
    pub fn admits(&self, url: &Url) -> bool {
        let origin = url.origin();
        origin.is_tuple() && origin.ascii_serialization() == self.0
    }

    /// Refuses `url`, a URL about to be contacted, when this origin does not
    /// admit it ([`Self::admits`]).
    ///
    /// # Errors
    /// Returns a [`RendererError::cross_site_redirect`] error naming `url`,
    /// credential-redacted, and this origin.
    pub fn check(&self, url: &Url) -> RendererResult<()> {
        if self.admits(url) {
            return Ok(());
        }
        Err(RendererError::cross_site_redirect(format!(
            "{} is outside the same-site crawl's pinned origin {}; refused before contact",
            redact_url_credentials(url.as_str()),
            self.0
        )))
    }

    /// The serialized origin.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PinnedOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// How a page is acquired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionMode {
    /// One page ([`WebFetcher::fetch`](super::WebFetcher::fetch)).
    SinglePage,
    /// One page of a crawl walked in this scope
    /// ([`WebFetcher::crawl`](super::WebFetcher::crawl)).
    Crawl(CrawlScope),
}

/// The immutable context of one page's render, handed to every rung
/// ([`Renderer::render`](super::Renderer::render)) and on to a host browser
/// ([`HeadlessRenderer::render_html`](super::HeadlessRenderer::render_html)).
/// A rung holds every URL it contacts to [`Self::pin`] before it resolves
/// or sends it, and on a managed node checks every hop and address it
/// reaches with [`Self::hosted_guard`]; one that cannot refuses the work
/// before any network activity.
#[derive(Debug, Clone)]
pub struct RenderContext {
    mode: AcquisitionMode,
    pin: Option<PinnedOrigin>,
    guard: Option<Arc<HostedEgressGuard>>,
}

impl RenderContext {
    /// One page's render, held to no origin and carrying no guard.
    #[must_use]
    pub const fn single_page() -> Self {
        Self {
            mode: AcquisitionMode::SinglePage,
            pin: None,
            guard: None,
        }
    }

    /// A page of a crawl walked in `scope`. A same-site crawl's page is held
    /// to `pin`, the walk's pinned origin, once the walk has one; its seed is
    /// rendered with none, and the seed's navigation-final origin becomes the
    /// pin. A cross-site crawl holds no page to an origin, so it keeps no
    /// `pin`.
    #[must_use]
    pub fn crawl_page(scope: CrawlScope, pin: Option<PinnedOrigin>) -> Self {
        let pin = match scope {
            CrawlScope::SameSite => pin,
            CrawlScope::CrossSite => None,
        };
        Self {
            mode: AcquisitionMode::Crawl(scope),
            pin,
            guard: None,
        }
    }

    /// This context on a managed (hosted) node, carrying its egress guard
    /// (SCAN C447).
    #[must_use]
    pub fn with_hosted_guard(mut self, guard: Arc<HostedEgressGuard>) -> Self {
        self.guard = Some(guard);
        self
    }

    /// How the page is acquired.
    #[must_use]
    pub const fn mode(&self) -> AcquisitionMode {
        self.mode
    }

    /// The origin every URL the render contacts is held to: a same-site
    /// crawl's pinned origin, after its seed.
    #[must_use]
    pub fn pin(&self) -> Option<&PinnedOrigin> {
        self.pin.as_ref()
    }

    /// A managed node's egress guard (SCAN C447); none on a self-hosted node.
    #[must_use]
    pub fn hosted_guard(&self) -> Option<&Arc<HostedEgressGuard>> {
        self.guard.as_ref()
    }

    /// Whether the page belongs to a same-site crawl, its seed included.
    #[must_use]
    pub const fn is_same_site_crawl(&self) -> bool {
        matches!(self.mode, AcquisitionMode::Crawl(CrawlScope::SameSite))
    }

    /// Whether the page's rung has to witness its navigation-final URL: a
    /// crawl walks on from it, and never on a request echo.
    pub(super) const fn requires_witnessed_final_url(&self) -> bool {
        matches!(self.mode, AcquisitionMode::Crawl(_))
    }

    /// Refuses `url`, a URL the render is about to contact (the page, a
    /// redirect hop, a navigation), when it is outside [`Self::pin`]; a
    /// context with no pin admits every URL here.
    ///
    /// # Errors
    /// Returns a [`RendererError::cross_site_redirect`] error when the pin
    /// does not admit `url` ([`PinnedOrigin::check`]).
    pub fn admit_hop(&self, url: &Url) -> RendererResult<()> {
        match &self.pin {
            Some(pin) => pin.check(url),
            None => Ok(()),
        }
    }
}
