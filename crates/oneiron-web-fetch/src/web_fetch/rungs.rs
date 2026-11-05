//! The built-in rungs' [`Renderer`] impls. The parent owns their types and
//! constructors; this module owns what each does on the wire.
//!
//! On a managed (hosted) node the ladder runs each rung through
//! [`Renderer::render_guarded`] with its egress guard (SCAN C447, FIX 6101),
//! and checks the navigation-final URL every rung hands back. What each rung
//! adds on top:
//! - readability: the host's client checks every redirect hop and every
//!   address it resolves at connect time when the host built it with the guard
//!   (the managed default ladder is). Whatever client it was given, this rung
//!   checks the address the final response actually came from before reading
//!   its body, so a re-resolved (rebound) final address is refused too; a
//!   private one passes only when the final URL is at an operator's private
//!   origin (FIX 7657).
//! - headless: the host browser receives the guard for every navigation,
//!   redirect and request it makes
//!   ([`HeadlessRenderer::render_html_guarded`](super::HeadlessRenderer::render_html_guarded)).
//!   A browser adapter that keeps the default navigates unchecked, and only
//!   the requested URL and the browser-final URL are checked.
//! - Firecrawl: the service resolves names and follows redirects inside its
//!   own process, so no hop or address it reaches can be checked from here.
//!   Checked: the requested URL before it is written into the scrape request,
//!   and the navigation-final URL the envelope reports (`metadata.url`) after.
//!   An envelope without `metadata.url` leaves the landing unwitnessed. The
//!   configured scrape endpoint is host configuration, never checked.

use super::render::{
    FirecrawlScrapeEnvelope, FirecrawlScrapeRequest, decode_response_body, extract_readable_page,
    read_capped_body, redact_url_credentials, renderer_final_url, renderer_request_url,
    transport_failure,
};
use super::{
    FirecrawlRenderer, HostedEgressGuard, NativeHeadlessRenderer, NativeReadabilityRenderer,
    RenderedPage, Renderer, RendererError, RendererKind, RendererResult,
};

impl NativeReadabilityRenderer {
    /// One GET through the host's client. With a managed node's `guard`, the
    /// address the final response came from is checked before its body is
    /// read (FIX 6101).
    fn get(&self, url: &str, guard: Option<&HostedEgressGuard>) -> RendererResult<RenderedPage> {
        let target = renderer_request_url(url)?;
        // Both failures below are rendered through the redaction seam. The
        // check above admitted `target`, but the client may have followed a
        // redirect since, and the URL inside a `reqwest` error is then the
        // peer's `Location` — which nothing here has vouched for. A refusal by
        // the host's egress guard comes back typed.
        let response = self
            .client
            .get(target)
            .send()
            .map_err(|error| transport_failure("web fetch GET failed", error))?;
        if let Some(guard) = guard {
            guard.admit_peer(response.remote_addr(), response.url())?;
        }
        // `error_for_status` accepts 3xx. That is wrong when the injected client
        // disables redirects: a redirect body is not the requested page. Require
        // the complete 2xx class explicitly before any response content is read.
        if !response.status().is_success() {
            let status = response.status();
            let target = redact_url_credentials(response.url().as_str());
            return Err(RendererError::transport(format!(
                "web fetch GET returned status {status} (target {target})"
            )));
        }
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

impl Renderer for NativeReadabilityRenderer {
    fn kind(&self) -> RendererKind {
        RendererKind::Readability
    }

    fn render(&self, url: &str) -> RendererResult<RenderedPage> {
        self.get(url, None)
    }

    fn render_guarded(&self, url: &str, guard: &HostedEgressGuard) -> RendererResult<RenderedPage> {
        self.get(url, Some(guard))
    }
}

impl NativeHeadlessRenderer {
    /// One host browser navigation. With a managed node's `guard`, the
    /// browser receives it for every navigation it makes (FIX 6101).
    fn navigate(
        &self,
        url: &str,
        guard: Option<&HostedEgressGuard>,
    ) -> RendererResult<RenderedPage> {
        // The host browser is a network boundary like any other, so the same
        // pre-transport check applies before a URL is handed to it.
        let target = renderer_request_url(url)?;
        let document = match guard {
            Some(guard) => self.headless.render_html_guarded(&target, guard)?,
            None => self.headless.render_html(&target)?,
        };
        if !(200..300).contains(&document.status) {
            return Err(RendererError::transport(format!(
                "headless target returned status {}",
                document.status
            )));
        }
        let ceiling = self.max_response_bytes.get();
        if document.html.len() > ceiling {
            return Err(RendererError::invalid_response(format!(
                "headless rendered body exceeded the {ceiling} byte ceiling"
            )));
        }
        let final_url = renderer_final_url(&document.final_url)?;
        extract_readable_page(&document.html, &final_url)
    }
}

impl Renderer for NativeHeadlessRenderer {
    fn kind(&self) -> RendererKind {
        RendererKind::Headless
    }

    fn render(&self, url: &str) -> RendererResult<RenderedPage> {
        self.navigate(url, None)
    }

    fn render_guarded(&self, url: &str, guard: &HostedEgressGuard) -> RendererResult<RenderedPage> {
        self.navigate(url, Some(guard))
    }
}

/// Keeps the default [`Renderer::render_guarded`]: the scrape service reaches
/// the target itself, so the ladder's checks of the requested URL and of the
/// reported navigation-final URL are all a managed node can apply (see the
/// module docs).
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
            // The endpoint was checked credential-free at construction, but a
            // provider redirect can still put userinfo into the URL the error
            // carries, so this boundary redacts like the native one.
            .map_err(|error| transport_failure("firecrawl scrape request failed", error))?;
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
