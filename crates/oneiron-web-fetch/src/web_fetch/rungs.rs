//! The built-in rungs' [`Renderer`] impls. The parent owns their types and
//! constructors; this module owns what each does on the wire.
//!
//! The ladder runs each rung in the page's [`RenderContext`]: a same-site
//! crawl's pinned origin (FIX 4734) and, on a managed (hosted) node, its
//! egress guard (SCAN C447, FIX 6101); it checks the navigation-final URL
//! every rung hands back. What each rung adds on top:
//! - readability: its client follows no redirect, so the rung follows each
//!   hop itself, and checks it before it is resolved or sent: credential-free
//!   http(s), inside the pinned origin, within the hop ceiling and no loop,
//!   and by the guard's address-literal and operator-origin rules. The
//!   client's resolver checks every address it connects to with the guard,
//!   and the rung checks the address each response actually came from before
//!   reading it, so a re-resolved (rebound) address is refused too; a private
//!   one passes only at an operator's private origin (FIX 7657).
//! - headless: the host browser receives the context and holds each
//!   navigation, redirect and request it makes to it
//!   ([`HeadlessRenderer::render_html`](super::HeadlessRenderer::render_html)).
//! - Firecrawl: the service resolves names and follows redirects inside its
//!   own process, so no hop or address it reaches can be checked from here,
//!   and no page of a same-site crawl goes to it. Checked: the requested URL
//!   before it is written into the scrape request, and the navigation-final
//!   URL the envelope reports (`metadata.url`) after. An envelope without
//!   `metadata.url` leaves the landing unwitnessed. The configured scrape
//!   endpoint is host configuration, never checked.

use std::collections::BTreeSet;

use reqwest::StatusCode;
use reqwest::Url;
use reqwest::blocking::Response;

use super::render::{
    FirecrawlScrapeEnvelope, FirecrawlScrapeRequest, decode_response_body, extract_readable_page,
    read_capped_body, redact_url_credentials, redirect_destination, redirect_target,
    renderer_final_url, renderer_request_target, renderer_request_url, transport_failure,
};
use super::{
    FirecrawlRenderer, NativeHeadlessRenderer, NativeReadabilityRenderer, RenderContext,
    RenderedPage, Renderer, RendererError, RendererKind, RendererResult,
};

/// How many redirect hops one readability GET follows before it fails
/// closed: reqwest's own default ceiling, kept now that the rung follows
/// each hop itself (FIX 4734).
const MAX_REDIRECT_HOPS: usize = 10;

impl NativeReadabilityRenderer {
    /// One GET of `url` in `context`, each redirect hop followed here as its
    /// own request (FIX 4734). The page and each hop are held to the
    /// context's pinned origin before anything resolves or sends them. With
    /// a managed node's guard, the address each response came from is
    /// checked before anything of it is read (FIX 6101). A redirect's body
    /// is never read as a page.
    fn get(&self, url: &str, context: &RenderContext) -> RendererResult<RenderedPage> {
        let mut target = renderer_request_target(url)?;
        context.admit_hop(&target)?;
        let mut chain = BTreeSet::from([target.to_string()]);
        loop {
            // A transport failure is rendered through the redaction seam: the
            // URL inside a `reqwest` error is the hop's, which may be a
            // peer's `Location`. A refusal by the guard's resolver comes back
            // typed.
            let response = self
                .client
                .get(target)
                .send()
                .map_err(|error| transport_failure("web fetch GET failed", error))?;
            if let Some(guard) = context.hosted_guard() {
                guard.admit_peer(response.remote_addr(), response.url())?;
            }
            if !is_followed_redirect(response.status()) {
                return self.read_page(response);
            }
            target = next_hop(&response, &mut chain, context)?;
        }
    }

    /// The page a response that is no followed redirect carries: refused
    /// unless 2xx, then its body read under the ceiling, decoded and
    /// extracted.
    fn read_page(&self, response: Response) -> RendererResult<RenderedPage> {
        // A 3xx this rung does not follow, like any other non-2xx, is not the
        // requested page. Require the complete 2xx class explicitly before
        // any response content is read.
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

/// Whether `status` is a redirect the readability rung follows: 301, 302,
/// 303, 307 and 308, as reqwest's default policy did.
fn is_followed_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

/// The next hop of a redirect `response`, admitted before anything resolves
/// or sends it (FIX 4734). Its `Location` is resolved; on a managed node the
/// guard's address-literal and operator-origin rules judge where it goes
/// first, whatever credentials or scheme it carries, and a refusal ends the
/// ladder typed (FIX 6101, FIX 7657). Then it must be credential-free
/// http(s), a refusal that ends the page's ladder too; inside the context's
/// pinned origin; within [`MAX_REDIRECT_HOPS`] of the requested page; and
/// new to `chain`, the URLs requested so far, which it joins. The client's
/// resolver checks a named hop's addresses as it connects.
fn next_hop(
    response: &Response,
    chain: &mut BTreeSet<String>,
    context: &RenderContext,
) -> RendererResult<Url> {
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .map(reqwest::header::HeaderValue::as_bytes);
    let destination = redirect_destination(response.url(), location)?;
    if let Some(guard) = context.hosted_guard()
        && let Some(refused) = guard.refuses_hop(&destination)
    {
        return Err(refused.request_error(destination.as_str()));
    }
    let next = redirect_target(&destination)?;
    context.admit_hop(&next)?;
    let shown = redact_url_credentials(next.as_str());
    if chain.len() > MAX_REDIRECT_HOPS {
        return Err(RendererError::transport(format!(
            "web fetch GET was redirected more than {MAX_REDIRECT_HOPS} times (next hop {shown})"
        )));
    }
    if !chain.insert(next.to_string()) {
        return Err(RendererError::transport(format!(
            "web fetch GET was redirected in a loop (back to {shown})"
        )));
    }
    Ok(next)
}

impl Renderer for NativeReadabilityRenderer {
    fn kind(&self) -> RendererKind {
        RendererKind::Readability
    }

    fn render(&self, url: &str, context: &RenderContext) -> RendererResult<RenderedPage> {
        self.get(url, context)
    }
}

impl Renderer for NativeHeadlessRenderer {
    fn kind(&self) -> RendererKind {
        RendererKind::Headless
    }

    /// One host browser navigation in `context`, which the browser holds
    /// every navigation, redirect and request it makes to (FIX 4734,
    /// FIX 6101).
    fn render(&self, url: &str, context: &RenderContext) -> RendererResult<RenderedPage> {
        // The host browser is a network boundary like any other, so the same
        // pre-transport checks apply before a URL is handed to it.
        let target = renderer_request_target(url)?;
        context.admit_hop(&target)?;
        let document = self.headless.render_html(target.as_str(), context)?;
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

/// The scrape service reaches the target itself, so the ladder's checks of
/// the requested URL and of the reported navigation-final URL are all a
/// managed node can apply, and a same-site crawl's page is never sent to it
/// (see the module docs).
impl Renderer for FirecrawlRenderer {
    fn kind(&self) -> RendererKind {
        RendererKind::Firecrawl
    }

    fn render(&self, url: &str, context: &RenderContext) -> RendererResult<RenderedPage> {
        // The ladder records a same-site crawl's page as unsupported here
        // before this runs; a direct caller is refused before the target is
        // written into a request (FIX 4734).
        if context.is_same_site_crawl() {
            return Err(RendererError::cross_site_redirect(
                "firecrawl follows redirects on its service, where a same-site crawl cannot hold them to its pinned origin; refused before the scrape request",
            ));
        }
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
