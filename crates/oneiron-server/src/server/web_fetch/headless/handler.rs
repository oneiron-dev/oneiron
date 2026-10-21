//! A render's custody of its pages' requests (FIX 7122, FIX 7332): each
//! HTTP(S) request the browser pauses (a navigation, a redirect hop, a
//! subresource) is performed here as one request, never followed past a
//! redirect, and its answer goes back as the server sent it, a 3xx with its
//! `Location` included. Its client uses no proxy. On a managed node it
//! resolves every name through the render's guard, as the engine's
//! single-hop client does, and connects only to the addresses the guard
//! admitted; an address-literal request resolves nothing, so it is checked
//! here before it is sent. A refusal is kept for the render and answered as
//! the host's destination refusal, in the engine's words; any other failure
//! fails only its request.
//!
//! The client is asynchronous, driven on the server's runtime from the
//! browser's own worker thread, so that the render's end cancels a request
//! still in flight, and the render answers without waiting on a page server
//! that never answers.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use oneiron::web_fetch::{
    HOSTED_INFRASTRUCTURE_REASON, HostedEgressGuard, HostedInfrastructureRefusal, RendererError,
};
use oneiron_browser::{BrowserError, BrowserRequestHandler, DestinationRefusal};
use oneiron_container::{HttpRequest, HttpResponse};
use reqwest::Url;

use super::Operation;

/// Request headers the client sets itself, or that frame one hop only: they
/// are not passed on, as the run's egress door passes none of them.
const CLIENT_REQUEST_HEADERS: [&str; 6] = [
    "host",
    "connection",
    "proxy-authorization",
    "transfer-encoding",
    "content-length",
    "accept-encoding",
];

/// Response headers that framed the bytes as they crossed, not as they are
/// handed back (the client decodes the encodings it asked for).
const HOP_RESPONSE_HEADERS: [&str; 4] = [
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "connection",
];

/// Performs a render's page requests.
pub(super) struct PageRequests {
    operation: Arc<Operation>,
    client: reqwest::Client,
    runtime: tokio::runtime::Handle,
}

/// Why a page request has no answer.
pub(super) enum Unanswered {
    /// The render's guard refused its destination; the render keeps the
    /// refusal.
    Refused,
    /// Any other failure, in words that name no URL.
    Failed(String),
}

impl Unanswered {
    fn failed(detail: impl std::fmt::Display) -> Self {
        Self::Failed(detail.to_string())
    }
}

impl PageRequests {
    /// The render's page requests, sent on `runtime`: through a client with
    /// no proxy, following no redirect, whose names resolve through the
    /// render's guard where it has one.
    pub(super) fn new(
        operation: Arc<Operation>,
        runtime: tokio::runtime::Handle,
    ) -> reqwest::Result<Self> {
        let builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none());
        let builder = match &operation.guard {
            Some(guard) => builder.dns_resolver(Arc::new(GuardedResolver(Arc::clone(guard)))),
            None => builder,
        };
        let client = builder.build()?;
        Ok(Self {
            operation,
            client,
            runtime,
        })
    }

    /// Performs `request` as one hop, unless the render ends first: its end
    /// cancels the request, which then fails.
    pub(super) fn perform(&self, request: HttpRequest) -> Result<HttpResponse, Unanswered> {
        let Some(_running) = self.operation.begin() else {
            return Err(Unanswered::failed("the render has ended"));
        };
        let mut stopped = self.operation.stopped();
        self.runtime.block_on(async {
            tokio::select! {
                answer = self.send(request) => answer,
                _ = stopped.wait_for(|stopped| *stopped) => {
                    Err(Unanswered::failed("the render ended before its answer"))
                }
            }
        })
    }

    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, Unanswered> {
        let url = Url::parse(&request.url).map_err(Unanswered::failed)?;
        // An address literal resolves nothing, so the client's guard never
        // sees it: it is checked here, before anything is sent.
        let literal = url
            .host_str()
            .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
            .and_then(|host| host.parse::<IpAddr>().ok());
        if let Some(ip) = literal {
            self.operation
                .check(&request.url, ip)
                .map_err(|_| Unanswered::Refused)?;
        }
        let method =
            reqwest::Method::from_bytes(request.method.as_bytes()).map_err(Unanswered::failed)?;
        let mut builder = self.client.request(method, url).body(request.body);
        for (name, value) in &request.headers {
            if !CLIENT_REQUEST_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                builder = builder.header(name, value);
            }
        }
        let response = builder
            .send()
            .await
            .map_err(|error| self.unanswered(error))?;
        let url = response.url().to_string();
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter(|(name, _)| !HOP_RESPONSE_HEADERS.contains(&name.as_str()))
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.to_string(), value.to_owned()))
            })
            .collect();
        let body = response
            .bytes()
            .await
            .map_err(|error| self.unanswered(error))?;
        Ok(HttpResponse {
            url,
            status,
            headers,
            body: body.to_vec(),
        })
    }

    /// `error`, a refusal where the render's guard failed its connection,
    /// which the render then keeps.
    fn unanswered(&self, error: reqwest::Error) -> Unanswered {
        if guard_refused(&error) {
            self.operation.refuse(RendererError::hosted_infrastructure(
                HostedInfrastructureRefusal.to_string(),
            ));
            Unanswered::Refused
        } else {
            Unanswered::failed(error.without_url())
        }
    }
}

impl BrowserRequestHandler for PageRequests {
    /// A refusal answers the host's destination refusal: the hosted
    /// infrastructure reason, in the engine's own words.
    fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, BrowserError> {
        self.perform(request)
            .map_err(|unanswered| match unanswered {
                Unanswered::Refused => BrowserError::DestinationRefused(DestinationRefusal {
                    reason: HOSTED_INFRASTRUCTURE_REASON.to_owned(),
                    message: HostedInfrastructureRefusal.to_string(),
                }),
                Unanswered::Failed(detail) => BrowserError::Navigation(detail),
            })
    }
}

/// Whether the render's guard failed `error`'s connection: the typed
/// refusal its resolver gave is in the error's chain. Never read from words.
fn guard_refused(error: &reqwest::Error) -> bool {
    std::iter::successors(std::error::Error::source(error), |&source| source.source()).any(
        |source| {
            source.is::<HostedInfrastructureRefusal>()
                || source
                    .downcast_ref::<io::Error>()
                    .and_then(io::Error::get_ref)
                    .is_some_and(|inner| inner.is::<HostedInfrastructureRefusal>())
        },
    )
}

/// A guarded render's resolver: every name its client connects to resolves
/// here, and a name with any address the guard refuses fails its connection
/// with the typed refusal; the connection goes only to the addresses just
/// admitted, as the engine's guarded client resolves.
struct GuardedResolver(Arc<HostedEgressGuard>);

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(resolve_admitted(
            Arc::clone(&self.0),
            name.as_str().to_owned(),
        ))
    }
}

async fn resolve_admitted(
    guard: Arc<HostedEgressGuard>,
    host: String,
) -> Result<reqwest::dns::Addrs, Box<dyn std::error::Error + Send + Sync>> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
    if guard.refuses_any(addresses.iter().map(SocketAddr::ip)) {
        return Err(Box::new(HostedInfrastructureRefusal));
    }
    Ok(Box::new(addresses.into_iter()))
}
