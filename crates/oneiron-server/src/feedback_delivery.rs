//! Deployment-selected feedback transport. Every send still crosses the core consent gate.
use oneiron::feedback::{
    FeedbackSendRoute, FeedbackTransport, FeedbackTransportRequest, REPORT_SIGNATURE_VERB,
    ReportPublisherEndpoint, ReportSignatureTransport, ReportSignatureTransportRequest,
};
use oneiron::outbound::{OutboundExecutionOutcome, OutboundExecutionRequest};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackDestination {
    Cloud,
    Collector,
    GithubIssue,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedbackDeliveryConfig {
    pub destination: FeedbackDestination,
    /// Exact destination, displayed in the approval card. Redirects are disabled.
    pub endpoint: String,
}
impl FeedbackDeliveryConfig {
    pub fn route(&self) -> FeedbackSendRoute {
        let channel = match self.destination {
            FeedbackDestination::Cloud => "feedback_cloud",
            FeedbackDestination::Collector => "feedback_collector",
            FeedbackDestination::GithubIssue => "feedback_github",
        };
        FeedbackSendRoute::new(channel, "send", &self.endpoint)
    }
}
/// The feedback destination `serve` runs with, and its credential.
pub struct FeedbackHost {
    pub config: FeedbackDeliveryConfig,
    pub bearer: Option<Zeroizing<String>>,
}
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum FeedbackDeliveryError {
    #[error("feedback endpoint must be HTTPS (or a loopback test endpoint)")]
    InvalidEndpoint,
    #[error("transport destination differs from the approved route")]
    RouteMismatch,
    #[error("feedback request failed")]
    Network,
    #[error("feedback destination returned HTTP {0}")]
    Http(u16),
}
/// What one POST carries: an approved bundle, or a content-free issue
/// signature (OF-420). Both ride one client, one exact route and one outcome
/// mapping.
#[derive(Clone, Copy)]
enum FeedbackWirePayload<'a> {
    Bundle {
        bytes: &'a [u8],
        digest: &'a str,
        encoding: &'static str,
    },
    IssueSignature {
        body: &'a [u8],
        digest: &'a str,
    },
}
pub struct HttpFeedbackTransport {
    config: FeedbackDeliveryConfig,
    client: reqwest::blocking::Client,
    bearer: Option<Zeroizing<String>>,
    last_error: Option<FeedbackDeliveryError>,
}
/// An endpoint a send can use: HTTPS (HTTP only on loopback), with no
/// credentials, query or fragment in the URL.
pub fn check_endpoint(endpoint: &str) -> Result<(), FeedbackDeliveryError> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| FeedbackDeliveryError::InvalidEndpoint)?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(FeedbackDeliveryError::InvalidEndpoint);
    }
    Ok(())
}
impl HttpFeedbackTransport {
    pub fn new(
        config: FeedbackDeliveryConfig,
        bearer: Option<Zeroizing<String>>,
    ) -> Result<Self, FeedbackDeliveryError> {
        check_endpoint(&config.endpoint)?;
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| FeedbackDeliveryError::Network)?;
        Ok(Self {
            config,
            client,
            bearer,
            last_error: None,
        })
    }
    pub fn last_error(&self) -> Option<&FeedbackDeliveryError> {
        self.last_error.as_ref()
    }
    fn deliver(
        &self,
        execution: &OutboundExecutionRequest<'_>,
        payload: FeedbackWirePayload<'_>,
    ) -> Result<String, FeedbackDeliveryError> {
        let route = self.config.route();
        let (verb, digest) = match payload {
            FeedbackWirePayload::Bundle { digest, .. } => (route.verb.as_str(), digest),
            FeedbackWirePayload::IssueSignature { digest, .. } => (REPORT_SIGNATURE_VERB, digest),
        };
        let intent = execution.intent;
        if intent.channel != route.channel || intent.verb != verb || intent.target != route.target {
            return Err(FeedbackDeliveryError::RouteMismatch);
        }
        if execution.space_posting.is_some() {
            return Err(FeedbackDeliveryError::RouteMismatch);
        }
        let github = self.config.destination == FeedbackDestination::GithubIssue;
        // A GitHub issue destination takes no signatures: each would open a
        // public issue, and nothing there deduplicates a retried POST.
        if github && matches!(payload, FeedbackWirePayload::IssueSignature { .. }) {
            return Err(FeedbackDeliveryError::RouteMismatch);
        }
        let mut post = self
            .client
            .post(&self.config.endpoint)
            .header("User-Agent", "oneiron-feedback")
            .header("Idempotency-Key", execution.intent_ref);
        post = match payload {
            FeedbackWirePayload::Bundle { encoding, .. } => post
                .header("X-Oneiron-Bundle-Digest", digest)
                // The token travels beside the bytes, so a receiver never guesses
                // which shape it was handed.
                .header("X-Oneiron-Bundle-Encoding", encoding),
            FeedbackWirePayload::IssueSignature { .. } => {
                post.header("X-Oneiron-Signature-Digest", digest)
            }
        };
        if let Some(token) = &self.bearer {
            post = post.bearer_auth(token.as_str());
        }
        post = match payload {
            FeedbackWirePayload::Bundle {
                bytes, encoding, ..
            } if github => {
                use base64::Engine;
                let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
                // Binary MessagePack survives the issue API's text-only body exactly.
                let body = serde_json::json!({"title":format!("Feedback {digest}"),
                    "body":format!("{encoding}\n```base64\n{encoded}\n```")});
                post.header("Content-Type", "application/json")
                    .body(body.to_string())
            }
            FeedbackWirePayload::Bundle { bytes, .. } => post
                .header("Content-Type", "application/msgpack")
                .body(bytes.to_vec()),
            FeedbackWirePayload::IssueSignature { body, .. } => post
                .header("Content-Type", "application/json")
                .body(body.to_vec()),
        };
        let response = post.send().map_err(|_| FeedbackDeliveryError::Network)?;
        if !response.status().is_success() {
            return Err(FeedbackDeliveryError::Http(response.status().as_u16()));
        }
        Ok(digest.to_owned())
    }

    /// The ordinary execution outcome of one POST. A client rejection proves
    /// non-delivery, except timeouts and operation conflicts: either can
    /// follow an accepted send. Network, redirect and server failures remain
    /// indeterminate.
    fn outcome(
        &mut self,
        delivered: Result<String, FeedbackDeliveryError>,
    ) -> OutboundExecutionOutcome {
        self.last_error = None;
        match delivered {
            Ok(reference) => OutboundExecutionOutcome::delivered_to_channel(reference),
            Err(error) => {
                let mut outcome = OutboundExecutionOutcome::failed(error.to_string());
                let possible_delivery = match error {
                    FeedbackDeliveryError::Network => true,
                    FeedbackDeliveryError::Http(status) => {
                        !(400..500).contains(&status) || matches!(status, 408 | 409)
                    }
                    _ => false,
                };
                if possible_delivery {
                    outcome = outcome.with_possible_delivery();
                }
                self.last_error = Some(error);
                outcome
            }
        }
    }
}
impl FeedbackTransport for HttpFeedbackTransport {
    fn send_feedback_bundle(
        &mut self,
        request: &FeedbackTransportRequest<'_>,
    ) -> OutboundExecutionOutcome {
        let delivered = self.deliver(
            request.execution,
            FeedbackWirePayload::Bundle {
                bytes: request.bundle_bytes,
                digest: request.bundle_digest,
                encoding: request.bundle_encoding,
            },
        );
        self.outcome(delivered)
    }
}
/// The typed adapter for a content-free issue signature (OF-420): the same
/// client, exact route, disabled redirects, `Idempotency-Key` and
/// possible-delivery mapping as a bundle, on the `signature` verb.
impl ReportSignatureTransport for HttpFeedbackTransport {
    fn destination(&self) -> Option<ReportPublisherEndpoint> {
        let route = self.config.route();
        Some(ReportPublisherEndpoint {
            channel: route.channel,
            endpoint: route.target,
        })
    }

    fn send_issue_signature(
        &mut self,
        request: &ReportSignatureTransportRequest<'_>,
    ) -> OutboundExecutionOutcome {
        let delivered = self.deliver(
            request.execution,
            FeedbackWirePayload::IssueSignature {
                body: request.body,
                digest: request.digest,
            },
        );
        self.outcome(delivered)
    }
}

#[cfg(test)]
mod tests;

#[derive(Debug, thiserror::Error)]
pub enum SendFeedbackError {
    #[error(transparent)]
    ApprovalOrDispatch(#[from] oneiron::feedback::FeedbackError),
    #[error(transparent)]
    Delivery(#[from] FeedbackDeliveryError),
}
/// Sends only to the configured destination. The caller approves the exact
/// route returned by `config.route()`; changing configuration invalidates that
/// approval. The send is `owner`'s and is admitted only while `owner`'s proof
/// still holds where it is admitted. Transport errors are typed after the
/// ordinary failure receipt is persisted. This blocking door belongs on the
/// host's blocking worker.
pub fn send_approved_feedback(
    vault: &oneiron::Vault,
    config: FeedbackDeliveryConfig,
    bearer: Option<Zeroizing<String>>,
    preview: &oneiron::feedback::FeedbackPreview,
    evaluation: &oneiron::genui::ConsentActionEvaluation,
    owner: &oneiron::consent::AuthenticatedOwner,
    now: u64,
) -> Result<oneiron::feedback::FeedbackSendOutcome, SendFeedbackError> {
    let owner_actor = owner.revalidate(vault).map_err(|_| {
        oneiron::feedback::FeedbackError::ApprovalNotGranted {
            outcome: "owner_not_authenticated",
        }
    })?;
    let actor = oneiron::outbound::OutboundDispatchActor {
        actor_class: "human".to_owned(),
        actor_ref: Some(owner_actor.to_hex()),
        actor_entity_ref: Some(owner_actor),
    };
    let context = oneiron::feedback::FeedbackSendContext::new(
        config.route(),
        actor,
        now,
        oneiron::outbound::OutboundDeliveryWindowDecision::DeliverNow,
    )
    .approved_by(owner.clone());
    // Validate before building a client or reading transport credentials.
    oneiron::feedback::feedback_dispatch_request(preview, &context, evaluation)?;
    let mut transport = HttpFeedbackTransport::new(config, bearer)?;
    let result =
        oneiron::feedback::send_feedback(vault, preview, &context, evaluation, &mut transport)?;
    if let Some(error) = transport.last_error {
        return Err(error.into());
    }
    Ok(result)
}
