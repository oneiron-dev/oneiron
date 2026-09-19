//! Deployment-selected feedback transport. Every send still crosses the core consent gate.
use oneiron::feedback::{FeedbackSendRoute, FeedbackTransport, FeedbackTransportRequest};
use oneiron::outbound::OutboundExecutionOutcome;
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
pub struct HttpFeedbackTransport {
    config: FeedbackDeliveryConfig,
    client: reqwest::blocking::Client,
    bearer: Option<Zeroizing<String>>,
    last_error: Option<FeedbackDeliveryError>,
}
impl HttpFeedbackTransport {
    pub fn new(
        config: FeedbackDeliveryConfig,
        bearer: Option<Zeroizing<String>>,
    ) -> Result<Self, FeedbackDeliveryError> {
        let url = reqwest::Url::parse(&config.endpoint)
            .map_err(|_| FeedbackDeliveryError::InvalidEndpoint)?;
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
        request: &FeedbackTransportRequest<'_>,
    ) -> Result<String, FeedbackDeliveryError> {
        let route = self.config.route();
        let intent = request.execution.intent;
        if intent.channel != route.channel
            || intent.verb != route.verb
            || intent.target != route.target
        {
            return Err(FeedbackDeliveryError::RouteMismatch);
        }
        let mut post = self
            .client
            .post(&self.config.endpoint)
            .header("User-Agent", "oneiron-feedback")
            .header("Idempotency-Key", request.execution.intent_ref)
            .header("X-Oneiron-Bundle-Digest", request.bundle_digest);
        if let Some(token) = &self.bearer {
            post = post.bearer_auth(token.as_str());
        }
        if self.config.destination == FeedbackDestination::GithubIssue {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(request.bundle_bytes);
            // Binary MessagePack survives the issue API's text-only body exactly.
            let body = serde_json::json!({"title":format!("Feedback {}",request.bundle_digest),
                "body":format!("{}\n```base64\n{}\n```",request.bundle_encoding,encoded)});
            post = post
                .header("Content-Type", "application/json")
                .body(body.to_string());
        } else {
            post = post
                .header("Content-Type", "application/msgpack")
                .body(request.bundle_bytes.to_vec());
        }
        let response = post.send().map_err(|_| FeedbackDeliveryError::Network)?;
        if !response.status().is_success() {
            return Err(FeedbackDeliveryError::Http(response.status().as_u16()));
        }
        Ok(request.bundle_digest.to_owned())
    }
}
impl FeedbackTransport for HttpFeedbackTransport {
    fn send_feedback_bundle(
        &mut self,
        request: &FeedbackTransportRequest<'_>,
    ) -> OutboundExecutionOutcome {
        self.last_error = None;
        match self.deliver(request) {
            Ok(reference) => OutboundExecutionOutcome::delivered_to_channel(reference),
            Err(error) => {
                let mut outcome = OutboundExecutionOutcome::failed(error.to_string());
                if matches!(
                    error,
                    FeedbackDeliveryError::Network | FeedbackDeliveryError::Http(_)
                ) {
                    outcome = outcome.with_possible_delivery();
                }
                self.last_error = Some(error);
                outcome
            }
        }
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
/// approval. Transport errors are typed after the ordinary failure receipt is
/// persisted. This blocking door belongs on the host's blocking worker.
pub fn send_approved_feedback(
    vault: &oneiron::Vault,
    config: FeedbackDeliveryConfig,
    bearer: Option<Zeroizing<String>>,
    preview: &oneiron::feedback::FeedbackPreview,
    evaluation: &oneiron::genui::ConsentActionEvaluation,
    actor: oneiron::outbound::OutboundDispatchActor,
    now: u64,
) -> Result<oneiron::feedback::FeedbackSendOutcome, SendFeedbackError> {
    let context = oneiron::feedback::FeedbackSendContext::new(
        config.route(),
        actor,
        now,
        oneiron::outbound::OutboundDeliveryWindowDecision::DeliverNow,
    );
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
