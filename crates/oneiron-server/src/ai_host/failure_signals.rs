//! The host's failure-signal sender (OF-380). Every pass hands the engine's
//! delivery door one batch, the tier-1 counts and the sealed code-fix
//! records, to POST to the configured publisher. The door decides whether
//! the owner's "Help improve Oneiron" switch is on, sends through the
//! outbound pipeline, and acks only what was delivered, so a pass that fails
//! loses nothing. This transport carries the bytes and judges nothing.
//!
//! Before it picks the sender, the host keeps the participation grant in
//! step with the switch once (FIX 1884): a deployment that stopped exporting
//! has its grant revoked even when no destination is configured and no
//! sender runs. That pass sends nothing.
use std::sync::Arc;
use std::time::Duration;

use oneiron::failure_signals::{
    FAILURE_SIGNALS_CHANNEL, FAILURE_SIGNALS_SEND_VERB, FailureSignalDelivery,
    FailureSignalTransport, FailureSignalTransportRequest,
};
use oneiron::outbound::{OutboundDispatchError, OutboundExecutionOutcome};
use zeroize::Zeroizing;

use crate::config::FailureSignalsConfig;
use crate::server::{HousekeepingAdmission, SyncServer};

/// Where this host sends, and with what credential.
pub(crate) struct FailureSignalHost {
    endpoint: String,
    bearer: Option<Zeroizing<String>>,
    every: Duration,
    batch: usize,
}

impl FailureSignalHost {
    /// The sender `config` describes; `None` when it names no destination.
    /// `hosted` takes our collector by default.
    pub(crate) fn new(
        config: &FailureSignalsConfig,
        hosted: bool,
        bearer: Option<Zeroizing<String>>,
    ) -> Option<Self> {
        Some(Self {
            endpoint: config.destination(hosted)?,
            bearer,
            every: Duration::from_secs(config.every_secs),
            batch: config.batch,
        })
    }
}

/// Keeps the participation grant in step once (FIX 1884), then starts the
/// sender when there is somewhere to send. Each pass, the grant's too, is
/// admitted through `admit`, the way a housekeeping pass is, and runs on a
/// blocking thread: the transport is a blocking client.
pub(crate) fn spawn(
    server: &Arc<SyncServer>,
    host: Option<FailureSignalHost>,
    admit: HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(server);
    tokio::spawn(async move {
        if let Some(server) = weak.upgrade()
            && let Some(admission) = admit()
        {
            reconcile(server, admission).await;
        }
        let Some(host) = host.map(Arc::new) else {
            return;
        };
        let mut tick = tokio::time::interval(host.every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            let Some(admission) = admit() else {
                continue;
            };
            let host = Arc::clone(&host);
            let pass = tokio::task::spawn_blocking(move || {
                let _admission = admission;
                deliver(&server, &host)
            })
            .await;
            match pass {
                Ok(Ok(FailureSignalDelivery::NotDelivered { outcome })) => {
                    tracing::warn!(
                        outcome = outcome.as_str(),
                        "failure signals wait for the next pass"
                    );
                }
                // By kind only: an engine error can quote the vault.
                Ok(Err(error)) => {
                    let kind = match &error {
                        OutboundDispatchError::Engine(error) => Some(error.kind()),
                        _ => None,
                    };
                    tracing::warn!(?kind, "failure signal pass stopped");
                }
                Err(error) => tracing::warn!(%error, "failure signal pass panicked"),
                Ok(Ok(_)) => {}
            }
        }
    })
}

/// The participation grant kept in step with the switch, once, with no
/// transport (FIX 1884). A failure is logged by kind and never stops the
/// sender, whose every pass keeps the grant in step too.
async fn reconcile(server: Arc<SyncServer>, admission: Box<dyn Send>) {
    let pass = tokio::task::spawn_blocking(move || {
        let _admission = admission;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_secs());
        server.vault().reconcile_failure_signal_participation(now)
    })
    .await;
    match pass {
        Ok(Ok(())) => {}
        // By kind only: an engine error can quote the vault.
        Ok(Err(error)) => {
            tracing::warn!(kind = ?error.kind(), "failure signal participation was not reconciled");
        }
        Err(error) => tracing::warn!(%error, "failure signal participation pass panicked"),
    }
}

fn deliver(
    server: &SyncServer,
    host: &FailureSignalHost,
) -> Result<FailureSignalDelivery, OutboundDispatchError> {
    let mut transport = HttpFailureSignalTransport::new(host)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_secs());
    server
        .vault()
        .deliver_failure_signals(&host.endpoint, host.batch, now, &mut transport)
}

struct HttpFailureSignalTransport<'a> {
    host: &'a FailureSignalHost,
    client: reqwest::blocking::Client,
}

impl<'a> HttpFailureSignalTransport<'a> {
    fn new(host: &'a FailureSignalHost) -> oneiron::Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| oneiron::Error::InvariantViolation("failure signal client"))?;
        Ok(Self { host, client })
    }
}

impl FailureSignalTransport for HttpFailureSignalTransport<'_> {
    fn send_failure_signals(
        &mut self,
        request: &FailureSignalTransportRequest<'_>,
    ) -> OutboundExecutionOutcome {
        let intent = request.execution.intent;
        if intent.channel != FAILURE_SIGNALS_CHANNEL
            || intent.verb != FAILURE_SIGNALS_SEND_VERB
            || intent.target != self.host.endpoint
        {
            return OutboundExecutionOutcome::failed("route_mismatch");
        }
        let mut post = self
            .client
            .post(&self.host.endpoint)
            .header("User-Agent", "oneiron-failure-signals")
            .header("Idempotency-Key", request.execution.intent_ref)
            .header("X-Oneiron-Batch-Digest", request.digest)
            .header("Content-Type", "application/json")
            .body(request.body.to_vec());
        if let Some(token) = &self.host.bearer {
            post = post.bearer_auth(token.as_str());
        }
        match post.send() {
            Ok(response) if response.status().is_success() => {
                OutboundExecutionOutcome::delivered_to_channel(request.digest)
            }
            // A client rejection proves non-delivery, except timeouts and
            // conflicts: either can follow an accepted send.
            Ok(response) => {
                let status = response.status().as_u16();
                let outcome = OutboundExecutionOutcome::failed(format!("http_{status}"));
                if (400..500).contains(&status) && !matches!(status, 408 | 409) {
                    outcome
                } else {
                    outcome.with_possible_delivery()
                }
            }
            Err(_) => OutboundExecutionOutcome::failed("network").with_possible_delivery(),
        }
    }
}
