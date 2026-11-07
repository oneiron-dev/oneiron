//! The owner's content-free failure-signal delivery diagnostics.

use oneiron::failure_signals::FailureSignalDeliveryStatus;
use serde::Serialize;

use super::OwnerResult;
use crate::server::SyncServer;

#[derive(Serialize)]
pub(crate) struct FailureSignalStatus {
    /// Configured publisher host, not the path or credentials and not proof
    /// that a sender is currently connected.
    destination_host: Option<String>,
    #[serde(flatten)]
    delivery: FailureSignalDeliveryStatus,
}

pub(crate) fn status(server: &SyncServer) -> OwnerResult<FailureSignalStatus> {
    let hosted = server.managed_issuer.is_some()
        || server.config.privacy_posture == oneiron::HostingPrivacyPosture::Hosted;
    let destination_host = server
        .config
        .failure_signals
        .destination(hosted)
        .and_then(|endpoint| reqwest::Url::parse(&endpoint).ok())
        .and_then(|url| url.host_str().map(str::to_owned));
    Ok(FailureSignalStatus {
        destination_host,
        delivery: server.vault().failure_signal_delivery_status()?,
    })
}
