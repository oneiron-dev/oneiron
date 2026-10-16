//! The server's direct Linear GraphQL mirror, using the production adapter.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use oneiron::LinearSyncError;
use oneiron::linear_sync::ServedLinearEgress;
use oneiron::outbound::{OutboundDispatchActor, OutboundDispatchGate, OutboundDispatchPolicyRisk};
use oneiron_linear::{
    HttpLinearClient, LinearHostChangeSource, LinearHostEgress, LinearTrackerConfig,
    VaultLinearOutboundDoor,
};
use serde::Deserialize;

use crate::server::SyncServer;

/// Non-secret host configuration at ONEIRON_LINEAR_CONFIG. The response
/// directory is private host custody, outside the replicated vault graph.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectConfig {
    team_id: String,
    status_ids: BTreeMap<String, String>,
    assignee_ids: BTreeMap<String, String>,
    page_size: u32,
    response_dir: PathBuf,
}

impl DirectConfig {
    fn tracker(&self) -> LinearTrackerConfig {
        LinearTrackerConfig {
            team_id: self.team_id.clone(),
            status_ids: self.status_ids.clone(),
            assignee_ids: self.assignee_ids.clone(),
            page_size: self.page_size,
        }
    }
}

pub(super) async fn spawn(
    server: Arc<SyncServer>,
    api_key: String,
    config_path: PathBuf,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    super::validate_server_auth(
        true,
        server.config.auth_secret.as_deref(),
        server.config.allow_unauthenticated,
    )?;
    let scheduler = super::scheduler_actor(std::env::var("ONEIRON_LINEAR_SCHEDULER_ACTOR").ok())?;
    let config =
        crate::logging::off_runtime("Linear direct setup", move || -> anyhow::Result<_> {
            let config: DirectConfig = serde_json::from_slice(&std::fs::read(config_path)?)?;
            config.tracker().validate()?;
            anyhow::ensure!(
                config.response_dir.is_absolute() && config.response_dir.is_dir(),
                "Linear response_dir must name an existing absolute host-private directory"
            );
            Ok(config)
        })
        .await??;
    let policy = server.vault().linear_mirror_policy()?;
    // Validate the credential and TLS client off the async runtime before start.
    let timeout = Duration::from_secs(policy.request_timeout_secs);
    let api_key = crate::logging::off_runtime("Linear direct client", move || {
        HttpLinearClient::with_timeout(&api_key, timeout).map(|_| api_key)
    })
    .await??;
    Ok(Some(tokio::spawn(async move {
        let mut wait = Duration::ZERO;
        let mut interval = policy.poll_interval_secs;
        loop {
            tokio::time::sleep(wait).await;
            let vault = Arc::clone(server.vault());
            let key = api_key.clone();
            let tracker = config.tracker();
            let responses = config.response_dir.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                let policy = vault
                    .linear_mirror_policy()
                    .map_err(LinearSyncError::Store)?;
                let budget = vault.linear_sync_budget().map_err(LinearSyncError::Store)?;
                let client = HttpLinearClient::with_timeout(
                    &key,
                    Duration::from_secs(policy.request_timeout_secs),
                )?;
                let inbound = LinearHostChangeSource::new(client.clone(), tracker.clone())?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |time| time.as_secs());
                let door = VaultLinearOutboundDoor::new(
                    &vault,
                    client,
                    responses,
                    OutboundDispatchActor {
                        actor_class: "system".to_owned(),
                        actor_ref: Some(scheduler.to_hex()),
                        actor_entity_ref: Some(scheduler),
                    },
                    OutboundDispatchGate {
                        has_opted_in: false,
                        has_permission: true,
                        policy_risk: OutboundDispatchPolicyRisk::Normal,
                    },
                    now,
                )?;
                let outbound = ServedLinearEgress::new(
                    &vault,
                    scheduler,
                    LinearHostEgress::new(door, tracker)?,
                );
                let result = super::synchronize_once(
                    &vault,
                    inbound,
                    outbound,
                    now,
                    budget.max_pull_pages_per_pass,
                )?;
                Ok::<_, LinearSyncError>((result, policy.poll_interval_secs))
            })
            .await;
            match outcome {
                Ok(Ok(((pushed, pulled), next_interval))) => {
                    interval = next_interval;
                    tracing::debug!(
                        pushed = pushed.len(),
                        pulled = pulled.applied,
                        "Linear direct mirror pass"
                    );
                }
                Ok(Err(LinearSyncError::RemoteChanged)) => {
                    // Linear has no atomic conditional issueUpdate input. Keep
                    // the dirty revision rather than silently overwrite a race.
                    tracing::warn!(
                        reason = "linear_conditional_update_unavailable",
                        "Linear update remains pending"
                    );
                }
                Ok(Err(_)) | Err(_) => {
                    tracing::warn!(
                        reason = "linear_sync_failed",
                        "Linear direct mirror pass failed; will retry"
                    );
                }
            }
            wait = Duration::from_secs(interval);
        }
    })))
}
