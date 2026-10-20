//! The server's direct Linear GraphQL mirror, using the production adapter.
use std::sync::Arc;
use std::time::Duration;

use oneiron::linear_sync::ServedLinearEgress;
use oneiron::outbound::{OutboundDispatchActor, OutboundDispatchGate, OutboundDispatchPolicyRisk};
use oneiron::{EntityId, LinearSyncError};
use oneiron_linear::{
    HttpLinearClient, LinearHostChangeSource, LinearHostEgress, LinearTrackerConfig,
    VaultLinearOutboundDoor,
};

use super::PassCredential;
use crate::config::LinearConfig;
use crate::server::{HousekeepingAdmission, SyncServer};

/// The direct mirror the checked `settings` name. The response directory is
/// private host custody, outside the replicated vault graph.
pub(super) async fn spawn(
    server: Arc<SyncServer>,
    settings: &LinearConfig,
    tracker: Option<LinearTrackerConfig>,
    scheduler: EntityId,
    credential: PassCredential,
    admit: HousekeepingAdmission,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    let tracker =
        tracker.ok_or_else(|| anyhow::anyhow!("a direct Linear mirror maps linear.team_id"))?;
    let endpoint = settings.graphql_endpoint()?;
    let response_dir = settings.response_dir.clone();
    let responses = crate::logging::off_runtime("Linear direct setup", move || {
        response_dir
            .filter(|dir| dir.is_absolute() && dir.is_dir())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Linear response_dir must name an existing absolute host-private directory"
                )
            })
    })
    .await??;
    let policy = server.vault().linear_mirror_policy()?;
    // Validate a key the environment holds, and the TLS client, off the
    // async runtime before start. A vault secret is read at each pass.
    let timeout = Duration::from_secs(policy.request_timeout_secs);
    if let PassCredential::Held(key) = &credential {
        let (key, setup_endpoint) = (Arc::clone(key), endpoint.clone());
        crate::logging::off_runtime("Linear direct client", move || {
            HttpLinearClient::with_endpoint(key.as_str(), setup_endpoint, timeout).map(|_| ())
        })
        .await??;
    }
    Ok(Some(tokio::spawn(async move {
        let mut wait = Duration::ZERO;
        let mut interval = policy.poll_interval_secs;
        loop {
            tokio::time::sleep(wait).await;
            wait = Duration::from_secs(interval);
            // A refused tick (a vault frozen for reap) asks again after it.
            let Some(admission) = admit() else {
                continue;
            };
            let vault = Arc::clone(server.vault());
            let credential = credential.clone();
            let tracker = tracker.clone();
            let responses = responses.clone();
            let endpoint = endpoint.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                // Held through the policy and budget reads, every Linear
                // request, the response journal and the cursor and receipt
                // settlement, even when its waiter is aborted.
                let _admission = admission;
                let policy = vault
                    .linear_mirror_policy()
                    .map_err(LinearSyncError::Store)?;
                let budget = vault.linear_sync_budget().map_err(LinearSyncError::Store)?;
                let result = credential.with(&vault, |key| {
                    let client = HttpLinearClient::with_endpoint(
                        key,
                        endpoint,
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
                    super::synchronize_once(
                        &vault,
                        inbound,
                        outbound,
                        now,
                        budget.max_pull_pages_per_pass,
                    )
                })?;
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
                Ok(Err(error)) => {
                    // FIX 6424 part 2a: a mutation the door held for the
                    // owner's approve-once press names the digest to press.
                    tracing::warn!(
                        reason = "linear_sync_failed",
                        approve_once = ?oneiron_linear::held_approve_once(&error),
                        "Linear direct mirror pass failed; will retry"
                    );
                }
                Err(_) => {
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
