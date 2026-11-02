//! The server's direct Linear GraphQL mirror, using the production adapter.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use oneiron::linear_sync::{LinearWait, ServedLinearEgress};
use oneiron::outbound::{OutboundDispatchActor, OutboundDispatchGate, OutboundDispatchPolicyRisk};
use oneiron::{EntityId, LinearSyncError, LinearSyncResult, Vault};
use oneiron_linear::{
    HttpLinearClient, LinearBodyLine, LinearHostChangeSource, LinearHostEgress,
    LinearTrackerConfig, VaultLinearOutboundDoor,
};

use super::PassCredential;
use crate::config::LinearConfig;
use crate::server::{HousekeepingAdmission, SyncServer};

/// What the direct mirror's door is built from, as its settings name it:
/// the tracker mapping, the GraphQL endpoint, the response directory and the
/// scheduler actor. The response directory keeps the host's content-free
/// delivery state, outside the replicated vault graph; the request and
/// response bytes are the TASK's body custody.
#[derive(Clone)]
pub(super) struct DirectSetup {
    tracker: LinearTrackerConfig,
    endpoint: reqwest::Url,
    responses: PathBuf,
    scheduler: EntityId,
}

/// One direct pass's, or one caller's push's, inbound source and egress.
type DirectPorts<'v> = (
    LinearHostChangeSource<HttpLinearClient>,
    ServedLinearEgress<'v, LinearHostEgress<VaultLinearOutboundDoor<'v, HttpLinearClient>>>,
);

impl DirectSetup {
    /// The setup the checked `settings` name, with `tracker`, their mapping.
    /// It reads the response directory, so it runs off the async runtime.
    pub(super) fn checked(
        settings: &LinearConfig,
        tracker: Option<LinearTrackerConfig>,
        scheduler: EntityId,
    ) -> anyhow::Result<Self> {
        let tracker =
            tracker.ok_or_else(|| anyhow::anyhow!("a direct Linear mirror maps linear.team_id"))?;
        let endpoint = settings.graphql_endpoint()?;
        let responses = (settings.response_dir.clone())
            .filter(|dir| dir.is_absolute() && dir.is_dir())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Linear response_dir must name an existing absolute host-private directory"
                )
            })?;
        Ok(Self {
            tracker,
            endpoint,
            responses,
            scheduler,
        })
    }

    /// The mirror's inbound source and outbound egress over the credential
    /// `key`, at `now`, its door decoding on `body_line` and waiting up to
    /// `rate_wait` for a full Rate window (FIX 8788): none for a background
    /// pass, whose full window leaves the TASK dirty for a later pass; a
    /// caller's own for its push (FIX 9382).
    pub(super) fn ports<'v>(
        &self,
        vault: &'v Vault,
        key: &str,
        body_line: &Arc<dyn LinearBodyLine>,
        (timeout, now, rate_wait): (Duration, u64, Duration),
    ) -> LinearSyncResult<DirectPorts<'v>> {
        let client = HttpLinearClient::with_endpoint(key, self.endpoint.clone(), timeout)?
            .with_body_line(Arc::clone(body_line));
        let inbound = LinearHostChangeSource::new(client.clone(), self.tracker.clone())?;
        let door = VaultLinearOutboundDoor::new(
            vault,
            client,
            self.responses.clone(),
            OutboundDispatchActor {
                actor_class: "system".to_owned(),
                actor_ref: Some(self.scheduler.to_hex()),
                actor_entity_ref: Some(self.scheduler),
            },
            OutboundDispatchGate {
                has_opted_in: false,
                has_permission: true,
                policy_risk: OutboundDispatchPolicyRisk::Normal,
            },
            now,
        )?
        .with_body_line(Arc::clone(body_line))
        .with_rate_wait(rate_wait);
        let outbound = ServedLinearEgress::new(
            vault,
            self.scheduler,
            LinearHostEgress::new(door, self.tracker.clone())?,
        );
        Ok((inbound, outbound))
    }
}

/// The direct mirror the checked `settings` name ([`DirectSetup`]).
pub(super) async fn spawn(
    server: Arc<SyncServer>,
    settings: &LinearConfig,
    tracker: Option<LinearTrackerConfig>,
    scheduler: EntityId,
    credential: PassCredential,
    admit: HousekeepingAdmission,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    let checked = settings.clone();
    let setup = crate::logging::off_runtime("Linear direct setup", move || {
        DirectSetup::checked(&checked, tracker, scheduler)
    })
    .await??;
    let policy = server.vault().linear_mirror_policy()?;
    // Validate a key the environment holds, and the TLS client, off the
    // async runtime before start. A vault secret is read at each pass.
    let timeout = Duration::from_secs(policy.request_timeout_secs);
    if let PassCredential::Held(key) = &credential {
        let (key, setup_endpoint) = (Arc::clone(key), setup.endpoint.clone());
        crate::logging::off_runtime("Linear direct client", move || {
            HttpLinearClient::with_endpoint(key.as_str(), setup_endpoint, timeout).map(|_| ())
        })
        .await??;
    }
    // FIX 8610: a tracker body's decode takes its bytes on the server's
    // retained-memory line.
    let body_line: Arc<dyn LinearBodyLine> =
        Arc::new(super::body_line::ServerBodyLine::of(&server));
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
            let setup = setup.clone();
            let body_line = Arc::clone(&body_line);
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
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |time| time.as_secs());
                    // A background pass waits for no Rate window (FIX 8788):
                    // a full one leaves the TASK dirty for a later pass.
                    let timeout = Duration::from_secs(policy.request_timeout_secs);
                    let (inbound, outbound) =
                        setup.ports(&vault, key, &body_line, (timeout, now, Duration::ZERO))?;
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
                Ok(Err(LinearSyncError::Waiting(waiting))) => {
                    // FIX 8788, 8610: nothing was refused; the TASK stays
                    // dirty and a later pass sends it.
                    tracing::debug!(
                        reason = match waiting {
                            LinearWait::RateWindow { .. } => {
                                oneiron::linear_sync::LINEAR_RATE_WINDOW_REASON
                            }
                            LinearWait::BodyMemory => "linear_body_memory_wait",
                        },
                        "Linear mutation waits; it stays pending"
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
