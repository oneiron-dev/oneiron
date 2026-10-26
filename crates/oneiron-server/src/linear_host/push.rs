//! A caller's own push of one TASK to Linear (FIX 8788, FIX 9382). The
//! scheduled passes wait for no Rate window: a full one leaves the TASK
//! dirty for a later pass. A caller who wants its TASK sent now asks the core
//! door `POST /v1/core/linear/push`, naming how long it waits; zero answers
//! at once. The push runs on the caller's blocking thread under the settings
//! the scheduled mirror runs under, as a pass sends it: every inbound page
//! reconciled first, then this TASK alone, when it owes the mirror its dirty
//! revision, through the same dual-actor admission, budget and conflict
//! checks, with the same row and acknowledgement. Only the wait is the
//! caller's.

use std::sync::Arc;
use std::time::Duration;

use oneiron::linear_sync::{ServedLinearEgress, VaultLinearTaskStore};
use oneiron::{
    EntityId, LinearChangeSource, LinearEgress, LinearMirrorReceipt, LinearSyncAdapter,
    LinearSyncError, LinearSyncResult,
};
use oneiron_linear::LinearBodyLine;

use super::direct::DirectSetup;
use super::{LinearBridge, PassCredential};
use crate::config::LinearMode;
use crate::server::SyncServer;

/// Why a caller's push did not go.
#[derive(Debug)]
pub(crate) enum LinearPushError {
    /// The server runs no Linear mirror, or its settings cannot run one.
    Unavailable(String),
    /// The push failed, or waits its turn ([`LinearSyncError::Waiting`]).
    Sync(LinearSyncError),
}

impl From<LinearSyncError> for LinearPushError {
    fn from(error: LinearSyncError) -> Self {
        Self::Sync(error)
    }
}

/// The server's retained-memory line a direct push decodes on, taken on the
/// async runtime before the push leaves it.
pub(crate) fn push_body_line(server: &SyncServer) -> Arc<dyn LinearBodyLine> {
    Arc::new(super::body_line::ServerBodyLine::of(server))
}

/// Pushes `task` as a pass would, its admission waiting up to `wait` for a
/// full Rate window, and its direct decodes on `body_line`. `None` when the
/// TASK owes the mirror nothing or a held push skips it. Runs on a blocking
/// thread: it reads the vault and calls the provider.
///
/// # Errors
///
/// [`LinearPushError::Unavailable`] when the server's `[linear]` settings
/// run no mirror; otherwise the push's own error.
pub(crate) fn push_task_now(
    server: &SyncServer,
    task: EntityId,
    wait: Duration,
    body_line: &Arc<dyn LinearBodyLine>,
) -> Result<Option<LinearMirrorReceipt>, LinearPushError> {
    let unavailable = |error: anyhow::Error| LinearPushError::Unavailable(error.to_string());
    let Some(settings) = server.config.linear.as_ref() else {
        return Err(LinearPushError::Unavailable(
            "this server runs no Linear mirror".to_owned(),
        ));
    };
    let Some(mode) = settings.mode else {
        return Err(LinearPushError::Unavailable(
            "the Linear mirror names no mode".to_owned(),
        ));
    };
    settings.validate().map_err(unavailable)?;
    super::validate_ingress(&server.config).map_err(unavailable)?;
    let scheduler = settings.scheduler_actor().map_err(unavailable)?;
    let credential = PassCredential::of(settings).map_err(unavailable)?;
    let vault = server.vault();
    let policy = vault
        .linear_mirror_policy()
        .map_err(LinearSyncError::Store)?;
    let budget = vault.linear_sync_budget().map_err(LinearSyncError::Store)?;
    let timeout = Duration::from_secs(policy.request_timeout_secs);
    let pages = budget.max_pull_pages_per_pass;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_secs());
    let pushed = match mode {
        LinearMode::Direct => {
            let tracker = settings.tracker().map_err(unavailable)?;
            let setup = DirectSetup::checked(settings, tracker, scheduler).map_err(unavailable)?;
            credential.with(vault, |key| {
                let (inbound, outbound) =
                    setup.ports(vault, key, body_line, (timeout, now, wait))?;
                push_one(vault, inbound, outbound, task, (now, pages))
            })?
        }
        LinearMode::Bridge => {
            let base = settings.bridge_base().map_err(unavailable)?;
            let client = reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| unavailable(error.into()))?;
            credential.with(vault, |token| {
                let inbound = LinearBridge::with_token(client, base, token, timeout)?;
                let bridge = inbound.clone().with_rate_wait(wait);
                let outbound = ServedLinearEgress::new(vault, scheduler, bridge);
                push_one(vault, inbound, outbound, task, (now, pages))
            })?
        }
    };
    Ok(pushed)
}

/// `task`'s push through `inbound` and `outbound`, at `now`, reconciling up
/// to `pages` inbound pages first.
fn push_one<I: LinearChangeSource, O: LinearEgress>(
    vault: &oneiron::Vault,
    inbound: I,
    outbound: O,
    task: EntityId,
    (now, pages): (u64, usize),
) -> LinearSyncResult<Option<LinearMirrorReceipt>> {
    LinearSyncAdapter::new(VaultLinearTaskStore::new(vault), inbound, outbound)
        .push_dirty_task(task, now, pages)
        .map(|(receipt, _)| receipt)
}
