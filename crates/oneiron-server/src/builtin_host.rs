//! The served host's side of the built-in connector packs (OF-519): the
//! connection checks only a served host can run, the channel handles it
//! keeps for every checked built-in channel, the provider webhooks those
//! handles serve, and the Slack app's manifest and OAuth install.

mod checks;
mod handles;
mod slack_app;
mod webhooks;

use std::sync::Arc;
use std::time::Duration;

pub(crate) use checks::HostConnectionChecks;
pub(crate) use handles::BuiltinHandles;
pub(crate) use slack_app::{
    ProviderSetup, SlackInstallLink, public_origin, slack_app_manifest, start_slack_install,
};
pub(crate) use webhooks::routes;

use crate::server::{HousekeepingAdmission, SyncServer};

/// How often the handles are reconciled with the installed packs and
/// their checks, whether or not any channel is Active.
const RECONCILE_EVERY: Duration = Duration::from_secs(30);

/// Starts the reconcile loop. Each pass reads the installed packs and keeps
/// one handle per built-in channel whose engine pack is Active and whose
/// connection check is Verified, dropping a handle the moment its receipt
/// or check goes. Each pass is admitted through `admit`, the way a
/// housekeeping pass is, so a vault frozen for reap reconciles nothing.
pub(crate) fn spawn(
    server: &Arc<SyncServer>,
    admit: HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    let server = Arc::clone(server);
    tokio::spawn(async move {
        loop {
            if let Some(admission) = admit() {
                let vault = Arc::clone(server.vault());
                let handles = Arc::clone(&server.builtin_handles);
                let base = server.config.oauth_resource_indicator.clone();
                let pass = tokio::task::spawn_blocking(move || {
                    let _admission = admission;
                    handles.reconcile(&vault, base.as_deref());
                })
                .await;
                if let Err(error) = pass {
                    tracing::warn!(%error, "built-in channel reconcile pass panicked");
                }
            }
            tokio::time::sleep(RECONCILE_EVERY).await;
        }
    })
}
