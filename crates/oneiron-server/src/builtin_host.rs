//! The served host's side of the built-in connector packs (OF-519): the
//! connection checks only a served host can run, the isolated probes that
//! qualify a built-in on them (FIX 710), the channel handles it
//! keeps for every checked built-in channel, the provider webhooks those
//! handles serve, the native mail pack's inbox reads, the transports its
//! served sinks send through, and the Slack app's manifest and OAuth install.

mod checks;
mod handles;
mod native_mail;
mod probes;
mod slack_app;
mod webhooks;

use std::sync::Arc;
use std::time::Duration;

use oneiron::outbound::{ServedEndpoints, ServedTransports};

pub(crate) use checks::HostConnectionChecks;
pub(crate) use handles::BuiltinHandles;
pub(crate) use slack_app::{
    ProviderSetup, SlackInstallLink, public_origin, slack_app_manifest, start_slack_install,
};
pub(crate) use webhooks::{hmac_matches, routes};

use crate::server::{HousekeepingAdmission, SyncServer};

/// How often the handles are reconciled with the installed packs and
/// their checks, whether or not any channel is Active.
const RECONCILE_EVERY: Duration = Duration::from_secs(30);

/// Installs this host's served transports on its vault (FIX 4435, 2096,
/// 1168): the `[channel_endpoints]` provider APIs, the `[native_mail]`
/// server and this server's connector calls, which every served sink on the
/// vault sends through. Call it before any worker sends; a second install
/// does nothing.
pub(crate) fn install_served_transports(server: &Arc<SyncServer>) {
    // Config validation refused a bad endpoint at load; this only keeps a
    // host that skipped it on the public APIs.
    let endpoints = server
        .config
        .channel_endpoints
        .endpoints()
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "[channel_endpoints] is invalid; the public provider APIs serve");
            ServedEndpoints::default()
        });
    let mut transports = ServedTransports::new(endpoints).with_connector_calls(Arc::new(
        crate::connector_call_host::ServerConnectorCalls::new(server),
    ));
    if let Some(mail) = &server.config.native_mail {
        match mail.stalwart() {
            Ok(placement) => transports = transports.with_native_mail(placement),
            Err(error) => {
                tracing::warn!(%error, "[native_mail] is invalid; email sends have no mail server");
            }
        }
    }
    server
        .vault()
        .install_served_transports(Arc::new(transports));
}

/// Starts the reconcile loop. Each pass reads the installed packs and keeps
/// one handle per built-in channel whose engine pack is Active and whose
/// connection check is Verified, dropping a handle the moment its receipt
/// or check goes, then reads the native mail pack's inboxes. Each pass is
/// admitted through `admit`, the way a housekeeping pass is, so a vault
/// frozen for reap reconciles nothing.
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
                let line = server.config.line;
                let native_mail = server.config.native_mail.clone();
                let pass = tokio::task::spawn_blocking(move || {
                    let _admission = admission;
                    handles.reconcile(&vault, base.as_deref(), &line);
                    handles.poll_native_mail(&vault, native_mail.as_ref());
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
