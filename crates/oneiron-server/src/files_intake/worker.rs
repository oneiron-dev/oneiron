//! `oneiron serve`'s rescans of every attached folder, Files sources
//! included (OF-554, FIX 6942): the one reconciliation they all share, never
//! a watcher of their own.

use std::sync::Arc;
use std::time::Duration;

use super::ImportWarning;
use crate::server::SyncServer;

/// How often `oneiron serve` rescans the attached folders.
const RESCAN_TICK: Duration = Duration::from_secs(5 * 60);

/// Rescans every attached folder from `oneiron serve` at start and every
/// [`RESCAN_TICK`], one pass at a time, off the async runtime, on every
/// posture: attaching a folder is the owner's standing act for it and
/// detaching ends it, so the folders the vault records are the whole policy.
/// A pass lands as the vault's local owner; a managed vault starts none,
/// since it keeps no standing import authority yet. A folder that is not
/// there now is said each pass and retracts nothing.
pub(crate) fn spawn_rescans(server: Arc<SyncServer>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RESCAN_TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let server = Arc::clone(&server);
            let pass = tokio::task::spawn_blocking(move || rescan_all(server.vault())).await;
            let error = match pass {
                Ok(Ok(())) => continue,
                Ok(Err(error)) => format!("{error:#}"),
                Err(error) => error.to_string(),
            };
            tracing::warn!(error = %error, "folder source rescan failed");
        }
    })
}

fn rescan_all(vault: &oneiron::Vault) -> anyhow::Result<()> {
    let sources = vault.folder_sources()?;
    if sources.is_empty() {
        return Ok(());
    }
    let owner = crate::owner::local_owner(vault)?;
    for source in &sources {
        match super::source::rescan(vault, &owner, source) {
            Ok((report, warnings)) => {
                for warning in &warnings {
                    if let ImportWarning::LimitCrossed {
                        row,
                        limit,
                        observed,
                    } = warning
                    {
                        tracing::warn!(
                            folder = %source.folder,
                            row = *row,
                            limit = *limit,
                            observed = *observed,
                            "folder source read past a [limits] row; read whole, and the row asks"
                        );
                    }
                }
                let moved = report.landed
                    + report.superseded
                    + report.proposed
                    + report.retracted
                    + report.restored
                    + report.name_only
                    + report.failed;
                if moved > 0 {
                    tracing::info!(
                        folder = %source.folder,
                        landed = report.landed,
                        superseded = report.superseded,
                        proposed = report.proposed,
                        retracted = report.retracted,
                        restored = report.restored,
                        name_only = report.name_only,
                        failed = report.failed,
                        "folder source rescanned"
                    );
                }
            }
            Err(error) => {
                let error = format!("{error:#}");
                tracing::warn!(folder = %source.folder, error = %error, "folder source rescan failed");
            }
        }
    }
    Ok(())
}
