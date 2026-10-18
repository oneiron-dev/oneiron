//! Due digests on a host that runs no Dreamer (OF-499). The weave digest
//! schedules and the proactivity digest are deterministic projections, so a
//! server with no `[models]`, or whose Dreamer did not start, still serves
//! them on their deadlines, on the vault's home node only. A vault no node
//! has claimed is claimed here, as the standing-question pump claims it,
//! except on a device of another home, which claims nothing.
//! With a Dreamer, its timer's Deadline passes serve them instead, so
//! exactly one runner does. It sleeps until the next digest falls due and
//! wakes early on a committed change.
use std::sync::Arc;
use std::time::Duration;

use oneiron::DreamerRunnerStore;

use crate::server::{HousekeepingAdmission, SyncServer};

/// How long the worker waits with nothing due, or off home, before it reads
/// again; a committed change wakes it sooner.
const IDLE_RECHECK: Duration = Duration::from_secs(60);
/// The shortest wait between passes: a digest still due after its pass
/// (a held schedule, or nothing to show) is read again no sooner.
const PASS_FLOOR: Duration = Duration::from_secs(30);

/// Starts the worker. Each pass runs on a blocking thread, held by `admit`
/// (a managed vault frozen for reap skips it).
pub(crate) fn spawn(
    server: &Arc<SyncServer>,
    admit: HousekeepingAdmission,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(server);
    // Subscribed before the first read, so no change between them is lost.
    let mut changes = server.vault().subscribe_proactivity_changes();
    tokio::spawn(async move {
        loop {
            let Some(server) = weak.upgrade() else {
                break;
            };
            let next = match admit() {
                Some(pass) => tokio::task::spawn_blocking(move || {
                    let _pass = pass;
                    serve_due(&server, oneiron_vault_contract::now_ts())
                })
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!(%error, "home digest pass stopped");
                    None
                }),
                None => None,
            };
            let wait = next.map_or(IDLE_RECHECK, |at| {
                Duration::from_secs(at.saturating_sub(oneiron_vault_contract::now_ts()))
                    .clamp(PASS_FLOOR, IDLE_RECHECK)
            });
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                changed = changes.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// One pass on the home node: the due proactivity digest, then each due
/// weave digest, each failure logged by kind on its own (their text can
/// quote the vault). Returns the earliest second either falls due next;
/// `None` off home, or when neither is armed.
fn serve_due(server: &SyncServer, now: u64) -> Option<u64> {
    let vault = server.vault();
    let home = crate::decision_graph::at_home(server, now).and_then(|home| {
        if !home {
            return Ok(None);
        }
        let local = DreamerRunnerStore::new(vault).local_home_node_candidate(true, true, false)?;
        Ok(Some(local.node_id))
    });
    let node = match home {
        Ok(node) => node?,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "home digests: the home node did not resolve");
            return None;
        }
    };
    // Only a digest that is due is emitted: a suspended one arms nothing.
    let proactivity = vault
        .next_proactivity_digest_at()
        .and_then(|due| match due {
            Some(at) if at <= now => {
                vault.emit_due_proactivity_digest(now, node)?;
                vault.next_proactivity_digest_at()
            }
            due => Ok(due),
        });
    let weave = vault
        .serve_due_weave_digests(now, node)
        .and_then(|_| vault.next_weave_digest_at());
    [("proactivity", proactivity), ("weave", weave)]
        .into_iter()
        .filter_map(|(digest, next)| {
            next.inspect_err(|error| {
                tracing::warn!(digest, kind = ?error.kind(), "home digest failed");
            })
            .ok()
            .flatten()
        })
        .min()
}
