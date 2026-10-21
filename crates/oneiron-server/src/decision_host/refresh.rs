//! Decision host person-threshold refresh.
//! Entry: spawn_person_threshold.
//! Definitions: this module owns the listed functions; types stay in the parent.

use super::{Arc, PERSON_THRESHOLD_SWEEP, SyncServer};

/// Keeps the host's person row on the newest accepted Coach revision: it
/// re-reads after each committed change, and every sweep for an accept whose
/// commit sent no change signal. `None` when the recipe names no person
/// question.
pub(crate) fn spawn_person_threshold(
    server: &Arc<SyncServer>,
) -> Option<tokio::task::JoinHandle<()>> {
    spawn_person_threshold_admitted(server, crate::server::admit_every_pass())
}

/// [`spawn_person_threshold`] on a host with a write freeze: each refresh is
/// admitted through `admit` and holds that admission on its blocking thread
/// until it ends.
pub(crate) fn spawn_person_threshold_admitted(
    server: &Arc<SyncServer>,
    admit: crate::server::HousekeepingAdmission,
) -> Option<tokio::task::JoinHandle<()>> {
    server.decision_host().person_start?;
    let weak = Arc::downgrade(server);
    // Subscribed before the first read, so no change between them is lost.
    let mut changes = server.vault().subscribe_proactivity_changes();
    Some(tokio::spawn(async move {
        loop {
            let Some(server) = weak.upgrade() else {
                break;
            };
            let admission = admit();
            let ran = tokio::task::spawn_blocking(move || {
                // A refused refresh (a vault frozen for reap) runs at the
                // next change or sweep.
                let Some(_admission) = admission else {
                    return Ok(());
                };
                server
                    .decision_host()
                    .refresh_person_threshold(server.vault())
            })
            .await;
            match ran {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "the person threshold refresh failed; it runs again on the next change");
                }
                Err(error) => tracing::warn!(%error, "the person threshold refresh stopped"),
            }
            tokio::select! {
                () = tokio::time::sleep(PERSON_THRESHOLD_SWEEP) => {}
                changed = changes.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
        }
    }))
}
