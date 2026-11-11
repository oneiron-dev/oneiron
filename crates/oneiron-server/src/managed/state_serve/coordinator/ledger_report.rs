//! Wake-ledger changes reported while the managed vault is serving.

use crate::managed::ledger::LEDGER_SCHEDULE_POLL;

use super::super::{Arc, ManagedState, ShutdownSignal, SyncServer, watch};

/// Reports the vault's training setting and its schedule to the supervisor
/// as they change (FIX 5575, FIX 7746), so a status read there never wakes
/// the vault and its next wake is the one the running vault would ask for.
///
/// Each notification on `changes` only says "re-read committed state", and
/// so does each [`LEDGER_SCHEDULE_POLL`] tick, since a lease, the sync queue
/// and a noted deadline move with no signal of their own: the report is read
/// again and pushed when the setting or the schedule moved from the last
/// report the supervisor took, or when it took none, so a refused push goes
/// out again on the next read. Notifications that land during a push are
/// read as one, since each report replaces the last whole. It takes no write
/// admission, so the reap freeze never holds it back, and it ends with
/// shutdown.
pub(super) fn spawn(
    state: Arc<ManagedState>,
    server: Arc<SyncServer>,
    mut changes: watch::Receiver<u64>,
    mut stop: ShutdownSignal,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut poll = tokio::time::interval(LEDGER_SCHEDULE_POLL);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The opening push has just read the report.
        poll.tick().await;
        loop {
            tokio::select! {
                () = &mut stop => return,
                changed = changes.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                _ = poll.tick() => {}
            }
            if let Err(_error) = state.ledger().push_live_if_changed(&server).await {
                tracing::warn!(
                    reason = "wake_ledger_export_failed",
                    "wake ledger report failed"
                );
            }
        }
    })
}
