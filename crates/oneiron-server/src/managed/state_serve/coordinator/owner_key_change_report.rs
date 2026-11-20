//! Owner key changes reported while the managed vault is serving.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::managed::ledger::LEDGER_SCHEDULE_POLL;
use crate::managed::owner_key_change_report::{SweepOutcome, sweep_once};

use super::super::{Arc, ShutdownSignal, SyncServer};

/// How many sweeps in a row may stop on a failure before the reporter backs
/// off to [`BACKOFF_SWEEP_EVERY`].
const FAILED_SWEEPS_BEFORE_BACKOFF: u32 = 3;

/// How often the reporter sweeps once [`FAILED_SWEEPS_BEFORE_BACKOFF`]
/// sweeps in a row stopped on a failure, until one succeeds.
const BACKOFF_SWEEP_EVERY: Duration = Duration::from_secs(10 * 60);

/// Reports this vault's owner key changes to the supervisor (Engine ruling
/// 21 Nov 06:00), so the control plane mails the account's owner each one.
///
/// Each [`LEDGER_SCHEDULE_POLL`] tick runs one sweep: it reads the list again
/// and sends every change the cursor row does not name yet, oldest first, so
/// a refused report goes out again on the next sweep. The tick, not each
/// committed write, starts a sweep: a sweep reads the whole authority log
/// and its fold, which a busy vault's every write would repeat, and a notice
/// up to one tick late is still in time. After
/// [`FAILED_SWEEPS_BEFORE_BACKOFF`] sweeps in a row that stopped on a
/// failure, sweeps run at most every [`BACKOFF_SWEEP_EVERY`] until one
/// succeeds. The sweep blocks on its socket, so it runs off the runtime's
/// threads; the task's end, by shutdown or by teardown's abort, sets the
/// sweep's stop flag, so a sweep in flight sends nothing more and ends within
/// one read slice. Managed boot wrote the cursor's baseline before anything
/// served, so every sweep sends what the row does not name. It takes no
/// write admission, so the reap freeze never holds it back.
pub(super) fn spawn(
    server: Arc<SyncServer>,
    mut stop: ShutdownSignal,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Some(report) = server.owner_key_change_report().cloned() else {
            return;
        };
        let stop_sweeps = Arc::new(AtomicBool::new(false));
        let _stop_on_end = SetOnDrop(Arc::clone(&stop_sweeps));
        let mut poll = tokio::time::interval(LEDGER_SCHEDULE_POLL);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut failures: u32 = 0;
        let mut last_sweep: Option<Instant> = None;
        loop {
            tokio::select! {
                () = &mut stop => return,
                _ = poll.tick() => {}
            }
            // Backed off: at most one sweep per window, until one succeeds.
            if failures >= FAILED_SWEEPS_BEFORE_BACKOFF
                && last_sweep.is_some_and(|at| at.elapsed() < BACKOFF_SWEEP_EVERY)
            {
                continue;
            }
            let (vault, report, stop) = (
                Arc::clone(server.vault()),
                report.clone(),
                Arc::clone(&stop_sweeps),
            );
            let outcome = tokio::task::spawn_blocking(move || sweep_once(&vault, &report, &stop))
                .await
                .unwrap_or(SweepOutcome::StoppedOnFailure);
            last_sweep = Some(Instant::now());
            match outcome {
                SweepOutcome::Clean => failures = 0,
                SweepOutcome::StoppedOnFailure => {
                    failures = failures.saturating_add(1);
                }
                SweepOutcome::Stopped => return,
            }
        }
    })
}

/// Sets its flag when dropped: the reporter task holds one, so its end by
/// return or by abort stops the sweep it left on the blocking pool.
struct SetOnDrop(Arc<AtomicBool>);

impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}
