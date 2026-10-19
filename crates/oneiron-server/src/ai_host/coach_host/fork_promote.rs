//! The host side of the project tree fork (ARCH-0079 #task-type, OF-420):
//! the engine forks a project's team-shape skill in closed form when the
//! project's own receipts read a clear winner the vault tree does not; the
//! host lends the replay judge that scores the fork against the head on the
//! project's held-out runs. The engine puts a winning fork in force.
use oneiron::dreamer_runner::DreamerAdmittedAttempt;
use oneiron::skill_optimize::HeldOutReplayNotes;

use crate::server::SyncServer;

/// One `coach.fork_promote` job.
pub(super) fn run(
    server: &SyncServer,
    admitted: &DreamerAdmittedAttempt,
    now: u64,
) -> oneiron::Result<()> {
    // No judge: no fork can be scored, so the pass forks nothing.
    let judge = crate::replay_judge::registered().map(|judge| judge as &dyn HeldOutReplayNotes);
    let report = server
        .vault()
        .run_coach_fork_promote(admitted, judge, now)?;
    tracing::debug!(?report, "the Coach forked project type trees");
    Ok(())
}
