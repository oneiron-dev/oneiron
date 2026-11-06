//! The residence upkeep tasks of one sync run (FIX 12037, FIX 12785).
//!
//! Each connection fills its own slots. The next connection starts with free
//! slots, and the tasks still running move to the run's earlier lists: a
//! reconnect cancels none of them. The run's end aborts the async rounds,
//! then waits for every task and for each blocking job a round started
//! ([`crate::sync::upkeep_jobs`]), so no upkeep write lands after the run (a
//! reap's export waits on this).

use tokio::task::JoinHandle;

use crate::sync::upkeep_jobs::{UpkeepJobs, UpkeepJobsEnded};

/// The upkeep tasks a sync run owns across its reconnects.
pub(in crate::sync::connection) struct UpkeepTasks {
    /// This connection's residence upkeep round: authority catch-up, then the
    /// sealed bundle relay.
    pub(super) sealed: Option<JoinHandle<()>>,
    /// This connection's retry of the committed pad tombstones no postcommit
    /// published (FIX 3849), then its world eviction (FIX 14534): one blocking
    /// job at a time, on the sealed relay's tick, every lane, federation's
    /// included.
    pub(super) tombstone: Option<JoinHandle<()>>,
    /// This connection's owed machine-history rounds (FIX 3820).
    pub(super) machine_history: Vec<JoinHandle<()>>,
    /// The async rounds of earlier connections still running.
    earlier_rounds: Vec<JoinHandle<()>>,
    /// The blocking jobs of earlier connections still running.
    earlier_blocking: Vec<JoinHandle<()>>,
    /// The mark each blocking job a round starts holds until it returns.
    jobs: UpkeepJobs,
    /// Closes once no job holds the mark.
    jobs_ended: UpkeepJobsEnded,
}

impl Default for UpkeepTasks {
    fn default() -> Self {
        let (jobs, jobs_ended) = UpkeepJobs::for_run();
        Self {
            sealed: None,
            tombstone: None,
            machine_history: Vec::new(),
            earlier_rounds: Vec::new(),
            earlier_blocking: Vec::new(),
            jobs,
            jobs_ended,
        }
    }
}

impl UpkeepTasks {
    /// Frees this connection's slots. The tasks still running move to the
    /// run's earlier lists; the finished ones are dropped.
    pub(super) fn retire_slots(&mut self) {
        self.earlier_rounds.extend(self.sealed.take());
        self.earlier_rounds.append(&mut self.machine_history);
        self.earlier_blocking.extend(self.tombstone.take());
        self.earlier_rounds.retain(|task| !task.is_finished());
        self.earlier_blocking.retain(|task| !task.is_finished());
    }

    /// The mark an async round runs its blocking jobs under
    /// ([`UpkeepJobs::scope`]).
    pub(super) fn jobs(&self) -> UpkeepJobs {
        self.jobs.clone()
    }

    /// Ends the run's upkeep: aborts every async round, then waits for every
    /// task and every blocking job, the earlier connections' included.
    pub(in crate::sync::connection) async fn end(mut self) {
        self.retire_slots();
        let Self {
            earlier_rounds,
            earlier_blocking,
            jobs,
            jobs_ended,
            ..
        } = self;
        for round in &earlier_rounds {
            round.abort();
        }
        for task in earlier_rounds.into_iter().chain(earlier_blocking) {
            let _ = task.await;
        }
        drop(jobs);
        jobs_ended.wait().await;
    }
}
