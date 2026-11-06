//! Core half of `store::deadline_jobs`: its store-layer items live in `oneiron_store::deadline_jobs` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::deadline_jobs::*;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::limit_ask::EngineLimit;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

impl Vault {
    /// `caller`'s place for one more deadline job: a recall or search whose
    /// door answers at its deadline and may leave its work running past the
    /// answer. Hold it in the job's work until that work ends.
    ///
    /// The job always runs. Past `limits.deadline_jobs_per_caller` it raises
    /// the typed `deadline_jobs_high` check, once per caller per
    /// `DEADLINE_JOBS_CHECK_WINDOW`: the row's question through the
    /// vault's limit port, which keeps the row and the count, and one log
    /// line naming the row, the caller and the count.
    pub fn admit_deadline_job(&self, caller: EntityId) -> DeadlineJob {
        let jobs = &self.store.deadline_jobs;
        let held = {
            let mut running = lock(&jobs.running);
            let held = running.entry(caller).or_default();
            *held = held.saturating_add(1);
            *held
        };
        let row = EngineLimit::DeadlineJobsPerCaller;
        if held > self.limit_watch().bound(row)
            && jobs.check_due(caller, Instant::now())
            && let Some(bound) = self.measure_limit(row, held)
        {
            tracing::warn!(
                kind = DEADLINE_JOBS_CHECK_KIND,
                row = row.key(),
                caller = %caller.to_hex(),
                count = held,
                bound,
                "a caller's deadline jobs passed their row and run on; is everything okay?"
            );
        }
        DeadlineJob {
            caller,
            running: Arc::clone(&jobs.running),
        }
    }
}
