//! Native reader nesting: the child's own seat and durable peer wait.

use oneiron::Vault;
use oneiron::code_run::{
    ReaderJobKind, ReaderJobState, ReaderJobs, ReaderRunEnd, SelfDurableWaitReason, SelfEffect,
    SpawnHostSeat, WaitDeliveries,
};
use oneiron::engine_executor::ParkedWait;
use oneiron::off_record::OffRecordSession;

use super::{Child, Duration, Instant, ReaderParentClock, Shared, Signal, lock, unix_millis_now};

impl Shared {
    /// A tick has observed settlements on the canonical and live room routes.
    pub(super) fn note_progress(&self) {
        let mut progress = lock(&self.progress);
        *progress = progress.wrapping_add(1);
        self.progressed.notify_all();
    }
}

impl Child {
    pub(super) fn nested_spawn_seat(&self) -> Option<SpawnHostSeat> {
        if self.job.kind != ReaderJobKind::Read {
            return None;
        }
        // Sampling monotonic time first cannot add the wall sample's cost
        // to the child window. left_ms has taken the parent's reserve once.
        let origin = Instant::now();
        let now = unix_millis_now();
        let clock = ReaderParentClock::until(origin + Duration::from_millis(self.left_ms(now)));
        Some(self.shared.seats.nested_seat(
            &self.job,
            clock,
            now,
            self.provider.reader_window_tokens(),
        ))
    }

    /// A resume must still be the exact claimed job, not a newer generation
    /// or a different route/source/actor reached by the same task id.
    fn nested_job_stands(
        &self,
        vault: &Vault,
        session: Option<&OffRecordSession<'_>>,
    ) -> Result<(), ReaderRunEnd> {
        let jobs = match (session, self.session.as_ref()) {
            (None, None) => ReaderJobs::canonical(vault),
            (Some(session), Some((_, participant))) => {
                ReaderJobs::for_session(session, *participant)
                    .map_err(|_| ReaderRunEnd::Failed("reader_binding_failed".to_owned()))?
            }
            _ => return Err(ReaderRunEnd::Failed("reader_binding_failed".to_owned())),
        };
        match jobs.job(self.job.task) {
            Ok(Some(job))
                if job.state == ReaderJobState::Active
                    && job.generation == self.job.generation
                    && job.run == self.job.run
                    && job.attempt == self.job.attempt
                    && job.kind == self.job.kind
                    && job.binding == self.job.binding =>
            {
                Ok(())
            }
            _ => Err(ReaderRunEnd::Failed("reader_binding_failed".to_owned())),
        }
    }

    /// Called only after the native executor and guest runtime have dropped.
    /// The original config, model seat, backend and budget guard stay with
    /// the child. Its next segment restores the native committed replay.
    pub(super) fn wait_for_nested(
        &self,
        vault: &Vault,
        session: Option<&OffRecordSession<'_>>,
        parked: &ParkedWait,
    ) -> Result<(), ReaderRunEnd> {
        if self.job.kind != ReaderJobKind::Read
            || parked.key.run != self.job.run
            || parked.wait.effect != SelfEffect::TasksWait
            || parked.wait.reason != SelfDurableWaitReason::PeerResult
            || parked.wait.prompt.as_deref()
                != Some(format!("task_wait_set:{}", parked.key.wait_id.to_hex()).as_str())
        {
            return Err(ReaderRunEnd::Failed("reader_child_waited".to_owned()));
        }
        // Do not hold all execution permits while the grandchildren that
        // can settle this wait are queued for those same permits. The
        // per-parent resident count stays held: descendants have their own
        // parent run, so it cannot block their window.
        drop(lock(&self.permit).take());
        let _ = self.signals.send(Signal::Freed);
        let deliveries = match (session, self.session.as_ref()) {
            (None, None) => WaitDeliveries::canonical(vault),
            (Some(session), Some((_, participant))) => {
                WaitDeliveries::for_session(session, *participant)
                    .map_err(|_| ReaderRunEnd::Failed("reader_binding_failed".to_owned()))?
            }
            _ => return Err(ReaderRunEnd::Failed("reader_binding_failed".to_owned())),
        };
        // The executor registered this exact key before returning Waiting.
        // Observe only; the executor owns the resume commit and wait cleanup.
        loop {
            // Capture before the routed read. A commit observed by a tick
            // between that read and sleeping changes the epoch, so the
            // corresponding wake cannot be lost.
            let observed = *lock(&self.shared.progress);
            self.nested_job_stands(vault, session)?;
            let left = self.left_ms(unix_millis_now());
            if left == 0 {
                return Err(ReaderRunEnd::Cutoff);
            }
            // Re-enter on a read/erase fault to surface the native typed
            // failure, rather than waiting forever on a reply we cannot read.
            let delivered = !matches!(deliveries.delivery(&parked.key), Ok(None));
            if delivered {
                let left = self.left_ms(unix_millis_now());
                if left == 0 {
                    return Err(ReaderRunEnd::Cutoff);
                }
                let permit = self
                    .runs
                    .admit_background_blocking_for(Duration::from_millis(left))
                    .map_err(|_| ReaderRunEnd::Cutoff)?;
                if self.left_ms(unix_millis_now()) == 0 {
                    return Err(ReaderRunEnd::Cutoff);
                }
                self.nested_job_stands(vault, session)?;
                *lock(&self.permit) = Some(permit);
                return Ok(());
            }
            let progress = lock(&self.shared.progress);
            let _waited = self
                .shared
                .progressed
                .wait_timeout_while(
                    progress,
                    Duration::from_millis(self.left_ms(unix_millis_now())),
                    |current| *current == observed,
                )
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}
