//! Poll disjoint MACRO buckets together, with one wake snapshot and meter.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

use super::*;

impl DreamerWakeDriver<'_> {
    /// Runs one MACRO pass with independent executors. Queue admission owns
    /// the bucket leases; all workers share the pass's budget, deadline and
    /// frozen evidence. MICRO and MESO keep their per-device sequential pass.
    /// Every admitted worker reaches settle/park before an error is returned.
    pub async fn run_wake_pass_concurrent<E: DreamerAttemptExecutor>(
        &mut self,
        input: RunWakePass,
        executors: &mut [E],
        cancel: &WakeCancellation,
    ) -> Result<WakePassReport> {
        if executors.is_empty() {
            return Err(crate::Error::InvalidConfig("wake has no executor".into()));
        }
        if input.scope != DreamerConsolidationScope::Macro || executors.len() == 1 {
            return self.run_wake_pass(input, &mut executors[0], cancel).await;
        }
        self.begin_wake(input.now)?;
        let prepared = crate::dreamer_consolidation::PreparedWake::capture_with_grants(
            self.vault,
            input.scope,
            input.host_scope.as_ref(),
        )?;
        let mut workers: Vec<_> = (0..executors.len())
            .map(|index| {
                let mut worker = DreamerWakeDriver::new(
                    self.vault,
                    self.budget_id.clone(),
                    self.deadline.clone(),
                );
                worker.guard = self.guard.clone();
                worker.milestones = self.milestones.clone();
                worker.tournament_candidate = self.tournament_candidate.clone();
                worker.consolidation_only = index != 0;
                if index == 0 {
                    worker.skill_optimizer = self.skill_optimizer.as_ref().map(|optimizer| {
                        crate::dreamer_runner::maintenance::CoachSkillOptimizer {
                            author: optimizer.author,
                            scorer: optimizer.scorer,
                            live: optimizer.live,
                        }
                    });
                }
                worker
            })
            .collect();
        #[cfg(feature = "sync")]
        {
            workers[0].progress = self.progress.take();
        }
        let mut reports = Vec::new();
        {
            type Pass<'p> = Pin<Box<dyn Future<Output = Result<WakePassReport>> + 'p>>;
            let mut passes: Vec<Option<Pass<'_>>> = workers
                .iter_mut()
                .zip(executors)
                .map(|(worker, executor)| {
                    Some(Box::pin(worker.run_prepared_wake_pass(
                        input.clone(),
                        executor,
                        cancel,
                        &prepared,
                    )) as Pass<'_>)
                })
                .collect();
            poll_fn(|cx| {
                let mut pending = false;
                for pass in &mut passes {
                    let Some(future) = pass.as_mut() else {
                        continue;
                    };
                    match future.as_mut().poll(cx) {
                        Poll::Pending => pending = true,
                        Poll::Ready(report) => {
                            reports.push(report);
                            *pass = None;
                        }
                    }
                }
                if pending {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
        }
        #[cfg(feature = "sync")]
        {
            self.progress = workers[0].progress.take();
        }
        for worker in workers {
            for signal in worker.steering {
                if !self
                    .steering
                    .iter()
                    .any(|old| old.threshold == signal.threshold)
                {
                    self.steering.push(signal);
                }
            }
        }
        let mut aggregate = WakePassReport {
            admitted: 0,
            completed: 0,
            failed: 0,
            deferred: 0,
            parked: 0,
            landed: 0,
            sources_truncated: 0,
            stop: WakePassStop::QueueEmpty,
        };
        for report in reports {
            let report = report?;
            aggregate.admitted = aggregate.admitted.saturating_add(report.admitted);
            aggregate.completed = aggregate.completed.saturating_add(report.completed);
            aggregate.failed = aggregate.failed.saturating_add(report.failed);
            aggregate.deferred = aggregate.deferred.saturating_add(report.deferred);
            aggregate.parked = aggregate.parked.saturating_add(report.parked);
            aggregate.landed = aggregate.landed.saturating_add(report.landed);
            aggregate.sources_truncated = aggregate
                .sources_truncated
                .saturating_add(report.sources_truncated);
            if report.stop != WakePassStop::QueueEmpty {
                aggregate.stop = report.stop;
            }
        }
        Ok(aggregate)
    }
}
