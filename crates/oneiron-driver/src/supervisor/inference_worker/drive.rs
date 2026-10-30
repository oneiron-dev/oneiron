//! A managed worker's driver: its install, and each incarnation's launch,
//! qualification, service, drain and stop, with the backoff between them.
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::llm::{
    WorkerDescriptor, WorkerFailure, WorkerFailureDetail, WorkerPhase, WorkerReadiness,
};

use super::{
    Inner, LaunchFailure, LoadGrant, Phase, RunningWorker, WORKER_CRASH_BACKOFF_SECS, WorkerExit,
};

/// How one incarnation ended.
enum Ended {
    Exited(WorkerExit),
    /// An abort killed and reaped it, with no drain.
    Aborted(WorkerExit),
    Stopped(Phase),
    Parked {
        readiness: WorkerReadiness,
        reason: String,
    },
}

/// The wait before relaunch number `attempt` (from zero).
fn backoff_delay(attempt: usize) -> Duration {
    let index = attempt.min(WORKER_CRASH_BACKOFF_SECS.len() - 1);
    Duration::from_secs(WORKER_CRASH_BACKOFF_SECS[index])
}

impl Inner {
    fn retiring(&self) -> bool {
        self.lock().retiring
    }

    /// Moves to `phase`, unless the worker is retiring.
    fn enter(&self, phase: Phase) -> bool {
        let entered = {
            let mut state = self.lock();
            if state.retiring {
                false
            } else {
                state.phase = phase;
                true
            }
        };
        self.notify();
        entered
    }

    /// Ends the driver in `phase`, unless demand arrived meanwhile and the
    /// worker is not retiring: then the driver goes on (`true`).
    fn finish_or_restart(&self, phase: Phase) -> bool {
        let idle_stopped = matches!(phase, Phase::IdleStopped);
        let restart = {
            let mut state = self.lock();
            let restart = !state.retiring && state.waiting > 0;
            if restart {
                if idle_stopped {
                    // Publish the completed pressure unload before the
                    // victim's own demand starts its next incarnation.
                    state.phase = Phase::IdleStopped;
                }
            } else {
                state.phase = phase;
                state.driving = false;
            }
            restart
        };
        if idle_stopped {
            // The completion stays readable even after a restart overwrites
            // the transient phase: outstanding waiters see the request end.
            self.lock().unload_requested = false;
        }
        self.notify();
        restart
    }

    fn note_failure(&self, reason: &str) {
        let mut state = self.lock();
        let phase = match &state.phase {
            Phase::Installing => WorkerPhase::Install,
            Phase::Starting => WorkerPhase::Launch,
            Phase::Qualifying => WorkerPhase::Qualify,
            Phase::Draining | Phase::IdleStopped => WorkerPhase::Drain,
            Phase::Ready(_) | Phase::Stopped | Phase::Backoff | Phase::Failed { .. } => {
                WorkerPhase::Serve
            }
        };
        state.failure_detail = Some(WorkerFailureDetail {
            model: self.spec.model.clone(),
            phase,
            reason: reason.to_owned(),
        });
    }

    /// Parks the worker until its config changes.
    fn park(&self, readiness: WorkerReadiness, reason: String) {
        tracing::warn!(
            worker = %self.spec.worker_id,
            model = %self.spec.model,
            %reason,
            "model worker parked until its config changes"
        );
        self.note_failure(&reason);
        {
            let mut state = self.lock();
            state.phase = Phase::Failed { readiness, reason };
            state.driving = false;
        }
        self.notify();
    }

    /// The incarnation is over: its leases are revoked.
    fn revoke(&self) {
        {
            let mut state = self.lock();
            state.incarnation = state.incarnation.wrapping_add(1);
            state.leases = 0;
            state.activity = None;
            state.epoch = None;
            state.abort = None;
        }
        self.notify();
    }

    /// Whether an abort was asked for the running incarnation.
    fn abort_requested(&self) -> bool {
        let state = self.lock();
        state.abort == Some(state.incarnation)
    }

    /// Resolves once an abort is asked for the running incarnation, so any
    /// wait on the worker (its liveness, its stats, its drain) ends there.
    async fn abort_wanted(&self) {
        loop {
            let mut changes = self.changed.subscribe();
            if self.abort_requested() {
                return;
            }
            let _ = changes.changed().await;
        }
    }

    /// Closes admission and kills the incarnation's process group, waiting
    /// for the reaper: no drain, nothing asked of the worker.
    async fn abort(&self, running: &dyn RunningWorker) -> Ended {
        {
            self.lock().phase = Phase::Draining;
        }
        self.notify();
        tracing::warn!(worker = %self.spec.worker_id, "model worker aborted; relaunching it");
        Ended::Aborted(running.abort().await)
    }

    /// Waits out relaunch number `attempt` in `Backoff`; `false` when the
    /// worker was retired meanwhile.
    async fn back_off(&self, attempt: &mut usize) -> bool {
        let delay = backoff_delay(*attempt);
        *attempt = attempt.saturating_add(1);
        if !self.enter(Phase::Backoff) {
            return false;
        }
        let deadline = tokio::time::Instant::now() + delay;
        loop {
            let mut changes = self.changed.subscribe();
            if self.retiring() {
                return false;
            }
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => return true,
                _ = changes.changed() => {}
            }
        }
    }

    /// One incarnation: its qualification, then its service until it exits,
    /// stops for idleness, is retired or parks.
    async fn serve(&self, running: &dyn RunningWorker, attempt: &mut usize) -> Ended {
        let observed = match self.qualify(running).await {
            Ok(observed) => observed,
            Err(ended) => return ended,
        };
        *attempt = 0;
        self.mark_loaded();
        {
            let mut state = self.lock();
            state.epoch = observed
                .identity
                .backend_epoch
                .as_ref()
                .map(|epoch| epoch.as_str().to_owned());
            state.phase = Phase::Ready(observed);
            state.failure_detail = None;
        }
        self.notify();
        tracing::info!(worker = %self.spec.worker_id, model = %self.spec.model, "model worker ready");
        let mut idle_since: Option<Instant> = None;
        let mut next_poll = tokio::time::Instant::now() + self.policy.activity_poll;
        loop {
            let mut changes = self.changed.subscribe();
            if self.abort_requested() {
                return self.abort(running).await;
            }
            if self.retiring() {
                return self.drain_and_stop(running, Phase::Stopped).await;
            }
            tokio::select! {
                biased;
                exit = running.exited() => return Ended::Exited(exit),
                _ = changes.changed() => continue,
                () = tokio::time::sleep_until(next_poll) => {}
            }
            next_poll = tokio::time::Instant::now() + self.policy.activity_poll;
            let activity = tokio::select! {
                biased;
                exit = running.exited() => return Ended::Exited(exit),
                () = self.abort_wanted() => return self.abort(running).await,
                activity = running.activity() => activity,
            };
            self.note_activity(activity);
            let now = Instant::now();
            let (unleased, used_at, unload_requested) = {
                let state = self.lock();
                (
                    state.leases == 0 && state.waiting == 0,
                    state.used_at,
                    state.unload_requested,
                )
            };
            let fresh_idle = activity.is_some_and(|activity| activity.is_idle());
            if unload_requested {
                if unleased && fresh_idle && self.close_if_idle() {
                    tracing::info!(worker = %self.spec.worker_id, "model worker unloaded under device pressure");
                    tokio::select! {
                        biased;
                        () = self.abort_wanted() => return self.abort(running).await,
                        _ = running.terminate(self.policy.stop_grace) => {}
                    }
                    return Ended::Stopped(Phase::IdleStopped);
                }
                continue;
            }
            let Some(span) = self.policy.idle_stop else {
                continue;
            };
            if !(unleased && fresh_idle) {
                idle_since = None;
                continue;
            }
            let since = idle_since.get_or_insert(now);
            let since = used_at.map_or(*since, |used| used.max(*since));
            if now.duration_since(since) >= span && self.close_if_idle() {
                tracing::info!(worker = %self.spec.worker_id, "model worker idle; stopping it");
                // An abort asked during the drain reaches the worker there.
                tokio::select! {
                    biased;
                    () = self.abort_wanted() => return self.abort(running).await,
                    _ = running.terminate(self.policy.stop_grace) => {}
                }
                return Ended::Stopped(Phase::IdleStopped);
            }
        }
    }

    /// The liveness poll, then the incarnation's one qualification input.
    /// A probe that got no answer goes back to the liveness poll; one that
    /// answered with missing or contradicting evidence parks the worker.
    async fn qualify(&self, running: &dyn RunningWorker) -> Result<WorkerDescriptor, Ended> {
        if !self.enter(Phase::Qualifying) {
            let _ = running.terminate(self.policy.stop_grace).await;
            return Err(Ended::Stopped(Phase::Stopped));
        }
        loop {
            if self.retiring() {
                let _ = running.terminate(self.policy.stop_grace).await;
                return Err(Ended::Stopped(Phase::Stopped));
            }
            let live = tokio::select! {
                biased;
                exit = running.exited() => return Err(Ended::Exited(exit)),
                () = self.abort_wanted() => return Err(self.abort(running).await),
                live = running.live() => live,
            };
            if live {
                let readiness = tokio::select! {
                    biased;
                    exit = running.exited() => return Err(Ended::Exited(exit)),
                    () = self.abort_wanted() => return Err(self.abort(running).await),
                    readiness = self.probe.probe(&self.spec) => readiness,
                };
                match readiness {
                    WorkerReadiness::Ready { observed } => return Ok(observed),
                    WorkerReadiness::Unchecked
                    | WorkerReadiness::Starting
                    | WorkerReadiness::Failed {
                        failure: WorkerFailure::Unreachable,
                        ..
                    } => {}
                    parked => {
                        let _ = running.terminate(self.policy.stop_grace).await;
                        let reason = match &parked {
                            WorkerReadiness::Failed { failure, .. } => {
                                format!("its qualification answer contradicts a pin ({failure:?})")
                            }
                            _ => "its qualification answer is missing evidence".to_owned(),
                        };
                        return Err(Ended::Parked {
                            readiness: parked,
                            reason,
                        });
                    }
                }
            }
            tokio::select! {
                biased;
                exit = running.exited() => return Err(Ended::Exited(exit)),
                () = tokio::time::sleep(self.policy.liveness_poll) => {}
            }
        }
    }

    /// Closes admission when no lease is held and nobody waits.
    fn close_if_idle(&self) -> bool {
        let closed = {
            let mut state = self.lock();
            if state.leases == 0 && state.waiting == 0 && !state.retiring && self.admission_idle() {
                state.phase = Phase::Draining;
                true
            } else {
                false
            }
        };
        self.notify();
        closed
    }

    /// Closes admission, waits for every lease and for the worker's own
    /// reported work to end, then terminates it. No deadline: live work is
    /// never cut.
    async fn drain_and_stop(&self, running: &dyn RunningWorker, next: Phase) -> Ended {
        {
            self.lock().phase = Phase::Draining;
        }
        self.notify();
        loop {
            let mut changes = self.changed.subscribe();
            if self.abort_requested() {
                return self.abort(running).await;
            }
            if self.lock().leases == 0 {
                break;
            }
            tokio::select! {
                biased;
                _ = running.exited() => return Ended::Stopped(next),
                _ = changes.changed() => {}
            }
        }
        loop {
            let activity = tokio::select! {
                biased;
                _ = running.exited() => return Ended::Stopped(next),
                () = self.abort_wanted() => return self.abort(running).await,
                activity = running.activity() => activity,
            };
            if activity.is_none_or(|activity| activity.is_idle()) {
                break;
            }
            tokio::select! {
                biased;
                _ = running.exited() => return Ended::Stopped(next),
                () = self.abort_wanted() => return self.abort(running).await,
                () = tokio::time::sleep(self.policy.liveness_poll) => {}
            }
        }
        // An abort asked during the drain reaches the worker there.
        tokio::select! {
            biased;
            () = self.abort_wanted() => return self.abort(running).await,
            _ = running.terminate(self.policy.stop_grace) => {}
        }
        Ended::Stopped(next)
    }

    async fn acquire_load_grant(&self) -> Result<Option<LoadGrant>, ()> {
        let Some(admission) = self.admission() else {
            return Ok(None);
        };
        let Some((_, declared)) = &self.device else {
            return Ok(None);
        };
        let declared = *declared;
        loop {
            let admission_changed = admission.changed();
            tokio::pin!(admission_changed);
            admission_changed.as_mut().enable();
            let mut worker_changed = self.changed.subscribe();
            if self.retiring() || self.abort_requested() {
                return Err(());
            }
            if let Some(grant) =
                admission.acquire_load(&self.spec.worker_id, &declared, self.resource_class())
            {
                return Ok(Some(grant));
            }
            tokio::select! {
                () = admission_changed.as_mut() => {},
                _ = worker_changed.changed() => {}
            }
        }
    }

    fn reserve_device(&self) {
        // With admission, the pre-launch grant owns all load bytes; Ready
        // promotes them to the steady row. The legacy path is unchanged.
        if self.admission().is_some() {
            return;
        }
        if let Some((ledger, declared)) = &self.device {
            ledger.reserve(&self.spec.worker_id, *declared);
        }
    }

    fn mark_loaded(&self) {
        if let (Some(admission), Some((_, declared))) = (self.admission(), &self.device) {
            admission.loaded(&self.spec.worker_id, *declared, self.resource_class());
        }
    }

    fn release_device(&self) {
        if let Some(admission) = self.admission() {
            admission.reaped(&self.spec.worker_id);
        } else if let Some((ledger, _)) = &self.device {
            ledger.release(&self.spec.worker_id);
        }
    }
}

/// A managed worker's driver: install, then launch, qualify and serve
/// incarnations until it parks, stops for idleness with no demand waiting,
/// or is retired.
pub(super) async fn drive(inner: Arc<Inner>) {
    let Some(launcher) = inner.launcher.clone() else {
        inner.finish_or_restart(Phase::Stopped);
        return;
    };
    let worker = inner.spec.worker_id.clone();
    let mut attempt = 0_usize;
    'install: loop {
        if !inner.enter(Phase::Installing) {
            inner.finish_or_restart(Phase::Stopped);
            return;
        }
        if let Err(failure) = launcher.install(&inner.spec).await {
            if failure.permanent {
                inner.park(failed(&failure), failure.reason);
                return;
            }
            inner.note_failure(&failure.reason);
            tracing::warn!(%worker, reason = %failure.reason, "model worker install failed; trying again");
            if !inner.back_off(&mut attempt).await {
                inner.finish_or_restart(Phase::Stopped);
                return;
            }
            continue 'install;
        }
        loop {
            if !inner.enter(Phase::Starting) {
                inner.finish_or_restart(Phase::Stopped);
                return;
            }
            let _load_grant = match inner.acquire_load_grant().await {
                Ok(grant) => grant,
                Err(()) => {
                    inner.finish_or_restart(Phase::Stopped);
                    return;
                }
            };
            let running = match launcher.launch(&inner.spec).await {
                Ok(running) => running,
                Err(failure) if failure.permanent => {
                    inner.park(failed(&failure), failure.reason);
                    return;
                }
                Err(failure) => {
                    inner.note_failure(&failure.reason);
                    tracing::warn!(%worker, reason = %failure.reason, "model worker did not start; trying again");
                    if !inner.back_off(&mut attempt).await {
                        inner.finish_or_restart(Phase::Stopped);
                        return;
                    }
                    continue;
                }
            };
            inner.reserve_device();
            let ended = inner.serve(&*running, &mut attempt).await;
            inner.release_device();
            inner.revoke();
            match ended {
                // An abort relaunches at once: the next incarnation serves
                // the other vaults, and its first call starts it anyway.
                Ended::Aborted(exit) => {
                    tracing::info!(%worker, exit = %exit.description, "aborted model worker reaped");
                }
                Ended::Exited(exit) => {
                    inner.note_failure(&exit.description);
                    tracing::warn!(%worker, exit = %exit.description, "model worker exited; relaunching after its backoff");
                    if !inner.back_off(&mut attempt).await {
                        inner.finish_or_restart(Phase::Stopped);
                        return;
                    }
                }
                Ended::Stopped(phase) => {
                    if !inner.finish_or_restart(phase) {
                        return;
                    }
                }
                Ended::Parked { readiness, reason } => {
                    inner.park(readiness, reason);
                    return;
                }
            }
        }
    }
}

/// A launch failure as the readiness it parks the worker in.
fn failed(failure: &LaunchFailure) -> WorkerReadiness {
    WorkerReadiness::Failed {
        failure: failure.failure,
        observed: None,
    }
}
