//! The one identity a claimed seat run holds everything under (FIX 9319,
//! FIX 9320): its claimed fence.
//!
//! Every registration the host makes for one claimed run is keyed by that
//! fence and retired with it, on every way out: the run's T1 destinations
//! (registered under the claimed attempt, which is the attempt a live run
//! holding that claim resolves to), the live run its CLI acts in when a
//! live-run owner registers one ([`SeatChildRuns`]), and the watch on the
//! claim ([`HostSeatLease`]). A claim lost while the run goes on retires
//! the destinations at once and stops the run's process; a successor's
//! registration is never touched.
//!
//! The CLI's own live run is a seam: no live-run owner registers a seat
//! child yet ([`NoSeatChildRuns`]), so a T1 grant's materialize still finds
//! no live run for the CLI, as before (FIX 9319 PART). The owner that does
//! registers a child live run whose leased try IS the claimed attempt, with
//! a credential scoped to that claim, never an unbound attempt id.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use oneiron::attempt_queue::AttemptId;
use oneiron::dispatch_byoa::ByoaExecutionFence;

use super::super::secret_destinations::{
    RunSecretDestinations, SecretDestination, SecretDestinations, is_env_name,
};
use super::lease::HostSeatLease;
use crate::server::SyncServer;

/// Where a seat run's child live run is registered: the live-run and
/// credential owners' seam (FIX 9319).
pub(super) trait SeatChildRuns: Send + Sync {
    /// Registers a live run whose leased try is `fence`'s claimed attempt,
    /// with a credential scoped to that claim attached for the run's CLI.
    /// `false` when this owner registers none.
    fn begin(&self, fence: &ByoaExecutionFence) -> bool;

    /// Retires what [`Self::begin`] registered for `fence`, and only that.
    fn retire(&self, fence: &ByoaExecutionFence);
}

/// No live-run owner registers seat children yet: the CLI acts in no live
/// run, as before.
pub(super) struct NoSeatChildRuns;

impl SeatChildRuns for NoSeatChildRuns {
    fn begin(&self, _fence: &ByoaExecutionFence) -> bool {
        false
    }

    fn retire(&self, _fence: &ByoaExecutionFence) {}
}

/// Everything one claimed run holds, under its fence.
pub(super) struct SeatChildRun<'a> {
    fence: ByoaExecutionFence,
    destinations: Option<HeldDestinations<'a>>,
    lease: Option<HostSeatLease>,
    child_runs: &'a dyn SeatChildRuns,
    attached: bool,
}

impl<'a> SeatChildRun<'a> {
    /// Registers the run's destinations and its child live run under
    /// `fence`, before any process starts, and watches the claim.
    pub(super) fn begin(
        server: &'a Arc<SyncServer>,
        fence: &ByoaExecutionFence,
        child_runs: &'a dyn SeatChildRuns,
    ) -> Self {
        let destinations = HeldDestinations::register(
            &server.secret_destinations,
            fence.attempt_id,
            &server.config.runtime.host_destinations,
        );
        let attached = child_runs.begin(fence);
        // A claim lost under the run retires its own destinations at once;
        // the run's process stops on the lease's flag.
        let retire = {
            let server = Arc::clone(server);
            let run = fence.attempt_id;
            let handle = destinations.as_ref().map(|held| held.handle.clone());
            move || {
                if let Some(handle) = handle {
                    server.secret_destinations.retire_own(run, &handle);
                }
            }
        };
        let lease = HostSeatLease::watch(Arc::clone(server.vault()), fence.clone(), retire);
        Self {
            fence: fence.clone(),
            destinations,
            lease: Some(lease),
            child_runs,
            attached,
        }
    }

    /// The destinations the run's processes are handed.
    pub(super) fn destinations(&self) -> Option<RunSecretDestinations> {
        self.destinations.as_ref().map(|held| held.handle.clone())
    }

    /// The flag the run's process stops on once its claim is lost.
    pub(super) fn stop_flag(&self) -> Option<Arc<AtomicBool>> {
        self.lease.as_ref().map(HostSeatLease::stop_flag)
    }

    /// The run's processes are done: retires everything it registered.
    /// Whether its claim was lost while it ran.
    pub(super) fn end(mut self) -> bool {
        let lost = self.lease.take().is_some_and(HostSeatLease::end);
        drop(self);
        lost
    }
}

impl Drop for SeatChildRun<'_> {
    fn drop(&mut self) {
        drop(self.lease.take());
        drop(self.destinations.take());
        if self.attached {
            self.child_runs.retire(&self.fence);
        }
    }
}

/// The destinations one leased run registered: retired, its own
/// registration only, when the run lets them go, on every way out.
struct HeldDestinations<'a> {
    registry: &'a SecretDestinations,
    run: AttemptId,
    handle: RunSecretDestinations,
}

impl<'a> HeldDestinations<'a> {
    /// Registers `bindings`, variable to effector, for `run`. A binding
    /// whose variable is no environment variable name or whose effector is
    /// blank is passed over, with a warning; with none left, nothing is
    /// registered and a T1 grant refuses by name, as before.
    fn register(
        registry: &'a SecretDestinations,
        run: AttemptId,
        bindings: &BTreeMap<String, String>,
    ) -> Option<Self> {
        let mut destinations = Vec::new();
        for (variable, effector) in bindings {
            if !is_env_name(variable) || effector.trim().is_empty() {
                tracing::warn!(
                    %variable,
                    "a runtime.host_destinations binding names no variable or no effector; passed over"
                );
                continue;
            }
            destinations.push(SecretDestination::env(variable.clone(), effector.trim()));
        }
        if destinations.is_empty() {
            return None;
        }
        match registry.register(run, destinations) {
            Ok(handle) => Some(Self {
                registry,
                run,
                handle,
            }),
            Err(error) => {
                tracing::warn!(%error, "a seat run's destinations were not registered");
                None
            }
        }
    }
}

impl Drop for HeldDestinations<'_> {
    fn drop(&mut self) {
        self.registry.retire_own(self.run, &self.handle);
    }
}
