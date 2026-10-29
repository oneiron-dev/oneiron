//! The life of a supervised worker (FIX 6755 slice 3, Engine call 3): a
//! platform runtime's managed process, kept on one worker of its dispatcher
//! for as long as the dispatcher lives.
//!
//! One supervisor thread holds a factory it can call again. Each session
//! goes Loading (started and handshaken by its factory), Calibrating (its
//! owner's held reference cases on this host, never through the
//! dispatcher), then Ready, and serves units until it faults. A crash, its
//! stream ended, broken or past a deadline, a reply that is not its
//! request's, a panic or a wrong count in a unit, takes it out of Ready at
//! once, idle or not: its routed calls go back to routing, the call in
//! flight fails with the worker's own receipt, and markers retry through
//! their owner. It is restarted after a backoff that starts at the
//! section's `retry_backoff_secs` and doubles up to `max_retry_backoff_secs`,
//! and the first good unit of a freshly admitted session resets it. An
//! identity mismatch or a parity failure is down: the worker stays
//! Unavailable, its reason named, for the rest of the process.
//!
//! Every wait observes the dispatcher's close. The close reaches a live
//! session's wait through the stop hook it registered, and the dispatcher's
//! drop joins every supervisor, each of which shuts its session down and
//! reaps it first. State and rank change under a short scheduler lock; no
//! spawn, read, wait, calibration or kill holds it.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, PoisonError, Weak};
use std::time::{Duration, Instant};

use super::worker::{Worker, WorkerDescriptor, WorkerSpec, WorkerState, serve_unit};
use super::{Dispatcher, Scheduler, Shared, WorkerId, add};

/// The reason a worker whose process ended while it was Ready leaves it.
const EXITED: &str = "worker_exited";

/// Why a supervised session ended, or never began.
#[derive(Debug)]
pub(crate) enum Fault {
    /// It crashed: Failed, and restarted after its backoff. The reason is a
    /// fixed name (`worker_exited`, `call_timeout`, ...).
    Crash(&'static str),
    /// It is not the pinned worker (`identity_mismatch:<field>`), its answers
    /// do not clear here (`parity_failed`), its Core ML row is not one this
    /// build runs (`coreml_unsupported_port`, `coreml_unsupported_heads`),
    /// its model did not load (`coreml_load_failed:<part>`,
    /// `coreml_io_mismatch:<tensor>`), or its in-process calibration failed
    /// (`calibration_failed:<detail>`): Unavailable until a new process.
    Down(String),
    /// The dispatcher closed.
    Stopped,
}

/// How long a crashed worker waits before each restart: `first`, doubling
/// up to `max`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Restart {
    first: Duration,
    max: Duration,
}

impl Restart {
    /// From the section's marker retry settings, in seconds: the restart
    /// has no constant of its own (Engine call 3).
    pub(crate) fn new(first_secs: u64, max_secs: u64) -> Self {
        let first = Duration::from_secs(first_secs.max(1));
        Self {
            first,
            max: Duration::from_secs(max_secs).max(first),
        }
    }
}

/// Starts one session of a supervised worker on its own thread.
type Factory = Box<dyn FnMut(&Lifeline) -> Result<Box<dyn Worker>, Fault> + Send>;
/// Admits a started session before it is Ready: the rank published for it,
/// or why it may not serve.
type Admit = Box<dyn FnMut(&mut dyn Worker) -> Result<usize, Fault> + Send>;

/// A supervised worker's bring-up, callable again after each crash.
pub(super) struct Supervised {
    pub(super) factory: Factory,
    pub(super) admit: Admit,
    pub(super) restart: Restart,
}

/// A supervised session's line back to its dispatcher, for the threads that
/// own its process. Weak, so it keeps no dispatcher open.
#[derive(Clone)]
pub(crate) struct Lifeline {
    shared: Weak<Shared>,
    index: usize,
}

impl Lifeline {
    /// Its process ended or broke its stream, as its own IO thread saw it: a
    /// Ready worker leaves Ready now, idle or not, its routed calls go back
    /// to routing and the scheduler wakes. In any other state, or once the
    /// dispatcher has closed, the change is its supervisor's to make.
    pub(crate) fn exited(&self) {
        if let Some(shared) = self.shared.upgrade() {
            let index = self.index;
            let wanted = |scheduler: &Scheduler| ready_and_open(scheduler, index);
            shared.settle_if(index, WorkerState::Failed, Some(EXITED), wanted);
        }
    }

    /// Runs `stop` when the dispatcher closes, or now if it has: how the
    /// close reaches the session's wait. A later session's replaces it.
    pub(crate) fn on_close(&self, stop: Box<dyn Fn() + Send>) {
        let Some(shared) = self.shared.upgrade() else {
            stop();
            return;
        };
        let mut scheduler = shared.lock();
        if scheduler.closed {
            drop(scheduler);
            stop();
            return;
        }
        scheduler.workers[self.index].stop = Some(stop);
    }
}

/// A dispatcher's door for an owner that runs beside it, as a platform
/// runtime's admission does: it adds workers and publishes ranks while the
/// dispatcher lives, and does nothing once it has gone. Weak, so an owner
/// never keeps a dispatcher open.
#[derive(Clone)]
pub(crate) struct DispatcherHandle {
    shared: Weak<Shared>,
}

impl Dispatcher {
    /// A handle on this dispatcher that does not keep it open.
    pub(crate) fn handle(&self) -> DispatcherHandle {
        DispatcherHandle {
            shared: Arc::downgrade(&self.shared),
        }
    }
}

impl DispatcherHandle {
    /// [`Dispatcher::add`], while the dispatcher is open.
    pub(crate) fn add(&self, spec: WorkerSpec) -> anyhow::Result<WorkerId> {
        let shared = self
            .shared
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("the oneironer dispatcher closed"))?;
        add(&shared, spec)
    }

    /// [`Dispatcher::publish_rank`], while the dispatcher lives.
    pub(crate) fn publish_rank(&self, worker: WorkerId, rank: usize) {
        if let Some(shared) = self.shared.upgrade() {
            shared.publish_rank(worker.0, rank);
        }
    }

    /// Takes `worker` out of service for good, while the dispatcher lives,
    /// for `why` (FIX 7108): it takes no more work, its routed calls go back
    /// to routing, and its thread ends, dropping its model, once the unit it
    /// runs is done.
    pub(crate) fn retire(&self, worker: WorkerId, why: &str) {
        if let Some(shared) = self.shared.upgrade() {
            shared.settle(worker.0, WorkerState::Unavailable, Some(why));
        }
    }
}

/// How one session ended, for its supervisor.
enum Ending {
    /// It crashed; `proven` once it had served a good unit.
    Crashed { proven: bool },
    /// The worker is down, or the dispatcher closed.
    Over,
}

/// Worker `index`'s supervisor, on its own thread for the dispatcher's
/// life: starts each session, serves it until it faults, and restarts it
/// after its backoff, on this one worker; it never adds another. It ends
/// when the dispatcher closes or the worker is down.
pub(super) fn supervise(
    shared: &Arc<Shared>,
    index: usize,
    descriptor: &WorkerDescriptor,
    mut supervised: Supervised,
) {
    let lifeline = Lifeline {
        shared: Arc::downgrade(shared),
        index,
    };
    let Restart { first, max } = supervised.restart;
    let mut delay = first;
    loop {
        if closed(shared) {
            return;
        }
        match session(shared, index, descriptor, &mut supervised, &lifeline) {
            Ending::Over => return,
            Ending::Crashed { proven } => {
                if proven {
                    delay = first;
                }
                if !rest(shared, delay) {
                    return;
                }
                delay = delay.saturating_mul(2).min(max);
                shared.settle(index, WorkerState::Loading, None);
            }
        }
    }
}

/// One session, from its start to its end. The worker is Loading on entry.
/// Its process is shut down and reaped as the session's worker drops, after
/// its state has moved.
fn session(
    shared: &Shared,
    index: usize,
    descriptor: &WorkerDescriptor,
    supervised: &mut Supervised,
    lifeline: &Lifeline,
) -> Ending {
    let started = catch_unwind(AssertUnwindSafe(|| (supervised.factory)(lifeline)));
    let mut worker = match started {
        Ok(Ok(worker)) => worker,
        Ok(Err(fault)) => return settle_fault(shared, index, fault),
        Err(_) => return settle_fault(shared, index, Fault::Crash("start_panicked")),
    };
    shared.settle(index, WorkerState::Calibrating, None);
    let admitted = catch_unwind(AssertUnwindSafe(|| (supervised.admit)(worker.as_mut())));
    match admitted {
        // Its owner's rank for it, published before it takes work.
        Ok(Ok(rank)) => shared.publish_rank(index, rank),
        Ok(Err(fault)) => return settle_fault(shared, index, fault),
        Err(_) => return settle_fault(shared, index, Fault::Crash("calibration_panicked")),
    }
    shared.settle(index, WorkerState::Ready, None);
    let mut proven = false;
    while let Some(unit) = shared.next_unit(index) {
        let fault = serve_unit(shared, index, descriptor, worker.as_mut(), unit)
            .or_else(|| worker.broken());
        if let Some(why) = fault {
            let wanted = |scheduler: &Scheduler| ready_and_open(scheduler, index);
            shared.settle_if(index, WorkerState::Failed, Some(why), wanted);
            return Ending::Crashed { proven };
        }
        proven = true;
    }
    // Out of Ready: the dispatcher closed, or the process ended while the
    // worker idled and its lifeline moved it.
    if closed(shared) {
        Ending::Over
    } else {
        Ending::Crashed { proven }
    }
}

/// Settles a session's `fault`: a crash is Failed, to restart; a down
/// worker Unavailable for good; a stop, or any fault once the dispatcher
/// has closed, moves nothing.
fn settle_fault(shared: &Shared, index: usize, fault: Fault) -> Ending {
    if closed(shared) {
        return Ending::Over;
    }
    match fault {
        Fault::Crash(why) => {
            shared.settle(index, WorkerState::Failed, Some(why));
            Ending::Crashed { proven: false }
        }
        Fault::Down(why) => {
            shared.settle(index, WorkerState::Unavailable, Some(&why));
            Ending::Over
        }
        Fault::Stopped => Ending::Over,
    }
}

/// Waits `delay` before a restart: `false` once the dispatcher closes,
/// whose close wakes it at once.
fn rest(shared: &Shared, delay: Duration) -> bool {
    let until = Instant::now() + delay;
    let mut scheduler = shared.lock();
    loop {
        if scheduler.closed {
            return false;
        }
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        scheduler = shared
            .work
            .wait_timeout(scheduler, left)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

fn closed(shared: &Shared) -> bool {
    shared.lock().closed
}

/// Whether worker `index` is Ready in an open dispatcher: the one state a
/// crash moves it out of.
fn ready_and_open(scheduler: &Scheduler, index: usize) -> bool {
    !scheduler.closed && scheduler.workers[index].state == WorkerState::Ready
}
