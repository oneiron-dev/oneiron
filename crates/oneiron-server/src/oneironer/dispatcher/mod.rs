//! The slot's one dispatcher (FIX 6755): every extraction call the slot takes
//! goes through it to a ready worker, and comes back with the facts of the
//! worker that ran it.
//!
//! One scheduler lock holds every decision. A live call takes a free ready
//! worker on arrival, the calibrated rank choosing when several are free;
//! when every worker is busy it joins the shorter waiting live queue, ties
//! taken in turn. Live goes before bulk at every unit a worker takes: a
//! worker that frees up takes its own live queue, then the oldest live call
//! waiting anywhere, and only then the next batch from the one shared bulk
//! queue. A running unit is never pre-empted, and while live calls keep
//! coming bulk waits: strict priority, with no starvation timer.
//!
//! Each worker runs one unit at a time on its own thread. No call builds a
//! model, and no worker keeps a queue the scheduler cannot see.
//!
//! A caller claims room in its class before its call queues ([`policy`]'s
//! pending caps); past the cap the claim waits on the caller's own thread,
//! or, for the tagging coordinator, as an awaited future on its class's own
//! signal ([`capacity`]), holding no scheduler lock and no store transaction.
//! Nothing is refused for a backlog: a call fails without a worker only when
//! no worker that can run it is ready or coming.
//!
//! A worker runs only the calls its qualified window holds ([`eligibility`]):
//! each call's window is counted once as it is submitted, outside every
//! lock, and a window longer than a short worker's goes to Candle, whose
//! window is the configured maximum. A worker that leaves Ready gives its
//! routed live calls back to routing, and each owner publishes its worker's
//! calibrated rank under the scheduler lock ([`Dispatcher::publish_rank`]).
//!
//! A platform runtime's worker is supervised ([`lifecycle`], FIX 6755 slice
//! 3): it is measured before it is Ready, leaves Ready the moment its
//! process ends, idle or not, and is restarted on the same worker after a
//! backoff. The dispatcher's close reaches every supervised session and
//! joins its supervisor, so no child process outlives it.
//!
//! The dispatcher belongs to its slot, one per server process: no static
//! holds a worker.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Instant;

use oneiron::memory::extraction::{EncoderAttempt, EncoderInput, ExecutionPick, ExtractionWork};
use tokio::sync::{Notify, oneshot};

use super::local::WindowCounter;

mod capacity;
mod eligibility;
mod lifecycle;
mod policy;
mod worker;

use policy::LIVE_BATCH_CAP;
use worker::WorkerState;

pub(crate) use capacity::{Completion, DispatchClaim, pending_cap};
pub(crate) use lifecycle::{DispatcherHandle, Fault, Lifeline, Restart};
pub(crate) use policy::BULK_BATCH_CAP;
pub(crate) use worker::{Worker, WorkerDescriptor, WorkerSpec};

/// Tool name on every failure the dispatcher reports itself.
const DISPATCH_TOOL: &str = "oneironer-dispatcher";
/// Why a call no worker can run is answered.
const NO_WORKER: &str = "no oneironer worker is ready";
/// The rank of a worker no owner has ranked yet: below every ranked one.
const UNRANKED: usize = usize::MAX;

/// One call, from its claim to its answer.
pub(super) struct Job {
    pub(super) input: EncoderInput,
    work: ExtractionWork,
    /// Its live window in tokens with specials, counted once as it was
    /// submitted: which workers may run it. 0 in a slot that counts none,
    /// whose one worker runs every call.
    window: usize,
    /// When it was queued: its wait is measured from here.
    pub(super) queued_at: Instant,
    reply: oneshot::Sender<EncoderAttempt>,
}

/// One unit a worker runs: its calls, each with why the worker runs it.
pub(super) type Unit = Vec<(Job, ExecutionPick)>;

/// The dispatcher's handle on one worker: what it is, how far up it is, its
/// rank, and the live calls routed to it.
struct WorkerHandle {
    /// What it runs as and the longest window it may run, fixed.
    descriptor: WorkerDescriptor,
    /// Its place in the calibrated rank: 0 is preferred.
    rank: usize,
    /// Inputs one unit of its may hold.
    batch: usize,
    state: WorkerState,
    /// Running a unit.
    busy: bool,
    /// Live calls routed to it, each with the rule that routed it.
    live: VecDeque<(Job, ExecutionPick)>,
    /// What ends its live session's waits when the dispatcher closes: a
    /// supervised worker's, set by each session it starts.
    stop: Option<Box<dyn Fn() + Send>>,
}

/// Everything the scheduler lock holds.
struct Scheduler {
    workers: Vec<WorkerHandle>,
    /// Live calls that came while no worker was ready and one was coming.
    unrouted: VecDeque<Job>,
    /// The one shared bulk queue: whichever ready worker frees up first
    /// takes its next batch.
    bulk: VecDeque<Job>,
    /// Live calls claimed and not yet answered.
    live_pending: usize,
    /// Bulk calls claimed and not yet answered.
    bulk_pending: usize,
    /// The one cursor busy ties rotate on.
    cursor: usize,
    /// Whether the slot serves one configured worker: a named device or an
    /// endpoint.
    pinned: bool,
    closed: bool,
}

impl Scheduler {
    fn pending(&mut self, work: ExtractionWork) -> &mut usize {
        match work {
            ExtractionWork::Live => &mut self.live_pending,
            ExtractionWork::Bulk => &mut self.bulk_pending,
        }
    }

    /// Queues `job`, or hands it back when no worker that can run it is
    /// ready or coming, or the dispatcher has closed.
    fn queue(&mut self, job: Job) -> Result<(), Job> {
        if self.closed {
            return Err(job);
        }
        match job.work {
            ExtractionWork::Live => self.route(job),
            ExtractionWork::Bulk if self.served(job.window) => {
                self.bulk.push_back(job);
                Ok(())
            }
            ExtractionWork::Bulk => Err(job),
        }
    }

    /// The next unit worker `index` runs: live calls first, else up to its
    /// batch of the shared bulk queue, each a call its window holds.
    fn take(&mut self, index: usize) -> Option<Unit> {
        let mut unit = Vec::new();
        while unit.len() < LIVE_BATCH_CAP
            && let Some((job, rule)) = self.next_live(index)
        {
            let pick = self.reason(index, rule, job.window);
            unit.push((job, pick));
        }
        if unit.is_empty() {
            let count = BULK_BATCH_CAP.min(self.workers[index].batch);
            for job in self.take_bulk(index, count) {
                let pick = self.reason(index, ExecutionPick::Free, job.window);
                unit.push((job, pick));
            }
        }
        if unit.is_empty() {
            return None;
        }
        self.workers[index].busy = true;
        Some(unit)
    }

    /// Every queued call, taken off its queue with its room given back.
    fn drain_queued(&mut self) -> Vec<Job> {
        let mut jobs: Vec<Job> = self.unrouted.drain(..).collect();
        jobs.extend(self.bulk.drain(..));
        for worker in &mut self.workers {
            jobs.extend(worker.live.drain(..).map(|(job, _)| job));
        }
        for job in &jobs {
            *self.pending(job.work) -= 1;
        }
        jobs
    }
}

/// The scheduler and its signals, shared with every worker's thread and
/// every claim.
pub(super) struct Shared {
    scheduler: Mutex<Scheduler>,
    /// How a call's window is counted; `None` in a slot that counts none.
    windows: Option<WindowCounter>,
    /// A worker may have a unit to take, or the dispatcher closed.
    work: Condvar,
    /// Room was given back: a blocking claim may have room.
    room: Condvar,
    /// Live room was given back: an async live claim may have room.
    live_room: Notify,
    /// Bulk room was given back: an async bulk claim may have room.
    bulk_room: Notify,
    /// Every supervised worker's thread, joined when the dispatcher closes.
    supervisors: Mutex<Vec<JoinHandle<()>>>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Scheduler> {
        self.scheduler
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// `input`'s window in tokens, counted with no lock held; 0 in a slot
    /// that counts none. A window that cannot be built fails its call as
    /// that call's infer would.
    pub(super) fn count(&self, input: &EncoderInput) -> oneiron::Result<usize> {
        self.windows
            .as_ref()
            .map_or(Ok(0), |windows| windows.count(input))
    }

    /// Blocks worker `index`'s thread until it has a unit; `None` once the
    /// dispatcher has closed or the worker has left for good. A worker out
    /// of Ready takes nothing, whatever woke it.
    pub(super) fn next_unit(&self, index: usize) -> Option<Unit> {
        let mut scheduler = self.lock();
        loop {
            let state = scheduler.workers[index].state;
            let left = matches!(state, WorkerState::Unavailable | WorkerState::Failed);
            if scheduler.closed || left {
                return None;
            }
            if state == WorkerState::Ready
                && let Some(unit) = scheduler.take(index)
            {
                return Some(unit);
            }
            scheduler = self
                .work
                .wait(scheduler)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// Worker `index` ran its unit: it is free, each call's room is given
    /// back, and each caller gets its answer.
    pub(super) fn finish(&self, index: usize, answered: Vec<(Job, EncoderAttempt)>) {
        {
            let mut scheduler = self.lock();
            scheduler.workers[index].busy = false;
            for (job, _) in &answered {
                *scheduler.pending(job.work) -= 1;
            }
        }
        self.work.notify_all();
        self.room_freed(answered.iter().map(|(job, _)| job.work));
        for (job, attempt) in answered {
            // A caller that stopped waiting has nothing to hear.
            let _ = job.reply.send(attempt);
        }
    }

    /// Moves worker `index` to `state`, under the scheduler lock. A worker
    /// out of Ready gives its routed live calls back to routing, their room
    /// and replies kept; every queued call no worker that can run it is
    /// ready or coming for is answered: no worker is left to run it.
    pub(super) fn settle(&self, index: usize, state: WorkerState, why: Option<&str>) {
        self.settle_if(index, state, why, |_| true);
    }

    /// [`Self::settle`], only when `wanted` holds of the scheduler under the
    /// same lock: whether it moved. However many threads see one crash, it
    /// moves the worker once.
    fn settle_if(
        &self,
        index: usize,
        state: WorkerState,
        why: Option<&str>,
        wanted: impl FnOnce(&Scheduler) -> bool,
    ) -> bool {
        let (engine, stranded) = {
            let mut scheduler = self.lock();
            if !wanted(&scheduler) {
                return false;
            }
            scheduler.workers[index].state = state;
            if state != WorkerState::Ready {
                scheduler.reroute(index);
            }
            let stranded = scheduler.stranded();
            (scheduler.workers[index].descriptor.engine(), stranded)
        };
        // A rerouted call may wait for a worker that is free now.
        self.work.notify_all();
        if let Some(why) = why {
            tracing::warn!(engine = %engine, state = state.as_str(), why, "oneironer worker");
        } else {
            tracing::info!(engine = %engine, state = state.as_str(), "oneironer worker");
        }
        if !stranded.is_empty() {
            self.room_freed(stranded.iter().map(|job| job.work));
            unrun(stranded, NO_WORKER);
        }
        true
    }

    /// Publishes worker `index`'s rank under the scheduler lock: routing and
    /// receipts read it from the next call on.
    pub(super) fn publish_rank(&self, index: usize, rank: usize) {
        self.lock().workers[index].rank = rank;
    }
}

/// Answers calls no worker ran: no execution, and the failure says why.
fn unrun(jobs: Vec<Job>, why: &str) {
    for job in jobs {
        answer(job, failure(DISPATCH_TOOL, why));
    }
}

/// Answers a call no worker ran with `error`. A caller that stopped waiting
/// has nothing to hear.
fn answer(job: Job, error: oneiron::Error) {
    let _ = job.reply.send(EncoderAttempt {
        execution: None,
        result: Err(error),
    });
}

/// A failure that carries its class and never any text a call read.
pub(super) fn failure(tool: &'static str, code: &str) -> oneiron::Error {
    oneiron::Error::UpstreamToolFailure {
        tool,
        code: code.to_owned(),
    }
}

/// One worker of a dispatcher, as its owner names it to rank it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WorkerId(usize);

/// The slot's dispatcher and the workers it owns.
pub(crate) struct Dispatcher {
    shared: Arc<Shared>,
}

impl Dispatcher {
    /// A dispatcher with no worker yet. `pinned` says the slot serves one
    /// configured worker, a named device or an endpoint: its receipts say so.
    /// `windows` counts each call's window, the one every worker of the slot
    /// builds; `None` for a slot whose one worker runs every call.
    pub(crate) fn new(pinned: bool, windows: Option<WindowCounter>) -> Self {
        Self {
            shared: Arc::new(Shared {
                windows,
                scheduler: Mutex::new(Scheduler {
                    workers: Vec::new(),
                    unrouted: VecDeque::new(),
                    bulk: VecDeque::new(),
                    live_pending: 0,
                    bulk_pending: 0,
                    cursor: 0,
                    pinned,
                    closed: false,
                }),
                work: Condvar::new(),
                room: Condvar::new(),
                live_room: Notify::new(),
                bulk_room: Notify::new(),
                supervisors: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Starts one worker on its own thread, Loading and unranked; it takes
    /// work once it is Ready. Callable at any time: a worker whose load is
    /// slow starts after the listener binds, and the workers already ready
    /// serve meanwhile.
    pub(crate) fn add(&self, spec: WorkerSpec) -> anyhow::Result<WorkerId> {
        add(&self.shared, spec)
    }

    /// Publishes `worker`'s calibrated rank, 0 preferred, under the
    /// scheduler lock (FIX 6755). Its owner calls it once the worker is
    /// measured: the slot for the Candle baseline its rows chose, and a
    /// platform runtime's admission for its own row. A slower ready worker
    /// stays in the pool, ranked below.
    pub(crate) fn publish_rank(&self, worker: WorkerId, rank: usize) {
        self.shared.publish_rank(worker.0, rank);
    }

    /// The window `input` builds, counted with the slot's tokenizer, `0`
    /// for a slot that counts none: a blocking encode (FIX 7331).
    pub(crate) fn count(&self, input: &EncoderInput) -> oneiron::Result<usize> {
        self.shared.count(input)
    }

    /// One call in `work`'s class: claims room, queues the call, and waits
    /// for the answer of the worker that ran it.
    pub(crate) fn call(&self, input: &EncoderInput, work: ExtractionWork) -> EncoderAttempt {
        let claim = capacity::claim_blocking(&self.shared, work);
        claim.submit(input.clone()).wait()
    }

    /// Room for one call in `work`'s class, for an async caller: awaited on
    /// its class's own signal with nothing held ([`capacity`]). The future
    /// owns its share of the scheduler, so it outlives this borrow; dropped
    /// before it resolves, it holds no room. It never refuses.
    pub(crate) fn claim_async(
        &self,
        work: ExtractionWork,
    ) -> impl std::future::Future<Output = DispatchClaim> + Send + 'static {
        capacity::claim(Arc::clone(&self.shared), work)
    }
}

/// [`Dispatcher::add`] on `shared`, for the dispatcher or a handle of it
/// (`lifecycle::DispatcherHandle`). The thread starts under the scheduler
/// lock, so a close that follows sees every supervisor it must join; a
/// closed dispatcher adds none.
fn add(shared: &Arc<Shared>, spec: WorkerSpec) -> anyhow::Result<WorkerId> {
    let descriptor = spec.descriptor().clone();
    let engine = descriptor.engine();
    let supervised = spec.supervised();
    let mut scheduler = shared.lock();
    anyhow::ensure!(!scheduler.closed, "the oneironer dispatcher closed");
    scheduler.workers.push(WorkerHandle {
        descriptor,
        rank: UNRANKED,
        batch: spec.batch().max(1),
        state: WorkerState::Loading,
        busy: false,
        live: VecDeque::new(),
        stop: None,
    });
    let index = scheduler.workers.len() - 1;
    let thread_shared = Arc::clone(shared);
    let spawned = std::thread::Builder::new()
        .name(format!("oneironer {engine}"))
        .spawn(move || worker::start(&thread_shared, index, spec));
    match spawned {
        Ok(thread) => {
            // An unsupervised thread outlives its handle and ends when the
            // dispatcher closes.
            if supervised {
                shared.supervisors().push(thread);
            }
            Ok(WorkerId(index))
        }
        Err(error) => {
            drop(scheduler);
            let why = Some("its thread did not start");
            shared.settle(index, WorkerState::Failed, why);
            Err(error.into())
        }
    }
}

impl Shared {
    fn supervisors(&self) -> MutexGuard<'_, Vec<JoinHandle<()>>> {
        self.supervisors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl Dispatcher {
    /// Closes: each worker's thread ends after the unit it runs, and every
    /// call still queued is answered, so no completion a claim outlived the
    /// dispatcher with waits for good. A call submitted later is answered at
    /// once. Each supervised session's wait is stopped, and its supervisor
    /// joined once it has shut its process down and reaped it. It blocks for
    /// those joins, so serve's teardown calls it on a blocking unit through
    /// [`super::SlotClose`] (FIX 7383); a second close finds nothing left.
    pub(crate) fn close(&self) {
        let (queued, stops) = {
            let mut scheduler = self.shared.lock();
            scheduler.closed = true;
            let stops: Vec<_> = scheduler
                .workers
                .iter_mut()
                .filter_map(|worker| worker.stop.take())
                .collect();
            (scheduler.drain_queued(), stops)
        };
        self.shared.work.notify_all();
        for stop in stops {
            stop();
        }
        if !queued.is_empty() {
            self.shared.room_freed(queued.iter().map(|job| job.work));
            unrun(queued, "the oneironer dispatcher closed");
        }
        let supervisors = std::mem::take(&mut *self.shared.supervisors());
        for supervisor in supervisors {
            let _ = supervisor.join();
        }
    }
}

impl Drop for Dispatcher {
    /// Closes, unless teardown already did ([`Dispatcher::close`]).
    fn drop(&mut self) {
        self.close();
    }
}
