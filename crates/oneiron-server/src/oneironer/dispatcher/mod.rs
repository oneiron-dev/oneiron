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
//! no worker is ready or coming.
//!
//! The dispatcher belongs to its slot, one per server process: no static
//! holds a worker.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use oneiron::memory::extraction::{
    EncoderAttempt, EncoderExecution, EncoderInput, ExecutionPick, ExtractionWork,
};
use tokio::sync::{Notify, oneshot};

mod capacity;
mod policy;
mod worker;

use policy::{BULK_BATCH_CAP, Candidate, LIVE_BATCH_CAP};
use worker::WorkerState;

pub(crate) use capacity::{Completion, DispatchClaim, pending_cap};
pub(crate) use worker::WorkerSpec;

/// Tool name on every failure the dispatcher reports itself.
const DISPATCH_TOOL: &str = "oneironer-dispatcher";

/// One call, from its claim to its answer.
pub(super) struct Job {
    pub(super) input: EncoderInput,
    work: ExtractionWork,
    /// When it was queued: its wait is measured from here.
    pub(super) queued_at: Instant,
    reply: oneshot::Sender<EncoderAttempt>,
}

/// One unit a worker runs: its calls, each with why the worker runs it.
pub(super) type Unit = Vec<(Job, ExecutionPick)>;

/// The dispatcher's handle on one worker: what it runs as, how far up it is,
/// its rank, and the live calls routed to it.
struct WorkerHandle {
    /// Its engine id, as receipts and logs name it.
    engine: String,
    /// Its place in the calibrated rank: 0 is preferred.
    rank: usize,
    /// Inputs one unit of its may hold.
    batch: usize,
    state: WorkerState,
    /// Running a unit.
    busy: bool,
    /// Live calls routed to it, each with the rule that routed it.
    live: VecDeque<(Job, ExecutionPick)>,
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

    fn ready(&self) -> bool {
        self.workers
            .iter()
            .any(|worker| worker.state == WorkerState::Ready)
    }

    fn coming(&self) -> bool {
        self.workers.iter().any(|worker| worker.state.coming())
    }

    /// Queues `job`, or hands it back when no worker is ready or coming to
    /// run it, or the dispatcher has closed.
    fn queue(&mut self, job: Job) -> Result<(), Job> {
        if self.closed {
            return Err(job);
        }
        match job.work {
            ExtractionWork::Live => {
                let candidates: Vec<Candidate> = self
                    .workers
                    .iter()
                    .enumerate()
                    .filter(|(_, worker)| worker.state == WorkerState::Ready)
                    .map(|(index, worker)| Candidate {
                        index,
                        rank: worker.rank,
                        free: !worker.busy && worker.live.is_empty(),
                        waiting: worker.live.len(),
                    })
                    .collect();
                if let Some((index, rule)) = policy::route_live(&candidates, &mut self.cursor) {
                    self.workers[index].live.push_back((job, rule));
                } else if self.coming() {
                    self.unrouted.push_back(job);
                } else {
                    return Err(job);
                }
            }
            ExtractionWork::Bulk if self.ready() || self.coming() => self.bulk.push_back(job),
            ExtractionWork::Bulk => return Err(job),
        }
        Ok(())
    }

    /// The next unit worker `index` runs: live calls first, else up to its
    /// batch of the shared bulk queue.
    fn take(&mut self, index: usize) -> Option<Unit> {
        let mut unit = Vec::new();
        while unit.len() < LIVE_BATCH_CAP
            && let Some((job, rule)) = self.next_live(index)
        {
            unit.push((job, self.reason(index, rule)));
        }
        if unit.is_empty() {
            let pick = self.reason(index, ExecutionPick::Free);
            let count = BULK_BATCH_CAP
                .min(self.workers[index].batch)
                .min(self.bulk.len());
            unit.extend(self.bulk.drain(..count).map(|job| (job, pick)));
        }
        if unit.is_empty() {
            return None;
        }
        self.workers[index].busy = true;
        Some(unit)
    }

    /// The live call worker `index` takes next: its own queue's, else the
    /// oldest waiting anywhere, which a worker that frees up takes before any
    /// bulk call.
    fn next_live(&mut self, index: usize) -> Option<(Job, ExecutionPick)> {
        if let Some(routed) = self.workers[index].live.pop_front() {
            return Some(routed);
        }
        let mut oldest = self.unrouted.front().map(|job| (None, job.queued_at));
        for (other, worker) in self.workers.iter().enumerate() {
            if let Some((job, _)) = worker.live.front()
                && oldest.is_none_or(|(_, at)| job.queued_at < at)
            {
                oldest = Some((Some(other), job.queued_at));
            }
        }
        let job = match oldest?.0 {
            None => self.unrouted.pop_front()?,
            Some(other) => self.workers[other].live.pop_front()?.0,
        };
        Some((job, ExecutionPick::Free))
    }

    /// Why worker `index` runs a call a routing `rule` gave it.
    fn reason(&self, index: usize, rule: ExecutionPick) -> ExecutionPick {
        let rank = self.workers[index].rank;
        let preferred_away = self
            .workers
            .iter()
            .any(|worker| worker.rank < rank && worker.state != WorkerState::Ready);
        policy::reason(self.pinned, preferred_away, rule)
    }

    /// Every queued call, once no worker is ready or coming to run it, with
    /// its room given back.
    fn stranded(&mut self) -> Vec<Job> {
        if self.ready() || self.coming() {
            return Vec::new();
        }
        self.drain_queued()
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
    /// A worker may have a unit to take, or the dispatcher closed.
    work: Condvar,
    /// Room was given back: a blocking claim may have room.
    room: Condvar,
    /// Live room was given back: an async live claim may have room.
    live_room: Notify,
    /// Bulk room was given back: an async bulk claim may have room.
    bulk_room: Notify,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Scheduler> {
        self.scheduler
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Blocks worker `index`'s thread until it has a unit; `None` once the
    /// dispatcher has closed.
    pub(super) fn next_unit(&self, index: usize) -> Option<Unit> {
        let mut scheduler = self.lock();
        loop {
            if scheduler.closed {
                return None;
            }
            if let Some(unit) = scheduler.take(index) {
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

    /// Moves worker `index` to `state`. A worker that leaves for good, with
    /// no other ready or coming, answers every queued call: no worker is
    /// left to run it.
    pub(super) fn settle(&self, index: usize, state: WorkerState, why: Option<&str>) {
        let (engine, stranded) = {
            let mut scheduler = self.lock();
            scheduler.workers[index].state = state;
            let stranded = scheduler.stranded();
            (scheduler.workers[index].engine.clone(), stranded)
        };
        if let Some(why) = why {
            tracing::warn!(engine = %engine, state = state.as_str(), why, "oneironer worker");
        } else {
            tracing::info!(engine = %engine, state = state.as_str(), "oneironer worker");
        }
        if !stranded.is_empty() {
            self.room_freed(stranded.iter().map(|job| job.work));
            unrun(stranded, "no oneironer worker is ready");
        }
    }
}

/// Answers calls no worker ran: no execution, and the failure says why.
fn unrun(jobs: Vec<Job>, why: &str) {
    for job in jobs {
        let _ = job.reply.send(EncoderAttempt {
            execution: None,
            result: Err(failure(DISPATCH_TOOL, why)),
        });
    }
}

/// A failure that carries its class and never any text a call read.
pub(super) fn failure(tool: &'static str, code: &str) -> oneiron::Error {
    oneiron::Error::UpstreamToolFailure {
        tool,
        code: code.to_owned(),
    }
}

/// The slot's dispatcher and the workers it owns.
pub(crate) struct Dispatcher {
    shared: Arc<Shared>,
}

impl Dispatcher {
    /// A dispatcher with no worker yet. `pinned` says the slot serves one
    /// configured worker, a named device or an endpoint: its receipts say so.
    pub(crate) fn new(pinned: bool) -> Self {
        Self {
            shared: Arc::new(Shared {
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
            }),
        }
    }

    /// Starts one worker on its own thread, Loading; it takes work once it is
    /// Ready. Callable at any time: a worker whose load is slow starts after
    /// the listener binds, and the workers already ready serve meanwhile.
    pub(crate) fn add(&self, spec: WorkerSpec) -> anyhow::Result<()> {
        let engine = EncoderExecution::engine_id(spec.runtime, spec.compute);
        let index = {
            let mut scheduler = self.shared.lock();
            scheduler.workers.push(WorkerHandle {
                engine: engine.clone(),
                rank: spec.rank,
                batch: spec.batch.max(1),
                state: WorkerState::Loading,
                busy: false,
                live: VecDeque::new(),
            });
            scheduler.workers.len() - 1
        };
        let shared = Arc::clone(&self.shared);
        let spawned = std::thread::Builder::new()
            .name(format!("oneironer {engine}"))
            .spawn(move || worker::serve(&shared, index, spec));
        match spawned {
            // The thread outlives this handle and ends when the dispatcher
            // closes.
            Ok(_detached) => Ok(()),
            Err(error) => {
                let why = Some("its thread did not start");
                self.shared.settle(index, WorkerState::Failed, why);
                Err(error.into())
            }
        }
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

impl Drop for Dispatcher {
    /// Closes: each worker's thread ends after the unit it runs, and every
    /// call still queued is answered, so no completion a claim outlived the
    /// dispatcher with waits for good. A call submitted later is answered at
    /// once.
    fn drop(&mut self) {
        let queued = {
            let mut scheduler = self.shared.lock();
            scheduler.closed = true;
            scheduler.drain_queued()
        };
        self.shared.work.notify_all();
        if !queued.is_empty() {
            self.shared.room_freed(queued.iter().map(|job| job.work));
            unrun(queued, "the oneironer dispatcher closed");
        }
    }
}
