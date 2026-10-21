//! Which worker may run which call (FIX 6755 slice 2b).
//!
//! Each call's live window is counted once, as it is submitted, outside
//! every lock; each worker carries the longest window it is qualified for
//! (`WorkerDescriptor`). A worker runs only the calls its window holds:
//! live routing picks among the ready workers that hold the call, a worker
//! steals only a live call it holds, and a bulk take is the oldest bulk
//! calls it holds, the others left queued in place so a long call at the
//! front never holds back the short ones behind it. Candle's window is the
//! configured `max_input_tokens`, so a window longer than a short worker's
//! goes to Candle and is never refused for its length.
//!
//! Eligibility splits no work by length: any ready worker that holds a call
//! may run it, by the same free, shorter-queue, rank and stealing rules,
//! live before bulk at every unit. A call is answered without a worker only
//! when no worker that holds it is ready or coming. The class pending caps
//! stay backpressure alone (`super::capacity`).

use std::collections::VecDeque;
use std::time::Instant;

use oneiron::memory::extraction::ExecutionPick;

use super::policy::{self, Candidate};
use super::worker::WorkerState;
use super::{Job, Scheduler, WorkerHandle};

impl WorkerHandle {
    /// Whether its qualified window holds a call of `window` tokens.
    pub(super) const fn fits(&self, window: usize) -> bool {
        window <= self.descriptor.max_window_tokens()
    }

    /// Whether it takes work now or may yet.
    fn ready_or_coming(&self) -> bool {
        self.state == WorkerState::Ready || self.state.coming()
    }
}

impl Scheduler {
    /// Whether a worker that holds a call of `window` tokens is ready or
    /// coming to run it.
    pub(super) fn served(&self, window: usize) -> bool {
        self.workers
            .iter()
            .any(|worker| worker.fits(window) && worker.ready_or_coming())
    }

    /// Whether a worker that holds a call of `window` tokens is coming.
    fn coming_for(&self, window: usize) -> bool {
        self.workers
            .iter()
            .any(|worker| worker.fits(window) && worker.state.coming())
    }

    /// Routes a live call to a ready worker that holds it, by the policy's
    /// rule; with none ready, it waits unrouted while one that holds it is
    /// coming. Handed back when none is ready or coming.
    pub(super) fn route(&mut self, job: Job) -> Result<(), Job> {
        let candidates: Vec<Candidate> = self
            .workers
            .iter()
            .enumerate()
            .filter(|(_, worker)| worker.state == WorkerState::Ready && worker.fits(job.window))
            .map(|(index, worker)| Candidate {
                index,
                rank: worker.rank,
                free: !worker.busy && worker.live.is_empty(),
                waiting: worker.live.len(),
            })
            .collect();
        if let Some((index, rule)) = policy::route_live(&candidates, &mut self.cursor) {
            self.workers[index].live.push_back((job, rule));
        } else if self.coming_for(job.window) {
            self.unrouted.push_back(job);
        } else {
            return Err(job);
        }
        Ok(())
    }

    /// The live call worker `index` takes next: its own queue's, each of
    /// which it holds, else the oldest it holds waiting anywhere, which a
    /// worker that frees up takes before any bulk call. It never steals a
    /// call its window does not hold.
    pub(super) fn next_live(&mut self, index: usize) -> Option<(Job, ExecutionPick)> {
        if let Some(routed) = self.workers[index].live.pop_front() {
            return Some(routed);
        }
        let max = self.workers[index].descriptor.max_window_tokens();
        let unrouted = self
            .unrouted
            .iter()
            .enumerate()
            .map(|(place, job)| (place, job.window, job.queued_at));
        let mut oldest = oldest_held(None, unrouted, max);
        for (other, worker) in self.workers.iter().enumerate() {
            let queued = worker
                .live
                .iter()
                .enumerate()
                .map(|(place, (job, _))| (place, job.window, job.queued_at));
            if let Some((queue, place, at)) = oldest_held(Some(other), queued, max)
                && oldest.is_none_or(|(_, _, held)| at < held)
            {
                oldest = Some((queue, place, at));
            }
        }
        let job = match oldest? {
            (None, place, _) => self.unrouted.remove(place)?,
            (Some(other), place, _) => self.workers[other].live.remove(place)?.0,
        };
        Some((job, ExecutionPick::Free))
    }

    /// Up to `count` of the oldest bulk calls worker `index` holds, in
    /// queue order. A call it does not hold stays queued in place for a
    /// worker that does.
    pub(super) fn take_bulk(&mut self, index: usize, count: usize) -> Vec<Job> {
        let max = self.workers[index].descriptor.max_window_tokens();
        let mut taken = Vec::new();
        let mut place = 0;
        while taken.len() < count && place < self.bulk.len() {
            if self.bulk[place].window <= max {
                taken.extend(self.bulk.remove(place));
            } else {
                place += 1;
            }
        }
        taken
    }

    /// Why worker `index` runs a call of `window` tokens a routing `rule`
    /// gave it: `fallback` when a worker ranked above it that holds the call
    /// is not ready. A better-ranked worker too short for the call is no
    /// fallback's reason.
    pub(super) fn reason(&self, index: usize, rule: ExecutionPick, window: usize) -> ExecutionPick {
        let rank = self.workers[index].rank;
        let preferred_away = self.workers.iter().any(|worker| {
            worker.rank < rank && worker.fits(window) && worker.state != WorkerState::Ready
        });
        policy::reason(self.pinned, preferred_away, rule)
    }

    /// Worker `index` left Ready: each live call routed to it goes through
    /// live routing again, to a ready worker that holds it, or unrouted
    /// while one is coming. Its room and its reply stay with it. A call no
    /// worker is ready or coming for waits for [`Self::stranded`].
    pub(super) fn reroute(&mut self, index: usize) {
        let routed = std::mem::take(&mut self.workers[index].live);
        for (job, _) in routed {
            if let Err(job) = self.route(job) {
                self.unrouted.push_back(job);
            }
        }
    }

    /// Every queued call no worker that holds it is ready or coming to run,
    /// taken off its queue with its room given back.
    pub(super) fn stranded(&mut self) -> Vec<Job> {
        let mut stranded = Vec::new();
        let (unrouted, gone): (VecDeque<Job>, VecDeque<Job>) = std::mem::take(&mut self.unrouted)
            .into_iter()
            .partition(|job| self.served(job.window));
        self.unrouted = unrouted;
        stranded.extend(gone);
        let (bulk, gone): (VecDeque<Job>, VecDeque<Job>) = std::mem::take(&mut self.bulk)
            .into_iter()
            .partition(|job| self.served(job.window));
        self.bulk = bulk;
        stranded.extend(gone);
        for index in 0..self.workers.len() {
            let (live, gone): (VecDeque<_>, VecDeque<_>) =
                std::mem::take(&mut self.workers[index].live)
                    .into_iter()
                    .partition(|(job, _)| self.served(job.window));
            self.workers[index].live = live;
            stranded.extend(gone.into_iter().map(|(job, _)| job));
        }
        for job in &stranded {
            *self.pending(job.work) -= 1;
        }
        stranded
    }
}

/// Where the oldest of `queued` that a window of `max` tokens holds waits:
/// `queue`, the unrouted one (`None`) or a worker's, its place there, and
/// when it was queued. Each of `queued` is its place, its window and when it
/// was queued.
fn oldest_held(
    queue: Option<usize>,
    queued: impl Iterator<Item = (usize, usize, Instant)>,
    max: usize,
) -> Option<(Option<usize>, usize, Instant)> {
    queued
        .filter(|&(_, window, _)| window <= max)
        .min_by_key(|&(_, _, at)| at)
        .map(|(place, _, at)| (queue, place, at))
}
