//! One worker: a model loaded on one engine, or the one opaque endpoint, on
//! its own thread. The thread brings it up (Loading, Warming, Calibrating),
//! then runs the units the dispatcher gives it, one at a time, until the
//! dispatcher closes. Only a Ready worker takes work. A cold or failed load
//! leaves the worker Failed for this process and writes no row.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Instant;

use oneiron::memory::extraction::{
    EncoderAttempt, EncoderExecution, EncoderInput, EncoderMessage, EncoderOutput,
    ExecutionCompute, ExecutionRuntime,
};

use super::super::endpoint::HttpTagger;
use super::super::engines::Engine;
use super::super::local::LocalTagger;
use super::{Shared, failure};
use crate::config::EmbedderDevice;
use crate::config::oneironer::OneironerRuntime;

/// Tool name on a failure a worker reports for its own thread.
const WORKER_TOOL: &str = "oneironer-worker";
/// The turn and message id of the input a worker warms on.
const WARM_ID: &str = "warm-up";
/// The text it warms on: no vault text.
const WARM_TEXT: &str = "Warming up.";

/// One concrete execution stream. Only its own thread runs it, and it holds
/// no queue of its own.
pub(crate) trait Worker: Send {
    /// One input to its semantic answer.
    fn run(&self, input: &EncoderInput) -> oneiron::Result<EncoderOutput>;
}

impl Worker for LocalTagger {
    fn run(&self, input: &EncoderInput) -> oneiron::Result<EncoderOutput> {
        self.infer(input)
    }
}

impl Worker for Arc<HttpTagger> {
    fn run(&self, input: &EncoderInput) -> oneiron::Result<EncoderOutput> {
        self.infer(input)
    }
}

/// Brings a worker's model up on its own thread.
type Load = Box<dyn FnOnce() -> anyhow::Result<Box<dyn Worker>> + Send>;
/// Measures a worker on its own thread: whether its answers clear the
/// bundle's reference.
type Calibrate = Box<dyn FnOnce(&dyn Worker) -> bool + Send>;

/// How far up a worker is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerState {
    /// Its model is loading on its own thread.
    Loading,
    /// It makes one untimed call before it takes work.
    Warming,
    /// It is measured against the bundle's reference before it takes work.
    Calibrating,
    /// It takes work.
    Ready,
    /// It runs, but its answers do not clear the bundle's reference here.
    Unavailable,
    /// Its load failed: it takes no work in this process.
    Failed,
}

impl WorkerState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Loading => "loading",
            Self::Warming => "warming",
            Self::Calibrating => "calibrating",
            Self::Ready => "ready",
            Self::Unavailable => "unavailable",
            Self::Failed => "failed",
        }
    }

    /// Whether it may still become Ready.
    pub(crate) const fn coming(self) -> bool {
        matches!(self, Self::Loading | Self::Warming | Self::Calibrating)
    }
}

/// A worker the dispatcher starts: what it runs as, where it ranks, and how
/// its thread brings it up.
pub(crate) struct WorkerSpec {
    pub(super) runtime: ExecutionRuntime,
    pub(super) compute: ExecutionCompute,
    /// Its place in the slot's calibrated rank: 0 is preferred.
    pub(super) rank: usize,
    /// Inputs one unit of its may hold: 1 for a worker that runs them one at
    /// a time.
    pub(super) batch: usize,
    load: Load,
    /// The untimed call it makes before it is Ready; `None` for a worker
    /// that warms itself.
    warm: Option<EncoderInput>,
    /// Its calibration before it is Ready; `None` when the slot's rows
    /// already rank it.
    calibrate: Option<Calibrate>,
}

impl WorkerSpec {
    /// A candle model loaded where it always loads (`engines::load`), before
    /// the listener binds. Its thread warms it once, and it is Ready.
    pub(crate) fn local(engine: Engine, rank: usize, tagger: LocalTagger) -> Self {
        Self {
            runtime: match engine.runtime {
                OneironerRuntime::Candle => ExecutionRuntime::Candle,
            },
            compute: match engine.device {
                // A load on `auto` runs on the built-in CPU engine.
                EmbedderDevice::Cpu | EmbedderDevice::Auto => ExecutionCompute::Cpu,
                EmbedderDevice::Metal => ExecutionCompute::Metal,
                EmbedderDevice::Cuda => ExecutionCompute::Cuda,
            },
            rank,
            // Candle runs one unpadded sequence at a time.
            batch: 1,
            load: Box::new(move || Ok(Box::new(tagger) as Box<dyn Worker>)),
            warm: Some(warm_input()),
            calibrate: None,
        }
    }

    /// The configured endpoint: one opaque worker, Ready at once. Its server
    /// warms itself, and one that is not up yet fails its calls, not the
    /// worker.
    pub(crate) fn endpoint(tagger: Arc<HttpTagger>) -> Self {
        Self {
            runtime: ExecutionRuntime::Endpoint,
            compute: ExecutionCompute::Opaque,
            rank: 0,
            // The dispatcher sends it one call at a time.
            batch: 1,
            load: Box::new(move || Ok(Box::new(tagger) as Box<dyn Worker>)),
            warm: None,
            calibrate: None,
        }
    }
}

/// The input a worker warms on: one short message, alone. Its answer is
/// dropped.
fn warm_input() -> EncoderInput {
    EncoderInput {
        turn: WARM_ID.to_owned(),
        messages: vec![EncoderMessage {
            id: WARM_ID.to_owned(),
            text: WARM_TEXT.to_owned(),
        }],
        context: Vec::new(),
        language: None,
        speaker: None,
    }
}

/// Worker `index`'s thread: brings it up, then runs what the dispatcher gives
/// it until the dispatcher closes. Every call it runs, failed or not, comes
/// back with its execution.
pub(super) fn serve(shared: &Shared, index: usize, spec: WorkerSpec) {
    let WorkerSpec {
        runtime,
        compute,
        load,
        warm,
        calibrate,
        ..
    } = spec;
    let Some(worker) = bring_up(shared, index, load, warm, calibrate) else {
        return;
    };
    while let Some(unit) = shared.next_unit(index) {
        let answered = unit
            .into_iter()
            .map(|(job, pick)| {
                let started = Instant::now();
                let result = catch_unwind(AssertUnwindSafe(|| worker.run(&job.input)))
                    .unwrap_or_else(|_| Err(failure(WORKER_TOOL, "the worker panicked")));
                let execution = EncoderExecution::new(
                    runtime,
                    compute,
                    pick,
                    started.saturating_duration_since(job.queued_at),
                    started.elapsed(),
                );
                let attempt = EncoderAttempt {
                    execution: Some(execution),
                    result,
                };
                (job, attempt)
            })
            .collect();
        shared.finish(index, answered);
    }
}

/// Loading, then Warming and Calibrating when the spec asks, then Ready.
/// `None` when the worker ends Failed or Unavailable.
fn bring_up(
    shared: &Shared,
    index: usize,
    load: Load,
    warm: Option<EncoderInput>,
    calibrate: Option<Calibrate>,
) -> Option<Box<dyn Worker>> {
    let worker = match catch_unwind(AssertUnwindSafe(load)) {
        Ok(Ok(worker)) => worker,
        Ok(Err(error)) => {
            let why = format!("its load failed: {error}");
            shared.settle(index, WorkerState::Failed, Some(&why));
            return None;
        }
        Err(_) => {
            shared.settle(index, WorkerState::Failed, Some("its load panicked"));
            return None;
        }
    };
    if let Some(input) = warm {
        shared.settle(index, WorkerState::Warming, None);
        // The warm-up only warms: a failed one leaves the worker taking work,
        // its calls failing and retrying one by one as an unwarmed one's do.
        let warmed = catch_unwind(AssertUnwindSafe(|| worker.run(&input)));
        if !matches!(warmed, Ok(Ok(_))) {
            tracing::warn!(worker = index, "an Oneironer worker's warm-up call failed");
        }
    }
    if let Some(calibrate) = calibrate {
        shared.settle(index, WorkerState::Calibrating, None);
        let cleared = catch_unwind(AssertUnwindSafe(|| calibrate(worker.as_ref())));
        if !matches!(cleared, Ok(true)) {
            let why = "its answers do not clear the bundle's reference";
            shared.settle(index, WorkerState::Unavailable, Some(why));
            return None;
        }
    }
    shared.settle(index, WorkerState::Ready, None);
    Some(worker)
}
