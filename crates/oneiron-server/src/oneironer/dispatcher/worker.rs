//! One worker: a model loaded on one engine, or the one opaque endpoint, on
//! its own thread. The thread brings it up (Loading, Warming, Calibrating),
//! then runs the units the dispatcher gives it, one at a time, until the
//! dispatcher closes. Only a Ready worker takes work. A cold or failed load
//! leaves the worker Failed for this process and writes no row.
//!
//! The worker seam is batch-capable (FIX 6755 slice 2b). A worker is built
//! on its own thread by its spec's loader, which alone crosses threads, and
//! never leaves that thread, so it need not be `Send`. Each unit is one
//! [`Worker::run_batch`] call: one result per call, in order. Each call
//! keeps its own receipt: its wait to the unit's start, and the unit's whole
//! run. Every worker carries a fixed [`WorkerDescriptor`], whose qualified
//! window decides which calls it may run (`super::eligibility`).

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Instant;

use oneiron::memory::extraction::{
    EncoderAttempt, EncoderExecution, EncoderInput, EncoderMessage, EncoderOutput,
    ExecutionCompute, ExecutionPick, ExecutionRuntime,
};

use super::super::endpoint::HttpTagger;
use super::super::engines::Engine;
use super::super::local::LocalTagger;
use super::{Job, Shared, failure};
use crate::config::EmbedderDevice;

/// Tool name on a failure a worker reports for its own thread.
const WORKER_TOOL: &str = "oneironer-worker";
/// The turn and message id of the input a worker warms on.
const WARM_ID: &str = "warm-up";
/// The text it warms on: no vault text.
const WARM_TEXT: &str = "Warming up.";

/// One concrete execution stream (FIX 6755). Only its own thread runs it,
/// and it holds no queue of its own. It is built on that thread and stays
/// there, so it need not be `Send`; only its spec's loader crosses threads.
pub(crate) trait Worker {
    /// One input to its semantic answer.
    fn run(&mut self, input: &EncoderInput) -> oneiron::Result<EncoderOutput>;

    /// One unit's inputs in one call: one result per input, in order. A
    /// worker that sends them as one request fails every input when that
    /// request fails. This one runs them one at a time.
    fn run_batch(&mut self, inputs: &[&EncoderInput]) -> Vec<oneiron::Result<EncoderOutput>> {
        inputs.iter().map(|input| self.run(input)).collect()
    }
}

impl Worker for LocalTagger {
    fn run(&mut self, input: &EncoderInput) -> oneiron::Result<EncoderOutput> {
        self.infer(input)
    }
}

impl Worker for Arc<HttpTagger> {
    fn run(&mut self, input: &EncoderInput) -> oneiron::Result<EncoderOutput> {
        self.infer(input)
    }
}

/// Brings a worker's model up on its own thread: the one part of a spec that
/// crosses threads.
type Load = Box<dyn FnOnce() -> anyhow::Result<Box<dyn Worker>> + Send>;
/// Measures a worker on its own thread against the bundle's reference: the
/// rank its owner gives its measured speed when its answers clear, `None`
/// when they do not.
type Calibrate = Box<dyn FnOnce(&mut dyn Worker) -> Option<usize> + Send>;

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

/// What a worker is, fixed when its spec is built (FIX 6755): the runtime
/// and compute its receipts name, the bytes it runs, and the longest window
/// it is qualified to run, in tokens with specials. A call whose window is
/// longer never reaches it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WorkerDescriptor {
    runtime: ExecutionRuntime,
    compute: ExecutionCompute,
    /// The bytes it loaded, by hash.
    artifact_sha16: String,
    max_window_tokens: usize,
}

impl WorkerDescriptor {
    pub(crate) fn new(
        runtime: ExecutionRuntime,
        compute: ExecutionCompute,
        artifact_sha16: &str,
        max_window_tokens: usize,
    ) -> Self {
        Self {
            runtime,
            compute,
            artifact_sha16: artifact_sha16.to_owned(),
            max_window_tokens,
        }
    }

    /// A Candle engine's. Its artifact is the stack its bundle hashes to,
    /// and its qualified window is the configured `max_input_tokens`: it
    /// runs every window the slot builds. Candle runs it whichever runtime
    /// setting chose it.
    pub(crate) fn candle(engine: Engine, stack: &str, max_input_tokens: usize) -> Self {
        let compute = match engine.device {
            // A load on `auto` runs on the built-in CPU engine.
            EmbedderDevice::Cpu | EmbedderDevice::Auto => ExecutionCompute::Cpu,
            EmbedderDevice::Metal => ExecutionCompute::Metal,
            EmbedderDevice::Cuda => ExecutionCompute::Cuda,
        };
        Self::new(ExecutionRuntime::Candle, compute, stack, max_input_tokens)
    }

    /// The endpoint's. The checkpoint it must report stands for its bytes,
    /// and its window is its own, which the host does not claim: it runs
    /// every call.
    pub(crate) fn endpoint(checkpoint: &str) -> Self {
        Self::new(
            ExecutionRuntime::Endpoint,
            ExecutionCompute::Opaque,
            checkpoint,
            usize::MAX,
        )
    }

    pub(crate) const fn runtime(&self) -> ExecutionRuntime {
        self.runtime
    }

    /// `runtime/compute`, as receipts, rows and logs name it.
    pub(crate) fn engine(&self) -> String {
        EncoderExecution::engine_id(self.runtime, self.compute)
    }

    pub(crate) fn artifact_sha16(&self) -> &str {
        &self.artifact_sha16
    }

    pub(crate) const fn max_window_tokens(&self) -> usize {
        self.max_window_tokens
    }
}

/// A worker the dispatcher starts: what it is, how many calls one unit of
/// its may carry, and how its thread brings it up. Its rank is published to
/// the dispatcher by its owner (`Dispatcher::publish_rank`).
pub(crate) struct WorkerSpec {
    descriptor: WorkerDescriptor,
    /// Inputs one unit of its may hold: 1 for a worker that runs them one at
    /// a time.
    batch: usize,
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
    pub(crate) fn local(engine: Engine, tagger: LocalTagger) -> Self {
        Self {
            descriptor: WorkerDescriptor::candle(
                engine,
                tagger.stack_sha16(),
                tagger.max_input_tokens(),
            ),
            // Candle runs one unpadded sequence at a time.
            batch: 1,
            load: Box::new(move || Ok(Box::new(tagger) as Box<dyn Worker>)),
            warm: Some(warm_input()),
            calibrate: None,
        }
    }

    /// The configured endpoint, which must report `checkpoint`: one opaque
    /// worker, Ready at once. Its server warms itself, and one that is not
    /// up yet fails its calls, not the worker.
    pub(crate) fn endpoint(tagger: Arc<HttpTagger>, checkpoint: &str) -> Self {
        Self {
            descriptor: WorkerDescriptor::endpoint(checkpoint),
            // The dispatcher sends it one call at a time.
            batch: 1,
            load: Box::new(move || Ok(Box::new(tagger) as Box<dyn Worker>)),
            warm: None,
            calibrate: None,
        }
    }

    /// A platform runtime's worker, started after the listener binds: `load`
    /// builds it on its own thread and warms it, then `calibrate` measures
    /// it there before it is Ready, and the rank it returns is published. A
    /// unit of its carries up to `batch` bulk calls in one
    /// [`Worker::run_batch`].
    #[expect(
        dead_code,
        reason = "the MLX and Core ML adapters build their workers by it (FIX 6755 slices 3, 2c)"
    )]
    pub(crate) fn background(
        descriptor: WorkerDescriptor,
        batch: usize,
        load: impl FnOnce() -> anyhow::Result<Box<dyn Worker>> + Send + 'static,
        calibrate: impl FnOnce(&mut dyn Worker) -> Option<usize> + Send + 'static,
    ) -> Self {
        Self {
            descriptor,
            batch,
            load: Box::new(load),
            warm: None,
            calibrate: Some(Box::new(calibrate)),
        }
    }

    pub(super) const fn descriptor(&self) -> &WorkerDescriptor {
        &self.descriptor
    }

    pub(super) const fn batch(&self) -> usize {
        self.batch
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
        descriptor,
        load,
        warm,
        calibrate,
        ..
    } = spec;
    let Some(mut worker) = bring_up(shared, index, load, warm, calibrate) else {
        return;
    };
    while let Some(unit) = shared.next_unit(index) {
        let started = Instant::now();
        let results = run_unit(worker.as_mut(), &unit);
        let ran = started.elapsed();
        let answered = unit
            .into_iter()
            .zip(results)
            .map(|((job, pick), result)| {
                // Each call waited to the unit's start; the unit's whole run
                // is each call's, never divided among them.
                let execution = EncoderExecution::new(
                    descriptor.runtime,
                    descriptor.compute,
                    pick,
                    started.saturating_duration_since(job.queued_at),
                    ran,
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

/// One unit as one [`Worker::run_batch`] call: one result per call, in
/// order. A worker that panics, or answers another number of calls, fails
/// every call of the unit.
fn run_unit(
    worker: &mut dyn Worker,
    unit: &[(Job, ExecutionPick)],
) -> Vec<oneiron::Result<EncoderOutput>> {
    let inputs: Vec<&EncoderInput> = unit.iter().map(|(job, _)| &job.input).collect();
    let code = match catch_unwind(AssertUnwindSafe(|| worker.run_batch(&inputs))) {
        Ok(results) if results.len() == inputs.len() => return results,
        Ok(_) => "the worker answered another number of calls",
        Err(_) => "the worker panicked",
    };
    inputs
        .iter()
        .map(|_| Err(failure(WORKER_TOOL, code)))
        .collect()
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
    let mut worker = match catch_unwind(AssertUnwindSafe(load)) {
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
        let measured = catch_unwind(AssertUnwindSafe(|| calibrate(worker.as_mut())));
        let Ok(Some(rank)) = measured else {
            let why = "its answers do not clear the bundle's reference";
            shared.settle(index, WorkerState::Unavailable, Some(why));
            return None;
        };
        // Its owner's rank for it, published before it takes work.
        shared.publish_rank(index, rank);
    }
    shared.settle(index, WorkerState::Ready, None);
    Some(worker)
}
