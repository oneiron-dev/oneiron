//! One worker: a model loaded on one engine, or the one opaque endpoint, on
//! its own thread. The thread brings it up (Loading, Warming), then runs the
//! units the dispatcher gives it, one at a time, until the dispatcher
//! closes. Only a Ready worker takes work. A cold or failed load leaves the
//! worker Failed for this process and writes no row. A platform runtime's
//! worker is supervised instead (`super::lifecycle`): measured before it is
//! Ready, and restarted on the same worker after a crash (FIX 6755 slice 3).
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
    EncoderAttempt, EncoderExecution, EncoderInput, EncoderMessage, EncoderOutput, EncoderRegister,
    ExecutionCompute, ExecutionPick, ExecutionRuntime,
};

use super::super::endpoint::HttpTagger;
use super::super::engines::Engine;
use super::super::local::LocalTagger;
use super::lifecycle::{Fault, Lifeline, Restart, Supervised};
use super::{Job, Shared, Unit, failure};
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

    /// Why it can take no further unit, once its process died or its
    /// stream broke: its supervisor then restarts it. A worker that runs in
    /// this process never breaks so.
    fn broken(&self) -> Option<&'static str> {
        None
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
    /// It runs, but it is not the pinned worker or its answers do not clear
    /// the bundle's reference here: it takes no work in this process.
    Unavailable,
    /// Its load failed, or a supervised worker crashed: it takes no work
    /// until its supervisor restarts it, if it has one.
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
    bring: Bring,
}

/// How a worker's thread brings it up.
enum Bring {
    /// Once: a load that fails leaves it Failed for this process. `warm` is
    /// the untimed call it makes before it is Ready; `None` for a worker
    /// that warms itself.
    Once {
        load: Load,
        warm: Option<EncoderInput>,
    },
    /// Again after each crash, by its supervisor (`super::lifecycle`).
    Supervised(Supervised),
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
            bring: Bring::Once {
                load: Box::new(move || Ok(Box::new(tagger) as Box<dyn Worker>)),
                warm: Some(warm_input()),
            },
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
            bring: Bring::Once {
                load: Box::new(move || Ok(Box::new(tagger) as Box<dyn Worker>)),
                warm: None,
            },
        }
    }

    /// A platform runtime's worker, started after the listener binds and
    /// supervised for the dispatcher's life (`super::lifecycle`): `factory`
    /// starts each session on the worker's own thread, warmed, then `admit`
    /// measures it there before it is Ready and returns the rank published
    /// for it. A crashed session starts again after `restart`'s backoff, on
    /// the same worker. A unit of its carries up to `batch` bulk calls in
    /// one [`Worker::run_batch`].
    pub(crate) fn background(
        descriptor: WorkerDescriptor,
        batch: usize,
        factory: impl FnMut(&Lifeline) -> Result<Box<dyn Worker>, Fault> + Send + 'static,
        admit: impl FnMut(&mut dyn Worker) -> Result<usize, Fault> + Send + 'static,
        restart: Restart,
    ) -> Self {
        Self {
            descriptor,
            batch,
            bring: Bring::Supervised(Supervised {
                factory: Box::new(factory),
                admit: Box::new(admit),
                restart,
            }),
        }
    }

    pub(super) const fn descriptor(&self) -> &WorkerDescriptor {
        &self.descriptor
    }

    pub(super) const fn batch(&self) -> usize {
        self.batch
    }

    /// Whether a supervisor runs it, which the dispatcher's close joins.
    pub(super) const fn supervised(&self) -> bool {
        matches!(self.bring, Bring::Supervised(_))
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
        following: Vec::new(),
        register: EncoderRegister::Live,
        language: None,
        speaker: None,
    }
}

/// Worker `index`'s thread: brings it up, then runs what the dispatcher gives
/// it until the dispatcher closes; a supervised worker's supervisor runs it
/// instead. Every call it runs, failed or not, comes back with its execution.
pub(super) fn start(shared: &Arc<Shared>, index: usize, spec: WorkerSpec) {
    let WorkerSpec {
        descriptor, bring, ..
    } = spec;
    match bring {
        Bring::Once { load, warm } => {
            let Some(mut worker) = bring_up(shared, index, load, warm) else {
                return;
            };
            while let Some(unit) = shared.next_unit(index) {
                // A unit's fault fails its calls; this worker serves on.
                serve_unit(shared, index, &descriptor, worker.as_mut(), unit);
            }
        }
        Bring::Supervised(supervised) => {
            super::lifecycle::supervise(shared, index, &descriptor, supervised);
        }
    }
}

/// Runs one unit and answers each of its calls with its execution: its wait
/// to the unit's start, and the unit's whole run, never divided among them.
/// The fault that takes a supervised worker down, when the worker panicked
/// or answered another number of calls.
pub(super) fn serve_unit(
    shared: &Shared,
    index: usize,
    descriptor: &WorkerDescriptor,
    worker: &mut dyn Worker,
    unit: Unit,
) -> Option<&'static str> {
    let started = Instant::now();
    let (results, fault) = run_unit(worker, &unit);
    let ran = started.elapsed();
    let answered = unit
        .into_iter()
        .zip(results)
        .map(|((job, pick), result)| {
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
    fault
}

/// One unit as one [`Worker::run_batch`] call over every window of its
/// calls, in order: one result per call, each call's windows merged into
/// its one answer (FIX 9518), and a call any of whose windows failed failing
/// with that window's error. A worker that panics, or answers another number
/// of windows, fails every call of the unit, and the fault is named.
fn run_unit(
    worker: &mut dyn Worker,
    unit: &[(Job, ExecutionPick)],
) -> (Vec<oneiron::Result<EncoderOutput>>, Option<&'static str>) {
    let inputs: Vec<&EncoderInput> = unit
        .iter()
        .flat_map(|(job, _)| job.windows.inputs())
        .collect();
    let (code, fault) = match catch_unwind(AssertUnwindSafe(|| worker.run_batch(&inputs))) {
        Ok(results) if results.len() == inputs.len() => {
            let mut results = results.into_iter();
            let answers = unit
                .iter()
                .map(|(job, _)| {
                    let parts: Vec<_> = results.by_ref().take(job.windows.len()).collect();
                    parts
                        .into_iter()
                        .collect::<oneiron::Result<Vec<EncoderOutput>>>()
                        .and_then(|outputs| job.windows.merge(outputs))
                })
                .collect();
            return (answers, None);
        }
        Ok(_) => (
            "the worker answered another number of calls",
            "wrong_result_count",
        ),
        Err(_) => ("the worker panicked", "worker_panicked"),
    };
    let failed = unit
        .iter()
        .map(|_| Err(failure(WORKER_TOOL, code)))
        .collect();
    (failed, Some(fault))
}

/// Loading, then Warming when the spec asks, then Ready. `None` when the
/// worker ends Failed.
fn bring_up(
    shared: &Shared,
    index: usize,
    load: Load,
    warm: Option<EncoderInput>,
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
    shared.settle(index, WorkerState::Ready, None);
    Some(worker)
}
