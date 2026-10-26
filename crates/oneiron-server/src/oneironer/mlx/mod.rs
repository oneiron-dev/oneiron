//! The server-owned managed MLX worker (FIX 6755 slice 3, contract rev 3
//! A1-A4): a bundle's `mlx-worker` platform row, run as a child process this
//! server starts, speaks to over stdio and reaps.
//!
//! The worker is one more worker of the slot's dispatcher, `mlx/metal`,
//! qualified for the row's 512-token window; a longer window goes to
//! Candle. Each call's window is Candle's own, built by the slot's window
//! counter, and its spans come back through Candle's containment and offset
//! formula, refined by no second decoder. A bulk unit goes to the worker as
//! one request, split only where the worker's batch or the frame codec
//! requires, never dropped or cut. A request that fails fails every call in
//! it with the worker's receipt; the dispatcher never replays it elsewhere,
//! and markers retry through their owner. A session that faults is broken,
//! and its supervisor restarts it (`dispatcher::lifecycle`).

mod frame;
mod process;
mod protocol;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use oneiron::memory::extraction::{
    EncoderInput, EncoderOutput, ExecutionCompute, ExecutionRuntime,
};

use super::dispatcher::{
    BULK_BATCH_CAP, Fault, Lifeline, Restart, Worker, WorkerDescriptor, WorkerSpec,
};
use super::endpoint::ModelCard;
use super::local::{Window, WindowCounter};
use process::Session;
use protocol::{Answer, Request, WorkerInput};

pub(crate) use protocol::{Expected, PROTOCOL, mismatch};

/// Tool name on every failure the MLX worker's calls report.
const MLX_TOOL: &str = "oneironer-mlx";
/// How long a worker has to load, verify, warm and handshake (A3b).
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(120);

/// What an admitted MLX row starts each session of its worker with.
pub(crate) struct Launch {
    /// The row's program, resolved inside its verified extraction.
    pub(crate) program: PathBuf,
    /// The row's arguments, then `--bundle` and `--max-input-tokens`.
    pub(crate) args: Vec<OsString>,
    /// What its handshake must name.
    pub(crate) expected: Expected,
    /// The slot's card: a worker that would answer as another is down.
    pub(crate) card: ModelCard,
    /// The slot's live windows, as Candle builds them.
    pub(crate) windows: Arc<WindowCounter>,
    /// The bundle's entity labels: each span must carry one.
    pub(crate) labels: Arc<BTreeSet<String>>,
    /// Each request's deadline: the section's `timeout_ms`.
    pub(crate) timeout: Duration,
}

/// What an MLX row's worker is: `mlx/metal`, the bytes of its worker archive
/// by hash, and its qualified window.
pub(crate) fn descriptor(worker_sha256: &str, max_window_tokens: usize) -> WorkerDescriptor {
    let artifact = worker_sha256.get(..16).unwrap_or(worker_sha256);
    WorkerDescriptor::new(
        ExecutionRuntime::Mlx,
        ExecutionCompute::Metal,
        artifact,
        max_window_tokens,
    )
}

/// The MLX worker's spec: `descriptor`, units of up to the dispatcher's bulk
/// cap, each session started from `launch` and admitted by `admit`, and a
/// crashed one started again after `restart`'s backoff.
pub(crate) fn spec(
    descriptor: WorkerDescriptor,
    launch: Launch,
    admit: impl FnMut(&mut dyn Worker) -> Result<usize, Fault> + Send + 'static,
    restart: Restart,
) -> WorkerSpec {
    let factory = move |lifeline: &Lifeline| MlxWorker::start(&launch, lifeline);
    WorkerSpec::background(descriptor, BULK_BATCH_CAP, factory, admit, restart)
}

/// One session of the worker, on its dispatcher worker's own thread.
struct MlxWorker {
    session: Session,
    windows: Arc<WindowCounter>,
    labels: Arc<BTreeSet<String>>,
    stack: String,
    /// Inputs one request may hold, as its handshake declared.
    max_batch: usize,
    timeout: Duration,
    /// Why it takes no further unit, once its session faulted.
    broken: Option<&'static str>,
}

/// A window to send, with the call it is the window of and the call's place
/// in its unit.
type Prepared<'a> = (usize, &'a EncoderInput, Window<'a>);

impl MlxWorker {
    /// Spawns a session and takes its handshake: the pinned worker, answering
    /// as the slot's card does, or a down fault naming the first field that
    /// differs. Its stop hook is registered before the first wait.
    fn start(launch: &Launch, lifeline: &Lifeline) -> Result<Box<dyn Worker>, Fault> {
        let exit = lifeline.clone();
        let on_exit = Box::new(move || exit.exited());
        let session = Session::spawn(&launch.program, &launch.args, on_exit)?;
        lifeline.on_close(session.stopper());
        let handshake = protocol::read_handshake(&session.first_frame(HANDSHAKE_DEADLINE)?)?;
        protocol::validate_handshake(&handshake, &launch.expected)
            .map_err(|field| Fault::Down(mismatch(field)))?;
        if handshake.card() != launch.card {
            return Err(Fault::Down(mismatch("card")));
        }
        handshake.log_ready();
        Ok(Box::new(Self {
            session,
            windows: Arc::clone(&launch.windows),
            labels: Arc::clone(&launch.labels),
            stack: launch.expected.stack_sha16.clone(),
            max_batch: handshake.max_batch(),
            timeout: launch.timeout,
            broken: None,
        }))
    }

    /// The answer to a call with no current message, made without a request:
    /// no span, as Candle answers it.
    fn empty(&self) -> EncoderOutput {
        EncoderOutput {
            spans: Vec::new(),
            links: Vec::new(),
            vad: None,
            context_links: Vec::new(),
            speaker_links: Vec::new(),
            mood_parts: Vec::new(),
            stack_sha16: Some(self.stack.clone()),
        }
    }

    /// The requests `prepared` goes in, as runs of it: each at most
    /// `max_batch` inputs whose serialized request fits one frame. A run is
    /// split there and only there. A window whose request alone does not
    /// fit is a run of its own, and fails at the codec.
    fn requests(&self, prepared: &[Prepared<'_>]) -> Vec<Range<usize>> {
        let empty = Request {
            id: u64::MAX,
            inputs: &[],
        };
        let overhead = serde_json::to_vec(&empty).unwrap_or_default().len();
        let mut runs = Vec::new();
        let (mut start, mut bytes) = (0, overhead);
        for (place, (_, input, window)) in prepared.iter().enumerate() {
            let size = serde_json::to_vec(&wire(input, window))
                .unwrap_or_default()
                .len();
            let held = place - start;
            // One comma joins it to the run's last input.
            let grown = bytes + size + usize::from(held > 0);
            if held > 0 && (held == self.max_batch || !frame::fits(grown)) {
                runs.push(start..place);
                (start, bytes) = (place, overhead + size);
            } else {
                bytes = grown;
            }
        }
        if start < prepared.len() {
            runs.push(start..prepared.len());
        }
        runs
    }

    /// One request of `prepared`, each reply mapped back to its call's
    /// messages: one result per window. A request error fails each window
    /// with its code; a fault of the session, or a reply whose spans are not
    /// its windows', fails each and breaks the worker.
    fn send(&mut self, prepared: &[Prepared<'_>]) -> Vec<oneiron::Result<EncoderOutput>> {
        let fail = |code: &str| -> Vec<oneiron::Result<EncoderOutput>> {
            prepared.iter().map(|_| Err(failure(code))).collect()
        };
        if let Some(why) = self.broken {
            return fail(why);
        }
        let inputs: Vec<WorkerInput<'_>> = prepared
            .iter()
            .map(|(_, input, window)| wire(input, window))
            .collect();
        let id = self.session.next_id();
        let request = Request {
            id,
            inputs: &inputs,
        };
        let payload = match serde_json::to_vec(&request) {
            Ok(payload) if frame::fits(payload.len()) => payload,
            _ => return fail("frame_too_large"),
        };
        let reply = self
            .session
            .exchange(payload, self.timeout)
            .and_then(|frame| {
                protocol::read_reply(&frame, id, inputs.len(), &self.stack, &self.labels)
            });
        let fault = match reply {
            Ok(Answer::Outputs(outputs)) => {
                let mapped: anyhow::Result<Vec<EncoderOutput>> = prepared
                    .iter()
                    .zip(outputs)
                    .map(|((_, _, window), output)| window.map_window_spans(output))
                    .collect();
                match mapped {
                    Ok(mapped) => return mapped.into_iter().map(Ok).collect(),
                    Err(_) => "bad_reply",
                }
            }
            Ok(Answer::Failed { code, input }) => {
                tracing::warn!(code, input, "oneironer mlx request failed");
                return fail(code);
            }
            Err(Fault::Crash(why)) => why,
            Err(Fault::Stopped) => "stopped",
            Err(Fault::Down(_)) => "bad_reply",
        };
        tracing::warn!(why = fault, "oneironer mlx session broken");
        self.broken = Some(fault);
        fail(fault)
    }
}

impl Worker for MlxWorker {
    fn run(&mut self, input: &EncoderInput) -> oneiron::Result<EncoderOutput> {
        self.run_batch(&[input])
            .pop()
            .unwrap_or_else(|| Err(failure("no_answer")))
    }

    /// Every input of the unit in as few requests as the worker's batch and
    /// the codec allow, one result per input, in order. A call with no
    /// current message is answered without a request; a window that cannot
    /// be built fails its call alone.
    fn run_batch(&mut self, inputs: &[&EncoderInput]) -> Vec<oneiron::Result<EncoderOutput>> {
        if let Some(why) = self.broken {
            return inputs.iter().map(|_| Err(failure(why))).collect();
        }
        let mut results: Vec<Option<oneiron::Result<EncoderOutput>>> = Vec::new();
        let mut prepared: Vec<Prepared<'_>> = Vec::new();
        for (place, &input) in inputs.iter().enumerate() {
            if input.messages.is_empty() {
                results.push(Some(Ok(self.empty())));
                continue;
            }
            match self.windows.window(input) {
                Ok(window) => {
                    results.push(None);
                    prepared.push((place, input, window));
                }
                Err(error) => results.push(Some(Err(error))),
            }
        }
        for run in self.requests(&prepared) {
            let run = &prepared[run];
            for ((place, _, _), result) in run.iter().zip(self.send(run)) {
                results[*place] = Some(result);
            }
        }
        results
            .into_iter()
            .map(|result| result.unwrap_or_else(|| Err(failure("no_answer"))))
            .collect()
    }

    fn broken(&self) -> Option<&'static str> {
        self.broken
    }
}

/// `window` as the worker reads it: its text, the current turn's byte range,
/// and `input`'s language as it came.
fn wire<'a>(input: &'a EncoderInput, window: &'a Window<'_>) -> WorkerInput<'a> {
    let turn = window.turn_range();
    WorkerInput {
        window_text: window.text(),
        turn_start: turn.start,
        turn_end: turn.end,
        language: input.language.as_deref(),
    }
}

/// A failed MLX call, by its fixed code alone: never text a call read or
/// the worker wrote.
fn failure(code: &str) -> oneiron::Error {
    oneiron::Error::UpstreamToolFailure {
        tool: MLX_TOOL,
        code: code.to_owned(),
    }
}
