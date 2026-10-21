//! Pinned, in-process Component Model execution for host-trusted code.
//!
//! The host supplies a QuickJS component implementing the canonical `wit/code-run.wit`, not guest
//! machine code. `from_component` also accepts a compatible bounded component
//! (for example an ABI conformance fixture); it makes no QuickJS provenance
//! claim. No WASI, environment, filesystem or network imports are linked.

mod isolated;
#[cfg(test)]
mod tests;
mod typed;
mod wire;

/// Types generated from the canonical guest/SDK WIT.
pub mod bindings {
    wasmtime::component::bindgen!({ path: "wit", world: "guest" });
}

use super::source::{PreparedSource, prepare_source, split_guest_error};
use super::{SandboxBoundaryAdapter, SandboxBoundaryContract, SandboxGuestTier};
use crate::engine_executor::{
    CANCEL_POLL_SLICE, JsCodeModeHost, JsCodeModeOutput, JsCodeModeRuntime, JsCodeModeStep,
    JsCodeModeStepOutcome, JsCodeModeStream, StepCancellation,
};
use crate::{Error, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

/// Component ABI shipped for hosts building the plain-JS interpreter artifact.
pub const GUEST_WIT: &str = include_str!("../../../wit/code-run.wit");

/// Per-step ceilings. Zero ceilings are never interpreted as unlimited.
#[derive(Debug, Clone, Copy)]
pub struct ComponentBudget {
    pub fuel: u64,
    pub memory_bytes: usize,
    /// The step's time allowance for guest execution and new host calls, not
    /// cancellation of host code. An admitted synchronous host callback runs to
    /// completion, and its elapsed time counts. Once the allowance is spent the
    /// step stops at its next safe point (before another host call or output, or
    /// at the guest's epoch check) and answers the typed `step_deadline` stop: not
    /// done, not failed, its finished host calls kept (FIX 7665). This is not a
    /// hard end-to-end RPC timeout.
    pub wall_time: Duration,
    pub host_calls: u32,
    pub message_bytes: usize,
    pub foreign_budget: super::microvm::ExecutionBudget,
}

impl Default for ComponentBudget {
    fn default() -> Self {
        Self {
            // The QuickJS factory's readiness probe alone burns 12,684,552 fuel
            // on the pinned first-party artifact; the default must admit it.
            // A streamed result costs the guest a few instructions a byte to
            // encode, so a step may emit hundreds of megabytes before its
            // fuel, not its wall time, ends it.
            fuel: 2_000_000_000,
            memory_bytes: 64 * 1024 * 1024,
            wall_time: Duration::from_secs(5),
            host_calls: 256,
            message_bytes: 1024 * 1024,
            foreign_budget: super::microvm::ExecutionBudget::default(),
        }
    }
}

/// An artifact pinned by the HOST before executing any generated source.
/// Each invocation uses a fresh store. Authority comes only from its host bridge.
pub struct WasmtimeComponentRuntime {
    engine: Engine,
    component: Component,
    component_bytes: std::sync::Arc<[u8]>,
    foreign_egress: Option<std::sync::Arc<dyn oneiron_container::EgressRelay>>,
    /// The host's measured disk floor foreign steps' proposed files spool on
    /// (FIX 7650); none spools them as before.
    proposal_spool: Option<std::sync::Arc<dyn super::ProposalSpoolFloor>>,
    budget: ComponentBudget,
    adapter: Option<Box<dyn SandboxBoundaryAdapter + Send>>,
}

impl WasmtimeComponentRuntime {
    /// Compiles WebAssembly Component Model bytes (or WAT), after checking the
    /// host-pinned BLAKE3 digest. Never deserializes executable native artifacts.
    pub fn from_component(bytes: &[u8], digest: [u8; 32], budget: ComponentBudget) -> Result<Self> {
        if bytes.len() > 64 * 1024 * 1024 || *blake3::hash(bytes).as_bytes() != digest {
            return Err(failure("component artifact pin mismatch or size limit"));
        }
        if budget.fuel == 0
            || budget.memory_bytes == 0
            || budget.wall_time.is_zero()
            || budget.host_calls == 0
            || budget.message_bytes == 0
            || !budget.foreign_budget.is_bounded()
            || budget.foreign_budget.pids > 4096
        {
            return Err(failure("component budget must bound every resource"));
        }
        let mut config = Config::new();
        config
            .wasm_component_model(true)
            .consume_fuel(true)
            .epoch_interruption(true)
            .max_wasm_stack(512 * 1024);
        let engine = Engine::new(&config).map_err(|_| failure("engine creation failed"))?;
        let component = Component::new(&engine, bytes).map_err(|_| failure("invalid component"))?;
        Ok(Self {
            engine,
            component,
            component_bytes: std::sync::Arc::from(bytes),
            foreign_egress: None,
            proposal_spool: None,
            budget,
            adapter: None,
        })
    }

    /// Shares pinned compiled code, but never a Store or attached capabilities.
    /// Each store checks its own deadline when the shared epoch counter advances.
    #[must_use]
    pub fn fresh(&self) -> Self {
        Self {
            engine: self.engine.clone(),
            component: self.component.clone(),
            component_bytes: std::sync::Arc::clone(&self.component_bytes),
            foreign_egress: self.foreign_egress.clone(),
            proposal_spool: self.proposal_spool.clone(),
            budget: self.budget,
            adapter: None,
        }
    }

    #[must_use]
    pub fn with_foreign_egress(
        mut self,
        relay: std::sync::Arc<dyn oneiron_container::EgressRelay>,
    ) -> Self {
        self.foreign_egress = Some(relay);
        self
    }

    /// Binds host-owned virtual file and handle-only credential services.
    /// When absent, those imports exist but refuse before accessing any resource.
    #[must_use]
    pub fn with_adapter(mut self, adapter: Box<dyn SandboxBoundaryAdapter + Send>) -> Self {
        self.adapter = Some(adapter);
        self
    }

    #[cfg(test)]
    fn execute(
        &mut self,
        step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        let prepared = prepare_source(step.script);
        let step = JsCodeModeStep {
            script: prepared.executed(),
            ..step
        };
        self.execute_cancellable(step, &prepared, host, &StepCancellation::never())
    }

    /// Runs one first-party step in process, until it finishes, fails, meets
    /// its deadline or is cancelled (FIX 600). A cancel stops the guest
    /// between host operations: the host loop returns at its next slice, and
    /// the store's epoch callback traps the guest on its own token. The
    /// worker is joined before this returns. `step.script` is what
    /// `prepared` executes; a guest failure names its TypeScript position.
    fn execute_cancellable(
        &mut self,
        step: JsCodeModeStep<'_>,
        prepared: &PreparedSource<'_>,
        host: &mut dyn JsCodeModeHost,
        cancel: &StepCancellation,
    ) -> Result<JsCodeModeStepOutcome> {
        if step.script.len() > self.budget.message_bytes {
            return Err(failure("script exceeds component message limit"));
        }
        // Wasmtime requires 'static store data. A bounded synchronous channel
        // keeps the borrowed, non-Send host on its caller's thread, with no
        // erased lifetimes or raw pointers. The worker remains IN PROCESS.
        let (events, requests) = mpsc::sync_channel(1);
        let engine = self.engine.clone();
        let component = self.component.clone();
        let budget = self.budget;
        let deadline = Instant::now()
            .checked_add(budget.wall_time)
            .ok_or(failure("invalid component deadline"))?;
        let nested = self.fresh();
        let mut bridge = Bridge {
            host,
            nested,
            adapter: if step.boundary.links_host_services() {
                self.adapter.as_deref_mut()
            } else {
                None
            },
            determinism: step.determinism,
            step_seq: step.seq,
            random_counter: 0,
            message_bytes: budget.message_bytes,
            held: HeldOutput::default(),
            output_failure: None,
            cancel,
        };
        let outcome = std::thread::scope(|scope| {
            let worker_engine = engine.clone();
            let worker_cancel = cancel.clone();
            let worker = scope.spawn(move || {
                let result = execute_component(
                    &worker_engine,
                    &component,
                    budget,
                    step.script,
                    prepared,
                    step.boundary,
                    events.clone(),
                    deadline,
                    worker_cancel,
                );
                let _ = events.send(HostEvent::Finished(result));
            });
            let result = drive_host(requests, &mut bridge, deadline);
            // Also interrupts a worker after a host-side refusal/timeout.
            // drive_host drops its receiver first, so blocked sends wake.
            engine.increment_epoch();
            // A store that armed its epoch deadline after that bump would
            // sleep through it, so a cancelled step bumps again each slice
            // until its worker has ended. Other stores on the engine only
            // read their own deadline and token again.
            while cancel.is_cancelled() && !worker.is_finished() {
                std::thread::sleep(CANCEL_POLL_SLICE);
                engine.increment_epoch();
            }
            result
        });
        // A cancel seen by the end wins over whatever else the step ended
        // with: a cancelled step never counts as run.
        cancel.check()?;
        match outcome? {
            Stepped::Ended(outcome) => bridge.held.into_outcome(outcome),
            Stepped::Deadline(calls) => bridge.held.into_deadline_outcome(&calls),
        }
    }
}

/// How a step's run ended: the guest's own end, or its time allowance reached
/// at a safe point, with the host calls that finished before it (FIX 7665).
enum Stepped {
    Ended(JsCodeModeStepOutcome),
    Deadline(Vec<&'static str>),
}

/// The typed stop a step answers when its time allowance is spent.
const STEP_DEADLINE: &str = "step_deadline";

/// The model's observation of a `step_deadline` stop: the step is not done
/// and did not fail, and every host call that finished in it took effect.
fn step_deadline_observation(calls: &[&'static str]) -> String {
    let mut counted: Vec<(&str, usize)> = Vec::new();
    for &name in calls {
        let seen = counted.iter().position(|(seen, _)| *seen == name);
        match seen {
            Some(at) => counted[at].1 += 1,
            None => counted.push((name, 1)),
        }
    }
    let finished = if counted.is_empty() {
        "none".to_owned()
    } else {
        counted
            .iter()
            .map(|(name, count)| match count {
                1 => (*name).to_owned(),
                n => format!("{name} x{n}"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "{STEP_DEADLINE}: this step used its time allowance and stopped at a safe point; it did \
         not fail. Host calls that finished in it took effect and keep their answers in this \
         run: {finished}. Continue from them in the next step without repeating a write that \
         finished, and keep each step's host work short."
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the worker takes the pinned component, its budget, the step and its stop conditions"
)]
fn execute_component(
    engine: &Engine,
    component: &Component,
    budget: ComponentBudget,
    script: &str,
    prepared: &PreparedSource<'_>,
    boundary: SandboxBoundaryContract,
    events: mpsc::SyncSender<HostEvent>,
    deadline: Instant,
    cancel: StepCancellation,
) -> Result<Stepped> {
    let limits = StoreLimitsBuilder::new()
        .memory_size(budget.memory_bytes)
        .memories(1)
        .tables(8)
        .instances(16)
        .table_elements(10_000)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(
        engine,
        State {
            events,
            limits,
            remaining_calls: budget.host_calls,
            message_bytes: budget.message_bytes,
        },
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(budget.fuel)
        .map_err(|_| failure("fuel setup failed"))?;
    store.set_epoch_deadline(1);
    // Epochs belong to the Engine, not a Store. A sibling's cleanup can wake
    // this store, but must not cancel it before its own host-owned deadline.
    // Its own step's cancel, read from its own token first, traps it.
    let stop = cancel.clone();
    // Set only by the deadline's own trap, so a spent allowance reads as the
    // typed stop and every other trap stays a failure.
    let spent = Arc::new(AtomicBool::new(false));
    let latch = Arc::clone(&spent);
    store.epoch_deadline_callback(move |_| {
        if stop.is_cancelled() {
            Err(wasmtime::Error::msg("component step cancelled"))
        } else if Instant::now() >= deadline {
            latch.store(true, Ordering::Relaxed);
            Err(wasmtime::Error::msg("component deadline exceeded"))
        } else {
            Ok(wasmtime::UpdateDeadline::Continue(1))
        }
    });
    // Read after the deadline is armed: a cancel that lands later is
    // followed by an epoch bump this store sees.
    cancel.check()?;
    if Instant::now() >= deadline {
        // No guest code has run: the whole step is still to do.
        return Ok(Stepped::Deadline(Vec::new()));
    }
    let mut linker = Linker::new(engine);
    typed::link_imports(&mut linker, boundary)?;
    let instance = match linker.instantiate(&mut store, component) {
        Ok(instance) => instance,
        Err(_) if spent.load(Ordering::Relaxed) => return Ok(Stepped::Deadline(Vec::new())),
        Err(_) => return Err(failure("component imports or instantiation refused")),
    };
    let run = instance
        .get_typed_func::<(String,), (std::result::Result<bindings::StepResult, String>,)>(
            &mut store, "run-step",
        )
        .map_err(|_| failure("component run-step ABI mismatch"))?;
    // Wasmtime performs canonical post-return inside call; a trap refuses the
    // step, except the deadline's own, which stops it.
    let (output,) = match run.call(&mut store, (script.to_owned(),)) {
        Ok(output) => output,
        Err(_) if spent.load(Ordering::Relaxed) => return Ok(Stepped::Deadline(Vec::new())),
        Err(_) => return Err(failure("component execution trapped")),
    };
    let output = output.map_err(|message| guest_failure(&message, prepared))?;
    // This runtime is the first-party lane. Proposal-only execution belongs to
    // the microVM guest; never silently turn a returned proposal into a write.
    if !output.proposals.is_empty() {
        return Err(failure("in-process tier does not admit proposal deltas"));
    }
    wire::decode_output(&output.result_json, budget.message_bytes).map(Stepped::Ended)
}

/// Answers the worker's host events until its step ends. It waits in
/// slices of [`CANCEL_POLL_SLICE`] and reads the step's token before and
/// after each host operation it admits and before it accepts the step's
/// end: a cancel it sees wins over the deadline, an output failure or a
/// worker failure that lands with it. An operation already admitted
/// settles first; once the deadline has passed it admits no new one, and the
/// step ends with the typed `step_deadline` stop (FIX 7665).
fn drive_host(
    requests: mpsc::Receiver<HostEvent>,
    bridge: &mut Bridge<'_>,
    deadline: Instant,
) -> Result<Stepped> {
    let mut finished = Vec::new();
    loop {
        bridge.cancel.check()?;
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            return Ok(Stepped::Deadline(finished));
        };
        match requests.recv_timeout(remaining.min(CANCEL_POLL_SLICE)) {
            Ok(HostEvent::Call { name, input, reply }) => {
                bridge.cancel.check()?;
                if Instant::now() >= deadline {
                    return Ok(Stepped::Deadline(finished));
                }
                let response = wire::dispatch(bridge, name, &input);
                bridge.cancel.check()?;
                finished.push(name);
                let _ = reply.send(response);
            }
            Ok(HostEvent::Output {
                target,
                frame,
                reply,
            }) => {
                bridge.cancel.check()?;
                if Instant::now() >= deadline {
                    return Ok(Stepped::Deadline(finished));
                }
                // A refused frame traps the guest, so no step goes on with
                // part of its result missing; the host's reason is the step's.
                let response = wire::output(bridge, target, frame).map_err(|error| {
                    bridge.output_failure = Some(error);
                    failure("streamed output refused")
                });
                bridge.cancel.check()?;
                let _ = reply.send(response);
            }
            Ok(HostEvent::Finished(result)) => {
                bridge.cancel.check()?;
                return match bridge.output_failure.take() {
                    Some(error) => Err(error),
                    None => match result {
                        Ok(Stepped::Deadline(_)) => Ok(Stepped::Deadline(finished)),
                        other => other,
                    },
                };
            }
            // A slice ended with no event: read the token and the deadline
            // again.
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bridge.cancel.check()?;
                return Err(failure("component deadline or worker failure"));
            }
        }
    }
}

impl JsCodeModeRuntime for WasmtimeComponentRuntime {
    fn bind_foreign_egress(
        &mut self,
        relay: std::sync::Arc<dyn oneiron_container::EgressRelay>,
    ) -> Result<()> {
        self.foreign_egress = Some(relay);
        Ok(())
    }

    fn bind_proposal_spool(&mut self, spool: std::sync::Arc<dyn super::ProposalSpoolFloor>) {
        self.proposal_spool = Some(spool);
    }

    fn run_step(
        &mut self,
        step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        self.run_step_cancellable(step, host, &StepCancellation::never())
    }

    fn run_step_cancellable(
        &mut self,
        step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
        cancel: &StepCancellation,
    ) -> Result<JsCodeModeStepOutcome> {
        // A step cancelled before it starts stages no guest at all.
        cancel.check()?;
        // Every source that reaches this runtime is prepared once, here,
        // before its backend is chosen (FIX 8276).
        let prepared = prepare_source(step.script);
        self.run_prepared_step_cancellable(step, &prepared, host, cancel)
    }

    fn run_prepared_step_cancellable(
        &mut self,
        step: JsCodeModeStep<'_>,
        prepared: &PreparedSource<'_>,
        host: &mut dyn JsCodeModeHost,
        cancel: &StepCancellation,
    ) -> Result<JsCodeModeStepOutcome> {
        // A step cancelled before it starts stages no guest at all.
        cancel.check()?;
        let step = JsCodeModeStep {
            script: prepared.executed(),
            ..step
        };
        let outcome = match super::microvm::select_backend_for_tier(step.boundary.tier())? {
            Some(backend) => isolated::run(self, step, backend, cancel),
            None => self.execute_cancellable(step, prepared, host, cancel),
        };
        cancel.check()?;
        outcome
    }
}

struct Bridge<'a> {
    host: &'a mut dyn JsCodeModeHost,
    /// What a call that runs a step of its own runs it on (OF-353's
    /// `self.skills.call`): this runtime's pinned component and budget, each
    /// such step on a fresh sibling with a store of its own.
    nested: WasmtimeComponentRuntime,
    adapter: Option<&'a mut (dyn SandboxBoundaryAdapter + Send + 'static)>,
    determinism: crate::code_run::CodeRunDeterminism,
    step_seq: u64,
    random_counter: u64,
    message_bytes: usize,
    held: HeldOutput,
    output_failure: Option<Error>,
    /// This step's token. Every host operation the bridge admits reads it
    /// before and after, and a call that runs a step of its own runs that
    /// step under a child of it.
    cancel: &'a StepCancellation,
}

/// One streamed frame's target, owned for the trip to the host thread.
enum StreamTarget {
    Console,
    Finish { start: bool },
    Store { start: bool },
    File(String),
}

impl StreamTarget {
    fn stream(&self) -> JsCodeModeStream<'_> {
        match self {
            Self::Console => JsCodeModeStream::Console,
            Self::Finish { start } => JsCodeModeStream::Finish { start: *start },
            Self::Store { start } => JsCodeModeStream::Store { start: *start },
            Self::File(path) => JsCodeModeStream::File(path),
        }
    }
}

/// The streamed result of a step whose host keeps no body store (a probe),
/// held for its outcome. A host whose answer may be large takes its frames
/// itself (a callable skill spools its own); nothing here refuses for size.
#[derive(Default)]
struct HeldOutput {
    console: Vec<u8>,
    finish: Vec<u8>,
    files: Vec<(String, Vec<u8>)>,
}

impl HeldOutput {
    fn take(&mut self, target: StreamTarget, frame: Vec<u8>) -> Result<()> {
        if let StreamTarget::Finish { start: true } = target {
            self.finish.clear();
        }
        match target {
            StreamTarget::Console => self.console.extend_from_slice(&frame),
            StreamTarget::Finish { .. } => self.finish.extend_from_slice(&frame),
            // A stored value is a result of the run: a host with no store
            // has nowhere to keep it.
            StreamTarget::Store { .. } => return Err(failure("store needs a result store")),
            StreamTarget::File(path) => match self.files.iter_mut().find(|(held, _)| *held == path)
            {
                Some((_, bytes)) => bytes.extend_from_slice(&frame),
                None => self.files.push((path, frame)),
            },
        }
        Ok(())
    }

    /// A step stopped by its deadline: its console lines so far, then the
    /// typed `step_deadline` stop naming its finished host calls, and its
    /// files. Not done, and not a failure (FIX 7665).
    fn into_deadline_outcome(self, calls: &[&'static str]) -> Result<JsCodeModeStepOutcome> {
        let mut observation = String::from_utf8(self.console)
            .map_err(|_| failure("streamed observation is not UTF-8"))?;
        if !observation.is_empty() && !observation.ends_with('\n') {
            observation.push('\n');
        }
        observation.push_str(&step_deadline_observation(calls));
        Ok(JsCodeModeStepOutcome {
            done: false,
            observation,
            outputs: self
                .files
                .into_iter()
                .map(|(path, bytes)| JsCodeModeOutput::new(path, bytes))
                .collect(),
        })
    }

    /// The step's outcome with what was held: the answer of a finished
    /// step, else its console lines, and its files.
    fn into_outcome(self, mut outcome: JsCodeModeStepOutcome) -> Result<JsCodeModeStepOutcome> {
        let text = if outcome.done {
            self.finish
        } else {
            self.console
        };
        if outcome.observation.is_empty() {
            outcome.observation = String::from_utf8(text)
                .map_err(|_| failure("streamed observation is not UTF-8"))?;
        }
        outcome.outputs.extend(
            self.files
                .into_iter()
                .map(|(path, bytes)| JsCodeModeOutput::new(path, bytes)),
        );
        Ok(outcome)
    }
}

struct State {
    events: mpsc::SyncSender<HostEvent>,
    limits: StoreLimits,
    remaining_calls: u32,
    message_bytes: usize,
}

enum HostEvent {
    Call {
        name: &'static str,
        input: String,
        reply: mpsc::SyncSender<Result<String>>,
    },
    Output {
        target: StreamTarget,
        frame: Vec<u8>,
        reply: mpsc::SyncSender<Result<u64>>,
    },
    Finished(Result<Stepped>),
}

/// Characters of a guest's error text a failed step keeps. A program can
/// throw text of any size; its head says why.
const GUEST_ERROR_CHARS: usize = 2048;

/// The guest's own error text for a failed step, so the model learns why its
/// program stopped. The guest's position header never reaches it; a
/// TypeScript program's error ends with where it threw in the TypeScript
/// source, past the text's cut, and a JavaScript program's is as it was.
fn guest_failure(message: &str, prepared: &PreparedSource<'_>) -> Error {
    let (message, at) = split_guest_error(message);
    let mut text: String = message.chars().take(GUEST_ERROR_CHARS).collect();
    if text.len() < message.len() {
        text.push_str(&format!(" … ({} bytes in all)", message.len()));
    }
    if let Some(position) = prepared.failure_position(at) {
        text.push_str(&position);
    }
    Error::InvalidConfig(format!("guest reported step failure: {text}"))
}

fn failure(detail: &'static str) -> Error {
    Error::InvalidConfig(detail.to_owned())
}
