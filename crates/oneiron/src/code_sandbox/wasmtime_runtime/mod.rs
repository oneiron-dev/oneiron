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

use super::{SandboxBoundaryAdapter, SandboxBoundaryContract, SandboxGuestTier};
use crate::engine_executor::{
    JsCodeModeHost, JsCodeModeOutput, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
    JsCodeModeStream,
};
use crate::{Error, Result};
use std::sync::mpsc;
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
    /// Cutoff for guest execution and new host calls, not cancellation of host code.
    /// An admitted synchronous host callback runs to completion. Its elapsed time
    /// counts, so an overrun refuses further guest work once it returns. Hosts must
    /// bound their own callbacks; this is not a hard end-to-end RPC timeout.
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
            foreign_budget: super::microvm::ExecutionBudget::new(30, 512, 64),
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

    fn execute(
        &mut self,
        step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
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
            held_limit: budget.memory_bytes,
            output_failure: None,
        };
        let outcome = std::thread::scope(|scope| {
            let worker_engine = engine.clone();
            scope.spawn(move || {
                let result = execute_component(
                    &worker_engine,
                    &component,
                    budget,
                    step.script,
                    step.boundary,
                    events.clone(),
                    deadline,
                );
                let _ = events.send(HostEvent::Finished(result));
            });
            let result = drive_host(requests, &mut bridge, deadline);
            // Also interrupts a worker after a host-side refusal/timeout.
            // drive_host drops its receiver first, so blocked sends wake.
            engine.increment_epoch();
            result
        })?;
        bridge.held.into_outcome(outcome)
    }
}

fn execute_component(
    engine: &Engine,
    component: &Component,
    budget: ComponentBudget,
    script: &str,
    boundary: SandboxBoundaryContract,
    events: mpsc::SyncSender<HostEvent>,
    deadline: Instant,
) -> Result<JsCodeModeStepOutcome> {
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
    store.epoch_deadline_callback(move |_| {
        if Instant::now() >= deadline {
            Err(wasmtime::Error::msg("component deadline exceeded"))
        } else {
            Ok(wasmtime::UpdateDeadline::Continue(1))
        }
    });
    if Instant::now() >= deadline {
        return Err(failure("component deadline exceeded before execution"));
    }
    let mut linker = Linker::new(engine);
    typed::link_imports(&mut linker, boundary)?;
    let instance = linker
        .instantiate(&mut store, component)
        .map_err(|_| failure("component imports or instantiation refused"))?;
    let run = instance
        .get_typed_func::<(String,), (std::result::Result<bindings::StepResult, String>,)>(
            &mut store, "run-step",
        )
        .map_err(|_| failure("component run-step ABI mismatch"))?;
    // Wasmtime performs canonical post-return inside call; either trap refuses the step.
    let (output,) = run
        .call(&mut store, (script.to_owned(),))
        .map_err(|_| failure("component execution trapped"))?;
    let output = output.map_err(|message| guest_failure(&message))?;
    // This runtime is the first-party lane. Proposal-only execution belongs to
    // the microVM guest; never silently turn a returned proposal into a write.
    if !output.proposals.is_empty() {
        return Err(failure("in-process tier does not admit proposal deltas"));
    }
    wire::decode_output(&output.result_json, budget.message_bytes)
}

fn drive_host(
    requests: mpsc::Receiver<HostEvent>,
    bridge: &mut Bridge<'_>,
    deadline: Instant,
) -> Result<JsCodeModeStepOutcome> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(failure("component deadline exceeded"))?;
        match requests.recv_timeout(remaining) {
            Ok(HostEvent::Call { name, input, reply }) => {
                let response = wire::dispatch(bridge, name, &input);
                let _ = reply.send(response);
            }
            Ok(HostEvent::Output {
                target,
                frame,
                reply,
            }) => {
                // A refused frame traps the guest, so no step goes on with
                // part of its result missing; the host's reason is the step's.
                let response = wire::output(bridge, target, frame).map_err(|error| {
                    bridge.output_failure = Some(error);
                    failure("streamed output refused")
                });
                let _ = reply.send(response);
            }
            Ok(HostEvent::Finished(result)) => {
                return match bridge.output_failure.take() {
                    Some(error) => Err(error),
                    None => result,
                };
            }
            Err(_) => return Err(failure("component deadline or worker failure")),
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

    fn run_step(
        &mut self,
        step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        match super::microvm::select_backend_for_tier(step.boundary.tier())? {
            Some(backend) => isolated::run(self, step, backend),
            None => self.execute(step, host),
        }
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
    held_limit: usize,
    output_failure: Option<Error>,
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

/// The streamed result of a step whose host keeps no body store (a probe, a
/// callable skill's JSON answer), held for its outcome within the
/// component's memory budget.
#[derive(Default)]
struct HeldOutput {
    console: Vec<u8>,
    finish: Vec<u8>,
    files: Vec<(String, Vec<u8>)>,
    bytes: usize,
}

impl HeldOutput {
    fn take(&mut self, target: StreamTarget, frame: Vec<u8>, limit: usize) -> Result<()> {
        if let StreamTarget::Finish { start: true } = target {
            self.bytes -= self.finish.len();
            self.finish.clear();
        }
        self.bytes = self.bytes.saturating_add(frame.len());
        if self.bytes > limit {
            return Err(failure(
                "streamed output exceeds what a host with no result store holds",
            ));
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
    Finished(Result<JsCodeModeStepOutcome>),
}

/// Characters of a guest's error text a failed step keeps. A program can
/// throw text of any size; its head says why.
const GUEST_ERROR_CHARS: usize = 2048;

/// The guest's own error text for a failed step, so the model learns why its
/// program stopped.
fn guest_failure(message: &str) -> Error {
    let mut text: String = message.chars().take(GUEST_ERROR_CHARS).collect();
    if text.len() < message.len() {
        text.push_str(&format!(" … ({} bytes in all)", message.len()));
    }
    Error::InvalidConfig(format!("guest reported step failure: {text}"))
}

fn failure(detail: &'static str) -> Error {
    Error::InvalidConfig(detail.to_owned())
}
