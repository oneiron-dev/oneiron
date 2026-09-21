//! Pinned, in-process Component Model execution for host-trusted code.
//!
//! The host supplies a QuickJS component implementing the canonical `wit/code-run.wit`, not guest
//! machine code. `from_component` also accepts a compatible bounded component
//! (for example an ABI conformance fixture); it makes no QuickJS provenance
//! claim. No WASI, environment, filesystem or network imports are linked.

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
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
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
}

impl Default for ComponentBudget {
    fn default() -> Self {
        Self {
            fuel: 10_000_000,
            memory_bytes: 64 * 1024 * 1024,
            wall_time: Duration::from_secs(5),
            host_calls: 256,
            message_bytes: 1024 * 1024,
        }
    }
}

/// An artifact pinned by the HOST before executing any generated source.
/// Each invocation uses a fresh store. Authority comes only from its host bridge.
pub struct WasmtimeComponentRuntime {
    engine: Engine,
    component: Component,
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
            budget: self.budget,
            adapter: None,
        }
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
        let mut bridge = Bridge {
            host,
            adapter: self.adapter.as_deref_mut(),
            determinism: step.determinism,
            step_seq: step.seq,
            random_counter: 0,
            message_bytes: budget.message_bytes,
        };
        std::thread::scope(|scope| {
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
        })
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
    let (output,) = run
        .call(&mut store, (script.to_owned(),))
        .map_err(|_| failure("component execution trapped"))?;
    run.post_return(&mut store)
        .map_err(|_| failure("component post-return trapped"))?;
    let output = output.map_err(|_| failure("guest reported step failure"))?;
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
            Ok(HostEvent::Finished(result)) => return result,
            Err(_) => return Err(failure("component deadline or worker failure")),
        }
    }
}

impl JsCodeModeRuntime for WasmtimeComponentRuntime {
    fn run_step(
        &mut self,
        step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        if step.boundary.tier() != SandboxGuestTier::FirstPartyDreamer {
            return Err(failure("foreign components require the microVM lane"));
        }
        self.execute(step, host)
    }
}

struct Bridge<'a> {
    host: &'a mut dyn JsCodeModeHost,
    adapter: Option<&'a mut (dyn SandboxBoundaryAdapter + Send + 'static)>,
    determinism: crate::code_run::CodeRunDeterminism,
    step_seq: u64,
    random_counter: u64,
    message_bytes: usize,
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
    Finished(Result<JsCodeModeStepOutcome>),
}

fn failure(detail: &'static str) -> Error {
    Error::InvalidConfig(detail.to_owned())
}
