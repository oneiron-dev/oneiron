//! The pinned QuickJS sandbox a hook body runs in.
//!
//! The `hook` world (`wit/hook/hook.wit`) imports a scoped read,
//! `ai.verdict` and the one outcome return, and exports `run-hook`. No WASI,
//! clock, random, file, network or verb import is linked. A verdict is
//! answered only for a fact hook the runner lets call one. Each run gets a fresh Store under the
//! code-mode limits, save one: a memory growth past them fails the guest's
//! allocation, which QuickJS throws as out of memory, where code mode traps.
//! Its `budget_ms` is an accounting deadline on the run's
//! [`HookRunContext`], never a stop (FIX 8842): start-up, reads and verdicts
//! are measured against it, each admitted callback's answer is delivered
//! even when late, and the body runs to its own end under its fuel and
//! memory. A body is prepared once, here, as code mode prepares a program
//! (FIX 9208): JavaScript runs byte for byte as written; TypeScript runs as
//! the JavaScript Oxc prints, its errors naming its TypeScript position; a
//! body neither parse takes runs as written, with a note, never refused.

/// Types generated from the hook world.
pub mod bindings {
    wasmtime::component::bindgen!({ path: "wit/hook/hook.wit", world: "hook" });
}

use super::{
    HookBodyRun, HookBodyRuntime, HookBodyUsage, HookPreparation, HookRunContext, HookVerdictCall,
};
use crate::code_sandbox::ComponentBudget;
use crate::code_sandbox::source::{PreparedSource, prepare_source, split_guest_error};
use crate::receipt::hex_lower;
use crate::{Error, Result};
use std::sync::mpsc;
use wasmtime::component::{Component, Linker};
use wasmtime::{
    Config, Engine, ResourceLimiter, Store, StoreContextMut, StoreLimits, StoreLimitsBuilder,
};

/// The hook world's WIT, for hosts building the guest.
pub const HOOK_WIT: &str = include_str!("../../../wit/hook/hook.wit");

/// The hook component this repository builds and reviews.
const HOOK_COMPONENT: &[u8] =
    include_bytes!("../../../../../components/code-run-quickjs/artifacts/quickjs-hook.wasm");

/// BLAKE3 of the checked-in hook component; its manifest row carries the SHA-256.
pub const HOOK_COMPONENT_BLAKE3: [u8; 32] = [
    0x0c, 0x16, 0xb8, 0x27, 0x34, 0x12, 0x47, 0xb6, 0x09, 0x56, 0x0e, 0x02, 0x18, 0xe6, 0xe1, 0xaa,
    0x11, 0x8c, 0xf7, 0xcf, 0x73, 0xb9, 0x4a, 0xbc, 0xe7, 0xc1, 0x39, 0xf5, 0xa5, 0xe9, 0xe0, 0x0a,
];

/// The three imports of the hook world, sorted. A component importing
/// anything else is refused before it runs.
const HOOK_IMPORTS: [&str; 3] = ["ai-verdict", "emit-outcome", "scoped-read"];
/// Bytes one `ai.verdict` answer may carry.
const VERDICT_RESPONSE_BYTES: usize = 256 * 1024;
/// Bytes one `ai.verdict` request may carry: a question, its options, its
/// evidence refs and its state.
const VERDICT_REQUEST_BYTES: usize = 64 * 1024;
/// What a body that may not call a model hears from `ai.verdict`.
const NO_VERDICT: &str = "ai_verdict_is_a_generative_fact_hooks";
/// Wasm stack, as code mode sets it.
const WASM_STACK_BYTES: usize = 512 * 1024;
/// The largest component accepted.
const MAX_COMPONENT_BYTES: usize = 64 * 1024 * 1024;
/// Characters of a body's error text a failed run keeps.
const GUEST_ERROR_CHARS: usize = 2048;
/// What the guest's allocator may take past the bytes it lowers. The body
/// and the input are each lowered by one allocation before any guest code
/// runs; each grows the memory by whole 64 KiB pages and adds a chunk
/// header and a top footer of a few hundred bytes, so the two take at most
/// two pages past their own bytes. Four pages hold that twice over.
const LOWERING_SLACK_BYTES: usize = 256 * 1024;
/// The guest's answer when it could not take the input (hook_guest.c
/// `INPUT_NOT_TAKEN`).
const INPUT_NOT_TAKEN: &str = "hook_input_not_taken";

/// The checked-in hook component and its BLAKE3 pin, for serve to build a
/// [`HookSandbox`].
#[must_use]
pub fn hook_component_bytes() -> (&'static [u8], [u8; 32]) {
    (HOOK_COMPONENT, HOOK_COMPONENT_BLAKE3)
}

/// A pinned, checked hook component. Compiled once; each run gets its own
/// Store and instance, so no state crosses runs.
pub struct HookSandbox {
    pre: bindings::HookPre<State>,
    budget: ComponentBudget,
    /// The longest hook input a run lowers into its guest, set by the
    /// guest's memory itself (`measure_input_limit`).
    input_limit: usize,
}

impl HookBodyRuntime for HookSandbox {
    fn runtime_identity(&self) -> Option<String> {
        Some(
            blake3::Hash::from(HOOK_COMPONENT_BLAKE3)
                .to_hex()
                .to_string(),
        )
    }

    fn run_hook(
        &self,
        body: &str,
        input_json: &str,
        context: &mut HookRunContext,
        read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> Result<HookBodyRun> {
        Self::run_hook(self, body, input_json, context, read)
    }

    fn run_fact_hook(
        &self,
        body: &str,
        input_json: &str,
        context: &mut HookRunContext,
        read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
        verdict: HookVerdictCall<'_>,
    ) -> Result<HookBodyRun> {
        self.run(body, input_json, context, read, verdict)
    }
}

impl HookSandbox {
    /// Checks the BLAKE3 pin, compiles the component, checks that it imports
    /// exactly the hook world's three functions and exports `run-hook`, then runs
    /// a plain-JS readiness probe through it.
    pub fn from_component(bytes: &[u8], pin: [u8; 32]) -> Result<Self> {
        if !bytes.starts_with(b"\0asm\x0d\0\x01\0")
            || bytes.len() > MAX_COMPONENT_BYTES
            || *blake3::hash(bytes).as_bytes() != pin
        {
            return Err(failure("hook component pin, header or size mismatch"));
        }
        let mut config = Config::new();
        config
            .wasm_component_model(true)
            .consume_fuel(true)
            .max_wasm_stack(WASM_STACK_BYTES);
        let engine = Engine::new(&config).map_err(|_| failure("hook engine creation failed"))?;
        let component =
            Component::new(&engine, bytes).map_err(|_| failure("invalid hook component"))?;
        {
            let ty = component.component_type();
            let mut imports: Vec<&str> = ty.imports(&engine).map(|(name, _)| name).collect();
            imports.sort_unstable();
            if imports != HOOK_IMPORTS {
                return Err(failure("hook component imports are not the hook world's"));
            }
        }
        let mut linker = Linker::new(&engine);
        link_imports(&mut linker)?;
        let pre = linker
            .instantiate_pre(&component)
            .map_err(|_| failure("hook component imports refused"))?;
        let pre = bindings::HookPre::new(pre)
            .map_err(|_| failure("hook component run-hook ABI mismatch"))?;
        let budget = ComponentBudget::default();
        let input_limit = measure_input_limit(&pre, budget)?;
        let sandbox = Self {
            pre,
            budget,
            input_limit,
        };
        sandbox.probe()?;
        Ok(sandbox)
    }

    /// The longest hook input, in bytes, a run lowers into its guest: the
    /// room a fresh instance's memory can still grow by, less the longest
    /// body lowered beside it and the allocator's slack, measured once on a
    /// fresh instance when the sandbox is built. A longer input is refused before the run
    /// and reported never taken. A shorter one always lowers, and one the
    /// guest then cannot parse beside it the guest answers not taken itself.
    #[must_use]
    pub const fn input_limit(&self) -> usize {
        self.input_limit
    }

    /// Runs one body; `read` answers `oneiron.read`, and `ai.verdict` is
    /// refused. Returns the emitted outcome JSON.
    pub fn run_hook(
        &self,
        body: &str,
        input_json: &str,
        context: &mut HookRunContext,
        read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
    ) -> Result<HookBodyRun> {
        let mut verdict = |_: &str| Err(NO_VERDICT.to_owned());
        self.run(body, input_json, context, read, &mut verdict)
    }

    fn run(
        &self,
        body: &str,
        input_json: &str,
        context: &mut HookRunContext,
        read: &mut dyn FnMut(&str) -> std::result::Result<String, String>,
        verdict: HookVerdictCall<'_>,
    ) -> Result<HookBodyRun> {
        // A body refused before its worker starts used nothing (FIX 9332).
        // The input is judged first: one the guest cannot take is never
        // taken, whatever else the hook gets wrong, so a skill answer's post
        // chain refuses it (REVIEW-9805).
        if input_json.len() > self.input_limit {
            context.report_usage(HookBodyUsage::NOT_RUN);
            context.report_input_not_taken();
            return Err(failure("hook input exceeds the guest memory"));
        }
        let budget_ms = context.budget_ms();
        if budget_ms == 0 || budget_ms > context.max_budget_ms() {
            context.report_usage(HookBodyUsage::NOT_RUN);
            return Err(failure("hook budget_ms is out of bounds"));
        }
        // Prepared once, for every route a body runs by (FIX 9208); the
        // authored body stays the body of record.
        let prepared = prepare_source(body);
        context.report_preparation(preparation(&prepared));
        let executed = prepared.executed();
        if executed.len() > self.budget.message_bytes {
            context.report_usage(HookBodyUsage::NOT_RUN);
            return Err(failure("hook body exceeds the message limit"));
        }
        // Wasmtime needs 'static store data, so the body runs on a scoped
        // worker and the borrowed `read` answers on this thread over a bounded
        // channel. The worker stays in process, and is joined before this
        // returns: the run's accounting ends after it.
        let (events, requests) = mpsc::sync_channel(1);
        let budget = self.budget;
        let pre = &self.pre;
        let prepared = &prepared;
        // Unavailable until the worker's end measures it.
        context.body_starts();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let (result, usage, input_not_taken) =
                    execute(pre, budget, prepared, input_json, events.clone());
                let _ = events.send(Event::Finished(result, usage, input_not_taken));
            });
            serve_reads(&requests, read, verdict, context)
        })
    }

    /// A real-JS round trip through both imports before the sandbox is used.
    fn probe(&self) -> Result<()> {
        let body = "const row = await oneiron.read({claim: input.hook.binding}); \
            return row.seen === 7 && Date.now() === input.now && typeof process === 'undefined' \
            && typeof fetch === 'undefined' && typeof require === 'undefined' \
            && typeof ai.verdict === 'function' ? {kind: 'nothing'} : {kind: 'skip', reason: 'probe'};";
        let input =
            r#"{"hook":{"binding":"00000000000000000000000000000001"},"now":1700000000000}"#;
        let mut context = HookRunContext::new(5_000);
        let run = self.run_hook(body, input, &mut context, &mut |request: &str| {
            if request == r#"{"claim":"00000000000000000000000000000001"}"# {
                Ok(r#"{"seen":7}"#.to_owned())
            } else {
                Err("probe_read_mismatch".to_owned())
            }
        })?;
        if run.outcome_json != r#"{"kind":"nothing"}"# || run.host_calls != 2 {
            return Err(failure("hook component readiness probe failed"));
        }
        Ok(())
    }
}

struct State {
    events: mpsc::SyncSender<Event>,
    limits: GuestLimits,
    host_calls: u32,
    outcome: Option<String>,
    trap: Option<&'static str>,
}

enum Event {
    Read {
        request: String,
        reply: mpsc::SyncSender<std::result::Result<String, String>>,
    },
    Verdict {
        request: String,
        reply: mpsc::SyncSender<std::result::Result<String, String>>,
    },
    /// The body's end: its result, what it used, measured on every path
    /// it took (FIX 9332), and whether the guest never took the input.
    Finished(Result<HookBodyRun>, HookBodyUsage, bool),
}

type Reply<T> = std::result::Result<T, String>;

/// A run's Store limits, recording the guest memory's size as they admit
/// it: what [`measure_input_limit`] reads off a fresh instance.
struct GuestLimits {
    limits: StoreLimits,
    /// The guest memory's size, in bytes, after its last admitted growth;
    /// a growth admitted that then fails leaves it high, which only
    /// shrinks the room measured.
    memory_bytes: usize,
    /// The guest memory's declared maximum, in bytes; `None` when it
    /// declares none.
    memory_maximum: Option<usize>,
}

impl ResourceLimiter for GuestLimits {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let admitted = self.limits.memory_growing(current, desired, maximum)?;
        self.memory_maximum = maximum;
        if admitted {
            self.memory_bytes = desired;
        }
        Ok(admitted)
    }

    fn memory_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.limits.memory_grow_failed(error)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        self.limits.table_growing(current, desired, maximum)
    }

    fn table_grow_failed(&mut self, error: wasmtime::Error) -> wasmtime::Result<()> {
        self.limits.table_grow_failed(error)
    }

    fn instances(&self) -> usize {
        self.limits.instances()
    }

    fn tables(&self) -> usize {
        self.limits.tables()
    }

    fn memories(&self) -> usize {
        self.limits.memories()
    }
}

impl State {
    fn refuse(&mut self, reason: &'static str) -> wasmtime::Error {
        self.trap = Some(reason);
        wasmtime::Error::msg(reason)
    }

    /// One scoped read, counted in the run's host calls: a count never
    /// refuses one (FIX 8841), and neither does the size of its request or
    /// its answer, which the body gets whole (FIX 9233).
    fn read(&mut self, request: String) -> wasmtime::Result<Reply<String>> {
        self.host_calls = self.host_calls.saturating_add(1);
        let (reply, response) = mpsc::sync_channel(1);
        if self.events.send(Event::Read { request, reply }).is_err() {
            return Err(self.refuse("hook host stopped"));
        }
        let Ok(answer) = response.recv() else {
            return Err(self.refuse("hook host stopped"));
        };
        Ok(answer)
    }

    /// One `ai.verdict` call, counted as a read is. The host answers it, or
    /// refuses it for a body that may not call a model.
    fn verdict(&mut self, request: String) -> wasmtime::Result<Reply<String>> {
        self.host_calls = self.host_calls.saturating_add(1);
        if request.len() > VERDICT_REQUEST_BYTES {
            return Ok(Err("verdict_request_over_budget".into()));
        }
        let (reply, response) = mpsc::sync_channel(1);
        if self.events.send(Event::Verdict { request, reply }).is_err() {
            return Err(self.refuse("hook host stopped"));
        }
        let Ok(answer) = response.recv() else {
            return Err(self.refuse("hook host stopped"));
        };
        Ok(match answer {
            Ok(verdict) if verdict.len() > VERDICT_RESPONSE_BYTES => {
                Err("verdict_response_over_budget".into())
            }
            Err(text) if text.len() > VERDICT_RESPONSE_BYTES => Err("verdict_refused".into()),
            answer => answer,
        })
    }

    /// The one outcome, whole whatever its size (FIX 10074, 10086). A
    /// malformed outcome comes back as a code; a second outcome after one
    /// was taken traps the body.
    fn emit(&mut self, outcome: String) -> wasmtime::Result<Reply<()>> {
        self.host_calls = self.host_calls.saturating_add(1);
        if self.outcome.is_some() {
            return Err(self.refuse("hook outcome already emitted"));
        }
        let kind = serde_json::from_str::<serde_json::Value>(&outcome)
            .ok()
            .is_some_and(|value| value.get("kind").is_some_and(serde_json::Value::is_string));
        if !kind {
            return Ok(Err("invalid_outcome".into()));
        }
        self.outcome = Some(outcome);
        Ok(Ok(()))
    }
}

fn link_imports(linker: &mut Linker<State>) -> Result<()> {
    let mut root = linker.root();
    root.func_wrap(
        "scoped-read",
        |mut cx: StoreContextMut<'_, State>, (request,): (String,)| {
            Ok((cx.data_mut().read(request)?,))
        },
    )
    .map_err(|_| failure("hook scoped-read link failed"))?;
    root.func_wrap(
        "ai-verdict",
        |mut cx: StoreContextMut<'_, State>, (request,): (String,)| {
            Ok((cx.data_mut().verdict(request)?,))
        },
    )
    .map_err(|_| failure("hook ai-verdict link failed"))?;
    root.func_wrap(
        "emit-outcome",
        |mut cx: StoreContextMut<'_, State>, (outcome,): (String,)| {
            Ok((cx.data_mut().emit(outcome)?,))
        },
    )
    .map_err(|_| failure("hook emit-outcome link failed"))?;
    Ok(())
}

/// A fresh Store under the run limits, its fuel set: `None` when the fuel
/// cannot be set.
fn new_store(
    pre: &bindings::HookPre<State>,
    budget: ComponentBudget,
    events: mpsc::SyncSender<Event>,
) -> Option<Store<State>> {
    let limits = StoreLimitsBuilder::new()
        .memory_size(budget.memory_bytes)
        .memories(1)
        .tables(8)
        .instances(16)
        .table_elements(10_000)
        // A failed growth is the guest's own out of memory: its allocation
        // fails, QuickJS throws, and before the body starts the guest
        // answers `hook_input_not_taken`. A trap here would end a run on an
        // input the body never judged as an ordinary failure
        // ([SKILL-POST-HOOK-INPUT-BODY-CHANNEL]).
        // RED PIN: a failed growth traps the store, as before 584c37bc487.
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(
        pre.engine(),
        State {
            events,
            limits: GuestLimits {
                limits,
                memory_bytes: 0,
                memory_maximum: None,
            },
            host_calls: 0,
            outcome: None,
            trap: None,
        },
    );
    store.limiter(|state| &mut state.limits);
    store.set_fuel(budget.fuel).ok()?;
    Some(store)
}

/// The longest hook input every run lowers into its guest: the room a
/// fresh instance's memory can still grow by past its instantiated size,
/// up to the lesser of its declared maximum and the Store's memory limit,
/// less the longest body the host lowers beside it and
/// [`LOWERING_SLACK_BYTES`]. Measured once, on an instance like every
/// run's: each run instantiates the same component under the same limits,
/// and instantiation runs no input-dependent code. An input within it
/// always lowers, so a lowering never aborts the guest (an abort is a
/// trap, not a typed failure); every later allocation the guest makes is
/// fallible, and one that fails before the body starts answers
/// `hook_input_not_taken`.
fn measure_input_limit(pre: &bindings::HookPre<State>, budget: ComponentBudget) -> Result<usize> {
    let (events, _requests) = mpsc::sync_channel(1);
    let mut store =
        new_store(pre, budget, events).ok_or_else(|| failure("hook fuel setup failed"))?;
    pre.instantiate(&mut store)
        .map_err(|_| failure("hook component instantiation refused"))?;
    let limits = &store.data().limits;
    let maximum = limits
        .memory_maximum
        .map_or(budget.memory_bytes, |declared| {
            declared.min(budget.memory_bytes)
        });
    maximum
        .checked_sub(limits.memory_bytes)
        .and_then(|room| room.checked_sub(budget.message_bytes))
        .and_then(|room| room.checked_sub(LOWERING_SLACK_BYTES))
        .ok_or_else(|| failure("hook guest memory leaves no room for an input"))
}

/// Runs the prepared body on a fresh Store: its result, beside what it
/// used, and whether the guest never took the input.
fn execute(
    pre: &bindings::HookPre<State>,
    budget: ComponentBudget,
    prepared: &PreparedSource<'_>,
    input_json: &str,
    events: mpsc::SyncSender<Event>,
) -> (Result<HookBodyRun>, HookBodyUsage, bool) {
    let Some(mut store) = new_store(pre, budget, events) else {
        // No fuel, no body: it used nothing.
        return (
            Err(failure("hook fuel setup failed")),
            HookBodyUsage::NOT_RUN,
            false,
        );
    };
    let ran = match pre.instantiate(&mut store) {
        // Wasmtime performs canonical post-return inside the call.
        Ok(hook) => Ok(hook.call_run_hook(&mut store, prepared.executed(), input_json)),
        Err(_) => Err(failure("hook component instantiation refused")),
    };
    // What the body used, read before its Store drops on every path it took,
    // a failed instantiation, a trap, a guest error and a missing emit
    // included (FIX 9332). A fuel read that fails measured nothing: its count
    // is unavailable, never a number.
    let usage = HookBodyUsage {
        fuel_used: store
            .get_fuel()
            .ok()
            .map(|left| budget.fuel.saturating_sub(left)),
        host_calls: Some(store.data().host_calls),
    };
    let state = store.into_data();
    let mut input_not_taken = false;
    let result = match ran {
        Err(error) => Err(error),
        Ok(Err(error)) => Err(match state.trap {
            Some(reason) => failure(reason),
            None => trap_failure(&error),
        }),
        Ok(Ok(Err(message))) if message == INPUT_NOT_TAKEN => {
            input_not_taken = true;
            Err(failure("hook input exceeds the guest memory"))
        }
        Ok(Ok(Err(message))) => Err(guest_failure(&message, prepared)),
        Ok(Ok(Ok(()))) => match state.outcome {
            Some(outcome_json) => Ok(HookBodyRun {
                outcome_json,
                fuel_used: usage.fuel_used,
                host_calls: state.host_calls,
            }),
            None => Err(failure("hook body emitted no outcome")),
        },
    };
    (result, usage, input_not_taken)
}

/// Answers the worker's reads and verdicts until the body ends. The budget
/// stops nothing (FIX 8842): it waits on the body however long it runs,
/// runs each admitted callback to its end, measured on `context`, and sends
/// its answer even when late. Only the worker's end, or its channel closing
/// without one, ends the wait. The end's usage goes on `context` before its
/// result returns; a channel that closes without an end leaves it
/// unavailable (FIX 9332).
fn serve_reads(
    requests: &mpsc::Receiver<Event>,
    read: &mut dyn FnMut(&str) -> Reply<String>,
    verdict: HookVerdictCall<'_>,
    context: &mut HookRunContext,
) -> Result<HookBodyRun> {
    loop {
        match requests.recv() {
            Ok(Event::Read { request, reply }) => {
                let _ = reply.send(context.read(|| read(&request)));
            }
            Ok(Event::Verdict { request, reply }) => {
                let _ = reply.send(context.verdict(|| verdict(&request)));
            }
            Ok(Event::Finished(result, usage, input_not_taken)) => {
                context.report_usage(usage);
                if input_not_taken {
                    context.report_input_not_taken();
                }
                return result;
            }
            Err(mpsc::RecvError) => return Err(failure("hook worker stopped without an end")),
        }
    }
}

fn trap_failure(error: &wasmtime::Error) -> Error {
    if matches!(
        error.downcast_ref::<wasmtime::Trap>(),
        Some(wasmtime::Trap::OutOfFuel)
    ) {
        failure("hook body ran out of fuel")
    } else {
        failure("hook body trapped")
    }
}

/// The body's own error text, so the receipt says why it stopped (FIX
/// 9208). The guest's position header never reaches it: it is split off
/// before the text is cut, and a TypeScript body's error ends with where it
/// threw in its TypeScript source, past the cut. A JavaScript body's error
/// reads as it always did.
fn guest_failure(message: &str, prepared: &PreparedSource<'_>) -> Error {
    let (message, at) = split_guest_error(message);
    let mut text: String = message.chars().take(GUEST_ERROR_CHARS).collect();
    if text.len() < message.len() {
        text.push_str(&format!(" … ({} bytes in all)", message.len()));
    }
    if let Some(position) = prepared.failure_position(at) {
        text.push_str(&position);
    }
    Error::InvalidConfig(format!("hook body failed: {text}"))
}

/// How `prepared` ran, for the run's record.
fn preparation(prepared: &PreparedSource<'_>) -> HookPreparation {
    HookPreparation {
        language: prepared.language().as_str().to_owned(),
        note: prepared.note().map(|note| note.code().to_owned()),
        identity: prepared
            .transpiled()
            .map(|transpiled| hex_lower(&transpiled.identity())),
    }
}

fn failure(detail: &'static str) -> Error {
    Error::InvalidConfig(detail.to_owned())
}
