//! The pinned QuickJS sandbox a hook body runs in.
//!
//! The `hook` world (`wit/hook/hook.wit`) imports a scoped read,
//! `ai.verdict` and the one outcome return, and exports `run-hook`. No WASI,
//! clock, random, file, network or verb import is linked. A verdict is
//! answered only for a fact hook the runner lets call one. Each run gets a fresh Store under the
//! code-mode limits. Its `budget_ms` is an accounting deadline on the run's
//! [`HookRunContext`], never a stop (FIX 8842): start-up, reads and verdicts
//! are measured against it, each admitted callback's answer is delivered
//! even when late, and the body runs to its own end under its fuel and
//! memory.

/// Types generated from the hook world.
pub mod bindings {
    wasmtime::component::bindgen!({ path: "wit/hook/hook.wit", world: "hook" });
}

use super::{HookBodyRun, HookBodyRuntime, HookRunContext, HookVerdictCall};
use crate::code_sandbox::wasmtime_runtime::ComponentBudget;
use crate::{Error, Result};
use std::sync::mpsc;
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, StoreContextMut, StoreLimits, StoreLimitsBuilder};

/// The hook world's WIT, for hosts building the guest.
pub const HOOK_WIT: &str = include_str!("../../../wit/hook/hook.wit");

/// The hook component this repository builds and reviews.
const HOOK_COMPONENT: &[u8] =
    include_bytes!("../../../../../components/code-run-quickjs/artifacts/quickjs-hook.wasm");

/// BLAKE3 of the checked-in hook component; its manifest row carries the SHA-256.
pub const HOOK_COMPONENT_BLAKE3: [u8; 32] = [
    0xb5, 0x64, 0xbe, 0x6f, 0xf8, 0x30, 0x63, 0x76, 0xc6, 0xba, 0xf4, 0xa3, 0xad, 0x62, 0x0b, 0x18,
    0x89, 0xf4, 0xf7, 0x77, 0x33, 0x46, 0x67, 0x40, 0x2d, 0x64, 0x9b, 0xca, 0x30, 0xa0, 0x71, 0x3e,
];

/// The three imports of the hook world, sorted. A component importing
/// anything else is refused before it runs.
const HOOK_IMPORTS: [&str; 3] = ["ai-verdict", "emit-outcome", "scoped-read"];
/// Bytes one read request may carry.
const READ_REQUEST_BYTES: usize = 4 * 1024;
/// Bytes one read answer may carry.
const READ_RESPONSE_BYTES: usize = 256 * 1024;
/// Bytes one `ai.verdict` request may carry: a question, its options, its
/// evidence refs and its state.
const VERDICT_REQUEST_BYTES: usize = 64 * 1024;
/// What a body that may not call a model hears from `ai.verdict`.
const NO_VERDICT: &str = "ai_verdict_is_a_generative_fact_hooks";
/// The longest body budget a hook selector may name.
const MAX_BUDGET_MS: u32 = 60_000;
/// Wasm stack, as code mode sets it.
const WASM_STACK_BYTES: usize = 512 * 1024;
/// The largest component accepted.
const MAX_COMPONENT_BYTES: usize = 64 * 1024 * 1024;
/// Characters of a body's error text a failed run keeps.
const GUEST_ERROR_CHARS: usize = 2048;

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
}

impl HookBodyRuntime for HookSandbox {
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
        let sandbox = Self {
            pre,
            budget: ComponentBudget::default(),
        };
        sandbox.probe()?;
        Ok(sandbox)
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
        let budget_ms = context.budget_ms();
        if budget_ms == 0 || budget_ms > MAX_BUDGET_MS {
            return Err(failure("hook budget_ms is out of bounds"));
        }
        if body.len() > self.budget.message_bytes || input_json.len() > self.budget.message_bytes {
            return Err(failure("hook body or input exceeds the message limit"));
        }
        // Wasmtime needs 'static store data, so the body runs on a scoped
        // worker and the borrowed `read` answers on this thread over a bounded
        // channel. The worker stays in process, and is joined before this
        // returns: the run's accounting ends after it.
        let (events, requests) = mpsc::sync_channel(1);
        let budget = self.budget;
        let pre = &self.pre;
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let result = execute(pre, budget, body, input_json, events.clone());
                let _ = events.send(Event::Finished(result));
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
    limits: StoreLimits,
    host_calls: u32,
    message_bytes: usize,
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
    Finished(Result<HookBodyRun>),
}

type Reply<T> = std::result::Result<T, String>;

impl State {
    fn refuse(&mut self, reason: &'static str) -> wasmtime::Error {
        self.trap = Some(reason);
        wasmtime::Error::msg(reason)
    }

    /// One scoped read, counted in the run's host calls: a count never
    /// refuses one (FIX 8841). Oversized requests and answers come back as
    /// codes.
    fn read(&mut self, request: String) -> wasmtime::Result<Reply<String>> {
        self.host_calls = self.host_calls.saturating_add(1);
        if request.len() > READ_REQUEST_BYTES {
            return Ok(Err("read_request_over_budget".into()));
        }
        let (reply, response) = mpsc::sync_channel(1);
        if self.events.send(Event::Read { request, reply }).is_err() {
            return Err(self.refuse("hook host stopped"));
        }
        let Ok(answer) = response.recv() else {
            return Err(self.refuse("hook host stopped"));
        };
        Ok(match answer {
            Ok(rows) if rows.len() > READ_RESPONSE_BYTES => Err("read_response_over_budget".into()),
            Err(code) if code.len() > READ_RESPONSE_BYTES => Err("read_refused".into()),
            answer => answer,
        })
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
            Ok(verdict) if verdict.len() > READ_RESPONSE_BYTES => {
                Err("verdict_response_over_budget".into())
            }
            Err(text) if text.len() > READ_RESPONSE_BYTES => Err("verdict_refused".into()),
            answer => answer,
        })
    }

    /// The one outcome. A malformed or oversized outcome comes back as a code;
    /// a second outcome after one was taken traps the body.
    fn emit(&mut self, outcome: String) -> wasmtime::Result<Reply<()>> {
        self.host_calls = self.host_calls.saturating_add(1);
        if self.outcome.is_some() {
            return Err(self.refuse("hook outcome already emitted"));
        }
        if outcome.len() > self.message_bytes {
            return Ok(Err("outcome_over_budget".into()));
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

fn execute(
    pre: &bindings::HookPre<State>,
    budget: ComponentBudget,
    body: &str,
    input_json: &str,
    events: mpsc::SyncSender<Event>,
) -> Result<HookBodyRun> {
    let limits = StoreLimitsBuilder::new()
        .memory_size(budget.memory_bytes)
        .memories(1)
        .tables(8)
        .instances(16)
        .table_elements(10_000)
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(
        pre.engine(),
        State {
            events,
            limits,
            host_calls: 0,
            message_bytes: budget.message_bytes,
            outcome: None,
            trap: None,
        },
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(budget.fuel)
        .map_err(|_| failure("hook fuel setup failed"))?;
    let hook = pre
        .instantiate(&mut store)
        .map_err(|_| failure("hook component instantiation refused"))?;
    // Wasmtime performs canonical post-return inside the call.
    let ran = hook.call_run_hook(&mut store, body, input_json);
    let fuel_used = budget.fuel.saturating_sub(store.get_fuel().unwrap_or(0));
    let state = store.into_data();
    match ran {
        Err(error) => Err(match state.trap {
            Some(reason) => failure(reason),
            None => trap_failure(&error),
        }),
        Ok(Err(message)) => Err(guest_failure(&message)),
        Ok(Ok(())) => Ok(HookBodyRun {
            outcome_json: state
                .outcome
                .ok_or(failure("hook body emitted no outcome"))?,
            fuel_used,
            host_calls: state.host_calls,
        }),
    }
}

/// Answers the worker's reads and verdicts until the body ends. The budget
/// stops nothing (FIX 8842): it waits on the body however long it runs,
/// runs each admitted callback to its end, measured on `context`, and sends
/// its answer even when late. Only the worker's end, or its channel closing
/// without one, ends the wait.
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
            Ok(Event::Finished(result)) => return result,
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

/// The body's own error text, so the receipt says why it stopped.
fn guest_failure(message: &str) -> Error {
    let mut text: String = message.chars().take(GUEST_ERROR_CHARS).collect();
    if text.len() < message.len() {
        text.push_str(&format!(" … ({} bytes in all)", message.len()));
    }
    Error::InvalidConfig(format!("hook body failed: {text}"))
}

fn failure(detail: &'static str) -> Error {
    Error::InvalidConfig(detail.to_owned())
}
