//! [CODE-MODE-STEP-SOURCES-UNWITNESSED]: the rows a code-mode step's model
//! call is sent with (`LlmBackend::generate_sourced`).
//!
//! One engine-executor REPL turn runs against a backend that keeps the
//! sources each call was sent with. A run whose host declared its task the
//! caller's own text (FIX 7087), as the MCP `execute_code` door does, names
//! its rows: the task names none, and the run's first request reads no row
//! but the run's own record. A run whose host declared no task, or declared
//! one and then added to it, still names none: its task is the host's, which
//! may carry rows no part of the set witnesses (Engine 03:58).
//!
//! Red on main: `step_source_rows` keeps the task part unknown for every
//! run, so the declared run's call is sent with no rows.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test code_mode_step_sources`.

#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use oneiron::code_run::{CodeRunDeterminism, GatedActorWrite};
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorStatus, EngineNativeExecutor,
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
};
use oneiron::llm::ReplyAssertions;
use oneiron::prompt::workspace_test_prompt_package_root;
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, Vault, VaultConfig, WriteActor,
};

/// The task the caller sent, as the run's host declared it.
const CALLER_TASK: &str = "list the open threads";

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("executor future unexpectedly pending"),
    }
}

/// Answers each call with one program, and keeps the sources each call was
/// sent with: `None` for a call sent through plain `generate`.
#[derive(Default)]
struct SourceKeepingBackend {
    sent: Mutex<Vec<Option<Vec<EntityId>>>>,
}

impl SourceKeepingBackend {
    fn answer(&self, sources: Option<Vec<EntityId>>) -> LlmGenerateFuture<'_> {
        self.sent.lock().expect("sent sources").push(sources);
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: "console.log('probe');".to_owned(),
                        signature: None,
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
                reply_assertions: ReplyAssertions::default(),
                token_scores: None,
            })
        })
    }

    fn sent(&self) -> Vec<Option<Vec<EntityId>>> {
        self.sent.lock().expect("sent sources").clone()
    }
}

impl LlmBackend for SourceKeepingBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.answer(None)
    }

    fn generate_sourced<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
        sources: Option<Vec<EntityId>>,
    ) -> LlmGenerateFuture<'a> {
        self.answer(sources)
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// Answers each step with a pending observation, as a program that only
/// logs does.
struct PendingRuntime;

impl JsCodeModeRuntime for PendingRuntime {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        _host: &mut dyn JsCodeModeHost,
    ) -> oneiron::Result<JsCodeModeStepOutcome> {
        Ok(JsCodeModeStepOutcome::pending("probe observation"))
    }
}

fn determinism_seed() -> [u8; 32] {
    let mut seed = [0_u8; 32];
    seed[..16].copy_from_slice(EntityId::now().as_bytes());
    seed[16..].copy_from_slice(EntityId::now().as_bytes());
    seed
}

fn owner_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    (dir, vault, owner)
}

fn executor_config(run_id: EntityId, task: &str) -> EngineExecutorConfig {
    EngineExecutorConfig {
        run_id,
        task: task.to_owned(),
        prompt_package_root: workspace_test_prompt_package_root()
            .expect("workspace test prompt package"),
        model: ModelId::new("test/executor@v1").expect("model id"),
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(1_719_000_001_000, determinism_seed()),
        limits: EngineExecutorLimits { soft_steps: 1 },
        wake: None,
    }
}

/// The sources the one step of a run of `task` was sent with, its host
/// having declared `declared` the caller's own task, if anything.
fn step_sources(
    run_id: EntityId,
    task: &str,
    declared: Option<&str>,
) -> Vec<Option<Vec<EntityId>>> {
    let (_dir, vault, owner) = owner_vault();
    let backend = SourceKeepingBackend::default();
    let lease = BudgetLease::for_test("code-mode-step-sources");
    let mut gated = GatedActorWrite::new(
        &vault,
        WriteActor::new(owner, EdgeActorClass::Agent),
        "run-code-mode-step-sources",
    )
    .expect("gated actor write");
    if let Some(declared) = declared {
        gated = gated.with_caller_task(run_id, declared);
    }
    let mut runtime = PendingRuntime;
    let config = executor_config(run_id, task);
    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated);
    let outcome = block_on_ready(executor.run(&config)).expect("the turn runs");
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 },
        "one step commits, then the run yields",
    );
    backend.sent()
}

#[test]
fn a_caller_declared_task_names_its_step_rows() {
    let run_id = EntityId::now();
    let sent = step_sources(run_id, CALLER_TASK, Some(CALLER_TASK));
    assert_eq!(
        sent,
        vec![Some(vec![run_id])],
        "the step's call names the rows its request was read from: the caller's task names \
         none, and the first request reads only the run's own record",
    );
}

#[test]
fn an_undeclared_task_names_no_step_rows() {
    let run_id = EntityId::now();
    let sent = step_sources(run_id, CALLER_TASK, None);
    assert_eq!(
        sent,
        vec![None],
        "a task its host declared no caller's own is the host's, and stays unknown",
    );
}

#[test]
fn a_declared_task_its_host_added_to_names_no_step_rows() {
    let run_id = EntityId::now();
    let task = format!("{CALLER_TASK}\n\nThe host's own addition.");
    let sent = step_sources(run_id, &task, Some(CALLER_TASK));
    assert_eq!(
        sent,
        vec![None],
        "a task the host added to is not the caller's text, byte for byte, and stays unknown",
    );
}
