//! Optional trailing speech must not turn a completed task into a door refusal.
#![cfg(oneiron_test_support)]

use std::collections::VecDeque;
use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use oneiron::claim::ScopedReadActorKey;
use oneiron::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, CodeRunDeterminism, GatedActorWrite, RunCall,
    SelfAgentVerbCall, SelfEffect,
};
use oneiron::code_sandbox::ComponentBudget;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorStatus,
    EngineNativeExecutor,
};
use oneiron::memory::HostWriteOrigin;
use oneiron::registry::ENTITY_TYPE_MESSAGE;
use oneiron::runtime_hooks::InvocationId;
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, Vault, VaultConfig, WriteActor,
};
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
use sha2::{Digest, Sha256};

const ANSWER: &str = "the task's answer";

struct SpeechDoor {
    admits_speech: bool,
}

impl AgentVerbDoor for SpeechDoor {
    fn call(
        &self,
        _call: &SelfAgentVerbCall,
        _origin: &HostWriteOrigin,
        _invocation: InvocationId,
    ) -> oneiron::Result<Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(Ok(AgentVerbAnswer::new(serde_json::Value::Null, None)))
    }

    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
        if !self.admits_speech && matches!(call, RunCall::Bridge(SelfEffect::Speak)) {
            return Err(AgentVerbRefusal {
                code: "mcp_grant_missing".to_owned(),
                hook_notice: None,
                reason_codes: Vec::new(),
            });
        }
        Ok(None)
    }
}

struct FixtureBackend {
    programs: Mutex<VecDeque<String>>,
}

impl LlmBackend for FixtureBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let program = self
            .programs
            .lock()
            .expect("fixture programs")
            .pop_front()
            .expect("the model was asked with no scripted reply left");
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: program,
                        signature: None,
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

fn quickjs_factory() -> QuickJsRuntimeFactory {
    let directory = std::env::var_os("ONEIRON_QUICKJS_ARTIFACT_DIR").map_or_else(
        || {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/code-run-quickjs/artifacts")
        },
        std::path::PathBuf::from,
    );
    let bytes = std::fs::read(directory.join("quickjs-first-party.wasm"))
        .expect("the pinned QuickJS component");
    let pin: [u8; 32] = Sha256::digest(&bytes).into();
    QuickJsRuntimeFactory::from_component(&bytes, pin, ComponentBudget::default())
        .expect("the QuickJS component passes its readiness probe")
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("a vault opens");
    (dir, vault)
}

fn run_task(vault: &Vault, admits_speech: bool) -> EngineExecutorOutcome {
    let actor = vault.ensure_embedded_owner_actor().expect("an owner actor");
    let backend = FixtureBackend {
        programs: Mutex::new(VecDeque::from([format!("finish({ANSWER:?});")])),
    };
    let lease = BudgetLease::for_test("trailing-bubble-door-refusal");
    let gated = GatedActorWrite::new(
        vault,
        WriteActor::new(actor, EdgeActorClass::Human),
        "run-trailing-bubble-door-refusal",
    )
    .expect("a dispatcher binds")
    .with_agent_verb_door(Arc::new(SpeechDoor { admits_speech }));
    let factory = quickjs_factory();
    let mut runtime = factory.runtime().expect("a guest runtime");
    let mut executor = EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, &gated);
    let config = EngineExecutorConfig {
        run_id: EntityId::now(),
        task: "return an answer".to_owned(),
        caller_source_digest: None,
        prompt_package_root: oneiron::prompt::workspace_test_prompt_package_root()
            .expect("the workspace test prompt package"),
        model: ModelId::new("test/executor@v1").expect("a model id"),
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32]),
        limits: EngineExecutorLimits::default(),
        wake: None,
    };
    let outcome = block_on_ready(executor.run(&config)).expect("the task returns its result");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    let answer = outcome
        .replay_record
        .outputs
        .iter()
        .find(|output| output.path.ends_with(".observation.txt"))
        .expect("the run's replay result holds its answer");
    assert_eq!(answer.preview.text, ANSWER);
    outcome
}

fn message_count(vault: &Vault) -> usize {
    vault
        .entities_by_type(ENTITY_TYPE_MESSAGE)
        .expect("stored MESSAGEs")
        .len()
}

#[test]
fn a_task_whose_door_refuses_its_trailing_bubble_returns_its_result_and_writes_no_message() {
    let (_dir, vault) = open_vault();
    let before = message_count(&vault);
    let outcome = run_task(&vault, false);
    assert_eq!(message_count(&vault), before);

    // An emit-time refusal alone would leave a retryable text intent behind.
    let checkpoint = outcome
        .replay_record
        .outputs
        .iter()
        .find(|output| output.path.ends_with(".implicit-speak.json"))
        .expect("the run checkpointed its speech intent");
    let bytes = vault
        .get_code_run_raw_output(checkpoint)
        .expect("the checkpoint reads")
        .expect("the checkpoint body is present");
    let intent: serde_json::Value = serde_json::from_slice(&bytes).expect("the intent parses");
    assert_eq!(intent["intent"], "result_only");
}

#[test]
fn a_task_whose_door_admits_its_trailing_bubble_writes_one_message() {
    let (_dir, vault) = open_vault();
    let before = message_count(&vault);
    run_task(&vault, true);
    assert_eq!(message_count(&vault), before + 1);
}
