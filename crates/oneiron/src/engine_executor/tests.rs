use std::{
    collections::VecDeque,
    future::Future,
    pin::pin,
    sync::Mutex,
    task::{Context, Poll, Waker},
};

use rmpv::Value;

use crate::{
    BudgetLease, ClaimCandidate, ClaimSubject, ContentPart, EdgeActorClass, EdgeKind,
    FatalLlmError, FinishReason, LlmGenerateFuture, LlmResponse, LlmStreamResult, LlmUsage,
    ModelId, TimeRange, WriteActor, code_run::SelfAskHumanCall, code_run::SelfDurableWaitReason,
    code_run::SelfEffect, code_run::SelfMemoryPutClaimCall, code_run::SelfMemoryPutEdgeCall,
    code_run::SelfMemoryWriteFixtureCall, code_run::SelfSpeechCall, registry::ENTITY_TYPE_PERSON,
};

use super::*;

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("test future unexpectedly pending"),
    }
}

fn open_test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), embedding_test_config()).expect("open vault");
    (dir, vault)
}

use crate::test_util::{embedding_test_config, entity};

fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn seed_person(vault: &Vault, seed: u8) -> EntityId {
    let id = entity(seed);
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, b"person")
        .expect("seed person");
    id
}

fn gated_actor_write<'a>(vault: &'a Vault, run_ref: &str) -> GatedActorWrite<'a> {
    let actor = seed_person(vault, 0xA0);
    GatedActorWrite::new(
        vault,
        WriteActor::new(actor, EdgeActorClass::Agent),
        run_ref,
    )
    .expect("gated actor write")
}

fn gate_decision_count(vault: &Vault) -> usize {
    vault
        .store
        .gate_decisions(100)
        .expect("gate decisions")
        .len()
}

fn bridge_outcome_kind(call: &CodeRunBridgeCall) -> &str {
    let Value::Map(entries) = &call.outcome else {
        panic!("bridge outcome must be a map");
    };
    entries
        .iter()
        .find_map(|(key, value)| {
            (key.as_str() == Some("kind"))
                .then(|| value.as_str().expect("outcome kind must be a string"))
        })
        .expect("bridge outcome kind")
}

fn model() -> ModelId {
    ModelId::new("test/executor@v1").expect("model id")
}

fn determinism() -> CodeRunDeterminism {
    CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32])
}

fn executor_config(run_id: EntityId, limits: EngineExecutorLimits) -> EngineExecutorConfig {
    EngineExecutorConfig {
        run_id,
        task: "remember the project status".to_owned(),
        model: model(),
        model_locality: ModelLocality::OwnServer,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: determinism(),
        limits,
    }
}

fn llm_response(text: impl Into<String>) -> LlmResponse {
    llm_response_with_finish(text, FinishReason::Stop)
}

fn llm_response_with_finish(text: impl Into<String>, finish_reason: FinishReason) -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text { text: text.into() }],
        },
        usage: LlmUsage::zero(),
        finish_reason,
    }
}

struct FixtureBackend {
    responses: Mutex<VecDeque<LlmResponse>>,
    requests: Mutex<Vec<LlmRequest>>,
}

impl FixtureBackend {
    fn new(responses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().map(llm_response).collect()),
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl LlmBackend for FixtureBackend {
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.requests.lock().expect("requests lock").push(request);
        let text = self
            .responses
            .lock()
            .expect("responses lock")
            .pop_front()
            .expect("fixture response");
        Box::pin(async move { Ok(text) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

struct FixtureRuntime {
    observations: VecDeque<JsCodeModeStepOutcome>,
    calls: VecDeque<Vec<SelfCall>>,
    seen: Vec<SeenStep>,
}

#[derive(Debug, Clone)]
struct SeenStep {
    seq: u64,
    script: String,
    boundary: SandboxBoundaryContract,
}

impl FixtureRuntime {
    fn new(observations: impl IntoIterator<Item = JsCodeModeStepOutcome>) -> Self {
        Self {
            observations: observations.into_iter().collect(),
            calls: VecDeque::new(),
            seen: Vec::new(),
        }
    }

    fn with_calls(mut self, calls: impl IntoIterator<Item = Vec<SelfCall>>) -> Self {
        self.calls = calls.into_iter().collect();
        self
    }
}

impl JsCodeModeRuntime for FixtureRuntime {
    fn run_step(
        &mut self,
        step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        self.seen.push(SeenStep {
            seq: step.seq,
            script: step.script.to_owned(),
            boundary: step.boundary,
        });
        if let Some(calls) = self.calls.pop_front() {
            for call in calls {
                let _ = host.dispatch_self(call)?;
            }
        }
        self.observations
            .pop_front()
            .ok_or(Error::InvariantViolation("missing fixture observation"))
    }
}

struct ErrorAfterCallsRuntime {
    calls: Vec<SelfCall>,
}

impl ErrorAfterCallsRuntime {
    fn new(calls: Vec<SelfCall>) -> Self {
        Self { calls }
    }
}

impl JsCodeModeRuntime for ErrorAfterCallsRuntime {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        for call in self.calls.drain(..) {
            let _ = host.dispatch_self(call)?;
        }
        Err(Error::InvariantViolation(
            "fixture runtime failed after bridge calls",
        ))
    }
}

#[test]
fn executor_uses_llm_backend_and_plain_js_boundary() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["const answer = 42;"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
    let gated_write = gated_actor_write(&vault, "run-boundary");
    let config = executor_config(entity(0x81), EngineExecutorLimits::default());

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let outcome = block_on_ready(executor.run(&config)).expect("executor run");

    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(outcome.steps_run, 1);
    assert_eq!(runtime.seen.len(), 1);
    assert_eq!(runtime.seen[0].seq, 0);
    assert_eq!(runtime.seen[0].script, "const answer = 42;");
    assert_eq!(
        runtime.seen[0].boundary.guest_language(),
        SandboxGuestLanguage::PlainJavaScript
    );
    assert_eq!(
        runtime.seen[0].boundary.component_boundary(),
        SandboxComponentBoundary::WasmtimeWit
    );
    assert!(runtime.seen[0].boundary.links_write_imports());
    let linked_imports = runtime.seen[0]
        .boundary
        .linked_imports()
        .iter()
        .map(|import| import.name())
        .collect::<Vec<_>>();
    for required in EXECUTOR_REQUIRED_HOST_IMPORTS {
        assert!(
            linked_imports.contains(required),
            "executor boundary must link advertised host import {required}"
        );
    }

    let requests = backend.requests.lock().expect("requests lock");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].envelope.purpose,
        CallPurpose::Other {
            name: ENGINE_EXECUTOR_PURPOSE_NAME.to_owned(),
        }
    );
    assert!(matches!(
        requests[0].envelope.class,
        CallClass::Durable { .. }
    ));
    let system = text_message(&requests[0].messages[0]);
    assert!(system.contains(PLAIN_JS_HOST_VERB_DTS));
    assert!(system.contains("plain JavaScript"));
    for advertised in [
        "function search",
        "function put_claim",
        "function supersede_claim",
        "function put_edge",
        "function askHuman",
        "function ask_human",
        "function now_unix_ms",
    ] {
        assert!(
            system.contains(advertised),
            "executor prompt must advertise linked host verb {advertised}"
        );
    }
    assert_eq!(outcome.replay_record.step_checkpoints.len(), 1);
    assert_ne!(
        outcome.replay_record.step_checkpoints[0].state_hash,
        [0; 32]
    );
    assert!(
        vault
            .get_code_run_replay_record(&config.run_id)
            .expect("load replay")
            .is_some()
    );
}

#[test]
fn executor_records_self_calls_through_dispatcher_and_waits_durably() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["await self.ask_human('continue?');"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::pending("waiting")])
        .with_calls([vec![SelfCall::AskHuman(SelfAskHumanCall::new("continue?"))]]);
    let gated_write = gated_actor_write(&vault, "run-wait");
    let config = executor_config(entity(0x82), EngineExecutorLimits::default());

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let outcome = block_on_ready(executor.run(&config)).expect("executor run");

    let EngineExecutorStatus::Waiting(wait) = outcome.status else {
        panic!("expected durable wait");
    };
    assert_eq!(wait.effect, SelfEffect::AskHuman);
    assert_eq!(wait.reason, SelfDurableWaitReason::HumanInput);
    assert_eq!(wait.prompt.as_deref(), Some("continue?"));
    assert_eq!(outcome.replay_record.bridge_calls.len(), 1);
    assert_eq!(outcome.replay_record.bridge_calls[0].seq, 0);
    assert_eq!(
        outcome.replay_record.bridge_calls[0].effect,
        SelfEffect::AskHuman
    );
    let stored = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("load replay")
        .expect("stored replay");
    assert_eq!(stored.bridge_calls.len(), 1);
}

#[test]
fn executor_blocks_later_self_calls_after_durable_wait() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["self.askHuman({ prompt: 'continue?' });"]);
    let lease = BudgetLease::for_test("executor-lease");
    let src = seed_person(&vault, 0xC1);
    let tgt = seed_person(&vault, 0xC2);
    let calls = vec![
        SelfCall::AskHuman(SelfAskHumanCall::new("continue?")),
        SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            src,
            EdgeKind::Mentions,
            tgt,
            0.9,
        )),
    ];
    let mut runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::pending("waiting")]).with_calls([calls]);
    let gated_write = gated_actor_write(&vault, "run-wait-barrier");
    let config = executor_config(entity(0x87), EngineExecutorLimits::default());
    let before = gate_decision_count(&vault);

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let outcome = block_on_ready(executor.run(&config)).expect("executor run");

    assert!(matches!(outcome.status, EngineExecutorStatus::Waiting(_)));
    assert_eq!(outcome.replay_record.bridge_calls.len(), 2);
    assert_eq!(
        outcome.replay_record.bridge_calls[0].effect,
        SelfEffect::AskHuman
    );
    assert_eq!(
        outcome.replay_record.bridge_calls[1].effect,
        SelfEffect::MemoryPutEdge
    );
    assert_eq!(
        gate_decision_count(&vault),
        before,
        "post-wait write must not reach GatedActorWrite"
    );
    assert!(
        vault
            .targets(&src, EdgeKind::Mentions, None)
            .expect("edge targets")
            .is_empty()
    );
}

#[test]
fn executor_self_writes_route_through_gated_actor_write_trap() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["await self.memory.put_edge(src, 'mentions', tgt);"]);
    let lease = BudgetLease::for_test("executor-lease");
    let src = seed_person(&vault, 0xB1);
    let tgt = seed_person(&vault, 0xB2);
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("unreachable")])
        .with_calls([vec![SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
            src,
            EdgeKind::Mentions,
            tgt,
            0.7,
        ))]]);
    let gated_write = gated_actor_write(&vault, "run-gated-write");
    let config = executor_config(
        entity(0x85),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 1,
        },
    );
    let before = gate_decision_count(&vault);

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let err = block_on_ready(executor.run(&config)).expect_err("pending gate rejects write");

    assert!(matches!(
        err,
        EngineExecutorError::Engine(Error::GateWriteRejected { .. })
    ));
    assert_eq!(gate_decision_count(&vault), before + 1);
    assert!(
        vault
            .targets(&src, EdgeKind::Mentions, None)
            .expect("edge targets")
            .is_empty()
    );
    let stored = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("load replay")
        .expect("stored denied-step replay");
    assert_eq!(stored.bridge_calls.len(), 1);
    assert_eq!(stored.bridge_calls[0].effect, SelfEffect::MemoryPutEdge);
    assert_eq!(bridge_outcome_kind(&stored.bridge_calls[0]), "denied");
    assert_eq!(stored.step_checkpoints.len(), 1);

    let retry_backend = FixtureBackend::new(std::iter::empty::<&str>());
    let mut retry_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
    let mut retry = EngineNativeExecutor::new(
        &vault,
        &retry_backend,
        &lease,
        &mut retry_runtime,
        &gated_write,
    );
    let retry_outcome = block_on_ready(retry.run(&config)).expect("retry reads checkpoint");
    assert_eq!(
        retry_outcome.status,
        EngineExecutorStatus::HardStepLimitReached
    );
    assert!(retry_runtime.seen.is_empty());
    assert!(
        retry_backend
            .requests
            .lock()
            .expect("requests lock")
            .is_empty()
    );
}

#[test]
fn executor_persists_bridge_calls_when_audited_write_fails() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["await self.memory.put_claim(claim);"]);
    let lease = BudgetLease::for_test("executor-lease");
    let missing_subject = entity(0xD5);
    let claim = entity(0xD6);
    let candidate = ClaimCandidate::new(
        "profile.favorite_place",
        ClaimSubject::Entity(missing_subject),
        Value::from("tea house"),
        0.8,
    );
    let mut runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::complete("unreachable")]).with_calls([vec![
            SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(claim, candidate, range(11), 12)),
        ]]);
    let gated_write = gated_actor_write(&vault, "run-audited-write-failure");
    let config = executor_config(
        entity(0x8E),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 1,
        },
    );
    let before = gate_decision_count(&vault);

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let err = block_on_ready(executor.run(&config)).expect_err("write failure returned");

    assert!(matches!(
        err,
        EngineExecutorError::Engine(Error::EntityNotFound)
    ));
    assert_eq!(gate_decision_count(&vault), before + 1);
    assert!(
        vault.get_claim(&claim).expect("claim lookup").is_none(),
        "failed claim write must not commit the claim"
    );
    let stored = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("load replay")
        .expect("stored failed-step replay");
    assert_eq!(stored.bridge_calls.len(), 1);
    assert_eq!(stored.bridge_calls[0].effect, SelfEffect::MemoryPutClaim);
    assert_eq!(bridge_outcome_kind(&stored.bridge_calls[0]), "failed");
    assert_eq!(stored.step_checkpoints.len(), 1);
    assert!(
        load_utf8_output(
            &ExecutorStorage::Canonical(&vault),
            &stored,
            &observation_output_path(0)
        )
        .expect("stored error observation")
        .contains("entity not found")
    );

    let retry_backend = FixtureBackend::new(std::iter::empty::<&str>());
    let mut retry_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
    let mut retry = EngineNativeExecutor::new(
        &vault,
        &retry_backend,
        &lease,
        &mut retry_runtime,
        &gated_write,
    );
    let retry_outcome = block_on_ready(retry.run(&config)).expect("retry reads checkpoint");
    assert_eq!(
        retry_outcome.status,
        EngineExecutorStatus::HardStepLimitReached
    );
    assert!(retry_runtime.seen.is_empty());
    assert!(
        retry_backend
            .requests
            .lock()
            .expect("requests lock")
            .is_empty()
    );
}

#[test]
fn executor_persists_bridge_calls_when_runtime_errors_after_dispatch() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["await self.memory.write_fixture(claim);"]);
    let lease = BudgetLease::for_test("executor-lease");
    let subject = seed_person(&vault, 0xD1);
    let claim = entity(0xD2);
    let candidate = ClaimCandidate::new(
        "profile.favorite_drink",
        ClaimSubject::Entity(subject),
        Value::from("matcha"),
        0.8,
    );
    let mut runtime = ErrorAfterCallsRuntime::new(vec![SelfCall::MemoryWriteFixture(
        SelfMemoryWriteFixtureCall::new(claim, candidate, range(7), 8),
    )]);
    let gated_write = gated_actor_write(&vault, "run-error-after-dispatch");
    let config = executor_config(
        entity(0x8B),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 1,
        },
    );

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let err = block_on_ready(executor.run(&config)).expect_err("runtime error returned");

    assert!(matches!(
        err,
        EngineExecutorError::Engine(Error::InvariantViolation(
            "fixture runtime failed after bridge calls"
        ))
    ));
    assert!(
        vault
            .get_claim(&claim)
            .expect("load committed claim")
            .is_some(),
        "host write committed before the runtime error"
    );
    let stored = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("load replay")
        .expect("stored failed-step replay");
    assert_eq!(stored.bridge_calls.len(), 1);
    assert_eq!(
        stored.bridge_calls[0].effect,
        SelfEffect::MemoryWriteFixture
    );
    assert_eq!(stored.step_checkpoints.len(), 1);
    assert!(
        load_utf8_output(
            &ExecutorStorage::Canonical(&vault),
            &stored,
            &observation_output_path(0)
        )
        .expect("stored error observation")
        .contains("fixture runtime failed after bridge calls")
    );

    let retry_backend = FixtureBackend::new(std::iter::empty::<&str>());
    let mut retry_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
    let mut retry = EngineNativeExecutor::new(
        &vault,
        &retry_backend,
        &lease,
        &mut retry_runtime,
        &gated_write,
    );
    let retry_outcome = block_on_ready(retry.run(&config)).expect("retry reads checkpoint");
    assert_eq!(
        retry_outcome.status,
        EngineExecutorStatus::HardStepLimitReached
    );
    assert!(retry_runtime.seen.is_empty());
    assert!(
        retry_backend
            .requests
            .lock()
            .expect("requests lock")
            .is_empty()
    );
}

#[test]
fn executor_persists_bridge_calls_when_output_recording_fails_after_dispatch() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["await self.memory.write_fixture(claim);"]);
    let lease = BudgetLease::for_test("executor-lease");
    let subject = seed_person(&vault, 0xD3);
    let claim = entity(0xD4);
    let candidate = ClaimCandidate::new(
        "profile.favorite_snack",
        ClaimSubject::Entity(subject),
        Value::from("senbei"),
        0.8,
    );
    let long_path = format!("{}.txt", "x".repeat(1100));
    let mut step_outcome = JsCodeModeStepOutcome::complete("done");
    step_outcome
        .outputs
        .push(JsCodeModeOutput::new(long_path, b"unreachable".to_vec()));
    let mut runtime =
        FixtureRuntime::new([step_outcome]).with_calls([vec![SelfCall::MemoryWriteFixture(
            SelfMemoryWriteFixtureCall::new(claim, candidate, range(9), 10),
        )]]);
    let gated_write = gated_actor_write(&vault, "run-output-error-after-dispatch");
    let config = executor_config(
        entity(0x8C),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 1,
        },
    );

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let err = block_on_ready(executor.run(&config)).expect_err("output validation error returned");

    assert!(matches!(
        err,
        EngineExecutorError::Engine(Error::InvalidCodeArtifactBody("raw output path"))
    ));
    assert!(
        vault
            .get_claim(&claim)
            .expect("load committed claim")
            .is_some(),
        "host write committed before output recording failed"
    );
    let stored = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("load replay")
        .expect("stored failed-step replay");
    assert_eq!(stored.bridge_calls.len(), 1);
    assert_eq!(
        stored.bridge_calls[0].effect,
        SelfEffect::MemoryWriteFixture
    );
    assert_eq!(stored.step_checkpoints.len(), 1);
    assert!(
        load_utf8_output(
            &ExecutorStorage::Canonical(&vault),
            &stored,
            &observation_output_path(0)
        )
        .expect("stored error observation")
        .contains("Runtime output recording failed after host bridge calls")
    );

    let retry_backend = FixtureBackend::new(std::iter::empty::<&str>());
    let mut retry_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
    let mut retry = EngineNativeExecutor::new(
        &vault,
        &retry_backend,
        &lease,
        &mut retry_runtime,
        &gated_write,
    );
    let retry_outcome = block_on_ready(retry.run(&config)).expect("retry reads checkpoint");
    assert_eq!(
        retry_outcome.status,
        EngineExecutorStatus::HardStepLimitReached
    );
    assert!(retry_runtime.seen.is_empty());
    assert!(
        retry_backend
            .requests
            .lock()
            .expect("requests lock")
            .is_empty()
    );
}

#[test]
fn executor_preserves_durable_wait_when_runtime_errors_after_wait() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["await self.ask_human('continue?');"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime =
        ErrorAfterCallsRuntime::new(vec![SelfCall::AskHuman(SelfAskHumanCall::new("continue?"))]);
    let gated_write = gated_actor_write(&vault, "run-wait-then-error");
    let config = executor_config(
        entity(0x8D),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 1,
        },
    );

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let outcome = block_on_ready(executor.run(&config)).expect("durable wait persists");

    let EngineExecutorStatus::Waiting(wait) = outcome.status else {
        panic!("expected durable wait");
    };
    assert_eq!(wait.effect, SelfEffect::AskHuman);
    assert_eq!(wait.reason, SelfDurableWaitReason::HumanInput);
    assert_eq!(outcome.steps_run, 1);
    let stored = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("load replay")
        .expect("stored wait replay");
    assert_eq!(stored.bridge_calls.len(), 1);
    assert_eq!(stored.step_checkpoints.len(), 1);

    let retry_backend = FixtureBackend::new(std::iter::empty::<&str>());
    let mut retry_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
    let mut retry = EngineNativeExecutor::new(
        &vault,
        &retry_backend,
        &lease,
        &mut retry_runtime,
        &gated_write,
    );
    let retry_outcome = block_on_ready(retry.run(&config)).expect("retry returns wait");
    assert!(matches!(
        retry_outcome.status,
        EngineExecutorStatus::Waiting(_)
    ));
    assert_eq!(retry_outcome.steps_run, 0);
    assert!(retry_runtime.seen.is_empty());
    assert!(
        retry_backend
            .requests
            .lock()
            .expect("requests lock")
            .is_empty()
    );
}

#[test]
fn executor_resumes_from_persisted_repl_record() {
    let (_dir, vault) = open_test_vault();
    let lease = BudgetLease::for_test("executor-lease");
    let config = executor_config(
        entity(0x83),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 3,
        },
    );
    let gated_write = gated_actor_write(&vault, "run-resume");

    let first_backend = FixtureBackend::new(["const first = true;"]);
    let mut first_runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::pending("first observation")]);
    let mut first = EngineNativeExecutor::new(
        &vault,
        &first_backend,
        &lease,
        &mut first_runtime,
        &gated_write,
    );
    let first_outcome = block_on_ready(first.run(&config)).expect("first run");
    assert_eq!(
        first_outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 }
    );

    let second_backend = FixtureBackend::new(["const second = true;"]);
    let mut second_runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::complete("first observation")]);
    let mut second = EngineNativeExecutor::new(
        &vault,
        &second_backend,
        &lease,
        &mut second_runtime,
        &gated_write,
    );
    let second_outcome = block_on_ready(second.run(&config)).expect("second run");

    assert_eq!(second_outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(second_outcome.replay_record.step_checkpoints.len(), 2);
    assert_eq!(second_runtime.seen[0].seq, 1);
    let requests = second_backend.requests.lock().expect("requests lock");
    let resumed_request = &requests[0];
    let transcript = resumed_request
        .messages
        .iter()
        .map(text_message)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(transcript.contains("const first = true;"));
    assert!(transcript.contains("first observation"));
}

#[test]
fn executor_allows_resume_with_different_soft_step_budget() {
    let (_dir, vault) = open_test_vault();
    let lease = BudgetLease::for_test("executor-lease");
    let config = executor_config(
        entity(0x8E),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 3,
        },
    );
    let gated_write = gated_actor_write(&vault, "run-soft-step-resume");

    let first_backend = FixtureBackend::new(["const first = true;"]);
    let mut first_runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::pending("first observation")]);
    let mut first = EngineNativeExecutor::new(
        &vault,
        &first_backend,
        &lease,
        &mut first_runtime,
        &gated_write,
    );
    let first_outcome = block_on_ready(first.run(&config)).expect("first run");
    assert_eq!(
        first_outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 }
    );

    let mut resumed_config = config.clone();
    resumed_config.limits.soft_steps = 2;
    let second_backend = FixtureBackend::new(["const second = true;"]);
    let mut second_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
    let mut second = EngineNativeExecutor::new(
        &vault,
        &second_backend,
        &lease,
        &mut second_runtime,
        &gated_write,
    );
    let second_outcome = block_on_ready(second.run(&resumed_config)).expect("resume run");

    assert_eq!(second_outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(second_outcome.replay_record.step_checkpoints.len(), 2);
    assert_eq!(second_runtime.seen[0].seq, 1);
}

#[test]
fn executor_rejects_resume_with_mismatched_config_identity() {
    let (_dir, vault) = open_test_vault();
    let lease = BudgetLease::for_test("executor-lease");
    let config = executor_config(
        entity(0x88),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 3,
        },
    );
    let gated_write = gated_actor_write(&vault, "run-config-drift");

    let first_backend = FixtureBackend::new(["const first = true;"]);
    let mut first_runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::pending("first observation")]);
    let mut first = EngineNativeExecutor::new(
        &vault,
        &first_backend,
        &lease,
        &mut first_runtime,
        &gated_write,
    );
    block_on_ready(first.run(&config)).expect("first run");

    let mut drifted = config.clone();
    drifted.task = "do a different task".to_owned();
    let second_backend = FixtureBackend::new(["const second = true;"]);
    let mut second_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
    let mut second = EngineNativeExecutor::new(
        &vault,
        &second_backend,
        &lease,
        &mut second_runtime,
        &gated_write,
    );
    let err = block_on_ready(second.run(&drifted)).expect_err("config drift rejected");

    assert!(matches!(
        err,
        EngineExecutorError::Engine(Error::InvalidConfig(message))
            if message == "engine executor config changed for existing run"
    ));
    assert!(second_runtime.seen.is_empty());
    assert!(
        second_backend
            .requests
            .lock()
            .expect("requests lock")
            .is_empty()
    );
}

#[test]
fn executor_returns_persisted_terminal_status_without_replaying() {
    let (_dir, vault) = open_test_vault();
    let lease = BudgetLease::for_test("executor-lease");
    let config = executor_config(entity(0x89), EngineExecutorLimits::default());
    let gated_write = gated_actor_write(&vault, "run-terminal-replay");

    let first_backend = FixtureBackend::new(["const done = true;"]);
    let mut first_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
    let mut first = EngineNativeExecutor::new(
        &vault,
        &first_backend,
        &lease,
        &mut first_runtime,
        &gated_write,
    );
    let first_outcome = block_on_ready(first.run(&config)).expect("first run");
    assert_eq!(first_outcome.status, EngineExecutorStatus::Complete);

    let replay_backend = FixtureBackend::new(std::iter::empty::<&str>());
    let mut replay_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
    let mut replay = EngineNativeExecutor::new(
        &vault,
        &replay_backend,
        &lease,
        &mut replay_runtime,
        &gated_write,
    );
    let replay_outcome = block_on_ready(replay.run(&config)).expect("terminal replay");

    assert_eq!(replay_outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(replay_outcome.steps_run, 0);
    assert!(replay_runtime.seen.is_empty());
    assert!(
        replay_backend
            .requests
            .lock()
            .expect("requests lock")
            .is_empty()
    );
}

#[test]
fn executor_ignores_runtime_outputs_that_look_like_terminal_markers() {
    let (_dir, vault) = open_test_vault();
    let lease = BudgetLease::for_test("executor-lease");
    let config = executor_config(
        entity(0x8B),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 3,
        },
    );
    let gated_write = gated_actor_write(&vault, "run-terminal-output-shadow");

    let first_backend = FixtureBackend::new(["const first = true;"]);
    let mut first_outcome = JsCodeModeStepOutcome::pending("first");
    first_outcome.outputs = vec![JsCodeModeOutput::new(
        "report.terminal.json",
        b"not a terminal marker".to_vec(),
    )];
    let mut first_runtime = FixtureRuntime::new([first_outcome]);
    let mut first = EngineNativeExecutor::new(
        &vault,
        &first_backend,
        &lease,
        &mut first_runtime,
        &gated_write,
    );
    let first_outcome = block_on_ready(first.run(&config)).expect("first run");
    assert_eq!(
        first_outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 }
    );

    let second_backend = FixtureBackend::new(["const second = true;"]);
    let mut second_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
    let mut second = EngineNativeExecutor::new(
        &vault,
        &second_backend,
        &lease,
        &mut second_runtime,
        &gated_write,
    );
    let second_outcome = block_on_ready(second.run(&config)).expect("resume run");

    assert_eq!(second_outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(second_runtime.seen.len(), 1);
    assert_eq!(second_runtime.seen[0].seq, 1);
}

#[test]
fn replay_record_guard_rejects_stale_append_generation() {
    let (_dir, vault) = open_test_vault();
    let lease = BudgetLease::for_test("executor-lease");
    let config = executor_config(
        entity(0x8A),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 3,
        },
    );
    let gated_write = gated_actor_write(&vault, "run-stale-append");
    let backend = FixtureBackend::new(["const first = true;"]);
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::pending("first")]);
    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    block_on_ready(executor.run(&config)).expect("first run");

    let base = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("load replay")
        .expect("stored replay");
    let stale_generation = base.generation().expect("base generation");
    let mut winner = base.clone();
    record_text_output(
        &ExecutorStorage::Canonical(&vault),
        &mut winner,
        "executor/repl/test-winner.txt".to_owned(),
        "winner",
    )
    .expect("winner output");
    vault
        .put_code_run_replay_record_if_generation(&winner, Some(stale_generation))
        .expect("winner append");

    let mut stale = base;
    record_text_output(
        &ExecutorStorage::Canonical(&vault),
        &mut stale,
        "executor/repl/test-stale.txt".to_owned(),
        "stale",
    )
    .expect("stale output");
    let err = vault
        .put_code_run_replay_record_if_generation(&stale, Some(stale_generation))
        .expect_err("stale append rejected");

    assert!(matches!(err, Error::ConcurrentWrite(_)));
    let stored = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("load replay")
        .expect("stored replay");
    assert!(
        stored
            .outputs
            .iter()
            .any(|output| output.path == "executor/repl/test-winner.txt")
    );
    assert!(
        !stored
            .outputs
            .iter()
            .any(|output| output.path == "executor/repl/test-stale.txt")
    );
}

#[test]
fn executor_retains_identical_runtime_output_bytes_under_distinct_paths() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["const done = true;"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut outcome = JsCodeModeStepOutcome::complete("done");
    outcome.outputs = vec![
        JsCodeModeOutput::new("first.txt", b"same bytes".to_vec()),
        JsCodeModeOutput::new("second.txt", b"same bytes".to_vec()),
    ];
    let mut runtime = FixtureRuntime::new([outcome]);
    let gated_write = gated_actor_write(&vault, "run-duplicate-output");
    let config = executor_config(entity(0x86), EngineExecutorLimits::default());

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let outcome = block_on_ready(executor.run(&config)).expect("executor run");

    let runtime_outputs = outcome
        .replay_record
        .outputs
        .iter()
        .filter(|output| output.path.contains("/output/"))
        .collect::<Vec<_>>();
    assert_eq!(runtime_outputs.len(), 2);
    assert_ne!(runtime_outputs[0].path, runtime_outputs[1].path);
    assert_eq!(runtime_outputs[0].handle, runtime_outputs[1].handle);
    for output in runtime_outputs {
        let raw = vault
            .get_code_run_raw_output(output)
            .expect("load raw output")
            .expect("raw output bytes");
        assert_eq!(raw, b"same bytes");
    }
}

#[test]
fn extract_plain_js_accepts_only_raw_js_or_whole_response_js_fence() {
    assert_eq!(
        extract_plain_js(&llm_response("```javascript\nconst ok = true;\n```")).expect("js fence"),
        "const ok = true;"
    );
    assert_eq!(
        extract_plain_js(&llm_response("await self.ask_human('continue?');")).expect("raw js"),
        "await self.ask_human('continue?');"
    );

    assert!(
        extract_plain_js(&llm_response(
            "Here is the code:\n```js\nconst answer = 42;\n```"
        ))
        .is_err()
    );
    assert!(extract_plain_js(&llm_response("I will search memory first.")).is_err());
    assert!(extract_plain_js(&llm_response("I will search memory first;")).is_err());
    assert!(
        extract_plain_js(&llm_response(
            "```js\nconst first = true;\n```\n```js\nconst second = true;\n```"
        ))
        .is_err()
    );
    assert!(extract_plain_js(&llm_response("```js\nconst ok = true;\n```\nThat is all.")).is_err());
    assert!(
        extract_plain_js(&llm_response_with_finish(
            "const partial = true;",
            FinishReason::Length
        ))
        .is_err()
    );
}

#[test]
fn step_state_hash_frames_variable_length_boundaries() {
    let request_hash = [0x11; 32];
    let left = JsCodeModeStepOutcome {
        done: false,
        observation: "observed".to_owned(),
        outputs: vec![
            JsCodeModeOutput::new("a", b"bc".to_vec()),
            JsCodeModeOutput::new("def", Vec::new()),
        ],
    };
    let right = JsCodeModeStepOutcome {
        done: false,
        observation: "observed".to_owned(),
        outputs: vec![
            JsCodeModeOutput::new("ab", b"c".to_vec()),
            JsCodeModeOutput::new("de", b"f".to_vec()),
        ],
    };

    let left_hash =
        step_state_hash([0; 32], 7, &request_hash, "const x = 1;", &left, &[]).expect("left hash");
    let right_hash = step_state_hash([0; 32], 7, &request_hash, "const x = 1;", &right, &[])
        .expect("right hash");

    assert_ne!(left_hash, right_hash);
}

#[test]
fn step_state_hash_frames_bridge_call_values() {
    let request_hash = [0x22; 32];
    let outcome = JsCodeModeStepOutcome::pending("observed");
    let left = CodeRunBridgeCall {
        seq: 0,
        effect: SelfEffect::MemorySearch,
        request: Value::Map(vec![(Value::from("a"), Value::from("bc"))]),
        outcome: Value::Map(vec![(Value::from("result"), Value::from("ok"))]),
        started_at_ms: 0,
        finished_at_ms: 0,
    };
    let right = CodeRunBridgeCall {
        seq: 0,
        effect: SelfEffect::MemorySearch,
        request: Value::Map(vec![(Value::from("ab"), Value::from("c"))]),
        outcome: Value::Map(vec![(Value::from("result"), Value::from("ok"))]),
        started_at_ms: 0,
        finished_at_ms: 0,
    };

    let left_hash = step_state_hash([0; 32], 7, &request_hash, "const x = 1;", &outcome, &[left])
        .expect("left hash");
    let right_hash = step_state_hash(
        [0; 32],
        7,
        &request_hash,
        "const x = 1;",
        &outcome,
        &[right],
    )
    .expect("right hash");

    assert_ne!(left_hash, right_hash);
}

#[test]
fn executor_rejects_typescript_code_fence() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["```ts\nconst answer: number = 42;\n```"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
    let gated_write = gated_actor_write(&vault, "run-typescript-reject");
    let config = executor_config(entity(0x84), EngineExecutorLimits::default());

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let err = block_on_ready(executor.run(&config)).expect_err("typescript fence rejected");

    assert!(matches!(
        err,
        EngineExecutorError::Engine(Error::InvalidClaimBody(
            "executor LLM response used a non-JS code fence"
        ))
    ));
    assert!(runtime.seen.is_empty());
}

fn text_message(message: &LlmMessage) -> String {
    message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// ONE-1305: composes guest response JSON for every dispatched bridge call
/// and captures it, mirroring what a real runtime returns to the guest.
struct BudgetCapturingRuntime {
    calls: Vec<SelfCall>,
    captured: std::sync::Arc<Mutex<Vec<serde_json::Value>>>,
}

impl JsCodeModeRuntime for BudgetCapturingRuntime {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        for call in self.calls.drain(..) {
            let response = host.dispatch_self(call)?;
            let guest_json = response.guest_json(serde_json::json!({"ok": true}));
            self.captured
                .lock()
                .expect("captured lock")
                .push(guest_json);
        }
        Ok(JsCodeModeStepOutcome::complete("done"))
    }
}

#[test]
fn every_host_call_response_carries_budget() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["const a = 1;"]);
    let lease = BudgetLease::for_test("executor-lease");
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake-pass",
        10_000,
        100,
        crate::BudgetExhaustionPolicy::Suspend,
    );
    let deadline = crate::WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 30_000));
    let captured = std::sync::Arc::new(Mutex::new(Vec::new()));
    let mut runtime = BudgetCapturingRuntime {
        calls: vec![
            SelfCall::MemorySearch(crate::code_run::SelfMemorySearchCall::new("status", 3)),
            SelfCall::MemorySearch(crate::code_run::SelfMemorySearchCall::new("plans", 2)),
            SelfCall::AskHuman(SelfAskHumanCall::new("continue?")),
        ],
        captured: std::sync::Arc::clone(&captured),
    };
    let gated_write = gated_actor_write(&vault, "run-budget-envelope");
    let config = executor_config(entity(0x8B), EngineExecutorLimits::default());

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write)
            .with_legibility(ExecutorLegibility {
                guard: &guard,
                deadline: &deadline,
            });
    let outcome = block_on_ready(executor.run(&config)).expect("executor run");
    assert!(matches!(
        outcome.status,
        EngineExecutorStatus::Waiting(_) | EngineExecutorStatus::Complete
    ));

    let captured = captured.lock().expect("captured lock");
    assert_eq!(captured.len(), 3, "one response per bridge call");
    for response in captured.iter() {
        let budget = response
            .get(GUEST_BUDGET_RESPONSE_KEY)
            .unwrap_or_else(|| panic!("response missing budget key: {response}"));
        let object = budget.as_object().expect("budget must be a JSON object");
        for key in [
            "remaining_units",
            "limit_units",
            "remaining_ms",
            "wrap_up",
            "finalize_by_ms",
        ] {
            assert!(object.contains_key(key), "budget missing {key}: {budget}");
        }
        assert_eq!(object.len(), 5, "exactly the five pinned keys");
        assert_eq!(object["limit_units"], serde_json::json!(10_000));
        assert_eq!(object["remaining_ms"], serde_json::json!(150_000));
        assert_eq!(object["wrap_up"], serde_json::json!(false));
        assert_eq!(object["finalize_by_ms"], serde_json::Value::Null);
    }
}

/// ONE-1305 hardening: typed `Denied`/`Failed` ERROR outcomes return
/// through the same chokepoint as successes, so their guest responses carry
/// the budget envelope too — while the run still fails afterwards with the
/// original error.
struct DeniedCaptureRuntime {
    calls: Vec<SelfCall>,
    captured: std::sync::Arc<Mutex<Vec<serde_json::Value>>>,
}

impl JsCodeModeRuntime for DeniedCaptureRuntime {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        for call in self.calls.drain(..) {
            let response = host.dispatch_self(call)?;
            self.captured
                .lock()
                .expect("captured lock")
                .push(response.guest_json(serde_json::json!({"ok": true})));
        }
        Ok(JsCodeModeStepOutcome::complete("done"))
    }
}

#[test]
fn denied_and_halted_error_responses_carry_budget() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["await self.memory.put_edge(src, 'mentions', tgt);"]);
    let lease = BudgetLease::for_test("executor-lease");
    let src = seed_person(&vault, 0xC1);
    let tgt = seed_person(&vault, 0xC2);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake-pass",
        10_000,
        100,
        crate::BudgetExhaustionPolicy::Suspend,
    );
    let deadline = crate::WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 30_000));
    let captured = std::sync::Arc::new(Mutex::new(Vec::new()));
    let mut runtime = DeniedCaptureRuntime {
        calls: vec![
            // The pending gate DENIES this write: a typed Denied RESPONSE.
            SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                src,
                EdgeKind::Mentions,
                tgt,
                0.7,
            )),
            // After the hard failure the bridge halts fail-closed: a typed
            // Failed RESPONSE, no further gate dispatch.
            SelfCall::MemorySearch(crate::code_run::SelfMemorySearchCall::new("status", 3)),
        ],
        captured: std::sync::Arc::clone(&captured),
    };
    let gated_write = gated_actor_write(&vault, "run-denied-budget");
    let config = executor_config(entity(0x8F), EngineExecutorLimits::default());
    let before = gate_decision_count(&vault);

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write)
            .with_legibility(ExecutorLegibility {
                guard: &guard,
                deadline: &deadline,
            });
    let err = block_on_ready(executor.run(&config)).expect_err("denied write still fails the run");
    assert!(matches!(
        err,
        EngineExecutorError::Engine(Error::GateWriteRejected { .. })
    ));
    assert_eq!(
        gate_decision_count(&vault),
        before + 1,
        "the halted call after the failure never dispatches"
    );

    let captured = captured.lock().expect("captured lock");
    assert_eq!(captured.len(), 2, "denied AND halted responses returned");
    for response in captured.iter() {
        let budget = response
            .get(GUEST_BUDGET_RESPONSE_KEY)
            .unwrap_or_else(|| panic!("error response missing budget key: {response}"));
        assert!(budget.is_object(), "budget must be a JSON object");
    }

    let stored = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("load replay")
        .expect("stored replay");
    assert_eq!(stored.bridge_calls.len(), 2);
    assert_eq!(bridge_outcome_kind(&stored.bridge_calls[0]), "denied");
    assert_eq!(bridge_outcome_kind(&stored.bridge_calls[1]), "failed");
    assert_eq!(stored.step_checkpoints.len(), 1);
}

/// The executor's replay codec round-trips the delegation effect and the
/// peer-result reason, so a restart re-surfaces a suspended delegation exactly
/// as it re-surfaces a consent wait. The landed tokens are unchanged.
#[test]
fn executor_replay_round_trips_task_delegate_and_peer_result() {
    let wait = SelfDurableWait {
        wait_id: crate::test_util::entity(0x2C),
        effect: SelfEffect::TaskDelegate,
        reason: SelfDurableWaitReason::PeerResult,
        prompt: None,
    };

    let stored = StoredDurableWait::from_wait(&wait);
    let restored = stored.clone().into_wait().expect("stored wait round-trips");

    assert_eq!(stored.effect, "self.tasks.delegate");
    assert_eq!(stored.reason, "peer_result");
    assert_eq!(restored, wait);
    assert_eq!(
        durable_wait_reason_str(SelfDurableWaitReason::OutboundEffect),
        "outbound_effect"
    );
    assert_eq!(
        usize::from(durable_wait_reason_from_str("peer_result_v2").is_err()),
        1
    );
    assert_eq!(
        usize::from(self_effect_from_str("self.tasks.delegate").is_ok()),
        1
    );
}

// ── ONE-1686 RT-04: the self.speak effect family ────────────────────────────

fn speech_bridge_orders(record: &CodeRunReplayRecord) -> Vec<(u64, &'static str, u32, bool, bool)> {
    record
        .bridge_calls
        .iter()
        .filter(|call| call.effect.is_speech())
        .map(|call| {
            let Value::Map(entries) = &call.outcome else {
                panic!("bridge outcome must be a map");
            };
            let field = |needle: &str| {
                entries
                    .iter()
                    .find_map(|(key, value)| (key.as_str() == Some(needle)).then_some(value))
                    .unwrap_or_else(|| panic!("speech outcome carries {needle}"))
            };
            (
                call.seq,
                call.effect.as_str(),
                u32::try_from(field("order").as_u64().expect("order is an integer"))
                    .expect("order fits u32"),
                field("is_visible").as_bool().expect("is_visible is a bool"),
                field("emitted").as_bool().expect("emitted is a bool"),
            )
        })
        .collect()
}

/// 0..N speech calls in ONE step, interleaved with a read and a gated write,
/// keep the bridge's exact ordering: nothing is buffered for a final response,
/// and every bubble carries the family's own message type, visibility, and the
/// call's own monotonically increasing order.
#[test]
fn executor_interleaves_speech_reads_and_gated_writes_in_bridge_order() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["await self.speak('one');"]);
    let lease = BudgetLease::for_test("executor-lease");
    let subject = seed_person(&vault, 0xC1);
    let calls = vec![
        SelfCall::Speak(SelfSpeechCall::new("first, out loud")),
        SelfCall::MemorySearch(crate::code_run::SelfMemorySearchCall::new("status", 3)),
        SelfCall::Think(SelfSpeechCall::new("second, privately")),
        SelfCall::MemoryWriteFixture(SelfMemoryWriteFixtureCall::new(
            entity(0xC2),
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(subject),
                Value::from("matcha"),
                0.8,
            ),
            range(3),
            4,
        )),
        SelfCall::Express(SelfSpeechCall::new("third, non-verbally")),
    ];
    let mut runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]).with_calls([calls]);
    let gated_write = gated_actor_write(&vault, "run-speech-interleave");
    let config = executor_config(entity(0xC0), EngineExecutorLimits::default());

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let outcome = block_on_ready(executor.run(&config)).expect("executor run");

    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    let record = &outcome.replay_record;
    // Exact bridge ordering: speech is dispatched where it was called, not
    // collected into a trailing response.
    assert_eq!(
        record
            .bridge_calls
            .iter()
            .map(|call| (call.seq, call.effect.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (0, "self.speak"),
            (1, "self.memory.search"),
            (2, "self.think"),
            (3, "self.memory.write_fixture"),
            (4, "self.express"),
        ]
    );
    // One bubble per call, each carrying its own bridge order and the
    // family's visibility. `emitted` is TRUE on a canonical run too
    // (ONE-1686): a speech effect materializes its MESSAGE or it fails.
    assert_eq!(
        speech_bridge_orders(record),
        vec![
            (0, "self.speak", 0, true, true),
            (2, "self.think", 2, false, true),
            (4, "self.express", 4, true, true),
        ]
    );
    assert_eq!(
        record
            .bridge_calls
            .iter()
            .filter(|call| call.emitted_speech())
            .count(),
        3,
        "all three explicit speech calls emitted"
    );
    // And the bubbles are REAL rows, in the run-scoped shell, complete: the
    // family's message type, the family's visibility, the call's text, the
    // bridge order. The trailing observation ("done") is distinct from all
    // three, so it is preserved as the implicit closing speak at order 5.
    assert_eq!(
        executor_bubbles(&vault, entity(0xA0)),
        vec![
            (
                "executor.speak".to_owned(),
                "first, out loud".to_owned(),
                true,
                0
            ),
            (
                "executor.think".to_owned(),
                "second, privately".to_owned(),
                false,
                2
            ),
            (
                "executor.express".to_owned(),
                "third, non-verbally".to_owned(),
                true,
                4
            ),
            ("executor.speak".to_owned(), "done".to_owned(), true, 5),
        ]
    );
    // All four ride ONE run-scoped conversation and ONE turn, both derived
    // from the run ref — not a fresh shell per utterance.
    let conversation =
        crate::code_run::canonical_speech_conversation_id("run-speech-interleave").expect("shell");
    assert_eq!(
        vault.get_entity_type(&conversation).expect("shell type"),
        Some(crate::registry::ENTITY_TYPE_CONVERSATION)
    );
    assert_eq!(
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_TURN)
            .expect("turn rows")
            .len(),
        1,
        "one canonical run speaks in one turn"
    );
    // The unrelated effects are byte-identical to what they encode without the
    // speech family present.
    assert_eq!(
        bridge_outcome_kind(&record.bridge_calls[1]),
        "memory_search"
    );
    assert_eq!(bridge_outcome_kind(&record.bridge_calls[3]), "memory_write");
    assert_eq!(record.step_checkpoints.len(), 1);
}

/// Speech obeys the existing fail-closed barrier: a call after a durable wait
/// is refused, emits no bubble, and is still REPLAY-VISIBLE as the wait row
/// the barrier records for every other effect.
#[test]
fn speech_after_a_durable_wait_stays_behind_the_fail_closed_barrier() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["await self.ask_human('continue?');"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::pending("waiting")]).with_calls([vec![
            SelfCall::Speak(SelfSpeechCall::new("before the wait")),
            SelfCall::AskHuman(SelfAskHumanCall::new("continue?")),
            SelfCall::Speak(SelfSpeechCall::new("after the wait")),
            SelfCall::Think(SelfSpeechCall::new("also after the wait")),
        ]]);
    let gated_write = gated_actor_write(&vault, "run-speech-barrier");
    let config = executor_config(entity(0xC3), EngineExecutorLimits::default());

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let outcome = block_on_ready(executor.run(&config)).expect("executor run");

    assert!(matches!(outcome.status, EngineExecutorStatus::Waiting(_)));
    let record = &outcome.replay_record;
    assert_eq!(
        record
            .bridge_calls
            .iter()
            .map(|call| (call.effect.as_str(), bridge_outcome_kind(call)))
            .collect::<Vec<_>>(),
        vec![
            ("self.speak", "speech"),
            ("self.ask_human", "durable_wait"),
            ("self.speak", "durable_wait"),
            ("self.think", "durable_wait"),
        ],
        "post-wait speech is parked by the barrier, and stays in the log"
    );
    assert_eq!(
        record
            .bridge_calls
            .iter()
            .filter(|call| call.emitted_speech())
            .count(),
        1,
        "only the pre-wait call emitted a bubble"
    );
}

/// A hard bridge failure halts speech exactly as it halts a write trap: the
/// guest sees a typed `Failed` response, the row is replay-visible, and no
/// bubble is emitted for it.
#[test]
fn speech_after_a_hard_failure_is_refused_fail_closed() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["await self.memory.put_edge();"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]).with_calls([vec![
            // A structural edge kind the trap refuses, which arms the barrier.
            SelfCall::MemoryPutEdge(SelfMemoryPutEdgeCall::new(
                entity(0xC5),
                EdgeKind::SameAs,
                entity(0xC6),
                1.0,
            )),
            SelfCall::Speak(SelfSpeechCall::new("never spoken")),
        ]]);
    let gated_write = gated_actor_write(&vault, "run-speech-halt");
    let config = executor_config(entity(0xC4), EngineExecutorLimits::default());

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let error = block_on_ready(executor.run(&config)).expect_err("step fails after the bridge");
    assert!(matches!(
        error,
        EngineExecutorError::Engine(Error::InvalidClaimBody(_))
    ));

    let stored = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("load replay")
        .expect("stored replay");
    assert_eq!(
        stored
            .bridge_calls
            .iter()
            .map(|call| (call.effect.as_str(), bridge_outcome_kind(call)))
            .collect::<Vec<_>>(),
        vec![("self.memory.put_edge", "failed"), ("self.speak", "failed"),]
    );
    assert_eq!(
        stored
            .bridge_calls
            .iter()
            .filter(|call| call.emitted_speech())
            .count(),
        0,
        "a barrier-refused speech row must not count as speech that happened"
    );
}

/// The speech family reaches the guest as advertised host verbs on the same
/// first-party boundary every other `self.*` effect is linked on.
#[test]
fn executor_boundary_and_prompt_advertise_the_speech_family() {
    let boundary = executor_boundary_contract().expect("boundary");
    let names = boundary
        .linked_imports()
        .iter()
        .map(|import| import.name())
        .collect::<Vec<_>>();
    for verb in ["self.speak", "self.think", "self.express"] {
        assert!(names.contains(&verb), "boundary must link {verb}");
        assert!(
            EXECUTOR_REQUIRED_HOST_IMPORTS.contains(&verb),
            "the executor must require {verb}"
        );
    }
    let prompt = executor_system_prompt();
    for advertised in ["function speak", "function think", "function express"] {
        assert!(prompt.contains(advertised));
    }
}

/// The session-bound half, where a bubble is actually materialized.
///
/// The room is flipped ON RECORD first, so the run's captured route is `Base`
/// and the MESSAGEs it writes are readable through the ordinary facade — the
/// same rows an off-record run would put in its overlay, through the same
/// door. Returns every executor MESSAGE the run left, in `order`.
fn executor_bubbles(vault: &Vault, actor: EntityId) -> Vec<(String, String, bool, u64)> {
    let facade = vault.memory(actor, EdgeActorClass::Agent);
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let mut ids = Vec::new();
    for row in vault
        .store
        .type_index
        .prefix_iter(&rtxn, &[crate::registry::ENTITY_TYPE_MESSAGE])
        .expect("message type index")
    {
        let (key, _) = row.expect("type index row");
        ids.push(
            EntityId::from_bytes(key[key.len() - 16..].try_into().expect("type index id"))
                .expect("message id"),
        );
    }
    drop(rtxn);

    let mut bubbles = ids
        .into_iter()
        .map(|id| {
            let view = facade
                .get_entity(&id.to_hex())
                .expect("get message")
                .expect("message exists");
            let body = view.body.expect("message body decodes");
            (
                body["type"].as_str().expect("message type").to_owned(),
                body["content"].as_str().unwrap_or_default().to_owned(),
                body["is_visible"].as_bool().expect("is_visible"),
                body["order"].as_u64().expect("order"),
            )
        })
        .collect::<Vec<_>>();
    bubbles.sort_by_key(|bubble| bubble.3);
    bubbles
}

fn session_speech_run(
    vault: &Vault,
    session_ref: &str,
    run_seed: u8,
    observation: &str,
    calls: Vec<SelfCall>,
) -> EntityId {
    use crate::off_record::OffRecordBackendClass;

    vault
        .enter_off_record_session(session_ref, OffRecordBackendClass::Local)
        .expect("enter session");
    let sessions = vault.off_record_session_vault();
    let session = sessions.bind(session_ref).expect("bind session");
    // On record, so the bubbles land in base where an ordinary reader sees
    // them. The route, shell and door are the session's either way.
    session.flip_on_record().expect("flip on record");

    let actor = seed_person(vault, run_seed);
    let gated_write = GatedActorWrite::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-session-speech",
    )
    .expect("session dispatcher");
    let backend = FixtureBackend::new(["await self.speak('hi');"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::complete(observation)]).with_calls([calls]);
    let config = executor_config(entity(run_seed ^ 0x0F), EngineExecutorLimits::default());
    {
        let mut executor = EngineNativeExecutor::for_off_record_session(
            &session,
            &backend,
            &lease,
            &mut runtime,
            &gated_write,
        )
        .expect("session executor");
        let outcome = block_on_ready(executor.run(&config)).expect("executor run");
        assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    }
    drop(gated_write);
    session.close().expect("close session");
    actor
}

/// Explicit speech on the bound session route: one durable MESSAGE per call,
/// authored by Companion, carrying the family's message type, the family's
/// visibility, the call's text, and the call's bridge order — plus the run's
/// DISTINCT trailing plaintext, which nobody has said yet (ONE-1686).
///
/// The suppression rule is about the TEXT, not about whether the run spoke at
/// all: dropping a distinct last word because an earlier, different bubble
/// exists loses the answer the run finished with.
#[test]
fn session_speech_keeps_distinct_trailing_plaintext_beside_explicit_bubbles() {
    let (_dir, vault) = open_test_vault();
    let actor = session_speech_run(
        &vault,
        "sess-speech",
        0xD1,
        "and here is the distinct last word",
        vec![
            SelfCall::Speak(SelfSpeechCall::new("out loud")),
            SelfCall::MemorySearch(crate::code_run::SelfMemorySearchCall::new("status", 2)),
            SelfCall::Think(SelfSpeechCall::new("to myself")),
            SelfCall::Express(SelfSpeechCall::new("*nods*")),
        ],
    );

    assert_eq!(
        executor_bubbles(&vault, actor),
        vec![
            ("executor.speak".to_owned(), "out loud".to_owned(), true, 0),
            (
                "executor.think".to_owned(),
                "to myself".to_owned(),
                false,
                2
            ),
            ("executor.express".to_owned(), "*nods*".to_owned(), true, 3),
            (
                "executor.speak".to_owned(),
                "and here is the distinct last word".to_owned(),
                true,
                4
            ),
        ],
        "one bubble per speech call, in bridge order, with per-family \
         visibility — and the distinct trailing plaintext preserved after them"
    );
}

/// The other half of the same rule: trailing plaintext that an explicit
/// emitted bubble ALREADY carries is suppressed, so the run says it once.
///
/// Only an EMITTED row suppresses. The comparison is on trimmed text, because
/// the fallback trims before it speaks — otherwise a trailing newline would
/// make the duplicate look distinct.
#[test]
fn session_speech_suppresses_trailing_plaintext_an_explicit_bubble_already_said() {
    let (_dir, vault) = open_test_vault();
    let actor = session_speech_run(
        &vault,
        "sess-speech-dup",
        0xD5,
        "  the one and only answer\n",
        vec![
            SelfCall::Speak(SelfSpeechCall::new("the one and only answer")),
            SelfCall::MemorySearch(crate::code_run::SelfMemorySearchCall::new("status", 2)),
        ],
    );

    assert_eq!(
        executor_bubbles(&vault, actor),
        vec![(
            "executor.speak".to_owned(),
            "the one and only answer".to_owned(),
            true,
            0
        )],
        "text an explicit bubble already carries is not repeated as a fallback"
    );
}

/// Explicit speech is CANONICAL, so the trailing plaintext fallback only fires
/// for a run that never spoke — and then exactly once, through the same door.
#[test]
fn silent_run_falls_back_to_one_trailing_plaintext_bubble() {
    let (_dir, vault) = open_test_vault();
    let actor = session_speech_run(
        &vault,
        "sess-silent",
        0xD2,
        "the answer is 42",
        vec![SelfCall::MemorySearch(
            crate::code_run::SelfMemorySearchCall::new("status", 2),
        )],
    );

    assert_eq!(
        executor_bubbles(&vault, actor),
        vec![(
            "executor.speak".to_owned(),
            "the answer is 42".to_owned(),
            true,
            1
        )],
        "a run that never called a speech verb still says its last word, once"
    );
}

/// A companion-authored bubble is the run's own: the witness door stamps the
/// dispatcher's bound actor, never a guest-named author.
#[test]
fn session_speech_bubbles_are_authored_by_companion() {
    let (_dir, vault) = open_test_vault();
    let actor = session_speech_run(
        &vault,
        "sess-author",
        0xD3,
        "",
        vec![SelfCall::Speak(SelfSpeechCall::new("mine to say"))],
    );

    let facade = vault.memory(actor, EdgeActorClass::Agent);
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let mut ids = Vec::new();
    for row in vault
        .store
        .type_index
        .prefix_iter(&rtxn, &[crate::registry::ENTITY_TYPE_MESSAGE])
        .expect("message type index")
    {
        let (key, _) = row.expect("type index row");
        ids.push(
            EntityId::from_bytes(key[key.len() - 16..].try_into().expect("type index id"))
                .expect("message id"),
        );
    }
    drop(rtxn);
    assert_eq!(ids.len(), 1, "one speech call, one bubble");

    let view = facade
        .get_entity(&ids[0].to_hex())
        .expect("get message")
        .expect("message exists");
    let body = view.body.expect("message body decodes");
    assert_eq!(body["author"], serde_json::json!("companion"));
    assert_eq!(body["type"], serde_json::json!("executor.speak"));
    assert_eq!(body["content"], serde_json::json!("mine to say"));
    assert_eq!(body["is_visible"], serde_json::json!(true));
}
