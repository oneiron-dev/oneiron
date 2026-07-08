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
    FatalLlmError, FinishReason, HnswConfig, LlmGenerateFuture, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, SelfAskHumanCall, SelfDurableWaitReason, SelfEffect, SelfMemoryPutClaimCall,
    SelfMemoryPutEdgeCall, SelfMemoryWriteFixtureCall, TimeRange, VaultConfig, WriteActor,
    registry::ENTITY_TYPE_PERSON,
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

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test-model-v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config
}

fn open_test_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), test_config()).expect("open vault");
    (dir, vault)
}

fn entity(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("entity id")
}

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
        load_utf8_output(&vault, &stored, &observation_output_path(0))
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
        load_utf8_output(&vault, &stored, &observation_output_path(0))
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
        load_utf8_output(&vault, &stored, &observation_output_path(0))
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
        &vault,
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
        &vault,
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
