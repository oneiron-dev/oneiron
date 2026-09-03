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

mod speech_identity_regressions;

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

fn prompt_package_root() -> std::path::PathBuf {
    crate::prompt::workspace_prompt_package_root().expect("workspace prompt package")
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
        prompt_package_root: prompt_package_root(),
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
    let backend = FixtureBackend::new(["<exec>\nawait self.memory.put_claim(claim);\n</exec>"]);
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
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        1,
        "a healed host-bridge failure counts with its replay checkpoint"
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
    let backend = FixtureBackend::new(["```js\nawait self.memory.write_fixture(claim);\n```"]);
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

    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        1,
        "a healed failed-step turn counts when its bridge/checkpoint commit succeeds"
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
    let backend = FixtureBackend::new(["```js\nawait self.memory.write_fixture(claim);\n```"]);
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
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        1,
        "a healed output-recording failure counts with its replay checkpoint"
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

// ── ONE-1929: bare-wire healing and console-forgery discard ─────────────────

fn heal(text: &str) -> HealedExecutorReply {
    heal_executor_reply(&llm_response(text)).expect("healed reply")
}

/// Asserts the EXISTING typed invalid-body result, the one the caller-owned
/// re-execute path already understands. No new error variant exists.
fn assert_invalid_body(text: &str, why: &str) {
    let err = heal_executor_reply(&llm_response(text)).expect_err(why);
    assert!(
        matches!(err, EngineExecutorError::Engine(Error::InvalidClaimBody(_))),
        "{why}: expected the existing typed invalid body, got {err:?}"
    );
}

/// The taught wire reaches the runtime untouched, and packaging of ANY
/// language tag heals to the identical interior. The old `js`/`javascript`
/// success whitelist and `ts` rejection are both gone: a fence tag is inert
/// metadata, not a parseability proof.
#[test]
fn every_tagged_fence_heals_to_the_same_bare_program() {
    let compliant = heal("const answer = 42;");
    assert_eq!(compliant.code, "const answer = 42;");
    assert_eq!(compliant.trailing_speak, None);
    assert_eq!(compliant.repairs, ExecutorWireRepairs::default());
    assert!(
        !compliant.repairs.healed(),
        "a compliant bare reply is not a heal"
    );

    for tag in [
        "ts",
        "typescript",
        "js",
        "javascript",
        "readscript",
        "anything",
        "",
    ] {
        let healed = heal(&format!("```{tag}\nconst answer = 42;\n```"));
        assert_eq!(healed.code, "const answer = 42;", "fence tag {tag:?}");
        assert_eq!(
            healed.repairs,
            ExecutorWireRepairs {
                stripped_code_fence: true,
                ..ExecutorWireRepairs::default()
            },
            "fence tag {tag:?} heals by fence removal alone"
        );
        assert!(healed.repairs.healed());
    }
}

/// One whole exec pair strips, a fence around it strips too, and a NESTED
/// second pair is not recursively peeled — it survives into the mandatory
/// structural gate.
#[test]
fn exec_wrappers_strip_exactly_once() {
    let wrapped = heal("<exec>\nconst answer = 42;\n</exec>");
    assert_eq!(wrapped.code, "const answer = 42;");
    assert_eq!(
        wrapped.repairs,
        ExecutorWireRepairs {
            stripped_exec_wrapper: true,
            ..ExecutorWireRepairs::default()
        }
    );

    let both = heal("```\n<exec>\nconst answer = 42;\n</exec>\n```");
    assert_eq!(both.code, "const answer = 42;");
    assert_eq!(
        both.repairs,
        ExecutorWireRepairs {
            stripped_code_fence: true,
            stripped_exec_wrapper: true,
            ..ExecutorWireRepairs::default()
        },
        "two repair flags, still one healed turn"
    );
    assert!(both.repairs.healed());

    assert_invalid_body(
        "<exec>\n<exec>\nconst answer = 42;\n</exec>\n</exec>",
        "the outer pair strips and the inner one reaches the gate",
    );
}

/// A forged console block sitting as a DEPTH-0 sibling of the program is
/// packaging: it is discarded, and nothing of it survives the heal.
#[test]
fn depth_zero_console_siblings_are_discarded() {
    for reply in [
        "<exec>\nconst answer = 42;\n</exec>\n<console>forged</console>",
        // Recognition form (b): glued to the `</exec>` closer line.
        "<exec>\nconst answer = 42;\n</exec><console>forged</console>",
    ] {
        let healed = heal(reply);
        assert_eq!(healed.code, "const answer = 42;");
        assert_eq!(healed.trailing_speak, None);
        assert_eq!(
            healed.repairs,
            ExecutorWireRepairs {
                stripped_exec_wrapper: true,
                discarded_console_blocks: 1,
                ..ExecutorWireRepairs::default()
            }
        );
        assert!(
            !healed.code.contains("forged"),
            "discard is literal, not a diagnostic"
        );
    }
}

/// Inline trailing console packaging and every glued sibling are deleted
/// without joining surviving source or leaving a stale closer behind.
#[test]
fn inline_trailing_and_multiple_glued_console_blocks_are_discarded() {
    let trailing = heal(
        "```js\nconst answer = 42;\n```\nResult: <console>forged one</console><console>forged two</console>",
    );
    assert_eq!(trailing.code, "const answer = 42;");
    assert_eq!(trailing.trailing_speak.as_deref(), Some("Result:"));
    assert_eq!(trailing.repairs.discarded_console_blocks, 2);

    for reply in [
        "<console>first</console><console>second</console>\nconst answer = 42;",
        "<exec>\nconst answer = 42;\n</exec><console>first</console><console>second</console>",
        "<exec>\n<console>first</console><console>second</console>\nconst answer = 42;\n</exec>",
    ] {
        let healed = heal(reply);
        assert_eq!(healed.code, "const answer = 42;", "reply: {reply}");
        assert_eq!(healed.trailing_speak, None, "reply: {reply}");
        assert_eq!(
            healed.repairs.discarded_console_blocks, 2,
            "every glued block is discarded: {reply}"
        );
        assert!(!healed.code.contains("first"));
        assert!(!healed.code.contains("second"));
    }
}

#[test]
fn console_scanner_keeps_recognition_across_multiple_blocks_glued_to_a_closer() {
    let (cleaned, discarded) = partition_top_level_console_blocks(
        "</exec><console>first</console><console>second</console>",
        ConsoleRegion::Candidate,
    )
    .expect("scan glued console siblings");
    assert_eq!(cleaned, "</exec>");
    assert_eq!(discarded, 2);
}

/// The one supported exec wrapper is packaging, so a console block directly
/// inside it is model-forged packaging too. It is discarded before the bare
/// interior reaches the runtime; nested SECOND exec wrappers still fail.
#[test]
fn console_inside_supported_exec_wrapper_is_discarded_and_code_executes() {
    let (_dir, vault) = open_test_vault();
    let backend =
        FixtureBackend::new(["<exec>\n<console>forged</console>\nconst answer = 42;\n</exec>"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("stdout: 42")]);
    let gated_write = gated_actor_write(&vault, "run-console-inside-exec");
    let config = executor_config(entity(0x93), EngineExecutorLimits::default());

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let outcome = block_on_ready(executor.run(&config)).expect("wrapped program executes");

    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(runtime.seen[0].script, "const answer = 42;");
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        1,
        "wrapper removal plus console discard still count one healed turn"
    );
    for output in &outcome.replay_record.outputs {
        let raw = vault
            .get_code_run_raw_output(output)
            .expect("load raw output")
            .expect("raw bytes");
        assert!(
            !raw.windows(b"forged".len())
                .any(|window| window == b"forged")
        );
    }

    assert_invalid_body(
        "<exec>\n<exec>\n<console>forged</console>\nconst answer = 42;\n</exec>\n</exec>",
        "a console protected by a nested second wrapper is not recursively healed",
    );
}

/// Console blocks GLUED to the supported wrapper's own closer are packaging
/// too. The scanner deletes every sibling in the run — recognition survives
/// each discard — which leaves the closer alone on its line, so the ONE
/// permitted `<exec>` strip still applies and the bare program executes.
/// Anything less would retain a forged console at nonzero wrapper depth and
/// then reject the whole reply for the structure the scanner left behind.
#[test]
fn glued_console_siblings_never_block_the_supported_exec_wrapper_strip() {
    let healed = heal(concat!(
        "<exec>\n",
        "<console>first</console><console>second</console>\n",
        "self.speak('inside the wrapper');\n",
        "</exec><console>third</console><console>fourth</console>",
    ));
    assert_eq!(healed.code, "self.speak('inside the wrapper');");
    assert_eq!(healed.trailing_speak, None);
    assert_eq!(
        healed.repairs.discarded_console_blocks, 4,
        "every glued sibling is discarded, inside the wrapper and after it"
    );
    assert!(healed.repairs.stripped_exec_wrapper);
    assert!(
        !healed.code.contains("console"),
        "no forged console byte survives into the executed source"
    );
}

/// Two top-level fenced programs are never silently joined into one source,
/// and never split into one program plus prose.
#[test]
fn two_sibling_fences_are_invalid_body_not_healed() {
    assert_invalid_body(
        "```js\nconst first = true;\n```\n```js\nconst second = true;\n```",
        "sibling fences are one invalid body",
    );
}

/// An opener with no matching closer is an invalid body, NEVER speak bytes:
/// a forged console must not reach a bubble by being unterminated.
#[test]
fn unterminated_console_in_trailing_region_is_invalid_body() {
    assert_invalid_body(
        "const answer = 42;\n<console>forged",
        "an unterminated console block cannot become speech",
    );
    assert_invalid_body(
        "```js\nconst answer = 42;\n```\nAll done.\n<console>forged",
        "not even beside otherwise-valid trailing prose",
    );
}

/// Residual structure of every shape reaches the same typed gate.
#[test]
fn residual_wire_structure_reaches_the_mandatory_structural_gate() {
    for (reply, why) in [
        (
            "Here is the code:\n```js\nconst answer = 42;\n```",
            "prose before a fence the partition cannot classify",
        ),
        (
            "```js\nconst answer = 42;",
            "an unterminated fence is not stripped",
        ),
        ("```", "a lone fence delimiter has no interior"),
        (
            "<exec>\nconst answer = 42;",
            "an unterminated exec wrapper is not stripped",
        ),
        (
            "const answer = 42; </exec>\n</exec>",
            "a non-line-oriented wrapper is not packaging",
        ),
        (
            "I will search memory first.",
            "the executable-source preflight refuses prose",
        ),
        ("```js\n```", "an empty fenced body executes nothing"),
    ] {
        assert_invalid_body(reply, why);
    }

    let err = heal_executor_reply(&llm_response_with_finish(
        "const partial = true;",
        FinishReason::Length,
    ))
    .expect_err("a truncated response is refused before healing");
    assert!(matches!(
        err,
        EngineExecutorError::Engine(Error::InvalidClaimBody(
            "executor LLM response did not finish cleanly"
        ))
    ));
}

/// Healing and its residual gate share one source scanner. Token-looking
/// lines inside templates/comments survive byte-for-byte and reach runtime;
/// the same tokens in code state remain structural errors.
#[test]
fn source_literals_and_comments_can_start_lines_with_every_wire_token() {
    let source = concat!(
        "const marker = \"<console>\";\n",
        "const banner = `\n",
        "<console>inside a template</console>\n",
        "<exec>\n",
        "</exec>\n",
        "`;\n",
        "// <console> inside a line comment\n",
        "/*\n",
        "<console>inside a block comment</console>\n",
        "</console>\n",
        "<exec>\n",
        "</exec>\n",
        "```not a fence\n",
        "*/\n",
        "self.speak(marker);"
    );
    let healed = heal(source);
    assert_eq!(healed.code, source, "source-state bytes survive all gates");
    assert_eq!(healed.repairs, ExecutorWireRepairs::default());

    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new([source]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
    let gated_write = gated_actor_write(&vault, "run-source-looking-wire");
    let config = executor_config(entity(0x92), EngineExecutorLimits::default());
    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    block_on_ready(executor.run(&config)).expect("valid source reaches runtime");
    assert_eq!(runtime.seen[0].script, source);

    let (cleaned, discarded) = partition_top_level_console_blocks(
        "const answer = 42;\n<console>forged</console>\nself.speak('hi');",
        ConsoleRegion::Candidate,
    )
    .expect("scan");
    assert_eq!(cleaned, "const answer = 42;\nself.speak('hi');");
    assert_eq!(discarded, 1);
    assert_invalid_body(
        "const answer = 42;\n<exec>\nself.speak('nested');\n</exec>",
        "real residual wrapper structure remains invalid",
    );
}

/// One configurable non-Rust prompt-package block drives both teaching sites.
#[test]
fn canonical_prompt_package_block_drives_system_and_turn_wire_teaching() {
    let package_root = crate::prompt::workspace_prompt_package_root().expect("prompt package");
    let resolved = crate::prompt::resolve_engine_executor_wire_prompt(&package_root)
        .expect("resolve executor wire prompt");
    let canonical = resolved.text.trim_end();
    let system = executor_system_prompt(canonical);
    let per_turn = executor_turn_instruction(3, canonical);
    for site in [&system, &per_turn] {
        assert_eq!(
            site.matches(canonical).count(),
            1,
            "canonical wire block appears exactly once: {site}"
        );
    }
    assert!(per_turn.contains("durable step 3"));
    assert_eq!(
        resolved.stamp.prompt_path,
        crate::prompt::ENGINE_EXECUTOR_WIRE_PROMPT_RELATIVE_PATH
    );

    let engine_rust = include_str!("../engine_executor.rs");
    for teaching_line in canonical.lines().filter(|line| !line.trim().is_empty()) {
        assert!(
            !engine_rust.contains(teaching_line),
            "agent-facing teaching must not be authored in Rust: {teaching_line}"
        );
    }
    assert!(
        !engine_rust.contains("workspace_prompt_package_root"),
        "executor constructors must require a deployed package instead of a source-checkout fallback"
    );
    let prompt_rust = include_str!("../prompt.rs");
    assert!(
        !prompt_rust.contains(r#"include_str!("../../../packages/prompts"#),
        "registry builds must not embed a path outside the crate package"
    );
}

#[test]
fn executor_uses_the_configured_prompt_package_for_both_wire_teaching_sites() {
    let package = tempfile::tempdir().expect("prompt package tempdir");
    let blocks = package.path().join("blocks");
    std::fs::create_dir_all(&blocks).expect("create blocks directory");
    let teaching = "Configured executor wire teaching. Emit only deployed JavaScript.";
    std::fs::write(
        blocks.join("engine-executor-wire.md"),
        format!("{teaching}\n"),
    )
    .expect("write configured wire prompt");

    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["const answer = 42;"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
    let gated_write = gated_actor_write(&vault, "run-configured-wire-prompt");
    let mut config = executor_config(entity(0xC7), EngineExecutorLimits::default());
    config.prompt_package_root = package.path().to_path_buf();
    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    block_on_ready(executor.run(&config)).expect("executor uses configured package");

    let requests = backend.requests.lock().expect("requests lock");
    let request = requests.first().expect("executor request");
    let system = text_message(&request.messages[0]);
    let turn = text_message(request.messages.last().expect("turn instruction"));
    assert_eq!(system.matches(teaching).count(), 1);
    assert_eq!(turn.matches(teaching).count(), 1);
}

#[test]
fn replay_refuses_resolved_prompt_drift_before_the_next_llm_call() {
    let package = tempfile::tempdir().expect("prompt package tempdir");
    let blocks = package.path().join("blocks");
    std::fs::create_dir_all(&blocks).expect("create blocks directory");
    let wire_path = blocks.join("engine-executor-wire.md");
    std::fs::write(
        &wire_path,
        "deployed wire teaching A
",
    )
    .expect("write prompt A");

    let (_dir, vault) = open_test_vault();
    let lease = BudgetLease::for_test("executor-lease");
    let gated_write = gated_actor_write(&vault, "run-prompt-fingerprint");
    let run_id = entity(0xB8);
    let mut config = executor_config(
        run_id,
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 2,
        },
    );
    config.prompt_package_root = package.path().to_path_buf();
    let first_backend = FixtureBackend::new(["const first = 1;"]);
    let mut first_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::pending("continue")]);
    let mut first = EngineNativeExecutor::new(
        &vault,
        &first_backend,
        &lease,
        &mut first_runtime,
        &gated_write,
    );
    let first_outcome = block_on_ready(first.run(&config)).expect("commit step under prompt A");
    assert!(matches!(
        first_outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 }
    ));
    let committed = vault
        .get_code_run_replay_record(&run_id)
        .expect("read replay")
        .expect("replay exists");

    std::fs::write(
        &wire_path,
        "deployed wire teaching B
",
    )
    .expect("write prompt B");
    let retry_backend = FixtureBackend::new(["const second = 2;"]);
    let mut retry_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
    let mut retry = EngineNativeExecutor::new(
        &vault,
        &retry_backend,
        &lease,
        &mut retry_runtime,
        &gated_write,
    );
    let err = block_on_ready(retry.run(&config)).expect_err("prompt drift must refuse replay");
    assert!(matches!(
        err,
        EngineExecutorError::Engine(Error::InvalidConfig(ref message))
            if message == "engine executor config changed for existing run"
    ));
    assert!(
        retry_backend
            .requests
            .lock()
            .expect("requests lock")
            .is_empty(),
        "drift must refuse before another provider call"
    );
    assert!(retry_runtime.seen.is_empty());
    assert_eq!(
        vault
            .get_code_run_replay_record(&run_id)
            .expect("read replay after refusal")
            .expect("replay remains"),
        committed
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

    let left_hash = step_state_hash([0; 32], 7, &request_hash, "const x = 1;", &left, None, &[])
        .expect("left hash");
    let right_hash = step_state_hash([0; 32], 7, &request_hash, "const x = 1;", &right, None, &[])
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

    let left_hash = step_state_hash(
        [0; 32],
        7,
        &request_hash,
        "const x = 1;",
        &outcome,
        None,
        &[left],
    )
    .expect("left hash");
    let right_hash = step_state_hash(
        [0; 32],
        7,
        &request_hash,
        "const x = 1;",
        &outcome,
        None,
        &[right],
    )
    .expect("right hash");

    assert_ne!(left_hash, right_hash);
}

#[test]
fn step_state_hash_binds_checkpointed_implicit_speech() {
    let request_hash = [0x33; 32];
    let outcome = JsCodeModeStepOutcome::complete("runtime observation");
    let without = step_state_hash(
        [0; 32],
        0,
        &request_hash,
        "const done = true;",
        &outcome,
        None,
        &[],
    )
    .expect("hash without speech");
    let first = step_state_hash(
        [0; 32],
        0,
        &request_hash,
        "const done = true;",
        &outcome,
        Some("first trailing answer"),
        &[],
    )
    .expect("hash first speech");
    let second = step_state_hash(
        [0; 32],
        0,
        &request_hash,
        "const done = true;",
        &outcome,
        Some("second trailing answer"),
        &[],
    )
    .expect("hash second speech");
    assert_ne!(without, first);
    assert_ne!(first, second);
}

/// The two MEASURED baseline failure classes: pure code in a `ts` fence and
/// pure code in another tagged fence. Both now execute through healing, and
/// each costs exactly one heal count on its own run.
#[test]
fn measured_baseline_tagged_fences_now_execute_through_healing() {
    for (seed, run_ref, reply) in [
        (0x84_u8, "run-ts-fence", "```ts\nconst answer = 42;\n```"),
        (
            0x8C,
            "run-tagged-fence",
            "```readscript\nconst answer = 42;\n```",
        ),
    ] {
        let (_dir, vault) = open_test_vault();
        let backend = FixtureBackend::new([reply]);
        let lease = BudgetLease::for_test("executor-lease");
        let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
        let gated_write = gated_actor_write(&vault, run_ref);
        let config = executor_config(entity(seed), EngineExecutorLimits::default());

        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
        let outcome = block_on_ready(executor.run(&config)).expect("fenced reply heals and runs");

        assert_eq!(outcome.status, EngineExecutorStatus::Complete);
        assert_eq!(runtime.seen.len(), 1);
        assert_eq!(
            runtime.seen[0].script, "const answer = 42;",
            "the runtime receives the bare healed interior for {reply:?}"
        );
        assert_eq!(
            vault
                .code_run_model_heal_count(&model())
                .expect("heal count")
                .healed_turns,
            1,
            "one healed durable turn for {reply:?}"
        );
        assert_eq!(
            load_utf8_output(
                &ExecutorStorage::Canonical(&vault),
                &outcome.replay_record,
                &script_output_path(0)
            )
            .expect("staged script"),
            "const answer = 42;",
            "only the healed program is staged"
        );
    }
}

/// Healing has no opinion about parseability. A structurally clean source
/// with a genuine JavaScript syntax error is SUBMITTED to the runtime and
/// fails on the existing runtime-error path — never as an invalid body.
#[test]
fn general_javascript_syntax_errors_reach_the_runtime_not_the_gate() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(["const answer = ;"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
    let gated_write = gated_actor_write(&vault, "run-js-syntax-error");
    let config = executor_config(entity(0x94), EngineExecutorLimits::default());

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let err = block_on_ready(executor.run(&config)).expect_err("the runtime rejects the source");

    assert!(
        matches!(
            err,
            EngineExecutorError::Engine(Error::InvariantViolation("missing fixture observation"))
        ),
        "syntax errors stay on the runtime-error path, got {err:?}"
    );
    assert_eq!(
        runtime.seen[0].script, "const answer = ;",
        "the gate passed it through untouched"
    );
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        0,
        "a runtime-error turn never counts"
    );
}

/// A room-mate's append between this run's step and its commit returns
/// `ConcurrentWrite`: the turn is not durably committed, so telemetry must
/// not advance for it.
struct ConcurrentAppendRuntime<'a> {
    vault: &'a Vault,
    run_id: EntityId,
}

impl JsCodeModeRuntime for ConcurrentAppendRuntime<'_> {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        _host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        let mut record = self
            .vault
            .get_code_run_replay_record(&self.run_id)?
            .ok_or(Error::CorruptedIndex("test replay record"))?;
        let generation = record.generation()?;
        let output = CodeRunRawOutput::from_bytes("executor/repl/room-mate.txt", b"room-mate")?;
        self.vault.put_code_run_raw_output(&output, b"room-mate")?;
        record.outputs.push(output);
        self.vault
            .put_code_run_replay_record_if_generation(&record, Some(generation))?;
        Ok(JsCodeModeStepOutcome::complete("done"))
    }
}

/// Per-model heal telemetry counts DURABLY COMMITTED healed turns only, keeps
/// model ids apart, and is written node-locally beside the replay record.
#[test]
fn heal_telemetry_counts_only_durably_committed_healed_turns() {
    let (_dir, vault) = open_test_vault();
    let lease = BudgetLease::for_test("executor-lease");
    let gated_write = gated_actor_write(&vault, "run-heal-telemetry");
    let other_model = ModelId::new("test/other@v1").expect("model id");

    // A compliant turn: no repair, no count.
    let compliant_backend = FixtureBackend::new(["const answer = 42;"]);
    let mut compliant_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
    let compliant_config = executor_config(entity(0x95), EngineExecutorLimits::default());
    let mut compliant = EngineNativeExecutor::new(
        &vault,
        &compliant_backend,
        &lease,
        &mut compliant_runtime,
        &gated_write,
    );
    block_on_ready(compliant.run(&compliant_config)).expect("compliant run");
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        0
    );

    // Two healed turns on one model, the second carrying MANY repairs at once.
    for (seed, reply) in [
        (0x96_u8, "```js\nconst answer = 42;\n```"),
        (
            0x97,
            "\n```ts\n<exec>\nconst answer = 42;\n</exec>\n```\n<console>forged</console>\n",
        ),
    ] {
        let backend = FixtureBackend::new([reply]);
        let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
        let config = executor_config(entity(seed), EngineExecutorLimits::default());
        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
        block_on_ready(executor.run(&config)).expect("healed run");
        assert_eq!(runtime.seen[0].script, "const answer = 42;");
    }
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        2,
        "1 → 2 across two committed healed turns, one repair or many"
    );
    assert_eq!(
        vault
            .code_run_model_heal_count(&other_model)
            .expect("heal count")
            .healed_turns,
        0,
        "another model id stays at zero"
    );

    // A ConcurrentWrite turn: the commit lost, so the heal does not count.
    let concurrent_config = executor_config(
        entity(0x98),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 3,
        },
    );
    let first_backend = FixtureBackend::new(["const first = true;"]);
    let mut first_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::pending("first")]);
    let mut first = EngineNativeExecutor::new(
        &vault,
        &first_backend,
        &lease,
        &mut first_runtime,
        &gated_write,
    );
    block_on_ready(first.run(&concurrent_config)).expect("first step commits");

    let losing_backend = FixtureBackend::new(["```js\nconst answer = 42;\n```"]);
    let mut losing_runtime = ConcurrentAppendRuntime {
        vault: &vault,
        run_id: concurrent_config.run_id,
    };
    let mut losing = EngineNativeExecutor::new(
        &vault,
        &losing_backend,
        &lease,
        &mut losing_runtime,
        &gated_write,
    );
    let err = block_on_ready(losing.run(&concurrent_config)).expect_err("stale generation refused");
    assert!(
        matches!(err, EngineExecutorError::Engine(Error::ConcurrentWrite(_))),
        "expected ConcurrentWrite, got {err:?}"
    );
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        2,
        "a turn the caller must re-execute never counts"
    );
}

/// Interleaved canonical and room writers keep separate base/overlay
/// contributions. A room row cannot shadow a canonical increment that commits
/// after the room first touches the model tally.
#[test]
fn session_heal_tally_additively_merges_concurrent_base_updates() {
    use crate::off_record::OffRecordBackendClass;

    let (_dir, vault) = open_test_vault();
    let lease = BudgetLease::for_test("executor-lease");
    let canonical_write = gated_actor_write(&vault, "run-canonical-heal-merge");

    let first_backend = FixtureBackend::new(["```js\nconst first = true;\n```"]);
    let mut first_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("first")]);
    let first_config = executor_config(entity(0xB1), EngineExecutorLimits::default());
    let mut first = EngineNativeExecutor::new(
        &vault,
        &first_backend,
        &lease,
        &mut first_runtime,
        &canonical_write,
    );
    block_on_ready(first.run(&first_config)).expect("first base commit");
    drop(first);

    vault
        .enter_off_record_session("sess-heal-merge", OffRecordBackendClass::Local)
        .expect("enter room");
    let sessions = vault.off_record_session_vault();
    let session = sessions.bind("sess-heal-merge").expect("bind room");
    let actor = seed_person(&vault, 0xB2);
    let session_write = GatedActorWrite::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-session-heal-merge",
    )
    .expect("session dispatcher");

    let room_backend = FixtureBackend::new(["```js\nconst room = 1;\n```"]);
    let mut room_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("room one")]);
    let room_config = executor_config(entity(0xB3), EngineExecutorLimits::default());
    let mut room = EngineNativeExecutor::for_off_record_session(
        &session,
        &room_backend,
        &lease,
        &mut room_runtime,
        &session_write,
    )
    .expect("session executor");
    block_on_ready(room.run(&room_config)).expect("first overlay commit");
    drop(room);

    let room_storage = ExecutorStorage::for_session(&session).expect("room storage");
    assert_eq!(
        room_storage
            .code_run_model_heal_count(&model())
            .expect("composed count")
            .healed_turns,
        2,
        "base 1 + overlay 1"
    );

    let second_backend = FixtureBackend::new(["```js\nconst second = true;\n```"]);
    let mut second_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("second")]);
    let second_config = executor_config(entity(0xB4), EngineExecutorLimits::default());
    let mut second = EngineNativeExecutor::new(
        &vault,
        &second_backend,
        &lease,
        &mut second_runtime,
        &canonical_write,
    );
    block_on_ready(second.run(&second_config)).expect("second base commit");
    drop(second);
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("base count")
            .healed_turns,
        2
    );
    assert_eq!(
        room_storage
            .code_run_model_heal_count(&model())
            .expect("composed count after concurrent base write")
            .healed_turns,
        3,
        "the later base increment remains visible beside overlay delta 1"
    );

    let room_backend = FixtureBackend::new(["```js\nconst room = 2;\n```"]);
    let mut room_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("room two")]);
    let room_config = executor_config(entity(0xB5), EngineExecutorLimits::default());
    let mut room = EngineNativeExecutor::for_off_record_session(
        &session,
        &room_backend,
        &lease,
        &mut room_runtime,
        &session_write,
    )
    .expect("second session executor");
    block_on_ready(room.run(&room_config)).expect("second overlay commit");
    assert_eq!(
        room_storage
            .code_run_model_heal_count(&model())
            .expect("final composed count")
            .healed_turns,
        4,
        "base 2 + overlay 2 without a lost or doubled turn"
    );

    drop(room);
    drop(room_storage);
    drop(session_write);
    session.close().expect("close room");
}

#[test]
fn same_run_id_is_refused_after_off_record_route_target_changes() {
    use crate::off_record::OffRecordBackendClass;

    let (_dir, vault) = open_test_vault();
    vault
        .enter_off_record_session("sess-replay-route-epoch", OffRecordBackendClass::Local)
        .expect("enter room");
    let sessions = vault.off_record_session_vault();
    let session = sessions.bind("sess-replay-route-epoch").expect("bind room");
    let actor = seed_person(&vault, 0xB9);
    let lease = BudgetLease::for_test("executor-lease");
    let config = executor_config(
        entity(0xBA),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 2,
        },
    );

    let overlay_write = GatedActorWrite::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-overlay-route-epoch",
    )
    .expect("overlay dispatcher");
    let first_backend = FixtureBackend::new(["```js
const privateStep = true;
```"]);
    let mut first_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::pending("private")]);
    let mut first = EngineNativeExecutor::for_off_record_session(
        &session,
        &first_backend,
        &lease,
        &mut first_runtime,
        &overlay_write,
    )
    .expect("overlay executor");
    let first_outcome = block_on_ready(first.run(&config)).expect("commit overlay step");
    assert!(matches!(
        first_outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 }
    ));
    drop(first);
    drop(overlay_write);
    assert!(
        vault
            .get_code_run_replay_record(&config.run_id)
            .expect("base replay lookup")
            .is_none(),
        "off-record replay must remain overlay-only"
    );
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("base tally")
            .healed_turns,
        0
    );

    session.flip_on_record().expect("flip room on record");
    let base_write = GatedActorWrite::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-base-route-epoch",
    )
    .expect("base dispatcher");
    let retry_backend = FixtureBackend::new(["```js
const mustNotRun = true;
```"]);
    let mut retry_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("must not run")]);
    let mut retry = EngineNativeExecutor::for_off_record_session(
        &session,
        &retry_backend,
        &lease,
        &mut retry_runtime,
        &base_write,
    )
    .expect("base executor");
    let error = block_on_ready(retry.run(&config)).expect_err("route target drift must refuse");
    assert!(matches!(
        error,
        EngineExecutorError::Engine(Error::InvalidConfig(ref message))
            if message == "engine executor config changed for existing run"
    ));
    drop(retry);
    assert!(
        retry_backend
            .requests
            .lock()
            .expect("requests lock")
            .is_empty(),
        "refusal must happen before re-execution"
    );
    assert!(retry_runtime.seen.is_empty());
    assert!(
        vault
            .get_code_run_replay_record(&config.run_id)
            .expect("base replay lookup after refusal")
            .is_none(),
        "refusal must not publish a replay that points at private raw outputs"
    );
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("base tally after refusal")
            .healed_turns,
        0,
        "refusal must not increment the durable base contribution"
    );
    let session_storage = ExecutorStorage::for_session(&session).expect("session storage");
    assert_eq!(
        session_storage
            .code_run_model_heal_count(&model())
            .expect("composed tally")
            .healed_turns,
        1,
        "the original overlay contribution remains exactly once"
    );

    drop(session_storage);
    drop(base_write);
    session.close().expect("close room");
}

/// A malformed tally row makes the combined transaction fail BEFORE replay
/// durability. Repairing the local row and retrying commits one checkpoint and
/// one signal, never a durable step followed by a telemetry error.
#[test]
fn heal_tally_failure_rolls_back_replay_and_retry_counts_once() {
    let (_dir, vault) = open_test_vault();
    let key = b"code_run:heal_count:v1:test/executor@v1";
    vault
        .with_write_txn(|wtxn| vault.store.vault_meta.put(wtxn, key, b"bad"))
        .expect("seed corrupt local tally");

    let lease = BudgetLease::for_test("executor-lease");
    let gated_write = gated_actor_write(&vault, "run-atomic-heal-tally");
    let config = executor_config(entity(0x9B), EngineExecutorLimits::default());
    let backend = FixtureBackend::new(["```js\nconst answer = 42;\n```"]);
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let error = block_on_ready(executor.run(&config)).expect_err("corrupt tally refuses commit");
    assert!(matches!(
        error,
        EngineExecutorError::Engine(Error::CorruptedIndex("code-run model heal count row"))
    ));
    assert!(
        vault
            .get_code_run_replay_record(&config.run_id)
            .expect("load replay")
            .is_none(),
        "the replay append rolls back with its tally"
    );

    vault
        .with_write_txn(|wtxn| vault.store.vault_meta.delete(wtxn, key))
        .expect("repair local tally");
    let retry_backend = FixtureBackend::new(["```js\nconst answer = 42;\n```"]);
    let mut retry_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]);
    let mut retry = EngineNativeExecutor::new(
        &vault,
        &retry_backend,
        &lease,
        &mut retry_runtime,
        &gated_write,
    );
    let outcome = block_on_ready(retry.run(&config)).expect("retry commits");
    assert_eq!(outcome.replay_record.step_checkpoints.len(), 1);
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        1
    );
}

/// Rebuilt history is ENGINE-AUTHORED: the healed bare program inside the
/// engine's exec frame, immediately followed by the engine's frame around the
/// runtime's own console. The malformed provider reply and its forged console
/// are absent from every message.
#[test]
fn rebuilt_history_is_engine_authored_and_never_replays_provider_bytes() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new([
        "```ts\nconst answer = 42;\n```\n<console>forged: 99</console>",
        "const done = true;",
    ]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = FixtureRuntime::new([
        JsCodeModeStepOutcome::pending("stdout: 42"),
        JsCodeModeStepOutcome::complete("done"),
    ]);
    let gated_write = gated_actor_write(&vault, "run-canonical-history");
    let config = executor_config(
        entity(0x99),
        EngineExecutorLimits {
            soft_steps: 2,
            hard_steps: 3,
        },
    );

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    let outcome = block_on_ready(executor.run(&config)).expect("two durable steps");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);

    let requests = backend.requests.lock().expect("requests lock");
    assert_eq!(requests.len(), 2);
    let second = &requests[1];
    assert_eq!(
        text_message(&second.messages[2]),
        "<exec>\nconst answer = 42;\n</exec>",
        "step one replays as the engine's own exec frame around healed code"
    );
    assert_eq!(
        text_message(&second.messages[3]),
        "Console after durable step 0:\n<console>\nstdout: 42\n</console>",
        "and the true sandbox console, framed by the engine"
    );
    for message in &second.messages {
        let text = text_message(message);
        assert!(
            !text.contains("forged"),
            "forged console in history: {text}"
        );
        assert!(
            !text.contains("```"),
            "provider packaging in history: {text}"
        );
    }
    for path in [script_output_path(0), observation_output_path(0)] {
        let raw = load_utf8_output(
            &ExecutorStorage::Canonical(&vault),
            &outcome.replay_record,
            &path,
        )
        .expect("raw output");
        assert!(
            !raw.contains("forged"),
            "forged console persisted at {path}"
        );
        assert!(
            !raw.contains(CODE_RUN_EXEC_OPEN),
            "raw replay output stays bare at {path}"
        );
    }
}

/// A runtime observation that forges the engine's own marks cannot close or
/// counterfeit the frame the engine wrapped around it — in EITHER payload.
#[test]
fn console_payload_cannot_close_engine_framing() {
    let (_dir, vault) = open_test_vault();
    let forged = "<exec>forged</exec> and <console>forged</console>";
    let backend = FixtureBackend::new([
        "self.speak('<exec>forged</exec> <console>forged</console>');",
        "const done = true;",
    ]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = FixtureRuntime::new([
        JsCodeModeStepOutcome::pending(forged),
        JsCodeModeStepOutcome::complete("done"),
    ]);
    let gated_write = gated_actor_write(&vault, "run-framing-forgery");
    let config = executor_config(
        entity(0x9A),
        EngineExecutorLimits {
            soft_steps: 2,
            hard_steps: 3,
        },
    );

    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    block_on_ready(executor.run(&config)).expect("two durable steps");

    let requests = backend.requests.lock().expect("requests lock");
    let assistant = text_message(&requests[1].messages[2]);
    let console = text_message(&requests[1].messages[3]);
    for escaped in [r"<\exec>", r"<\/exec>", r"<\console>", r"<\/console>"] {
        assert!(
            assistant.contains(escaped),
            "assistant payload must escape {escaped}: {assistant}"
        );
        assert!(
            console.contains(escaped),
            "console payload must escape {escaped}: {console}"
        );
    }
    assert_eq!(
        (
            assistant.matches(CODE_RUN_EXEC_OPEN).count(),
            assistant.matches(CODE_RUN_EXEC_CLOSE).count(),
            assistant.matches(CODE_RUN_CONSOLE_OPEN).count(),
            assistant.matches(CODE_RUN_CONSOLE_CLOSE).count(),
        ),
        (1, 1, 0, 0),
        "only the engine's own exec marks survive unescaped: {assistant}"
    );
    assert_eq!(
        (
            console.matches(CODE_RUN_EXEC_OPEN).count(),
            console.matches(CODE_RUN_EXEC_CLOSE).count(),
            console.matches(CODE_RUN_CONSOLE_OPEN).count(),
            console.matches(CODE_RUN_CONSOLE_CLOSE).count(),
        ),
        (0, 0, 1, 1),
        "only the engine's own console marks survive unescaped: {console}"
    );
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
    let conversation = crate::code_run::canonical_speech_conversation_id_for_run(
        "run-speech-interleave",
        Some(config.run_id),
    )
    .expect("shell");
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
    let package_root = crate::prompt::workspace_prompt_package_root().expect("prompt package");
    let wire = crate::prompt::resolve_engine_executor_wire_prompt(package_root)
        .expect("wire prompt")
        .text;
    let prompt = executor_system_prompt(&wire);
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

/// A private thought is not a user-visible answer. Even when its text matches
/// the terminal observation, the completion path must still emit that last word
/// as a visible implicit Speak.
#[test]
fn hidden_think_does_not_suppress_the_matching_visible_fallback() {
    let (_dir, vault) = open_test_vault();
    let actor = session_speech_run(
        &vault,
        "sess-think-fallback",
        0xD6,
        "the answer remained private",
        vec![SelfCall::Think(SelfSpeechCall::new(
            "the answer remained private",
        ))],
    );

    assert_eq!(
        executor_bubbles(&vault, actor),
        vec![
            (
                "executor.think".to_owned(),
                "the answer remained private".to_owned(),
                false,
                0,
            ),
            (
                "executor.speak".to_owned(),
                "the answer remained private".to_owned(),
                true,
                1,
            ),
        ],
        "hidden text cannot stand in for the visible trailing answer",
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

/// The implicit payload and terminal checkpoint commit before the witness
/// side effect. A stale replay append therefore emits no bubble; retry commits
/// and emits exactly one, and a terminal resume cannot emit it again.
#[test]
fn trailing_implicit_speech_is_checkpoint_bound_across_conflict_and_retry() {
    use crate::off_record::OffRecordBackendClass;

    let (_dir, vault) = open_test_vault();
    vault
        .enter_off_record_session("sess-speech-replay", OffRecordBackendClass::Local)
        .expect("enter session");
    let sessions = vault.off_record_session_vault();
    let session = sessions.bind("sess-speech-replay").expect("bind session");
    session.flip_on_record().expect("flip on record");
    let actor = seed_person(&vault, 0xD6);
    let gated_write = GatedActorWrite::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-speech-replay",
    )
    .expect("session dispatcher");
    let lease = BudgetLease::for_test("executor-lease");
    let config = executor_config(
        entity(0xDA),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 3,
        },
    );

    let first_backend = FixtureBackend::new(["const pending = true;"]);
    let mut first_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::pending("pending")]);
    let mut first = EngineNativeExecutor::for_off_record_session(
        &session,
        &first_backend,
        &lease,
        &mut first_runtime,
        &gated_write,
    )
    .expect("first executor");
    block_on_ready(first.run(&config)).expect("seed checkpoint");
    drop(first);

    let losing_backend =
        FixtureBackend::new(["```js\nconst done = true;\n```\nFinal answer after replay."]);
    let mut losing_runtime = ConcurrentAppendRuntime {
        vault: &vault,
        run_id: config.run_id,
    };
    let mut losing = EngineNativeExecutor::for_off_record_session(
        &session,
        &losing_backend,
        &lease,
        &mut losing_runtime,
        &gated_write,
    )
    .expect("losing executor");
    let error = block_on_ready(losing.run(&config)).expect_err("stale append refused");
    assert!(matches!(
        error,
        EngineExecutorError::Engine(Error::ConcurrentWrite(_))
    ));
    assert!(
        executor_bubbles(&vault, actor).is_empty(),
        "a bubble cannot precede the replay commit it belongs to"
    );
    drop(losing);

    let retry_backend =
        FixtureBackend::new(["```js\nconst done = true;\n```\nFinal answer after replay."]);
    let mut retry_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("runtime done")]);
    let record = {
        let mut retry = EngineNativeExecutor::for_off_record_session(
            &session,
            &retry_backend,
            &lease,
            &mut retry_runtime,
            &gated_write,
        )
        .expect("retry executor");
        let outcome = block_on_ready(retry.run(&config)).expect("retry commits and speaks");
        assert_eq!(outcome.status, EngineExecutorStatus::Complete);
        outcome.replay_record
    };
    assert_eq!(
        executor_bubbles(&vault, actor),
        vec![(
            "executor.speak".to_owned(),
            "Final answer after replay.".to_owned(),
            true,
            0,
        )]
    );
    assert_eq!(
        load_utf8_output(
            &ExecutorStorage::for_session(&session).expect("session storage"),
            &record,
            &implicit_speak_output_path(1),
        )
        .expect("checkpointed implicit payload"),
        "Final answer after replay."
    );

    let terminal_backend = FixtureBackend::new(std::iter::empty::<&str>());
    let mut terminal_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
    let mut terminal = EngineNativeExecutor::for_off_record_session(
        &session,
        &terminal_backend,
        &lease,
        &mut terminal_runtime,
        &gated_write,
    )
    .expect("terminal executor");
    let outcome = block_on_ready(terminal.run(&config)).expect("terminal replay");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(executor_bubbles(&vault, actor).len(), 1);

    drop(terminal);
    drop(gated_write);
    session.close().expect("close session");
}

#[test]
fn off_record_implicit_witness_retry_reuses_the_same_overlay_message() {
    use crate::off_record::OffRecordBackendClass;

    let (_dir, vault) = open_test_vault();
    vault
        .enter_off_record_session("sess-overlay-speech-retry", OffRecordBackendClass::Local)
        .expect("enter session");
    let sessions = vault.off_record_session_vault();
    let session = sessions
        .bind("sess-overlay-speech-retry")
        .expect("bind session");
    let actor = seed_person(&vault, 0xC8);
    let storage = ExecutorStorage::for_session(&session).expect("session storage");
    let run_ref = "sess-overlay-speech-retry";
    // Derived exactly the way the door derives it: the assertion is that the
    // SAME host identity is reached twice, not that a hard-coded id survives.
    let message_id =
        crate::code_run::executor_speech_message_id(run_ref, 0).expect("derive message id");
    for _ in 0..2 {
        // An overlay receipt carries SESSION-LOCAL aliases, so the row itself is
        // the evidence: the second call must converge on the id the first wrote.
        storage
            .witness_executor_utterance(
                run_ref,
                None,
                ExecutorUtterance::Speak,
                "overlay-idempotent-speech-token",
                1_719_000_001,
                0,
                WriteActor::new(actor, EdgeActorClass::Agent),
            )
            .expect("idempotent overlay witness");
    }
    let hits = session
        .search_text("overlay-idempotent-speech-token", 10)
        .expect("search overlay after retry");
    assert_eq!(hits.iter().filter(|hit| hit.id == message_id).count(), 1);

    drop(storage);
    session.close().expect("close session");
}

fn retry_terminal_speech_after_session_restart(
    vault: &Vault,
    sessions: &crate::off_record::OffRecordSessionVault<'_>,
    actor: EntityId,
    lease: &BudgetLease,
    config: &EngineExecutorConfig,
    attempt: u8,
) {
    use crate::off_record::OffRecordBackendClass;

    vault
        .enter_off_record_session("sess-implicit-recovery", OffRecordBackendClass::Local)
        .expect("re-enter session after restart");
    let session = sessions
        .bind("sess-implicit-recovery")
        .expect("rebind session after restart");
    session.flip_on_record().expect("flip rebound session");
    let gated_write = GatedActorWrite::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-implicit-recovery-retry",
    )
    .expect("rebound session dispatcher");
    let retry_backend = FixtureBackend::new(std::iter::empty::<&str>());
    let mut retry_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
    let mut retry = EngineNativeExecutor::for_off_record_session(
        &session,
        &retry_backend,
        lease,
        &mut retry_runtime,
        &gated_write,
    )
    .expect("retry executor");
    let outcome = block_on_ready(retry.run(config)).expect("terminal recovery");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(outcome.steps_run, 0);
    drop(retry);
    assert!(retry_runtime.seen.is_empty());
    assert_eq!(
        executor_bubbles(vault, actor),
        vec![(
            "executor.speak".to_owned(),
            "Recovered terminal answer.".to_owned(),
            true,
            0,
        )],
        "terminal retry {attempt} must not mint a second bubble"
    );
    drop(gated_write);
    session.close().expect("close retry session");
}

/// A terminal replay remains responsible for its checkpointed implicit
/// speech after a post-commit failure. Recovery reuses stable host-owned
/// witness ids, so both the first retry and later terminal resumes converge on
/// the same bubble.
#[test]
fn terminal_retry_recovers_post_commit_implicit_speech_without_duplicates() {
    use crate::off_record::OffRecordBackendClass;

    let (_dir, vault) = open_test_vault();
    vault
        .enter_off_record_session("sess-implicit-recovery", OffRecordBackendClass::Local)
        .expect("enter session");
    let sessions = vault.off_record_session_vault();
    let session = sessions
        .bind("sess-implicit-recovery")
        .expect("bind session");
    session.flip_on_record().expect("flip on record");
    let actor = seed_person(&vault, 0xDB);
    let gated_write = GatedActorWrite::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-implicit-recovery",
    )
    .expect("session dispatcher");
    let lease = BudgetLease::for_test("executor-lease");
    let config = executor_config(entity(0xDC), EngineExecutorLimits::default());

    let backend =
        FixtureBackend::new(["```js\nconst done = true;\n```\nRecovered terminal answer."]);
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("runtime done")]);
    let mut first = EngineNativeExecutor::for_off_record_session(
        &session,
        &backend,
        &lease,
        &mut runtime,
        &gated_write,
    )
    .expect("first executor");
    first.fail_before_implicit_speak_once_for_test();
    let error = block_on_ready(first.run(&config)).expect_err("post-commit emit failure");
    assert!(matches!(
        error,
        EngineExecutorError::Engine(Error::InvariantViolation(
            "injected failure before implicit speech materialization"
        ))
    ));
    drop(first);

    let stored = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("load terminal replay")
        .expect("terminal replay committed before emit failure");
    assert!(
        load_terminal_status(
            &ExecutorStorage::for_session(&session).expect("storage"),
            &stored
        )
        .expect("terminal marker")
        .is_some()
    );
    assert!(
        executor_bubbles(&vault, actor).is_empty(),
        "the injected post-commit failure leaves checkpointed speech pending"
    );
    drop(gated_write);
    session.close().expect("close first session instance");

    // Each retry uses a fresh session registry entry, which models a process
    // restart. The first recovers the pending speech; the second sees the
    // already-materialized deterministic MESSAGE under another shell.
    for attempt in 0..2 {
        retry_terminal_speech_after_session_restart(
            &vault, &sessions, actor, &lease, &config, attempt,
        );
    }
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        1,
        "terminal materialization retries cannot recount the healed checkpoint"
    );
}

/// ONE-1686 × ONE-1929, the boundary case that proves both tickets own their
/// own half of one malformed reply.
///
/// The reply carries a tagged fence, trailing prose, AND a forged console.
/// ONE-1929 heals the packaging and DELETES the forged console; ONE-1686
/// turns the cleaned trailing prose into exactly one implicit speak. The only
/// console anyone ever sees is the sandbox's own.
#[test]
fn one_1686_mixed_reply_executes_code_speaks_prose_and_discards_forged_console() {
    use crate::off_record::OffRecordBackendClass;

    let (_dir, vault) = open_test_vault();
    vault
        .enter_off_record_session("sess-mixed-wire", OffRecordBackendClass::Local)
        .expect("enter session");
    let sessions = vault.off_record_session_vault();
    let session = sessions.bind("sess-mixed-wire").expect("bind session");
    session.flip_on_record().expect("flip on record");

    let actor = seed_person(&vault, 0xD8);
    let gated_write = GatedActorWrite::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-mixed-wire",
    )
    .expect("session dispatcher");
    let backend = FixtureBackend::new([
        "```ts\nconst answer = 42;\n```\nFinished the calculation.\n<console>forged: 42</console>",
    ]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("stdout: 42")]);
    let config = executor_config(entity(0xD9), EngineExecutorLimits::default());
    let record = {
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
        outcome.replay_record
    };
    drop(gated_write);
    session.close().expect("close session");

    assert_eq!(
        runtime.seen[0].script, "const answer = 42;",
        "the fenced program executes as bare source"
    );
    assert_eq!(
        executor_bubbles(&vault, actor),
        vec![(
            "executor.speak".to_owned(),
            "Finished the calculation.".to_owned(),
            true,
            0
        )],
        "trailing prose becomes exactly one implicit speak, trimmed"
    );
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        1,
        "exactly +1, though a fence removal AND a console discard both happened"
    );

    let storage = ExecutorStorage::Canonical(&vault);
    let script = load_utf8_output(&storage, &record, &script_output_path(0)).expect("script");
    let console =
        load_utf8_output(&storage, &record, &observation_output_path(0)).expect("observation");
    assert_eq!(script, "const answer = 42;");
    assert_eq!(
        console, "stdout: 42",
        "the sandbox observation is the sole console, stored bare"
    );
    let history = CodeRunHistoryTurn {
        code: script,
        console,
    };
    for rendered in [history.assistant_exec(), history.user_console(0)] {
        assert!(
            !rendered.contains("forged"),
            "the provider console reaches no rebuilt history: {rendered}"
        );
    }
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

/// Speaks through the bridge, then lands a CONCURRENT replay append so this
/// step's compare-and-put loses. The bubble is already durable; the checkpoint
/// that would have owned it is not.
struct SpeakThenLoseTheAppendRuntime<'a> {
    vault: &'a Vault,
    run_id: EntityId,
    text: &'static str,
}

impl JsCodeModeRuntime for SpeakThenLoseTheAppendRuntime<'_> {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        let _ = host.dispatch_self(SelfCall::Speak(SelfSpeechCall::new(self.text)))?;
        let mut record = self
            .vault
            .get_code_run_replay_record(&self.run_id)?
            .ok_or(Error::CorruptedIndex("test replay record"))?;
        let generation = record.generation()?;
        let output = CodeRunRawOutput::from_bytes("executor/repl/room-mate.txt", b"room-mate")?;
        self.vault.put_code_run_raw_output(&output, b"room-mate")?;
        record.outputs.push(output);
        self.vault
            .put_code_run_replay_record_if_generation(&record, Some(generation))?;
        Ok(JsCodeModeStepOutcome::complete("done"))
    }
}

/// ONE-1929: EXPLICIT speech is replay-stable, not just the implicit fallback.
///
/// `self.speak` commits its bubble at the moment the guest calls it, so a step
/// whose replay append then fails leaves a durable MESSAGE behind an
/// uncommitted checkpoint. The retry runs the same replay state, so the host
/// stamps the same bridge position — and because the TURN/MESSAGE identity is
/// derived from that position rather than minted per attempt, the door
/// recognizes the row it already wrote. One utterance, one bubble, across a
/// failed append and its retry.
#[test]
fn explicit_speech_survives_a_failed_replay_append_without_a_second_bubble() {
    use crate::off_record::OffRecordBackendClass;

    let (_dir, vault) = open_test_vault();
    vault
        .enter_off_record_session("sess-explicit-replay", OffRecordBackendClass::Local)
        .expect("enter session");
    let sessions = vault.off_record_session_vault();
    let session = sessions.bind("sess-explicit-replay").expect("bind session");
    session.flip_on_record().expect("flip on record");
    let actor = seed_person(&vault, 0xE8);
    let gated_write = GatedActorWrite::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-explicit-replay",
    )
    .expect("session dispatcher");
    let lease = BudgetLease::for_test("executor-lease");
    let config = executor_config(
        entity(0xE9),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 3,
        },
    );

    // One committed step first, so the replay row the losing attempt races
    // against exists. It speaks nothing, so the bridge ordering the next step
    // stamps still starts at zero.
    let seed_backend = FixtureBackend::new(["const pending = true;"]);
    let mut seed_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::pending("pending")]);
    let mut seed = EngineNativeExecutor::for_off_record_session(
        &session,
        &seed_backend,
        &lease,
        &mut seed_runtime,
        &gated_write,
    )
    .expect("seed executor");
    block_on_ready(seed.run(&config)).expect("seed checkpoint");
    drop(seed);

    let losing_backend = FixtureBackend::new(["await self.speak('said exactly once');"]);
    let mut losing_runtime = SpeakThenLoseTheAppendRuntime {
        vault: &vault,
        run_id: config.run_id,
        text: "said exactly once",
    };
    let mut losing = EngineNativeExecutor::for_off_record_session(
        &session,
        &losing_backend,
        &lease,
        &mut losing_runtime,
        &gated_write,
    )
    .expect("losing executor");
    let error = block_on_ready(losing.run(&config)).expect_err("stale append refused");
    assert!(matches!(
        error,
        EngineExecutorError::Engine(Error::ConcurrentWrite(_))
    ));
    drop(losing);
    assert_eq!(
        executor_bubbles(&vault, actor),
        vec![(
            "executor.speak".to_owned(),
            "said exactly once".to_owned(),
            true,
            0,
        )],
        "the explicit bubble committed before the append that failed"
    );
    assert_eq!(
        vault
            .get_code_run_replay_record(&config.run_id)
            .expect("read replay")
            .expect("replay row")
            .step_checkpoints
            .len(),
        1,
        "the losing attempt committed no checkpoint of its own"
    );

    let retry_backend = FixtureBackend::new(["await self.speak('said exactly once');"]);
    // The terminal plaintext is the SAME words the explicit bubble said, which
    // is exactly what the trailing fallback's per-text suppression is about: a
    // run that spoke and then finished with those words has already said them.
    // (Distinct trailing prose is a last word of its own and is deliberately
    // KEPT — see `session_speech_keeps_distinct_trailing_plaintext_beside_explicit_bubbles`.)
    let mut retry_runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::complete("said exactly once")]).with_calls([
            vec![SelfCall::Speak(SelfSpeechCall::new("said exactly once"))],
        ]);
    let record = {
        let mut retry = EngineNativeExecutor::for_off_record_session(
            &session,
            &retry_backend,
            &lease,
            &mut retry_runtime,
            &gated_write,
        )
        .expect("retry executor");
        let outcome = block_on_ready(retry.run(&config)).expect("retry commits");
        assert_eq!(outcome.status, EngineExecutorStatus::Complete);
        outcome.replay_record
    };
    assert_eq!(
        executor_bubbles(&vault, actor),
        vec![(
            "executor.speak".to_owned(),
            "said exactly once".to_owned(),
            true,
            0,
        )],
        "the retry converges on the bubble it already wrote"
    );
    assert_eq!(
        record.bridge_calls.len(),
        1,
        "one speech row lands in the committed replay"
    );
    assert!(
        record.bridge_calls[0].emitted_speech(),
        "explicit speech still suppresses the trailing fallback"
    );

    drop(gated_write);
    session.close().expect("close session");
}

/// A witness ceiling refusal is a POLICY answer with `gate.*` reason codes, and
/// the executor classifies bridge outcomes by exactly that typing. Collapsing
/// every facade refusal into `InvariantViolation` at the session wrapper turned
/// a legitimate actor-ceiling refusal into an untyped `Failed`. The typed
/// refusal must reach the dispatcher, the replay row, and the run's own error.
#[test]
fn witness_ceiling_refusal_stays_typed_through_the_executor_seam() {
    use crate::off_record::OffRecordBackendClass;

    let (_dir, vault) = open_test_vault();
    vault
        .enter_off_record_session("sess-typed-denial", OffRecordBackendClass::Local)
        .expect("enter session");
    let sessions = vault.off_record_session_vault();
    let session = sessions.bind("sess-typed-denial").expect("bind session");
    session.flip_on_record().expect("flip on record");
    let actor = seed_person(&vault, 0xE4);
    // The ceiling row must NAME this writer. Witness MESSAGE ingress is
    // transcript RECORDING, so a class-wide row deliberately does not clamp it
    // — "no row for the writer" keeps ordinary conversation recordable. An
    // owner-authored actor-ref-bound row is the lever that refuses, so the
    // manifest is installed once the actor it binds exists.
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        entity(0xE3),
        &proposed_agent_manifest(&actor.to_hex()),
    )
    .expect("install policy manifest");
    let gated_write = GatedActorWrite::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-typed-denial",
    )
    .expect("session dispatcher");
    let lease = BudgetLease::for_test("executor-lease");
    let config = executor_config(entity(0xE5), EngineExecutorLimits::default());
    let backend = FixtureBackend::new(["await self.speak('refused by the ceiling');"]);
    let mut runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::complete("done")]).with_calls([vec![
            SelfCall::Speak(SelfSpeechCall::new("refused by the ceiling")),
        ]]);

    let error = {
        let mut executor = EngineNativeExecutor::for_off_record_session(
            &session,
            &backend,
            &lease,
            &mut runtime,
            &gated_write,
        )
        .expect("session executor");
        block_on_ready(executor.run(&config)).expect_err("the ceiling refuses the bubble")
    };
    let EngineExecutorError::Engine(engine_error) = &error else {
        panic!("the witness refusal must stay an engine error: {error:?}");
    };
    assert_eq!(
        engine_error.kind(),
        crate::error::ErrorKind::GateWriteRejected,
        "an actor-ceiling refusal is a gate rejection, not an invariant violation"
    );
    let denial = engine_error.gate_denial().expect("typed gate denial");
    assert!(
        !denial.reason_codes().is_empty(),
        "the reason classification survives the session wrapper"
    );
    assert!(
        executor_bubbles(&vault, actor).is_empty(),
        "a refused bubble is never materialized"
    );

    let stored = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("read replay")
        .expect("failed step is durable");
    assert_eq!(stored.bridge_calls.len(), 1);
    assert_eq!(
        bridge_outcome_kind(&stored.bridge_calls[0]),
        "denied",
        "the replay row records a typed Denied outcome, not a generic failure"
    );

    drop(gated_write);
    session.close().expect("close session");
}

/// A minimal manifest whose agent ceiling is `proposed`, bound to `actor_ref`:
/// the witness ceiling door parks that agent's MESSAGE instead of admitting it.
///
/// The row carries `actor_ref` because a MESSAGE is transcript recording, not
/// claim admission: the owner's lever over it is a row that NAMES the writer,
/// and a class-wide row alone leaves ordinary recording available.
fn proposed_agent_manifest(actor_ref: &str) -> Vec<u8> {
    let manifest = Value::Map(vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("executor-witness-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (Value::from("rules"), Value::Array(Vec::new())),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("agent")),
                (Value::from("actor_ref"), Value::from(actor_ref)),
                (Value::from("ceiling"), Value::from("proposed")),
            ])]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest).expect("encode manifest");
    data
}

/// Deployed-prompt drift must not strand a checkpointed bubble.
///
/// The run commits its terminal checkpoint — implicit payload and all — and
/// then fails while materializing the bubble. Before the recovery can run, the
/// prompt package is re-deployed with different bytes. Binding the resolved
/// fingerprint INTO run identity made that redeploy refuse the resume, so the
/// checkpointed utterance could never be spoken. Identity still refuses a
/// drifted resume that owes provider work (see
/// `replay_refuses_resolved_prompt_drift_before_the_next_llm_call`); a terminal
/// record owes none, and recovers.
#[test]
fn prompt_drift_still_recovers_a_terminal_checkpointed_bubble() {
    use crate::off_record::OffRecordBackendClass;

    let package = tempfile::tempdir().expect("prompt package tempdir");
    let blocks = package.path().join("blocks");
    std::fs::create_dir_all(&blocks).expect("create blocks directory");
    let wire_path = blocks.join("engine-executor-wire.md");
    std::fs::write(&wire_path, "deployed wire teaching A\n").expect("write prompt A");

    let (_dir, vault) = open_test_vault();
    let sessions = vault.off_record_session_vault();
    let lease = BudgetLease::for_test("executor-lease");
    let mut config = executor_config(entity(0xE6), EngineExecutorLimits::default());
    config.prompt_package_root = package.path().to_path_buf();
    let actor = {
        vault
            .enter_off_record_session("sess-prompt-drift", OffRecordBackendClass::Local)
            .expect("enter session");
        let session = sessions.bind("sess-prompt-drift").expect("bind session");
        session.flip_on_record().expect("flip on record");
        let actor = seed_person(&vault, 0xE7);
        let gated_write = GatedActorWrite::for_off_record_session(
            &session,
            WriteActor::new(actor, EdgeActorClass::Agent),
            "run-prompt-drift",
        )
        .expect("session dispatcher");
        let backend =
            FixtureBackend::new(["```js\nconst done = true;\n```\nSpoken under teaching A."]);
        let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("runtime done")]);
        let mut first = EngineNativeExecutor::for_off_record_session(
            &session,
            &backend,
            &lease,
            &mut runtime,
            &gated_write,
        )
        .expect("first executor");
        first.fail_before_implicit_speak_once_for_test();
        let error = block_on_ready(first.run(&config)).expect_err("post-commit emit failure");
        assert!(matches!(
            error,
            EngineExecutorError::Engine(Error::InvariantViolation(
                "injected failure before implicit speech materialization"
            ))
        ));
        drop(first);
        assert!(
            executor_bubbles(&vault, actor).is_empty(),
            "the checkpointed utterance is still pending"
        );
        drop(gated_write);
        session.close().expect("close first session instance");
        actor
    };

    // The prompt package is re-deployed between the commit and the recovery.
    std::fs::write(&wire_path, "deployed wire teaching B\n").expect("write prompt B");

    vault
        .enter_off_record_session("sess-prompt-drift", OffRecordBackendClass::Local)
        .expect("re-enter session");
    let session = sessions.bind("sess-prompt-drift").expect("rebind session");
    session.flip_on_record().expect("flip rebound session");
    let gated_write = GatedActorWrite::for_off_record_session(
        &session,
        WriteActor::new(actor, EdgeActorClass::Agent),
        "run-prompt-drift-retry",
    )
    .expect("rebound session dispatcher");
    let retry_backend = FixtureBackend::new(std::iter::empty::<&str>());
    let mut retry_runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
    let mut retry = EngineNativeExecutor::for_off_record_session(
        &session,
        &retry_backend,
        &lease,
        &mut retry_runtime,
        &gated_write,
    )
    .expect("retry executor");
    let outcome = block_on_ready(retry.run(&config)).expect("terminal recovery under drift");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(outcome.steps_run, 0);
    drop(retry);
    assert!(
        retry_backend
            .requests
            .lock()
            .expect("requests lock")
            .is_empty(),
        "terminal recovery needs no provider request, drifted teaching or not"
    );
    assert!(retry_runtime.seen.is_empty());
    assert_eq!(
        executor_bubbles(&vault, actor),
        vec![(
            "executor.speak".to_owned(),
            "Spoken under teaching A.".to_owned(),
            true,
            0,
        )],
        "the checkpointed payload is spoken exactly once, from the record"
    );

    drop(gated_write);
    session.close().expect("close retry session");
}

/// A healed turn whose STEP fails still counts once — and only once — for each
/// of the three families that commit a failed-step checkpoint.
///
/// The signal is "this model needed its wire repaired", not "this step
/// succeeded". A runtime error after bridge calls, a hard host-bridge failure,
/// and an output-recording failure all persist a checkpoint through the same
/// atomic replay-and-tally transaction, so each is one committed healed turn.
/// Counting only the success path would under-report exactly the model whose
/// output is worst, and counting outside the transaction would let a durable
/// failed step be recorded without its signal (or vice versa).
#[test]
fn healed_failed_step_families_each_count_exactly_one_committed_turn() {
    let (_dir, vault) = open_test_vault();
    let lease = BudgetLease::for_test("executor-lease");
    let gated_write = gated_actor_write(&vault, "run-healed-failed-steps");
    let one_step = EngineExecutorLimits {
        soft_steps: 1,
        hard_steps: 1,
    };

    // 1. Runtime error after bridge calls, from a FENCED reply.
    let runtime_subject = seed_person(&vault, 0x71);
    let runtime_backend = FixtureBackend::new(["```js\nawait self.memory.write_fixture(c);\n```"]);
    let mut runtime_error = ErrorAfterCallsRuntime::new(vec![SelfCall::MemoryWriteFixture(
        SelfMemoryWriteFixtureCall::new(
            entity(0x72),
            ClaimCandidate::new(
                "profile.favorite_drink",
                ClaimSubject::Entity(runtime_subject),
                Value::from("matcha"),
                0.8,
            ),
            range(7),
            8,
        ),
    )]);
    let runtime_config = executor_config(entity(0x73), one_step);
    let mut executor = EngineNativeExecutor::new(
        &vault,
        &runtime_backend,
        &lease,
        &mut runtime_error,
        &gated_write,
    );
    block_on_ready(executor.run(&runtime_config)).expect_err("runtime error after bridge calls");
    drop(executor);
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        1,
        "a healed turn whose runtime failed after its bridge calls counts once"
    );

    // 2. Hard host-bridge failure, from an `<exec>`-WRAPPED reply.
    let bridge_backend =
        FixtureBackend::new(["<exec>\nawait self.memory.put_claim(claim);\n</exec>"]);
    let mut bridge_runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("unreachable")])
        .with_calls([vec![SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            entity(0x75),
            ClaimCandidate::new(
                "profile.favorite_place",
                // A subject that does not exist: the audited write fails.
                ClaimSubject::Entity(entity(0x74)),
                Value::from("tea house"),
                0.8,
            ),
            range(11),
            12,
        ))]]);
    let bridge_config = executor_config(entity(0x76), one_step);
    let mut executor = EngineNativeExecutor::new(
        &vault,
        &bridge_backend,
        &lease,
        &mut bridge_runtime,
        &gated_write,
    );
    block_on_ready(executor.run(&bridge_config)).expect_err("hard host bridge failure");
    drop(executor);
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        2,
        "a healed turn whose bridge call was refused counts once"
    );

    // 3. Output-recording failure after bridge calls, from a FENCED reply.
    let output_subject = seed_person(&vault, 0x77);
    let output_backend = FixtureBackend::new(["```js\nawait self.memory.write_fixture(c);\n```"]);
    let mut step_outcome = JsCodeModeStepOutcome::complete("done");
    step_outcome.outputs.push(JsCodeModeOutput::new(
        format!("{}.txt", "x".repeat(1100)),
        b"unreachable".to_vec(),
    ));
    let mut output_runtime =
        FixtureRuntime::new([step_outcome]).with_calls([vec![SelfCall::MemoryWriteFixture(
            SelfMemoryWriteFixtureCall::new(
                entity(0x78),
                ClaimCandidate::new(
                    "profile.favorite_snack",
                    ClaimSubject::Entity(output_subject),
                    Value::from("senbei"),
                    0.8,
                ),
                range(9),
                10,
            ),
        )]]);
    let output_config = executor_config(entity(0x79), one_step);
    let mut executor = EngineNativeExecutor::new(
        &vault,
        &output_backend,
        &lease,
        &mut output_runtime,
        &gated_write,
    );
    block_on_ready(executor.run(&output_config)).expect_err("output recording failure");
    drop(executor);
    assert_eq!(
        vault
            .code_run_model_heal_count(&model())
            .expect("heal count")
            .healed_turns,
        3,
        "a healed turn whose output recording failed counts once"
    );

    // Every one of those three steps is durable, each with its own checkpoint.
    for config in [&runtime_config, &bridge_config, &output_config] {
        assert_eq!(
            vault
                .get_code_run_replay_record(&config.run_id)
                .expect("load replay")
                .expect("failed step is durable")
                .step_checkpoints
                .len(),
            1,
        );
    }
}

// ─── ONE-1314 · lineage crosses the resume, host-internally ─────────────────

/// Appends one already-recorded bridge call to the run's DURABLE history,
/// exactly as a step that parked on that effect would have left it.
fn append_durable_bridge_call(
    vault: &Vault,
    run_id: EntityId,
    call: &SelfCall,
    outcome: &SelfDispatchOutcome,
) {
    let mut record = vault
        .get_code_run_replay_record(&run_id)
        .expect("load replay")
        .expect("stored replay");
    let generation = record.generation().expect("replay generation");
    let seq = record.bridge_calls.len() as u64;
    let at_ms = determinism().frozen_unix_ms.saturating_add(seq);
    record.bridge_calls.push(
        CodeRunBridgeCall::record(seq, call, outcome, at_ms, at_ms).expect("bridge call row"),
    );
    vault
        .put_code_run_replay_record_if_generation(&record, Some(generation))
        .expect("append durable bridge call");
}

/// Runs one step that dispatches a claim write, resuming the given run under a
/// FRESH gated write, and returns the landed claim's evidence entries.
fn resume_with_claim_write(
    vault: &Vault,
    config: &EngineExecutorConfig,
    run_ref: &str,
    claim: EntityId,
    subject: EntityId,
) -> Vec<(Value, Value)> {
    let lease = BudgetLease::for_test("executor-lease");
    let backend = FixtureBackend::new(["await self.memory.put_claim(candidate);"]);
    let candidate = ClaimCandidate::new(
        "profile.favorite_drink",
        ClaimSubject::Entity(subject),
        Value::from("sencha"),
        0.9,
    );
    let mut runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::complete("written")]).with_calls([vec![
            SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(claim, candidate, range(5), 6)),
        ]]);
    // FRESH dispatcher: nothing about the earlier step survives in memory, so
    // whatever lineage this write carries came from the durable record.
    let gated_write = gated_actor_write(vault, run_ref);
    let mut executor =
        EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, &gated_write);
    let outcome = block_on_ready(executor.run(config)).expect("resumed run");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);

    let stored = vault
        .get_claim(&claim)
        .expect("read claim")
        .expect("stored claim");
    let Some(Value::Map(evidence)) = stored.evidence else {
        panic!("expected write envelope evidence");
    };
    evidence
}

fn evidence_lineage_members(evidence: &[(Value, Value)]) -> Option<Vec<String>> {
    let entry = evidence.iter().find_map(|(key, value)| {
        (key.as_str() == Some(crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_LINEAGE_KEY))
            .then_some(value)
    })?;
    let Value::Array(members) = entry else {
        panic!("lineage evidence is an array of source strings");
    };
    Some(
        members
            .iter()
            .map(|member| member.as_str().expect("source string").to_owned())
            .collect(),
    )
}

/// Runs the first, yielding step of a two-step lineage fixture.
fn park_first_step(vault: &Vault, config: &EngineExecutorConfig, run_ref: &str) {
    let lease = BudgetLease::for_test("executor-lease");
    let backend = FixtureBackend::new(["const first = true;"]);
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::pending("first observation")]);
    let gated_write = gated_actor_write(vault, run_ref);
    let mut executor =
        EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, &gated_write);
    let outcome = block_on_ready(executor.run(config)).expect("first run");
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 }
    );
}

/// `lineage_tamper_rejected`, runtime arm.
///
/// A run that reached OUTSIDE cannot come back after the resume and write as
/// if it never had. An outbound effect parks its step, so the write always
/// lands in a later step against a fresh dispatcher; the durable bridge-call
/// history is the only record of the hop, and the executor stamps the write
/// from it host-internally — nothing in the guest call, and nothing the guest
/// authored, participates.
#[test]
fn lineage_tamper_rejected() {
    let (_dir, vault) = open_test_vault();
    let subject = seed_person(&vault, 0xD1);
    let claim = entity(0xD2);
    let config = executor_config(
        entity(0xD3),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 3,
        },
    );

    park_first_step(&vault, &config, "run-lineage-outbound");
    append_durable_bridge_call(
        &vault,
        config.run_id,
        &SelfCall::OutboundFixture(crate::code_run::SelfFixtureEffectCall::new("send message")),
        &SelfDispatchOutcome::DurableWait(SelfDurableWait {
            wait_id: entity(0xD4),
            effect: SelfEffect::OutboundFixture,
            reason: SelfDurableWaitReason::OutboundEffect,
            prompt: Some("send message".to_owned()),
        }),
    );

    let evidence = resume_with_claim_write(&vault, &config, "run-lineage-outbound", claim, subject);
    let lineage = evidence_lineage_members(&evidence)
        .expect("the post-resume write carries the durable history's lineage");
    assert!(lineage.contains(&crate::ClaimSource::Generated.as_str().to_owned()));
    assert!(
        lineage.contains(&crate::ClaimSource::ToolOutput.as_str().to_owned()),
        "the parked outbound hop rides the write that resumed after it"
    );

    let stored = vault
        .get_claim(&claim)
        .expect("read claim")
        .expect("stored claim");
    assert_eq!(
        stored.source,
        Some(crate::ClaimSource::Generated),
        "the host-bound declaration is unchanged; lineage is the second axis"
    );
}

/// NEG arm: a run whose durable history is only memory reads stays trivially
/// `Generated`. Memory access is not a tool effect.
#[test]
fn lineage_stays_trivial_without_an_external_effect() {
    let (_dir, vault) = open_test_vault();
    let subject = seed_person(&vault, 0xD5);
    let claim = entity(0xD6);
    let config = executor_config(
        entity(0xD7),
        EngineExecutorLimits {
            soft_steps: 1,
            hard_steps: 3,
        },
    );

    park_first_step(&vault, &config, "run-lineage-reads-only");
    append_durable_bridge_call(
        &vault,
        config.run_id,
        &SelfCall::MemorySearch(crate::code_run::SelfMemorySearchCall::new("tea", 1)),
        &SelfDispatchOutcome::MemorySearch(crate::code_run::SelfMemorySearchResult {
            query: "tea".to_owned(),
            results: Vec::new(),
        }),
    );

    let evidence =
        resume_with_claim_write(&vault, &config, "run-lineage-reads-only", claim, subject);
    assert!(
        evidence_lineage_members(&evidence).is_none(),
        "a read-only history stamps no lineage entry at all"
    );
}
