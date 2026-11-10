//! E2E CODE-RUNTIME-02: a code-run correction record names the model that answered.
//!
//! One engine-executor REPL turn runs against a scripted backend whose reply
//! carries a ladder served receipt. The correction read back through
//! `vault.code.corrections` names the receipt's `model_id` (the rung that
//! served the reply), not the run's configured seat model. A reply with a
//! bare receipt falls back to the configured model, and a reply the turn
//! refuses records the serving rung the same way.

#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use oneiron::code_run::{CodeRunDeterminism, GatedActorWrite};
use oneiron::consent::AuthenticatedOwner;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorOutcome, EngineExecutorResult,
    EngineExecutorStatus, EngineNativeExecutor, JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep,
    JsCodeModeStepOutcome,
};
use oneiron::llm::ReplyAssertions;
use oneiron::memory::code_run_doors::CodeRunCorrectionsRequest;
use oneiron::prompt::workspace_test_prompt_package_root;
use oneiron::store::GateDecisionId;
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, Vault, VaultConfig, WriteActor,
};

const CONFIGURED_MODEL_ID: &str = "seat/generative_reasoner@1cadcf6de87a";
const SERVED_MODEL_ID: &str = "code-rt02/code-runtime-fixture-v1@e2e-v1";

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("executor future unexpectedly pending"),
    }
}

struct ScriptedBackend {
    response: LlmResponse,
}

impl LlmBackend for ScriptedBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let response = self.response.clone();
        Box::pin(async move { Ok(response) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

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

fn served_receipt() -> serde_json::Value {
    serde_json::json!({
        "provider": "code-rt02",
        "requested_model": "code-runtime-fixture-v1",
        "rung": 0,
        "failed_rungs": 0,
        "model_id": SERVED_MODEL_ID,
        "usage": {},
    })
}

fn scripted_response(text: &str, raw_provider: serde_json::Value) -> LlmResponse {
    let mut usage = LlmUsage::zero();
    usage.raw_provider = raw_provider;
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: text.to_owned(),
                signature: None,
            }],
        },
        usage,
        finish_reason: FinishReason::Stop,
        reply_assertions: ReplyAssertions::default(),
        token_scores: None,
    }
}

fn determinism_seed() -> [u8; 32] {
    let mut seed = [0_u8; 32];
    seed[..16].copy_from_slice(EntityId::now().as_bytes());
    seed[16..].copy_from_slice(EntityId::now().as_bytes());
    seed
}

fn owner_vault() -> (tempfile::TempDir, Vault, EntityId, AuthenticatedOwner) {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    (dir, vault, owner, proof)
}

fn executor_config(run_id: EntityId) -> EngineExecutorConfig {
    EngineExecutorConfig {
        run_id,
        task: "name the serving model".to_owned(),
        prompt_package_root: workspace_test_prompt_package_root()
            .expect("workspace test prompt package"),
        model: ModelId::new(CONFIGURED_MODEL_ID).expect("seat model id"),
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(1_719_000_001_000, determinism_seed()),
        limits: EngineExecutorLimits { soft_steps: 1 },
        wake: None,
    }
}

fn run_single_turn(
    vault: &Vault,
    owner: EntityId,
    config: &EngineExecutorConfig,
    response: LlmResponse,
) -> EngineExecutorResult<EngineExecutorOutcome> {
    let backend = ScriptedBackend { response };
    let lease = BudgetLease::for_test("correction-model");
    let gated = GatedActorWrite::new(
        vault,
        WriteActor::new(owner, EdgeActorClass::Agent),
        "run-correction-model",
    )
    .expect("gated actor write");
    let mut runtime = PendingRuntime;
    let mut executor = EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, &gated);
    block_on_ready(executor.run(config))
}

fn step_zero_model_id(
    vault: &Vault,
    owner: EntityId,
    proof: &AuthenticatedOwner,
    run_id: EntityId,
) -> String {
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let page = memory
        .code_run_corrections_as(
            proof,
            CodeRunCorrectionsRequest {
                run_ref: run_id.to_hex(),
                after_step: None,
                limit: None,
            },
        )
        .expect("correction page");
    assert_eq!(page.records.len(), 1, "one response records one correction");
    assert_eq!(page.records[0].step, 0, "the record is step zero");
    page.records[0].model_id.clone()
}

#[test]
fn accepted_turn_records_the_serving_rung_model() {
    let (_dir, vault, owner, proof) = owner_vault();
    let run_id = EntityId::now();
    let config = executor_config(run_id);
    let outcome = run_single_turn(
        &vault,
        owner,
        &config,
        scripted_response("console.log('probe');", served_receipt()),
    )
    .expect("the accepted turn runs");
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 },
        "one step commits, then the run yields",
    );
    assert_eq!(
        step_zero_model_id(&vault, owner, &proof, run_id),
        SERVED_MODEL_ID,
    );
}

#[test]
fn bare_receipt_falls_back_to_the_configured_model() {
    let (_dir, vault, owner, proof) = owner_vault();
    let run_id = EntityId::now();
    let config = executor_config(run_id);
    let outcome = run_single_turn(
        &vault,
        owner,
        &config,
        scripted_response("console.log('probe');", serde_json::json!({})),
    )
    .expect("the accepted turn runs");
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 },
        "one step commits, then the run yields",
    );
    assert_eq!(
        step_zero_model_id(&vault, owner, &proof, run_id),
        CONFIGURED_MODEL_ID,
    );
}

#[test]
fn rejected_turn_records_the_serving_rung_model() {
    let (_dir, vault, owner, proof) = owner_vault();
    let run_id = EntityId::now();
    let config = executor_config(run_id);
    let outcome = run_single_turn(
        &vault,
        owner,
        &config,
        scripted_response(
            "<exec>\n<exec>\nconsole.log('must not run');\n</exec>\n</exec>",
            served_receipt(),
        ),
    );
    assert!(
        outcome.is_err(),
        "a reply with nested exec wrappers is refused by the normalizer"
    );
    assert_eq!(
        step_zero_model_id(&vault, owner, &proof, run_id),
        SERVED_MODEL_ID,
    );
}
