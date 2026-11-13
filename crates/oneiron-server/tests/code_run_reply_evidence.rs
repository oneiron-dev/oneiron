#![cfg(oneiron_test_support)]
//! RAW-PROVIDER-EVIDENCE-READ (CODE-RUNTIME-02): `vault.code.reply_evidence`
//! reads the model reply a code run step received, as the executor kept it
//! before healing, as untrusted evidence, by byte range. The owner reads it
//! over the facade; a step with no kept reply and an unknown run read as
//! absent; a caller that is neither the owner, the run's actor nor a Steward
//! is refused.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test code_run_reply_evidence`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::code_run::{CodeRunDeterminism, GatedActorWrite};
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, EngineExecutorStatus, EngineNativeExecutor,
    JsCodeModeHost, JsCodeModeRuntime, JsCodeModeStep, JsCodeModeStepOutcome,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::ReplyAssertions;
use oneiron::prompt::workspace_test_prompt_package_root;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{
    BudgetLease, ContentPart, EdgeActorClass, EntityId, FatalLlmError, FinishReason, LlmBackend,
    LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmStreamResult,
    LlmUsage, ModelId, ModelLocality, ModelTierRef, TimeRange, Vault, VaultConfig, WriteActor,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const VERB_PATH: &str = "/v1/core/facade/vault.code.reply_evidence";
/// The reply as the model sent it: the program and a trailing comment the
/// executor keeps in the evidence.
const REPLY_TEXT: &str = "console.log('probe'); // reply evidence marker";

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

fn reply_message() -> LlmMessage {
    LlmMessage {
        role: LlmMessageRole::Assistant,
        content: vec![ContentPart::Text {
            text: REPLY_TEXT.to_owned(),
            signature: None,
        }],
    }
}

fn scripted_response() -> LlmResponse {
    LlmResponse {
        message: reply_message(),
        usage: LlmUsage::zero(),
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

/// One real executor turn of run `run_id` as `owner`: the scripted model
/// answers once, the step commits, and the run yields.
fn run_one_turn(vault: &Vault, owner: EntityId, run_id: EntityId) {
    let config = EngineExecutorConfig {
        run_id,
        task: "keep the reply as evidence".to_owned(),
        prompt_package_root: workspace_test_prompt_package_root()
            .expect("workspace test prompt package"),
        model: ModelId::new("seat/generative_reasoner@1cadcf6de87a").expect("seat model id"),
        model_locality: ModelLocality::OwnServer,
        seat_effort: None,
        global_tier: ModelTierRef("executor-tier".to_owned()),
        determinism: CodeRunDeterminism::new(1_719_000_001_000, determinism_seed()),
        limits: EngineExecutorLimits { soft_steps: 1 },
        wake: None,
    };
    let backend = ScriptedBackend {
        response: scripted_response(),
    };
    let lease = BudgetLease::for_test("reply-evidence");
    let gated = GatedActorWrite::new(
        vault,
        WriteActor::new(owner, EdgeActorClass::Agent),
        "run-reply-evidence",
    )
    .expect("gated actor write");
    let mut runtime = PendingRuntime;
    let mut executor = EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, &gated);
    let outcome = block_on_ready(executor.run(&config)).expect("the turn runs");
    assert_eq!(
        outcome.status,
        EngineExecutorStatus::Yielded { next_step_seq: 1 },
        "one step commits, then the run yields",
    );
}

/// Who signs a request: the self-hosted root (the owner), or a holder key.
enum Caller<'a> {
    Owner,
    Holder(&'a CapabilitySlip, &'a SigningKey),
}

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    run: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, _owner_proof) = embedded_owner(&vault)?;
        let run = EntityId::now();
        run_one_turn(&vault, owner, run);
        let root = vault.ensure_host_root_slip(&issuer)?;
        let server = Arc::new(SyncServer::new(
            vault.clone(),
            SyncServerConfig {
                auth_secret: Some("code-run-reply-evidence".into()),
                ..Default::default()
            },
        )?);
        Ok(Self {
            app: build_app(server),
            vault,
            issuer,
            root,
            run,
            _dir: dir,
        })
    }

    /// A distinct person's `core:read` slip: no owner, not the run's actor,
    /// no Steward.
    fn stranger(&self) -> TestResult<(CapabilitySlip, SigningKey)> {
        let person = EntityId::now();
        self.vault.put_entity(
            &person,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a person who did not run the code",
        )?;
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let mut claims = self.root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [0x71; 32];
        claims.holder_ref = person.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
        Ok((self.vault.mint_capability_slip(&self.issuer, claims)?, key))
    }

    async fn read(&self, caller: &Caller<'_>, input: Value) -> TestResult<(u16, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let (slip, signature) = match caller {
            Caller::Owner => (
                &self.root,
                self.issuer.binding_proof(&self.root, &challenge)?,
            ),
            Caller::Holder(slip, key) => (
                *slip,
                key.sign(&slip.binding_transcript(&challenge)?)
                    .to_bytes()
                    .to_vec(),
            ),
        };
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let request = Request::post(VERB_PATH)
            .header("authorization", format!("Bearer {}", slip.to_token()?))
            .header("x-oneiron-binding", binding.to_string())
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status().as_u16();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, body))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The bytes a read served.
fn served_bytes(view: &Value) -> TestResult<Vec<u8>> {
    let encoded = view["body_base64"]
        .as_str()
        .ok_or("the read serves its bytes")?;
    Ok(base64::engine::general_purpose::STANDARD.decode(encoded)?)
}

#[test]
fn the_owner_reads_a_steps_kept_reply_as_untrusted_evidence() -> TestResult {
    on_engine_stack(owner_and_stranger_read_the_kept_reply)
}

async fn owner_and_stranger_read_the_kept_reply() -> TestResult {
    let fixture = Fixture::new()?;
    let run = fixture.run.to_hex();
    let owner = Caller::Owner;

    // The whole reply, as the model sent it, labelled untrusted.
    let (status, view) = fixture
        .read(&owner, json!({ "run_ref": run, "step": 0 }))
        .await?;
    assert_eq!(status, 200, "the owner reads the step's reply: {view}");
    assert_eq!(view["trust"], "untrusted", "{view}");
    assert_eq!(view["encoding"], "llm_message_json", "{view}");
    assert!(view["withheld"].is_null(), "{view}");
    assert_eq!(view["run_ref"], run, "{view}");
    assert_eq!(view["byte_offset"], 0, "{view}");
    assert!(
        view["next_byte_offset"].is_null(),
        "one read covers it: {view}"
    );
    let whole = served_bytes(&view)?;
    assert_eq!(view["total_bytes"], whole.len(), "{view}");
    let kept: LlmMessage = serde_json::from_slice(&whole)?;
    assert_eq!(
        kept,
        reply_message(),
        "the evidence is the reply before healing"
    );

    // By byte range: the first read names where the next starts, and the
    // two reads join to the whole.
    let (status, head) = fixture
        .read(
            &owner,
            json!({ "run_ref": run, "step": 0, "byte_limit": 16 }),
        )
        .await?;
    assert_eq!(status, 200, "{head}");
    assert_eq!(head["next_byte_offset"], 16, "{head}");
    let (status, rest) = fixture
        .read(
            &owner,
            json!({ "run_ref": run, "step": 0, "byte_offset": 16 }),
        )
        .await?;
    assert_eq!(status, 200, "{rest}");
    assert!(rest["next_byte_offset"].is_null(), "{rest}");
    let mut joined = served_bytes(&head)?;
    joined.extend(served_bytes(&rest)?);
    assert_eq!(joined, whole, "the ranges join to the whole reply");

    // Absent: a step the run kept no reply for, and a run that does not
    // exist.
    let (status, absent) = fixture
        .read(&owner, json!({ "run_ref": run, "step": 1 }))
        .await?;
    assert_eq!(status, 200, "{absent}");
    assert!(absent.is_null(), "no reply was kept for step 1: {absent}");
    let (status, absent) = fixture
        .read(
            &owner,
            json!({ "run_ref": EntityId::now().to_hex(), "step": 0 }),
        )
        .await?;
    assert_eq!(status, 200, "{absent}");
    assert!(absent.is_null(), "an unknown run is absent: {absent}");

    // A zero-byte read is a malformed request.
    let (status, refused) = fixture
        .read(
            &owner,
            json!({ "run_ref": run, "step": 0, "byte_limit": 0 }),
        )
        .await?;
    assert_eq!(status, 400, "{refused}");

    // A reader of the vault that is not the owner, the run's actor or a
    // Steward is refused, and served nothing.
    let (slip, key) = fixture.stranger()?;
    let (status, refused) = fixture
        .read(
            &Caller::Holder(&slip, &key),
            json!({ "run_ref": run, "step": 0 }),
        )
        .await?;
    assert_eq!(
        status, 403,
        "a stranger is refused the run's reply: {refused}"
    );
    assert!(refused.get("body_base64").is_none(), "{refused}");
    assert!(
        !refused.to_string().contains("reply evidence marker"),
        "{refused}"
    );
    Ok(())
}
