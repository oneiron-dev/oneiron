//! FIX OFF-RECORD-RUN-POLICY-REFUSAL-500: a session run's talk-only refusal
//! answers at `self.off_record.execute` as the caller's refusal, never as a
//! failure of the run.
//!
//! The owner's run in a stretch entered alone supersedes one claim with
//! another, a durable memory write, which an off-record session refuses
//! (canon `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:237`,
//! "Off-record runs still reject durable memory writes"). Calling again with
//! the same `run_ref` meets the same refusal, so the door answers 403
//! `FORBIDDEN` with the session's own advice, as its other doors answer the
//! talk-only refusal (`MemoryError::from` for `ErrorKind::OffRecordTalkOnly`),
//! and not 500 `INTERNAL_SERVER_ERROR` with "Call again with the same
//! run_ref". One test per way the run's program takes the refusal:
//! - it lets the rejection throw, so the guest's step failure carries none of
//!   the refusal's words (the step keeps the session's typed refusal);
//! - it catches the rejection and finishes, so the step ends on the typed
//!   refusal it met.
//!
//! The server runs the checked-in QuickJS component as its code-mode host,
//! its model a script that answers each call with the next program (the
//! fixture of `self_off_record_doors.rs`, OPUS-DOORS-PRIVACY #8696). The owner
//! calls on the host-root credential of a profiled install.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support
//! --test off_record_run_refusal_status`.

#![cfg(unix)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::code_run::CodeRunDeterminism;
use oneiron::engine_executor::{EngineExecutorConfig, EngineExecutorLimits};
use oneiron::llm::SingleRouteBackend;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, ContentPart, EntityId, FatalLlmError,
    FinishReason, LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, LlmResult, LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, Vault,
    VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::mcp::{CodeRunLimits, McpQuickJsProvider, checked_in_quickjs_runtime};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The runner's handle for the run each test enters.
const RUN: &str = "refusal-status-run";
/// What the talk-only refusal says.
const TALK_ONLY: &str = "is talk-only";
/// The session's own advice on the talk-only refusal.
const ON_RECORD_ADVICE: &str = "Start a separate on-record session.";

/// One served vault with a code-mode host: the owner on the host root of a
/// profiled install.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
}

/// One reply: its status and its JSON.
struct Reply {
    status: StatusCode,
    body: Value,
}

impl Reply {
    /// The body of a 200, or a failure naming the call and the reply.
    fn ok(self, call: &str) -> Value {
        assert_eq!(self.status, StatusCode::OK, "{call} answered {}", self.body);
        self.body
    }

    /// The refusal's `error.code`.
    fn code(&self) -> &str {
        self.body["error"]["code"].as_str().unwrap_or("")
    }

    /// The refusal's `error.message`.
    fn message(&self) -> &str {
        self.body["error"]["message"].as_str().unwrap_or("")
    }

    /// Whether one of the refusal's `error.suggestions` says `words`.
    fn suggests(&self, words: &str) -> bool {
        self.body["error"]["suggestions"]
            .as_array()
            .is_some_and(|suggestions| {
                suggestions
                    .iter()
                    .any(|suggestion| suggestion.as_str().is_some_and(|text| text.contains(words)))
            })
    }
}

/// The model of a code host: each call answers with the next scripted
/// program, and a call past the last one with a program that throws.
struct ScriptedModel {
    programs: Mutex<VecDeque<String>>,
}

impl SingleRouteBackend for ScriptedModel {
    fn preflight(&self, _request: &LlmRequest, _stream: bool) -> LlmResult<()> {
        Ok(())
    }
}

impl LlmBackend for ScriptedModel {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let text = self
            .programs
            .lock()
            .expect("the scripted programs")
            .pop_front()
            .unwrap_or_else(|| {
                "throw new Error('the scripted model has no program left');".to_owned()
            });
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text,
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

/// A served vault whose server runs the checked-in QuickJS component as its
/// code-mode host, its model answering each call with the next of
/// `programs`. The vault holds no model manifest, so a run takes the
/// configured model with no seat.
fn code_host(programs: &[&str]) -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    config.dimensions = 4;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    // The component compiles and passes its readiness probe: blocking work,
    // kept off the runtime's other tasks.
    let runtime = tokio::task::block_in_place(checked_in_quickjs_runtime)
        .expect("the checked-in QuickJS component passes its readiness probe");
    let model = Arc::new(ScriptedModel {
        programs: Mutex::new(
            programs
                .iter()
                .map(|program| (*program).to_owned())
                .collect(),
        ),
    });
    let provider = McpQuickJsProvider::new(
        Arc::new(runtime),
        model,
        BudgetGuard::new(
            "off-record-run-refusal-status",
            1_000_000,
            BudgetExhaustionPolicy::Suspend,
        ),
        EngineExecutorConfig {
            run_id: EntityId::now(),
            task: "template".to_owned(),
            prompt_package_root: oneiron::prompt::workspace_test_prompt_package_root()
                .expect("the workspace test prompt package"),
            model: ModelId::new("fixture/refusal-status@v1").expect("a model id"),
            model_locality: ModelLocality::OnDevice,
            seat_effort: None,
            global_tier: ModelTierRef("fixture".to_owned()),
            determinism: CodeRunDeterminism::new(1_719_000_001_000, [0x5e; 32]),
            limits: EngineExecutorLimits::default(),
            wake: None,
        },
    )
    .expect("the QuickJS code-mode provider");
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("off-record-run-refusal-status".into()),
            ..Default::default()
        },
    )
    .expect("create server")
    .with_mcp_quickjs_provider(provider, CodeRunLimits::default());
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    Host {
        _dir: dir,
        vault,
        app: build_app(Arc::new(server)),
        issuer,
        owner_slip,
        owner_token,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Host {
    /// The owner's call to `verb` at its facade route.
    async fn send(&self, verb: &str, input: Value) -> Reply {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = hex(&self
            .issuer
            .binding_proof(&self.owner_slip, &challenge)
            .expect("owner holder proof"));
        let binding =
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string();
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", binding)
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("the app's response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the response body");
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{verb} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        Reply { status, body }
    }

    /// The owner starts a stretch alone under `name`, off record; the handle
    /// later calls name it by.
    async fn start(&self, name: &str) -> String {
        let view = self
            .send(
                "vault.off_record.start",
                json!({"session_ref": name, "mode": "off_record", "backend": "local"}),
            )
            .await
            .ok("vault.off_record.start");
        view["session_ref"]
            .as_str()
            .expect("the stretch's handle")
            .to_owned()
    }

    /// The owner's run of the scripted program in a fresh stretch entered
    /// alone under `name`: the door's answer.
    async fn execute(&self, name: &str) -> Reply {
        let session = self.start(name).await;
        self.send(
            "self.off_record.execute",
            json!({
                "session_ref": session,
                "run_ref": RUN,
                "task": "supersede one claim with another",
            }),
        )
        .await
    }
}

/// The program's durable write: one claim superseded by another.
fn supersede_call() -> String {
    format!(
        "vault.claims.supersede({{newId: {:?}, oldId: {:?}, now: 1719000000}})",
        EntityId::now().to_hex(),
        EntityId::now().to_hex(),
    )
}

/// The door's answer is the talk-only refusal as the caller's: 403
/// `FORBIDDEN`, the refusal's own words and the session's advice, none of a
/// run failure's.
fn assert_answers_the_talk_only_refusal(reply: &Reply) {
    assert_eq!(
        reply.status,
        StatusCode::FORBIDDEN,
        "the run's durable write answers 403, not a run failure: {}",
        reply.body
    );
    assert_eq!(
        reply.code(),
        "FORBIDDEN",
        "the refusal's code is the session's: {}",
        reply.body
    );
    assert!(
        reply.message().contains(TALK_ONLY),
        "the refusal names the talk-only session: {}",
        reply.body
    );
    assert!(
        reply.suggests(ON_RECORD_ADVICE),
        "the refusal advises an on-record session: {}",
        reply.body
    );
    assert!(
        !reply.suggests("same run_ref"),
        "the refusal never advises calling again with the same run_ref: {}",
        reply.body
    );
}

/// A program that lets the session's refusal throw: the guest's step failure
/// carries none of its words, and the door still answers the typed refusal.
#[test]
fn a_talk_only_write_the_program_lets_throw_answers_forbidden() {
    run_on_engine_stack("off-record-refusal-uncaught", || async {
        let program = format!("await {};\nfinish(\"superseded\");", supersede_call());
        let host = code_host(&[program.as_str()]);
        let reply = host.execute("refusal-status-uncaught").await;
        assert_answers_the_talk_only_refusal(&reply);
    });
}

/// A program that catches the session's refusal and finishes: the step ends
/// on the typed refusal it met, and the door answers it as the caller's.
#[test]
fn a_talk_only_write_the_program_catches_answers_forbidden() {
    run_on_engine_stack("off-record-refusal-caught", || async {
        let program = format!(
            "try {{\n  await {};\n}} catch (refused) {{}}\nfinish(\"caught\");",
            supersede_call()
        );
        let host = code_host(&[program.as_str()]);
        let reply = host.execute("refusal-status-caught").await;
        assert_answers_the_talk_only_refusal(&reply);
    });
}
