#![cfg(all(oneiron_test_support, feature = "code-sandbox-wasmtime"))]
//! [ADMITTED-SKILL-CALL-LARGE-POST-VIEW-SPILL] (FIX-LIST 29927): an admitted
//! `self.skills.call` whose post-hook view is larger than one reply spills
//! that view and binds it to the run as a readable result; a small view
//! stays inline.
//!
//! - `an_admitted_skill_call_spills_a_large_post_hook_view_to_a_readable_card`:
//!   a 600 KiB answer with a small title under a live Redact post hook. The
//!   reply is a readable `r1` card, not the view inline; reading the card
//!   back serves the redacted view (the whole text, no title); the run's
//!   record holds one view-served row and binds `r1` to the spilled view,
//!   while the real answer stays record-only under no binding. Red without
//!   the fix: the reply is the 600 KiB view inline, with `text` and no
//!   `handle`.
//! - `an_admitted_skill_call_keeps_a_small_post_hook_view_inline`: the same
//!   skill and hook with a 100-byte answer. The reply is the redacted view
//!   inline (no `handle`, the text, no title). Green with and without the
//!   fix.
//! - `an_admitted_deep_answer_is_judged_by_its_outer_post_hook_as_text`
//!   ([SKILL-ANSWER-DEEP-JSON-STACK-SAFE] part 2b): an answer with the
//!   title and 150 arrays nested under `deep`, past what a value may hold,
//!   under the same Redact. The facade's post chain judges it as JSON text:
//!   the reply is the readable `r1` card of the redacted view, which reads
//!   back with no title and its whole depth, while the real answer stays
//!   record-only under no binding. Red at the red pin (the admitted entry's
//!   refusal of a deep answer put back): the call is refused, "nests too
//!   deep".
//!
//! The run is the seeded default agent's root run, leased and registered
//! live through `oneiron_server::test_doors::live_run_step`; its own agent's
//! credential attaches over `POST /v1/core/live-runs/{run}/attach`, as
//! `tests/skill_pack_load_doors.rs` does. Skills run on the checked-in
//! production QuickJS host the test binds.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test admitted_skill_call_large_view_spill`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::agent_def::AgentDefinition;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, SpendScopeId, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{CapabilitySlip, MachineRole, holder_proof_challenge};
use oneiron::code_run::{CODE_RUN_RNG_SEED_LEN, CodeRunDeterminism};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::engine_executor::{
    EngineExecutorConfig, EngineExecutorLimits, JsCodeModeRuntime, RESULT_REPLY_INLINE_BYTES,
};
use oneiron::federation::{Scope as SlipScope, ScopeAxis};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{
    AttemptQueue, BudgetLease, EntityId, FatalLlmError, LlmBackend, LlmGenerateFuture, LlmRequest,
    LlmStreamResult, ModelId, ModelLocality, ModelTierRef, Vault, VaultConfig, WriteActor,
};
use oneiron_agent_runtime::code_sandbox::quickjs::QuickJsRuntimeFactory;
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::mcp::{
    CodeRunLimits, McpCodeModeProvider, McpEngineNativeCodeHost, bind_mcp_code_execution_host,
    checked_in_quickjs_runtime,
};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::live_run_step::register_live_run;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// The model the run executes on.
const MODEL: &str = "fixture/model@1";
/// The run's budget: roomy enough that no write here meets its cap.
const RUN_UNITS: u64 = 1_000_000;
/// The lease owner the test claims the run's try as, as a pump holds it.
const WORKER: &str = "admitted-skill-call-large-view-spill";
/// The large answer's padding: its redacted view is past the inline size
/// but under any hook input cap.
const BIG_BYTES: usize = 600_000;
/// The small answer's padding: its redacted view stays inline.
const SMALL_BYTES: usize = 100;
/// The deep answer's nesting: arrays around `0` under `deep`, past the
/// depth a value may hold (127).
const DEEP_LEVELS: usize = 150;

/// The test's code host provider: the checked-in production QuickJS
/// component, so skills run real JS, over a backend that answers nothing.
struct SkillProvider {
    factory: Arc<QuickJsRuntimeFactory>,
    backend: SilentBackend,
    lease: BudgetLease,
}

impl McpCodeModeProvider for SkillProvider {
    fn production_runtime_available(&self) -> bool {
        true
    }

    fn backend(&self) -> &dyn LlmBackend {
        &self.backend
    }

    fn lease(&self) -> &BudgetLease {
        &self.lease
    }

    fn runtime(&self) -> Box<dyn JsCodeModeRuntime + Send> {
        Box::new(self.factory.runtime().expect("a skill runtime"))
    }

    /// A fixed fixture config, as the other code host fixtures give: the
    /// skill-call door reads only the runtime and code check, never this.
    fn executor_config(
        &self,
        _: &Vault,
        run_id: EntityId,
        task: &str,
    ) -> oneiron::Result<EngineExecutorConfig> {
        Ok(EngineExecutorConfig {
            run_id,
            task: task.to_owned(),
            prompt_package_root: oneiron::prompt::workspace_test_prompt_package_root()
                .expect("workspace test prompt package"),
            model: ModelId::new(MODEL).expect("fixture model id"),
            model_locality: ModelLocality::OnDevice,
            seat_effort: None,
            global_tier: ModelTierRef("fixture-tier".to_owned()),
            determinism: CodeRunDeterminism::new(1_000, [7; CODE_RUN_RNG_SEED_LEN]),
            limits: EngineExecutorLimits::default(),
            wake: None,
        })
    }
}

/// A backend that answers nothing: skills run JS only and make no model
/// calls.
struct SilentBackend;

impl LlmBackend for SilentBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move { Err(FatalLlmError::InvalidRequest.into()) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The first 300 characters of `value`, for failure messages that never
/// dump 600 KiB.
fn short(value: &Value) -> String {
    value.to_string().chars().take(300).collect()
}

/// A served vault, one leased run of the default agent registered live, its
/// agent's own credential attached, and a Redact post hook on
/// `self.skills.call` hiding the answer's title.
struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    run: EntityId,
    slip: CapabilitySlip,
    holder: SigningKey,
    handle: String,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (owner, proof) = embedded_owner(&vault)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("admitted-skill-call-large-view-spill".into()),
                ..Default::default()
            },
        )?);

        // The checked-in production QuickJS host, so the skill runs real
        // JS. Bound once per process; parallel tests bind equivalent hosts.
        // Compiled off the async runtime, as its docs ask.
        let factory = tokio::task::spawn_blocking(checked_in_quickjs_runtime).await??;
        let provider = SkillProvider {
            factory: Arc::new(factory),
            backend: SilentBackend,
            lease: BudgetLease::for_test("admitted-skill-call-large-view-spill"),
        };
        let _bound = bind_mcp_code_execution_host(Arc::new(McpEngineNativeCodeHost::new(
            Arc::new(provider),
            CodeRunLimits::default(),
            Arc::default(),
        )));

        let (attempt, actor, definition, scope) = leased_run(&vault)?;
        let run = EntityId::now();
        register_live_run(
            &server,
            run,
            actor,
            &attempt,
            MODEL,
            definition,
            Some(scope),
        )?;

        // The run's own agent, on a credential of its own that reads and
        // writes, as `token agent` pairs one.
        let holder = SigningKey::from_bytes(&[0x7b; 32]);
        let mut claims = root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [0x7a; 32];
        claims.holder_ref = actor.entity_ref().to_hex();
        claims.binding_key = holder.verifying_key().to_bytes();
        claims.actor_class = Some("agent".to_owned());
        claims.scope = SlipScope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let slip = vault.mint_capability_slip(&issuer, claims)?;

        // A Redact post hook on the verb hiding the answer's title. The
        // facade post chain judges the whole answer unframed, so the path
        // is `/title`, as the engine's admitted skill-call tests bind it.
        oneiron::test_doors::typed_reply_handle::bind_redact_post_hook_for_actors(
            &vault,
            owner,
            &proof,
            "self.skills.call",
            Vec::new(),
        )?;
        oneiron::test_doors::typed_reply_handle::install_redact_runtime(
            &vault,
            vec!["/title".to_owned()],
        )?;

        let mut fixture = Self {
            app: build_app(server),
            vault,
            run,
            slip,
            holder,
            handle: String::new(),
            _dir: dir,
        };
        let (status, body) = fixture
            .post(
                &format!("/v1/core/live-runs/{}/attach", run.to_hex()),
                json!({}),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "the run's agent attaches: {body}");
        fixture.handle = body["liveRun"]
            .as_str()
            .ok_or("the attach answers a handle")?
            .to_owned();
        Ok(fixture)
    }

    /// A request signed by the agent's own holder key.
    async fn post(&self, path: &str, body: Value) -> TestResult<(StatusCode, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = self
            .holder
            .sign(&self.slip.binding_transcript(&challenge)?)
            .to_bytes();
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let request = Request::post(path)
            .header("authorization", format!("Bearer {}", self.slip.to_token()?))
            .header("x-oneiron-binding", binding.to_string())
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, body))
    }

    /// `self.skills.call` of `skill` with `bytes` padding on the attached
    /// run.
    async fn call(&self, skill: EntityId, bytes: usize) -> TestResult<(StatusCode, Value)> {
        self.post(
            "/v1/core/facade/self.skills.call",
            json!({
                "live_run": self.handle,
                "spec": {"skill": skill.to_hex(), "args": {"bytes": bytes}},
            }),
        )
        .await
    }

    /// The active callable whose answer is `title` and a `text` of
    /// `skillArgs.bytes` bytes of `b`.
    fn large_skill(&self) -> TestResult<EntityId> {
        Ok(oneiron::test_doors::callable_skill::put_active_callable(
            &self.vault,
            "fixture.large-view",
            "finish(JSON.stringify({title:\"secret-title-7\",text:\"b\".repeat(skillArgs.bytes)}));",
            &serde_json::json!({"bytes": "integer"}),
            &serde_json::json!({"title": "string", "text": "string"}),
        )?)
    }

    /// The active callable whose answer is `title` and `deep`,
    /// [`DEEP_LEVELS`] arrays around `0`.
    fn deep_skill(&self) -> TestResult<EntityId> {
        Ok(oneiron::test_doors::callable_skill::put_active_callable(
            &self.vault,
            "fixture.deep-view",
            &format!(
                "let deep = 0;for (let i = 0; i < {DEEP_LEVELS}; i++) deep = [deep];finish(JSON.stringify({{title:\"secret-title-7\",deep}}));"
            ),
            &serde_json::json!({"bytes": "integer"}),
            &serde_json::json!("object"),
        )?)
    }

    /// The whole text of the run's result `reference`, paged through its
    /// slices.
    fn read_result_text(&self, reference: &str) -> TestResult<String> {
        let mut input = json!({"bytes": [0]});
        let mut text = String::new();
        loop {
            let reply = self.vault.read_code_run_result(
                self.run,
                reference,
                Some(oneiron::code_run::ResultFacet::Slice),
                input,
                |_| Ok(false),
            )?;
            let piece = reply
                .get("output")
                .ok_or_else(|| format!("a slice serves its output: {}", short(&reply)))?;
            text.push_str(
                piece
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("a slice serves text: {}", short(&reply)))?,
            );
            if piece.get("done").and_then(Value::as_bool).unwrap_or(false) {
                break;
            }
            input = piece
                .get("next")
                .cloned()
                .ok_or_else(|| format!("an unfinished slice names its next: {}", short(&reply)))?;
        }
        Ok(text)
    }
}

/// The leased try of a root run of the seeded default agent, dispatched with
/// a budget so it spends under a scope of its own: the try, the run's actor,
/// its frozen definition and its scope.
fn leased_run(
    vault: &Vault,
) -> TestResult<(AttemptRecord, WriteActor, AgentDefinition, SpendScopeId)> {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let dispatcher = AgentDispatcher::new(vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatcher.dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some(WORKER.to_owned()),
            now: 1,
        },
        AgentSpawnContext::default()
            .with_depth_remaining(1)
            .with_budget(RUN_UNITS),
    )?
    else {
        return Err("expected one fresh root run".into());
    };
    let actor = agent_dispatch_actor(&status.input)?;
    let queue = AttemptQueue::new(vault);
    let mut leased = None;
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == status.attempt.id {
            leased = queue.get(row.id)?;
            break;
        }
    }
    let leased = leased.ok_or("the run's try is ready to claim")?;
    let scope = dispatcher
        .spend_scope_for_attempt(leased.id)?
        .ok_or("the budgeted run spends under a scope")?;
    Ok((leased, actor, status.input.definition, scope))
}

#[test]
fn an_admitted_skill_call_spills_a_large_post_hook_view_to_a_readable_card() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let skill = fixture.large_skill()?;
        let redacted = serde_json::json!({"text": "b".repeat(BIG_BYTES)}).to_string();
        assert!(
            redacted.len() > RESULT_REPLY_INLINE_BYTES,
            "the fixture's redacted view is past the inline size"
        );
        let (status, body) = fixture.call(skill, BIG_BYTES).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "the admitted skill call answers: {}",
            short(&body)
        );
        // Red without the fix: the reply is the redacted view inline, a
        // 600 KiB object with `text` and no `handle`.
        let handle = body
            .get("handle")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                panic!(
                    "a large post-hook view spills to a card, not inline: {}",
                    short(&body)
                )
            });
        assert!(
            body.get("text").is_none(),
            "a spilled view answers its card, not its bytes: {}",
            short(&body)
        );
        assert_eq!(
            body.get("name").and_then(Value::as_str),
            Some("r1"),
            "the card binds the run's first free name: {}",
            short(&body)
        );
        // Reading the card back serves the redacted view: the whole text,
        // no title.
        let view: Value = serde_json::from_str(&fixture.read_result_text("r1")?)?;
        assert!(
            view.get("title").is_none(),
            "the card serves the redacted view: {}",
            short(&view)
        );
        assert_eq!(
            view.get("text").and_then(Value::as_str).map(str::len),
            Some(BIG_BYTES)
        );
        // The run's record: one view-served row and one binding naming the
        // card's body, while the real answer stays record-only under no
        // binding.
        let record = fixture
            .vault
            .get_code_run_replay_record(&fixture.run)?
            .ok_or("the run keeps its record")?;
        assert_eq!(record.bridge_calls.len(), 1);
        assert!(
            record.bridge_calls[0].hook_view_served,
            "the row stands as a view-served row"
        );
        assert_eq!(record.bindings.len(), 1);
        assert_eq!(record.bindings[0].name, "r1");
        assert_eq!(record.bindings[0].handle, handle);
        assert!(
            !record.bindings[0].path.ends_with(".record-only.json"),
            "the binding names the spilled view, not the real body"
        );
        let real = record
            .outputs
            .iter()
            .find(|output| output.path.ends_with(".record-only.json"))
            .ok_or("the real answer records record-only")?;
        assert!(
            record
                .bindings
                .iter()
                .all(|binding| binding.handle != real.handle),
            "no binding names the real answer's body"
        );
        Ok(())
    })
}

#[test]
fn an_admitted_skill_call_keeps_a_small_post_hook_view_inline() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let skill = fixture.large_skill()?;
        let (status, body) = fixture.call(skill, SMALL_BYTES).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "the admitted skill call answers: {body}"
        );
        assert!(
            body.get("handle").is_none(),
            "a small post-hook view stays inline, not a card: {body}"
        );
        assert!(
            body.get("title").is_none(),
            "the inline view is redacted: {body}"
        );
        assert_eq!(
            body.get("text").and_then(Value::as_str).map(str::len),
            Some(SMALL_BYTES)
        );
        Ok(())
    })
}

#[test]
fn an_admitted_deep_answer_is_judged_by_its_outer_post_hook_as_text() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let skill = fixture.deep_skill()?;
        let (status, body) = fixture.call(skill, 0).await?;
        // Red at the red pin: the call is refused, "nests too deep".
        assert_eq!(
            status,
            StatusCode::OK,
            "the admitted deep answer is judged, not refused: {}",
            short(&body)
        );
        assert_eq!(
            body.get("name").and_then(Value::as_str),
            Some("r1"),
            "a view too deep for a value answers its card: {}",
            short(&body)
        );
        let view = fixture.read_result_text("r1")?;
        assert!(
            !view.contains("secret-title-7"),
            "the card serves the redacted view: {}",
            view.chars().take(300).collect::<String>()
        );
        assert!(
            view.contains(&format!(
                "{}0{}",
                "[".repeat(DEEP_LEVELS),
                "]".repeat(DEEP_LEVELS)
            )),
            "the view keeps its whole depth"
        );
        // The run's record: one view-served row and one binding naming the
        // card's body, while the real answer stays record-only under no
        // binding.
        let record = fixture
            .vault
            .get_code_run_replay_record(&fixture.run)?
            .ok_or("the run keeps its record")?;
        assert_eq!(record.bridge_calls.len(), 1);
        assert!(
            record.bridge_calls[0].hook_view_served,
            "the row stands as a view-served row"
        );
        assert_eq!(record.bindings.len(), 1);
        assert!(
            !record.bindings[0].path.ends_with(".record-only.json"),
            "the binding names the spilled view, not the real body"
        );
        let real = record
            .outputs
            .iter()
            .find(|output| output.path.ends_with(".record-only.json"))
            .ok_or("the real answer records record-only")?;
        assert!(
            record
                .bindings
                .iter()
                .all(|binding| binding.handle != real.handle),
            "no binding names the real answer's body"
        );
        Ok(())
    })
}
