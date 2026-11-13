#![cfg(oneiron_test_support)]
//! [RUN-STEP-DOOR-SERVER-TEST] (FIX-LIST 23040, 23150, 23621): `ai.steps.submit`
//! on an agent's attached live run, through the server's facade, with a paid
//! provider behind it.
//!
//! - A step's physical calls spend on the run's own scope: its answer, and
//!   a paid attempt that failed after it went out, which pays its
//!   reservation, are both booked there.
//! - The attachment is asked again before each physical admission: a
//!   credential revoked after the first attempt went out sends no retry.
//! - A credential revoked while the provider call is in flight gets no
//!   answer and sends no retry; what the call spent is still booked on the
//!   run's scope.
//!
//! The run is the seeded default agent's root run, dispatched with a budget
//! and leased. `oneiron_server::test_doors::live_run_step` registers it as
//! the pump's entry does, and the agent's own credential attaches over
//! `POST /v1/core/live-runs/{run}/attach`. Run with:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test run_step_live_run`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::agent_def::AgentModel;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, SpendScopeId, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::{Scope as SlipScope, ScopeAxis};
use oneiron::llm::Scope;
use oneiron::llm::model_step::{
    ModelStepReceipt, ModelStepResult, ModelStepRetryPolicy, ModelStepSubmitRequest,
};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{
    AttemptQueue, CallClass, CallEnvelope, CallPurpose, ContentPart, EntityId, LlmMessage,
    LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence, Vault, VaultConfig,
};
use oneiron_server::ai_host::AiHost;
use oneiron_server::build_app;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::live_run_step::register_live_run;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// The paid model the step names: provider `paid`, model `step-model`, at
/// the provider's revision.
const MODEL: &str = "paid/step-model@r1";
/// The run's budget: roomy enough that no call here meets its cap.
const RUN_UNITS: u64 = 1_000_000;
/// The lease owner the test claims the run's try as, as a pump holds it.
const WORKER: &str = "run-step-live-run";
/// The slip id of the agent's own credential, so the test can revoke it.
const AGENT_SLIP: [u8; 32] = [0x5a; 32];
/// Attempts a retrying step may make: past the schedule's 250, 1000 and
/// 4000 ms, the fifth goes out about 9.25 s after the first, after the at
/// most 6.25 s a failed provider's offer rests.
const RETRYING: ModelStepRetryPolicy = ModelStepRetryPolicy { max_attempts: 5 };
/// One attempt and no retry.
const ONCE: ModelStepRetryPolicy = ModelStepRetryPolicy { max_attempts: 1 };

/// FakeLlm as a paid provider: keyed (`key_env`), so its calls are paid
/// work, on the operator's own server.
fn models_text(base_url: &str) -> String {
    format!(
        "default = \"paid:step-model\"\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.paid]\nkind = \"openai-compat\"\nbase_url = \"{base_url}\"\n\
         key_env = \"HOME\"\nrevision = \"r1\"\nlocality = \"own_server\"\n"
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A served vault, one leased run of the default agent spending under its
/// own scope, registered live, and its agent's own credential attached.
struct Fixture {
    app: Router,
    host: AiHost,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    model: FakeLlm,
    scope: SpendScopeId,
    slip: CapabilitySlip,
    holder: SigningKey,
    handle: String,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// `script`: the provider's replies, in order; past it, a 500.
    async fn new(script: Vec<Reply>) -> TestResult<Self> {
        let model = FakeLlm::start(script, None).await;
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (_owner, _owner_proof) = embedded_owner(&vault)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("run-step-live-run".into()),
                ..Default::default()
            },
        )?;
        let models = ModelsConfig::from_toml(&models_text(&model.base_url), None)?;
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        let server = Arc::new(server);

        let (leased, actor, mut definition, scope) = leased_run(&vault)?;
        definition.models = vec![AgentModel {
            model_ref: ModelId::new(MODEL)?,
            when: "all model steps".to_owned(),
        }];
        let run = EntityId::now();
        register_live_run(
            &server,
            run,
            actor,
            &leased,
            MODEL,
            definition,
            Some(scope.clone()),
        )?;

        // The run's own agent, on a credential of its own that reads and
        // writes, as `token agent` pairs one.
        let holder = SigningKey::from_bytes(&[0x5b; 32]);
        let mut claims = root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = AGENT_SLIP;
        claims.holder_ref = actor.entity_ref().to_hex();
        claims.binding_key = holder.verifying_key().to_bytes();
        claims.actor_class = Some("agent".to_owned());
        claims.scope = SlipScope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let slip = vault.mint_capability_slip(&issuer, claims)?;

        let mut fixture = Self {
            app: build_app(server),
            host,
            vault,
            issuer,
            model,
            scope,
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

    /// `ai.steps.submit` of step `key` on the attached run.
    async fn submit(
        &self,
        key: &str,
        retry: ModelStepRetryPolicy,
    ) -> TestResult<(StatusCode, Value)> {
        let input = ModelStepSubmitRequest {
            live_run: Some(self.handle.clone()),
            step_key: key.to_owned(),
            request: step_request()?,
            retry,
        };
        self.post(
            "/v1/core/facade/ai.steps.submit",
            serde_json::to_value(input)?,
        )
        .await
    }

    /// What the run's scope has booked.
    fn spent(&self) -> TestResult<u64> {
        Ok(AgentDispatcher::new(&self.vault)
            .spend_read(&self.scope)?
            .spent_units)
    }

    /// Requests the provider has received.
    fn sent(&self) -> usize {
        self.model.seen().len()
    }

    /// Revokes the agent's credential, as the owner's revoke does.
    fn revoke(&self) -> TestResult {
        Ok(self
            .vault
            .revoke_capability_slip(&self.issuer, AGENT_SLIP)?)
    }

    /// Resolves once the provider has received `count` requests.
    async fn wait_sent(&self, count: usize) -> TestResult {
        for _ in 0..3_000 {
            if self.sent() >= count {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Err(format!("the provider never received {count} request(s)").into())
    }

    async fn finish(self) {
        self.host.shutdown().await;
    }
}

/// The leased try of a root run of the seeded default agent, dispatched
/// with a budget so it spends under a scope of its own: the try, the run's
/// actor, its frozen definition and its scope.
fn leased_run(
    vault: &Vault,
) -> TestResult<(
    AttemptRecord,
    oneiron::WriteActor,
    oneiron::agent_def::AgentDefinition,
    SpendScopeId,
)> {
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

/// One text step on the paid model.
fn step_request() -> TestResult<LlmRequest> {
    Ok(LlmRequest {
        model: ModelId::new(MODEL)?,
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Scope::default(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: "finish this model step".to_owned(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    })
}

/// The receipt in `body`, which must have finished.
fn finished(status: StatusCode, body: &Value) -> TestResult {
    assert_eq!(status, StatusCode::OK, "the step answers: {body}");
    let receipt: ModelStepReceipt = serde_json::from_value(body.clone())?;
    assert!(
        matches!(receipt.result, Some(ModelStepResult::Finished { .. })),
        "the step finished: {body}"
    );
    Ok(())
}

#[test]
fn a_steps_answer_and_its_failed_paid_attempt_both_spend_on_the_runs_scope() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new(vec![
            Reply::text("the first step finished"),
            Reply::Status(500),
            Reply::text("the second step finished"),
        ])
        .await?;
        assert_eq!(fixture.spent()?, 0, "nothing is booked before a call");

        // One attempt that answers: its usage is booked on the run's scope.
        let (status, body) = fixture.submit("answered", ONCE).await?;
        finished(status, &body)?;
        assert_eq!(fixture.sent(), 1);
        let answered = fixture.spent()?;
        assert!(
            answered > 0,
            "the answered call's spend is on the run's scope"
        );

        // A paid attempt that went out and failed, then its retry, which
        // answers as the first step's did. The failed attempt pays its
        // reservation, on the same scope.
        let (status, body) = fixture.submit("retried", RETRYING).await?;
        finished(status, &body)?;
        assert_eq!(
            fixture.sent(),
            3,
            "the failed attempt and its one retry went out"
        );
        let retried = fixture.spent()? - answered;
        assert!(
            retried > answered,
            "the failed paid attempt's charge is booked beside its retry's answer: \
             the retried step booked {retried}, one answer {answered}"
        );
        fixture.finish().await;
        Ok(())
    })
}

#[test]
fn a_credential_revoked_after_the_first_attempt_went_out_sends_no_retry() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new(vec![
            Reply::Status(500),
            Reply::text("a retry the revoked run never sends"),
        ])
        .await?;

        // The first attempt goes out and fails; the step would retry it
        // once the offer's rest is over. The credential is revoked first.
        let (submitted, revoked) = tokio::join!(fixture.submit("revoked", RETRYING), async {
            fixture.wait_sent(1).await?;
            fixture.revoke()
        });
        revoked?;
        let (status, body) = submitted?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a call whose credential was revoked is refused: {body}"
        );
        assert_eq!(
            fixture.sent(),
            1,
            "the attachment is asked before the retry's admission, so no retry is sent"
        );
        fixture.finish().await;
        Ok(())
    })
}

#[test]
fn a_credential_revoked_while_its_call_is_in_flight_gets_no_answer_and_the_call_is_booked()
-> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new(vec![Reply::Hold {
            text: "an answer the revoked run never gets".to_owned(),
        }])
        .await?;

        let (submitted, revoked) = tokio::join!(fixture.submit("in-flight", RETRYING), async {
            fixture.model.wait_holding().await;
            let revoked = fixture.revoke();
            fixture.model.release();
            revoked
        });
        revoked?;
        let (status, body) = submitted?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a call whose credential was revoked in flight gets no answer: {body}"
        );
        assert_eq!(fixture.sent(), 1, "no retry is sent");
        assert!(
            fixture.spent()? > 0,
            "the paid call's spend is booked on the run's scope though the run got no answer"
        );
        fixture.finish().await;
        Ok(())
    })
}
