//! A durable model step whose provider is down waits out its offer's health
//! rest without spending a declared attempt (FIX 11226): `ai.steps.submit`'s
//! `retry.max_attempts` counts the sends the step makes, and the rest still
//! holds the offer for every other call. A rest longer than one submission
//! waits parks the step, which resumes on its own once the offer is back.
//! A pass that stops mid-way keeps the sends it made.
#![allow(clippy::unwrap_used)]

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fake_llm::{FakeLlm, Reply};
use oneiron::llm::model_step::{self, ModelStepRetryPolicy, ModelStepSubmit};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose,
    FatalLlmError, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmMessage, LlmRequest,
    LlmStreamResult, ModelId, ModelLocality, ModelTierRef, ResponseFormat, RetryableLlmError,
    TierPrecedence, Vault, VaultConfig,
};
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "owner";
const MODEL: &str = "local/reasoner@rev-a";

/// Runs the test `make` builds on a runtime whose threads carry the engine's
/// stack ([`oneiron_server::ENGINE_THREAD_STACK_BYTES`]): the facade's
/// generated dispatch frames overflow a test thread's default stack (FIX
/// 16372).
fn on_engine_stack<F: std::future::Future<Output = ()>>(make: impl FnOnce() -> F + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(oneiron_server::ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(oneiron_server::ENGINE_THREAD_STACK_BYTES)
                .build()
                .unwrap()
                .block_on(make());
        })
        .unwrap()
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

/// One exact model on the scripted provider; `extra` is more of `[models]`.
fn models(base_url: &str, extra: &str) -> ModelsConfig {
    ModelsConfig::from_toml(
        &format!(
            r#"{extra}
[providers.local]
kind = "local-openai-compat"
base_url = "{base_url}"
revision = "rev-a"
timeout_secs = 5
[roles.generative_reasoner]
rungs = [{{ model = "local:reasoner" }}]
[dreamer]
enabled = false
"#
        ),
        None,
    )
    .unwrap()
}

/// The served app over a fresh vault, its AI host attached under `models`.
async fn served(
    dir: &std::path::Path,
    models: &ModelsConfig,
) -> (Arc<Vault>, axum::Router, AiHost) {
    let vault = Arc::new(Vault::open(dir, VaultConfig::device()).unwrap());
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some(SECRET.into()),
            ..Default::default()
        },
    )
    .unwrap();
    let (server, host) = AiHost::attach(server, Some(models)).await;
    (vault, build_app(Arc::new(server)), host)
}

/// `ai.steps.submit` as the host root's owner, for `step_key` with
/// `max_attempts` declared.
fn submit(vault: &Vault, step_key: &str, max_attempts: u8) -> Request<Body> {
    owner_post(
        vault,
        "ai.steps.submit",
        serde_json::to_vec(&step(step_key, max_attempts)).unwrap(),
    )
}

/// One text step to the exact model, for `step_key` with `max_attempts`
/// declared.
fn step(step_key: &str, max_attempts: u8) -> ModelStepSubmit {
    ModelStepSubmit {
        step_key: step_key.into(),
        request: LlmRequest {
            model: ModelId::new(MODEL).unwrap(),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Default::default(),
                purpose: CallPurpose::AnswerGen,
                class: CallClass::BestEffort,
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::AnswerGen,
                    ModelTierRef("global".into()),
                ),
                response_format: ResponseFormat::Text,
                locality: ModelLocality::OwnServer,
                host_keyless: false,
                host_paid: false,
            },
            messages: vec![
                serde_json::from_value::<LlmMessage>(
                    json!({"role": "user", "content": [{"kind": "text", "text": "hello"}]}),
                )
                .unwrap(),
            ],
            tools: vec![],
            params: Default::default(),
            provider_options: Default::default(),
            host_segments: None,
        },
        retry: ModelStepRetryPolicy { max_attempts },
    }
}

/// `ai.steps.receipt` as the host root's owner, for `step_key`.
fn read_receipt(vault: &Vault, step_key: &str) -> Request<Body> {
    owner_post(
        vault,
        "ai.steps.receipt",
        serde_json::to_vec(&json!({"step_key": step_key})).unwrap(),
    )
}

/// The facade `verb` with `body`, signed by the host root's owner.
fn owner_post(vault: &Vault, verb: &str, body: Vec<u8>) -> Request<Body> {
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
    let slip = vault.ensure_host_root_slip(&issuer).unwrap();
    let timestamp = vault.now_recorded_at();
    let nonce = oneiron::EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = issuer
        .binding_proof(&slip, challenge.as_bytes())
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Request::post(format!("/v1/core/facade/{verb}"))
        .header(
            "authorization",
            format!("Bearer {}", slip.to_token().unwrap()),
        )
        .header(
            "x-oneiron-binding",
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
        )
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn receipt(app: &axum::Router, request: Request<Body>) -> Value {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    assert_eq!(status, StatusCode::OK, "{body:#}");
    body
}

/// 503, then an answer, with three attempts declared: the 503 rests the
/// offer for its health (5 s on the shipped first rest), the step's first
/// retry meets the rest unsent and waits for it, spending nothing, and its
/// second send answers. On main the retries meet the rest, spend both
/// attempts unsent, and the step fails after one send.
#[test]
fn a_step_waits_out_its_offers_health_rest_and_sends_again() {
    on_engine_stack(|| async {
        let fake = FakeLlm::start(vec![Reply::Status(503), Reply::text("recovered")], None).await;
        let dir = tempfile::tempdir().unwrap();
        let (vault, app, host) = served(dir.path(), &models(&fake.base_url, "")).await;
        let body = receipt(&app, submit(&vault, "health-recovers", 3)).await;
        assert_eq!(fake.seen().len(), 2, "two sends: {body:#}");
        assert_eq!(body["result"]["status"], "finished", "{body:#}");
        assert!(body.to_string().contains("recovered"), "{body:#}");
        host.shutdown().await;
    });
}

/// Three 503s with three attempts declared and a one-second first rest
/// (`[models] health_rest_secs`): each send rests the offer, each retry waits
/// the rest out unsent, and the step sends three times before it fails.
#[test]
fn a_steps_declared_attempts_are_its_sends() {
    on_engine_stack(|| async {
        let fake = FakeLlm::start(
            vec![Reply::Status(503), Reply::Status(503), Reply::Status(503)],
            Some(Reply::text("unreached")),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let (vault, app, host) =
            served(dir.path(), &models(&fake.base_url, "health_rest_secs = 1")).await;
        let body = receipt(&app, submit(&vault, "health-exhausts", 3)).await;
        assert_eq!(fake.seen().len(), 3, "three sends: {body:#}");
        assert_eq!(body["result"]["status"], "failed", "{body:#}");
        assert_eq!(body["result"]["failure"]["class"], "retryable", "{body:#}");
        assert_eq!(
            body["result"]["failure"]["llm"],
            json!({"Retryable": "ServerError"}),
            "{body:#}"
        );
        host.shutdown().await;
    });
}

/// Reads the step's receipt until its result is no longer parked, for up to
/// `secs` seconds; the last receipt read.
async fn settled(app: &axum::Router, vault: &Vault, step_key: &str, secs: u64) -> Value {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        let body = receipt(app, read_receipt(vault, step_key)).await;
        let status = body["result"]["status"].clone();
        if (status != "parked" && !status.is_null()) || std::time::Instant::now() >= end {
            return body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// A rest longer than the submission waits (`[models] step_rest_wait_secs =
/// 0`) parks the step: the receipt says parked, with when the offer is back
/// and the one send made, and the receipt door says so too. Once the rest
/// ends the step resumes on its own and its second send answers.
#[test]
fn a_step_parks_past_its_rest_wait_and_resumes_on_its_own() {
    on_engine_stack(|| async {
        let fake = FakeLlm::start(vec![Reply::Status(503), Reply::text("resumed")], None).await;
        let dir = tempfile::tempdir().unwrap();
        let extra = "health_rest_secs = 2\nstep_rest_wait_secs = 0";
        let (vault, app, host) = served(dir.path(), &models(&fake.base_url, extra)).await;
        let body = receipt(&app, submit(&vault, "health-parks", 3)).await;
        assert_eq!(body["result"]["status"], "parked", "{body:#}");
        assert_eq!(body["result"]["sends"], 1, "{body:#}");
        assert!(
            body["result"]["until"].as_u64().unwrap() > vault.now_recorded_at(),
            "{body:#}"
        );
        assert_eq!(fake.seen().len(), 1, "{body:#}");
        let read = receipt(&app, read_receipt(&vault, "health-parks")).await;
        assert_eq!(read["result"]["status"], "parked", "{read:#}");
        let done = settled(&app, &vault, "health-parks", 20).await;
        assert_eq!(done["result"]["status"], "finished", "{done:#}");
        assert!(done.to_string().contains("resumed"), "{done:#}");
        assert_eq!(fake.seen().len(), 2, "{done:#}");
        host.shutdown().await;
    });
}

/// The sends a parked step made count against its declared attempts across
/// its resumes: three 503s with three attempts declared park the step twice,
/// and it fails on its third send in all, never three sends a resume.
#[test]
fn a_parked_steps_resumes_keep_its_declared_attempts() {
    on_engine_stack(|| async {
        let fake = FakeLlm::start(
            vec![Reply::Status(503), Reply::Status(503), Reply::Status(503)],
            Some(Reply::text("unreached")),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let extra = "health_rest_secs = 1\nstep_rest_wait_secs = 0";
        let (vault, app, host) = served(dir.path(), &models(&fake.base_url, extra)).await;
        let body = receipt(&app, submit(&vault, "health-park-exhausts", 3)).await;
        assert_eq!(body["result"]["status"], "parked", "{body:#}");
        let done = settled(&app, &vault, "health-park-exhausts", 30).await;
        assert_eq!(done["result"]["status"], "failed", "{done:#}");
        assert_eq!(done["result"]["failure"]["class"], "retryable", "{done:#}");
        assert_eq!(fake.seen().len(), 3, "{done:#}");
        host.shutdown().await;
    });
}

/// A first health rest outside one to sixty seconds is refused at load.
#[test]
fn a_health_rest_outside_its_range_is_refused() {
    for secs in [0, 61] {
        let text = format!(
            "health_rest_secs = {secs}\n[providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"http://127.0.0.1:9\"\n"
        );
        let error = ModelsConfig::from_toml(&text, None).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("health_rest_secs must be between 1 and 60"),
            "{secs}: {error}"
        );
    }
}

/// A provider whose every send fails 503, held off by its health rest once:
/// the rest is no send. `second_send` is told once the second send failed.
struct DownOnce {
    rests: Mutex<VecDeque<usize>>,
    sends: AtomicUsize,
    second_send: tokio::sync::Notify,
}

impl LlmBackend for DownOnce {
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let sends = self.sends.load(Ordering::SeqCst);
        let mut rests = self.rests.lock().unwrap();
        let error = if rests.front() == Some(&sends) {
            rests.pop_front();
            RetryableLlmError::HealthRest {
                retry_after: Some(60),
                resets_at: Vec::new(),
            }
        } else {
            if self.sends.fetch_add(1, Ordering::SeqCst) + 1 == 2 {
                self.second_send.notify_one();
            }
            RetryableLlmError::ServerError
        };
        Box::pin(async move { Err(LlmError::Retryable(error)) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// Review round 1 of #6966: a pass that stops mid-way keeps the sends it
/// made. Three attempts declared, no rest wait, and a provider down for
/// every send: the first pass sends once and parks on the offer's rest; the
/// second sends again and stops in its retry wait, as a host that stops
/// does; the third may send only once more. On the park's head the stopped
/// pass's send was never kept, and the third pass sends twice: four sends.
#[test]
fn a_stopped_pass_keeps_the_sends_it_made() {
    on_engine_stack(|| async {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _app, host) = served(dir.path(), &models("http://127.0.0.1:9", "")).await;
        let actor = vault.ensure_embedded_owner_actor().unwrap();
        let owner = vault
            .authenticate_owner(
                actor,
                &actor.to_hex(),
                true,
                oneiron::store::GateDecisionId::now(),
            )
            .unwrap();
        let guard = BudgetGuard::new("model-step", u64::MAX, BudgetExhaustionPolicy::default());
        let backend = DownOnce {
            rests: Mutex::new(VecDeque::from([1])),
            sends: AtomicUsize::new(0),
            second_send: tokio::sync::Notify::new(),
        };
        let pass = || {
            model_step::submit_as_owner(
                &vault,
                &owner,
                step("stopped-pass", 3),
                &backend,
                &guard,
                Duration::ZERO,
            )
        };
        let parked = serde_json::to_value(pass().await.unwrap()).unwrap();
        assert_eq!(parked["result"]["status"], "parked", "{parked:#}");
        assert_eq!(parked["result"]["sends"], 1, "{parked:#}");
        tokio::select! {
            biased;
            () = backend.second_send.notified() => {}
            stopped = pass() => panic!("the second pass ran to its end: {stopped:?}"),
        }
        assert_eq!(backend.sends.load(Ordering::SeqCst), 2);
        let done = serde_json::to_value(pass().await.unwrap()).unwrap();
        assert_eq!(done["result"]["status"], "failed", "{done:#}");
        assert_eq!(
            backend.sends.load(Ordering::SeqCst),
            3,
            "three attempts declared: {done:#}"
        );
        host.shutdown().await;
    });
}
