//! Both inference doors name the vault policy's typed refusal
//! (STEP-DOOR-REFUSAL-REASON): `ai.steps.submit` and `/v1/llm/generate`
//! refuse a call whose envelope says on device, for a model this host serves
//! at its own server, with the status each door had and the authorizer's
//! reason in the body. Nothing is sent.
#![allow(clippy::unwrap_used)]

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use fake_llm::{FakeLlm, Reply};
use oneiron::llm::model_step::{ModelStepRetryPolicy, ModelStepSubmit};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, LlmMessage, LlmRequest, ModelId, ModelLocality,
    ModelTierRef, ResponseFormat, TierPrecedence, Vault, VaultConfig,
};
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "owner";
const MODEL: &str = "local/reasoner@rev-a";
const REASON: &str = "model locality differs from bound transport";

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

/// One exact model on the scripted provider, served at the host's own server.
fn models(base_url: &str) -> ModelsConfig {
    ModelsConfig::from_toml(
        &format!(
            r#"
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

/// A text call to the exact model whose envelope says it runs on device.
fn on_device_call() -> LlmRequest {
    LlmRequest {
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
            locality: ModelLocality::OnDevice,
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
    }
}

/// A POST of `body` to `path`, signed by the host root's owner.
fn owner_post(vault: &Vault, path: &str, body: Vec<u8>) -> Request<Body> {
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
    Request::post(path)
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

async fn answer(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The step door keeps its 400 BAD_REQUEST and names the inference door's
/// code and reason; the raw door keeps its 400 `invalid_request` and names
/// the reason as its message. On main both bodies name neither.
#[test]
fn a_locality_refusal_names_its_reason_at_both_inference_doors() {
    on_engine_stack(|| async {
        let fake = FakeLlm::start(vec![], Some(Reply::text("unreached"))).await;
        let dir = tempfile::tempdir().unwrap();
        let (vault, app, host) = served(dir.path(), &models(&fake.base_url)).await;

        let step = ModelStepSubmit {
            step_key: "on-device-refused".into(),
            request: on_device_call(),
            retry: ModelStepRetryPolicy { max_attempts: 1 },
        };
        let (status, body) = answer(
            &app,
            owner_post(
                &vault,
                "/v1/core/facade/ai.steps.submit",
                serde_json::to_vec(&step).unwrap(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body:#}");
        assert_eq!(body["error"]["code"], "BAD_REQUEST", "{body:#}");
        let named = format!("refused this model-step request (invalid_request): {REASON}");
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(&named)),
            "{body:#}"
        );

        let (status, body) = answer(
            &app,
            owner_post(
                &vault,
                "/v1/llm/generate",
                serde_json::to_vec(&on_device_call()).unwrap(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body:#}");
        assert_eq!(
            body,
            json!({"error": {"code": "invalid_request", "message": REASON}}),
            "{body:#}"
        );

        assert!(fake.seen().is_empty(), "nothing is sent");
        host.shutdown().await;
    });
}
