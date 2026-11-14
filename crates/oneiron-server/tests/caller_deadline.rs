//! The caller's own deadline on raw calls (census L9-23; ARCH-0036
//! #offers-quota-built: "the caller's own deadline on role, raw and chat
//! calls"; RULING CALLER-DEADLINE-WIRE = B). `POST /v1/llm/generate` and
//! `POST /v1/llm/stream` take `deadline_ms`, the memory proxy's field (FIX
//! 8189), on the proxy's one clock: milliseconds from when the call arrived.
//! It replaces the wait row as the call's budget. A call waits for a resting
//! offer only within what is left, so one whose every usable offer rests past
//! it answers `rate_limited` at once with the earliest reset; only a send the
//! clock cuts answers `timeout` (504, or the stream's last line). With no
//! `deadline_ms` a raw call keeps its own default: open, its caller's
//! connection is its deadline (FIX 8213; RULING RAW-NO-DEADLINE-WAIT = A).
//!
//! Red on main: the raw doors read no deadline and run every call open. A
//! call whose offer rests past its deadline waits the rest out, and a send
//! that never answers holds the call past the test's bound.
//!
//! The server is `AiHost::attach` over a `[models]` section whose one local
//! offer is a scripted fake model, so a refusal's rest is kept in the vault
//! and the ladder waits on it as served. The owner calls with the host-root
//! credential of a profiled install, in process (`oneshot`); only the fake
//! model listens on a loopback port.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test caller_deadline`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/fake_llm.rs"]
mod fake_llm;

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use engine_stack::run_on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, EntityId, LlmMessage, LlmMessageRole,
    LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence, Vault,
    VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::server::SyncServer;
use serde_json::{Value, json};
use tokio::time::Instant;
use tower::ServiceExt;

/// The configured server secret that selects secret-based rooting at boot.
const AUTH_SECRET: &str = "caller-deadline-auth-secret";

/// The model every call names: the `[models]` section's one local offer.
const MODEL: &str = "local/test-model@live";

/// What the fake model answers once it serves.
const SERVED: &str = "served on the caller's clock";

/// How long a call may take before the test calls it unanswered: past every
/// deadline below, short of the rest the first test's offer takes.
const ANSWER_BOUND: Duration = Duration::from_secs(20);

/// Test (1): the deadline, and the rest that runs past it.
const SHORT_DEADLINE_MS: u64 = 5_000;
const LONG_REST_SECS: u64 = 30;

/// Test (2): the rest, and the deadline that outlasts it.
const SHORT_REST_SECS: u64 = 2;
const LONG_DEADLINE_MS: u64 = 15_000;

/// Test (3): the deadline that cuts a send still out.
const CUT_DEADLINE_MS: u64 = 1_500;

/// The fake model's limit refusal, naming `secs` until it is back.
fn limited(secs: u64) -> Reply {
    Reply::Error {
        status: 429,
        headers: vec![("retry-after".into(), secs.to_string())],
        body: json!({"error": {"message": "rate limit", "type": "rate_limit_error"}}),
    }
}

/// A served vault whose raw routes reach only the fake model, and the
/// owner's host-root credential.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    host: AiHost,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    fake: FakeLlm,
}

async fn served(script: Vec<Reply>, fallback: Reply) -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let fake = FakeLlm::start(script, Some(fallback)).await;
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some(AUTH_SECRET.to_owned()),
            ..Default::default()
        },
    )
    .expect("create server");
    let toml = format!(
        "default = \"local:test-model\"\n\
         [providers.local]\n\
         kind = \"local-openai-compat\"\n\
         base_url = \"{}\"\n",
        fake.base_url
    );
    let models = ModelsConfig::from_toml(&toml, None).expect("models section");
    let (server, host) = AiHost::attach(server, Some(&models)).await;
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    // The owner's acts are carried by this install's live machine profile,
    // as a serving start or `init` enrols it.
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    Served {
        _dir: dir,
        vault,
        app: build_app(Arc::new(server)),
        host,
        issuer,
        root,
        fake,
    }
}

/// The raw call's body: a request for [`MODEL`], with `deadline_ms` beside
/// it when the caller names one.
fn body(deadline_ms: Option<u64>) -> Value {
    let request = LlmRequest {
        model: ModelId::new(MODEL).expect("model id"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
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
                text: "say something".into(),
                signature: None,
            }],
        }],
        tools: vec![],
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    };
    let mut body = serde_json::to_value(&request).expect("encode request");
    if let Some(deadline_ms) = deadline_ms {
        body["deadline_ms"] = json!(deadline_ms);
    }
    body
}

/// A raw call's answer, read whole.
#[derive(Debug)]
struct Answered {
    status: StatusCode,
    /// The refusal's body, or the stream's last line.
    last: Value,
    /// The whole body, as text.
    text: String,
    /// From the call's send to its body's end.
    took: Duration,
}

impl Answered {
    /// The error code of the refusal or of the stream's last line.
    fn code(&self) -> Option<&str> {
        self.last["error"]["code"].as_str()
    }
}

impl Served {
    fn owner_binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .issuer
            .binding_proof(&self.root, challenge.as_bytes())
            .expect("owner holder proof")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    /// The owner's `POST /v1/llm/{verb}`, read whole within `bound`: `None`
    /// when it has not ended by then.
    async fn call(
        &self,
        verb: &str,
        deadline_ms: Option<u64>,
        bound: Duration,
    ) -> Option<Answered> {
        let request = Request::post(format!("/v1/llm/{verb}"))
            .header(
                "authorization",
                format!("Bearer {}", self.root.to_token().expect("root token")),
            )
            .header("x-oneiron-binding", self.owner_binding())
            .header("content-type", "application/json")
            .body(Body::from(body(deadline_ms).to_string()))
            .expect("raw call request");
        let app = self.app.clone();
        let sent = Instant::now();
        let (status, bytes) = tokio::time::timeout(bound, async move {
            let response = app.oneshot(request).await.expect("raw call response");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("raw call body");
            (status, bytes)
        })
        .await
        .ok()?;
        let took = sent.elapsed();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        // A refusal is one JSON body; a stream's lines end with its last.
        let last = text
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .and_then(|line| serde_json::from_str(line).ok())
            .unwrap_or(Value::Null);
        Some(Answered {
            status,
            last,
            text,
            took,
        })
    }
}

/// The seconds from now until the reset a typed `rate_limited` error names:
/// its `retry_after`, or its first `resets_at` still ahead, wherever the
/// error's encoding nests them.
fn named_reset(llm: &Value) -> Option<u64> {
    match llm {
        Value::Object(fields) => {
            if let Some(after) = fields.get("retry_after").and_then(Value::as_u64) {
                return Some(after);
            }
            if let Some(at) = fields
                .get("resets_at")
                .and_then(Value::as_array)
                .and_then(|resets| resets.first())
                .and_then(Value::as_u64)
            {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock after the epoch")
                    .as_secs();
                return Some(at.saturating_sub(now));
            }
            fields.values().find_map(named_reset)
        }
        _ => None,
    }
}

/// Test (1): every offer the call may use rests past its deadline, so it
/// answers `rate_limited` at once, with the reset, and never waits the
/// deadline out.
#[test]
fn a_deadline_shorter_than_the_rest_answers_rate_limited_at_once_with_the_reset() {
    run_on_engine_stack("caller-deadline-rest-past", || async {
        let served = served(Vec::new(), limited(LONG_REST_SECS)).await;
        for verb in ["generate", "stream"] {
            let answered = served
                .call(verb, Some(SHORT_DEADLINE_MS), ANSWER_BOUND)
                .await
                .unwrap_or_else(|| {
                    panic!(
                        "{verb}: a call whose one offer rests {LONG_REST_SECS} s past its \
                         {SHORT_DEADLINE_MS} ms deadline answers within {ANSWER_BOUND:?}"
                    )
                });
            assert_eq!(
                answered.code(),
                Some("rate_limited"),
                "{verb}: the refusal is rate_limited, got {answered:?}"
            );
            assert!(
                answered.status == StatusCode::TOO_MANY_REQUESTS
                    || (verb == "stream" && answered.status == StatusCode::OK),
                "{verb}: 429 before a stream starts, got {answered:?}"
            );
            assert!(
                answered.took < Duration::from_millis(SHORT_DEADLINE_MS),
                "{verb}: answered at once, before the deadline, got {answered:?}"
            );
            let reset = named_reset(&answered.last["error"]["llm"])
                .unwrap_or_else(|| panic!("{verb}: the refusal names its reset: {answered:?}"));
            assert!(
                reset * 1_000 > SHORT_DEADLINE_MS,
                "{verb}: the reset ({reset} s) is past the deadline, got {answered:?}"
            );
        }
        assert!(!served.fake.seen().is_empty(), "the resting offer was sent");
        served.host.shutdown().await;
    });
}

/// Test (2): the offer is back within the deadline, so the call waits for
/// it and is served.
#[test]
fn a_deadline_longer_than_the_rest_waits_then_serves() {
    run_on_engine_stack("caller-deadline-rest-within", || async {
        let served = served(Vec::new(), Reply::text(SERVED)).await;
        for verb in ["generate", "stream"] {
            served.fake.push(limited(SHORT_REST_SECS));
            let answered = served
                .call(verb, Some(LONG_DEADLINE_MS), ANSWER_BOUND)
                .await
                .unwrap_or_else(|| {
                    panic!(
                        "{verb}: a call whose offer is back in {SHORT_REST_SECS} s answers \
                         within its {LONG_DEADLINE_MS} ms deadline"
                    )
                });
            assert_eq!(
                answered.status,
                StatusCode::OK,
                "{verb}: served, got {answered:?}"
            );
            assert_eq!(answered.code(), None, "{verb}: no error, got {answered:?}");
            assert!(
                answered.text.contains(SERVED),
                "{verb}: the answer is the model's, got {answered:?}"
            );
            assert!(
                answered.took >= Duration::from_secs(1),
                "{verb}: the call waited for the offer back, got {answered:?}"
            );
        }
        served.host.shutdown().await;
    });
}

/// Test (3): a send still out at the deadline is cut there, with `timeout`.
#[test]
fn a_send_the_deadline_cuts_answers_timeout() {
    run_on_engine_stack("caller-deadline-cut", || async {
        let served = served(
            Vec::new(),
            Reply::Hold {
                text: "never sent".into(),
            },
        )
        .await;
        for verb in ["generate", "stream"] {
            let answered = served
                .call(verb, Some(CUT_DEADLINE_MS), ANSWER_BOUND)
                .await
                .unwrap_or_else(|| {
                    panic!(
                        "{verb}: a send still out at the {CUT_DEADLINE_MS} ms deadline is \
                         cut there"
                    )
                });
            assert_eq!(
                answered.code(),
                Some("timeout"),
                "{verb}: the cut call answers timeout, got {answered:?}"
            );
            let status = if verb == "stream" {
                StatusCode::OK
            } else {
                StatusCode::GATEWAY_TIMEOUT
            };
            assert_eq!(
                answered.status, status,
                "{verb}: 504, or a started stream's last line, got {answered:?}"
            );
            assert!(
                answered.took >= Duration::from_millis(CUT_DEADLINE_MS),
                "{verb}: cut at the deadline, not before, got {answered:?}"
            );
        }
        assert!(!served.fake.seen().is_empty(), "the held send went out");
        served.fake.release();
        served.host.shutdown().await;
    });
}

/// Test (4): with no `deadline_ms` a raw call keeps its own default, open
/// (RULING RAW-NO-DEADLINE-WAIT = A): it waits out a rest past the vault's
/// wait row, which a call on that row would refuse at once.
#[test]
fn a_raw_call_with_no_deadline_stays_open_past_the_wait_row() {
    run_on_engine_stack("caller-deadline-none", || async {
        let served = served(Vec::new(), Reply::text(SERVED)).await;
        let wait_row = served
            .vault
            .provider_cooldown_policy()
            .expect("the vault's cooldown rows")
            .max_wait_secs;
        let rest = wait_row + 5;
        served.fake.push(limited(rest));
        let answered = served
            .call("generate", None, Duration::from_secs(rest + 30))
            .await
            .expect("an open call is served once its offer is back");
        assert_eq!(
            answered.status,
            StatusCode::OK,
            "served, not refused on the {wait_row} s wait row, got {answered:?}"
        );
        assert!(
            answered.text.contains(SERVED),
            "the answer is the model's, got {answered:?}"
        );
        assert!(
            answered.took >= Duration::from_secs(wait_row),
            "the call waited past the {wait_row} s wait row, got {answered:?}"
        );
        served.host.shutdown().await;
    });
}
