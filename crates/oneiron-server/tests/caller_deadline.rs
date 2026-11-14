//! The caller's own deadline on role, raw and chat calls (census L9-23;
//! ARCH-0036 #offers-quota-built; RULING CALLER-DEADLINE-WIRE = B).
//! `POST /v1/llm/generate`, `POST /v1/llm/stream`, `POST /v1/ai/chat` and the
//! role door's generate (`vault.models.roles.invoke`) take `deadline_ms`, the
//! memory proxy's field (FIX 8189), on the proxy's one clock: milliseconds
//! from when the call arrived. It replaces the wait row as the call's budget.
//! A call waits for a resting offer only within what is left, so one whose
//! every usable offer rests past it answers `rate_limited` at once with the
//! earliest reset; only a send the clock cuts answers `timeout` (504, or a
//! stream's last line). With no `deadline_ms` each door keeps its own default
//! (RULING RAW-NO-DEADLINE-WAIT = A): a raw call stays open, its caller's
//! connection its deadline (FIX 8213); a chat turn and a role call keep the
//! vault's wait row. Chat and the role door answer a rate limit and a timeout
//! with those codes on every call, deadline or not (RULING
//! CHAT-ROLE-DEADLINE-CODES = A).
//!
//! Red on main: the raw doors read no deadline and run every call open. A
//! call whose offer rests past its deadline waits the rest out, and a send
//! that never answers holds the call past the test's bound. The chat and role
//! doors refuse `deadline_ms` as an unknown field, and answer a rate limit on
//! the wait row as `turn_not_admitted`/`turn_failed` (chat) or a bad request
//! (role door).
//!
//! The server is `AiHost::attach` over a `[models]` section whose one local
//! offer is a scripted fake model, so a refusal's rest is kept in the vault
//! and the ladder waits on it as served. Its shorthand seats the chat role
//! (`generative_reasoner`) on that offer; the role door's tests pin the role
//! to it in a model manifest. The owner calls with the host-root credential
//! of a profiled install, in process (`oneshot`), a chat turn as from this
//! device's loopback; only the fake model listens on a loopback port.
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

/// A request for [`MODEL`].
fn request() -> LlmRequest {
    LlmRequest {
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
    }
}

/// The raw call's body: [`request`], with `deadline_ms` beside it when the
/// caller names one.
fn body(deadline_ms: Option<u64>) -> Value {
    let mut body = serde_json::to_value(request()).expect("encode request");
    if let Some(deadline_ms) = deadline_ms {
        body["deadline_ms"] = json!(deadline_ms);
    }
    body
}

/// A chat turn's body: a new conversation, whole or streamed, with
/// `deadline_ms` when the caller names one.
fn chat_body(deadline_ms: Option<u64>, stream: bool) -> Value {
    let mut body = json!({
        "conversation_ref": EntityId::now().to_hex(),
        "text": "say something",
        "stream": stream,
    });
    if let Some(deadline_ms) = deadline_ms {
        body["deadline_ms"] = json!(deadline_ms);
    }
    body
}

/// The role the role door's tests call: the chat role, which the shorthand
/// seats on [`MODEL`] and [`pin_every_role`] pins there.
const ROLE: &str = "generative_reasoner";

/// The role door's generate of [`ROLE`]: [`request`], with `deadline_ms`
/// when the caller names one.
fn role_body(deadline_ms: Option<u64>) -> Value {
    let mut generate = json!({
        "kind": "generate",
        "request": serde_json::to_value(request()).expect("encode request"),
    });
    if let Some(deadline_ms) = deadline_ms {
        generate["deadline_ms"] = json!(deadline_ms);
    }
    json!({"role": ROLE, "input": generate})
}

/// A model manifest pinning every role to [`MODEL`] on the LLM slot at its
/// own-server route, its extraction teacher probe-approved, as an owner pins
/// one: the role door serves a generative role only through a manifest.
fn pin_every_role(vault: &Vault) {
    use oneiron::llm::manifest::{
        MODEL_ROLES, ModelBinding, ModelManifest, ModelRole, ModelSlot, TeacherProbeApproval,
    };
    let model = ModelId::new(MODEL).expect("model id");
    let encoder = ModelId::new(format!(
        "{}/{}-encoder@{}",
        model.provider(),
        model.name(),
        model.revision()
    ))
    .expect("encoder model id");
    let manifest = ModelManifest {
        version: 2,
        roles: MODEL_ROLES
            .into_iter()
            .map(|role| {
                let (model, slot) = if role == ModelRole::ExtractionEncoder {
                    (encoder.clone(), ModelSlot::Oneironer)
                } else {
                    (model.clone(), ModelSlot::Llm)
                };
                (
                    role,
                    ModelBinding {
                        model,
                        slot,
                        tier: ModelTierRef("pinned".into()),
                        route_models: BTreeMap::new(),
                        disposition: None,
                        reads_audio: false,
                    },
                )
            })
            .collect(),
        routes: [
            (ModelSlot::Llm, ModelLocality::OwnServer),
            (ModelSlot::Embedder, ModelLocality::OnDevice),
            (ModelSlot::Oneironer, ModelLocality::OnDevice),
        ]
        .into_iter()
        .collect(),
        verdict: None,
        seat_policy: None,
    };
    let approval = TeacherProbeApproval::for_scored_checkpoint(
        &manifest,
        &vault
            .teacher_probe_policy(None)
            .expect("teacher probe policy"),
        1_000_000,
    )
    .expect("teacher probe approval");
    vault
        .set_model_manifest_with_teacher_approval(&manifest, &approval)
        .expect("the owner's model manifest");
}

/// A door the tests call with a deadline, or none.
#[derive(Clone, Copy, Debug)]
enum Door {
    /// `POST /v1/ai/chat`, whole or streamed.
    Chat { stream: bool },
    /// `POST /v1/core/facade/vault.models.roles.invoke`, a generate.
    Role,
}

impl Door {
    /// Both forms of a chat turn.
    const CHAT: [Self; 2] = [Self::Chat { stream: false }, Self::Chat { stream: true }];

    fn streams(self) -> bool {
        matches!(self, Self::Chat { stream: true })
    }
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
    /// The error code of the refusal or of the stream's last line: a raw
    /// line's `error.code`, or a chat line's `code` beside its `error` type.
    fn code(&self) -> Option<&str> {
        self.last["error"]["code"].as_str().or_else(|| {
            self.last["code"]
                .as_str()
                .filter(|_| self.last["type"] == "error")
        })
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
        self.post(&format!("/v1/llm/{verb}"), body(deadline_ms), false, bound)
            .await
    }

    /// The owner's call of `door` with `deadline_ms`, read whole within
    /// `bound`: `None` when it has not ended by then.
    async fn ask(&self, door: Door, deadline_ms: Option<u64>, bound: Duration) -> Option<Answered> {
        match door {
            Door::Chat { stream } => {
                self.post("/v1/ai/chat", chat_body(deadline_ms, stream), true, bound)
                    .await
            }
            Door::Role => {
                self.post(
                    "/v1/core/facade/vault.models.roles.invoke",
                    role_body(deadline_ms),
                    false,
                    bound,
                )
                .await
            }
        }
    }

    /// The owner's `POST path` with `body`, read whole within `bound`: `None`
    /// when it has not ended by then. A `loopback` call comes from this
    /// device's loopback, as a chat turn must: it binds its sitting to the
    /// caller's machine.
    async fn post(
        &self,
        path: &str,
        body: Value,
        loopback: bool,
        bound: Duration,
    ) -> Option<Answered> {
        let mut request = Request::post(path)
            .header(
                "authorization",
                format!("Bearer {}", self.root.to_token().expect("root token")),
            )
            .header("x-oneiron-binding", self.owner_binding())
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("owner call request");
        if loopback {
            request.extensions_mut().insert(axum::extract::ConnectInfo(
                std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 40_000)),
            ));
        }
        let app = self.app.clone();
        let sent = Instant::now();
        let (status, bytes) = tokio::time::timeout(bound, async move {
            let response = app.oneshot(request).await.expect("owner call response");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("owner call body");
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
/// error's encoding nests them (the typed facade spells them `retryAfter`
/// and `resetsAt`).
fn named_reset(llm: &Value) -> Option<u64> {
    match llm {
        Value::Object(fields) => {
            if let Some(after) = ["retry_after", "retryAfter"]
                .into_iter()
                .find_map(|name| fields.get(name).and_then(Value::as_u64))
            {
                return Some(after);
            }
            if let Some(at) = ["resets_at", "resetsAt"]
                .into_iter()
                .find_map(|name| fields.get(name))
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
        let (wait_row, rest) = wait_row_and_a_rest_past_it(&served);
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

/// `door`'s call with `deadline_ms` answers `rate_limited` within `within`,
/// naming a reset more than `past` away: 429 before a stream starts, or a
/// started chat stream's last line.
async fn assert_rate_limited(
    served: &Served,
    door: Door,
    deadline_ms: Option<u64>,
    within: Duration,
    past: Duration,
) {
    let answered = served
        .ask(door, deadline_ms, ANSWER_BOUND)
        .await
        .unwrap_or_else(|| {
            panic!("{door:?}: a call whose one offer rests past its budget answers within {ANSWER_BOUND:?}")
        });
    assert_eq!(
        answered.code(),
        Some("rate_limited"),
        "{door:?}: the refusal is rate_limited, got {answered:?}"
    );
    assert!(
        answered.status == StatusCode::TOO_MANY_REQUESTS
            || (door.streams() && answered.status == StatusCode::OK),
        "{door:?}: 429 before a stream starts, got {answered:?}"
    );
    assert!(
        answered.took < within,
        "{door:?}: answered at once, within {within:?}, got {answered:?}"
    );
    let reset = named_reset(&answered.last)
        .unwrap_or_else(|| panic!("{door:?}: the refusal names its reset: {answered:?}"));
    assert!(
        Duration::from_secs(reset) > past,
        "{door:?}: the reset ({reset} s) is past {past:?}, got {answered:?}"
    );
}

/// `door`'s call, its offer back in [`SHORT_REST_SECS`], waits within its
/// [`LONG_DEADLINE_MS`] deadline and is served.
async fn assert_served_after_the_rest(served: &Served, door: Door) {
    served.fake.push(limited(SHORT_REST_SECS));
    let answered = served
        .ask(door, Some(LONG_DEADLINE_MS), ANSWER_BOUND)
        .await
        .unwrap_or_else(|| {
            panic!(
                "{door:?}: a call whose offer is back in {SHORT_REST_SECS} s answers within its \
                 {LONG_DEADLINE_MS} ms deadline"
            )
        });
    assert_eq!(
        answered.status,
        StatusCode::OK,
        "{door:?}: served, got {answered:?}"
    );
    assert_eq!(
        answered.code(),
        None,
        "{door:?}: no error, got {answered:?}"
    );
    assert!(
        answered.text.contains(SERVED),
        "{door:?}: the answer is the model's, got {answered:?}"
    );
    assert!(
        answered.took >= Duration::from_secs(1),
        "{door:?}: the call waited for the offer back, got {answered:?}"
    );
}

/// `door`'s call, its send still out at its [`CUT_DEADLINE_MS`] deadline, is
/// cut there with `timeout`: 504, or a started chat stream's last line.
async fn assert_cut_with_timeout(served: &Served, door: Door) {
    let answered = served
        .ask(door, Some(CUT_DEADLINE_MS), ANSWER_BOUND)
        .await
        .unwrap_or_else(|| {
            panic!("{door:?}: a send still out at the {CUT_DEADLINE_MS} ms deadline is cut there")
        });
    assert_eq!(
        answered.code(),
        Some("timeout"),
        "{door:?}: the cut call answers timeout, got {answered:?}"
    );
    let status = if door.streams() {
        StatusCode::OK
    } else {
        StatusCode::GATEWAY_TIMEOUT
    };
    assert_eq!(
        answered.status, status,
        "{door:?}: 504, or a started stream's last line, got {answered:?}"
    );
    assert!(
        answered.took >= Duration::from_millis(CUT_DEADLINE_MS),
        "{door:?}: cut at the deadline, not before, got {answered:?}"
    );
}

/// Test (1) on chat: its offer rests past the turn's deadline, so the turn
/// answers `rate_limited` at once with the reset. The streamed turn meets
/// the rest on its own send and ends its stream with that line; the whole
/// turn after it is refused before its stream starts (429).
#[test]
fn a_chat_turn_whose_rest_outlasts_its_deadline_answers_rate_limited_at_once() {
    run_on_engine_stack("caller-deadline-chat-rest-past", || async {
        let served = served(Vec::new(), limited(LONG_REST_SECS)).await;
        for door in [Door::Chat { stream: true }, Door::Chat { stream: false }] {
            assert_rate_limited(
                &served,
                door,
                Some(SHORT_DEADLINE_MS),
                Duration::from_millis(SHORT_DEADLINE_MS),
                Duration::from_millis(SHORT_DEADLINE_MS),
            )
            .await;
        }
        assert!(!served.fake.seen().is_empty(), "the resting offer was sent");
        served.host.shutdown().await;
    });
}

/// Test (1) on the role door: its pinned offer rests past the call's
/// deadline, so it answers `rate_limited` (429) at once with the reset.
#[test]
fn a_role_call_whose_rest_outlasts_its_deadline_answers_rate_limited_at_once() {
    run_on_engine_stack("caller-deadline-role-rest-past", || async {
        let served = served(Vec::new(), limited(LONG_REST_SECS)).await;
        pin_every_role(&served.vault);
        assert_rate_limited(
            &served,
            Door::Role,
            Some(SHORT_DEADLINE_MS),
            Duration::from_millis(SHORT_DEADLINE_MS),
            Duration::from_millis(SHORT_DEADLINE_MS),
        )
        .await;
        assert!(!served.fake.seen().is_empty(), "the resting offer was sent");
        served.host.shutdown().await;
    });
}

/// Test (2) on chat, whole and streamed: the offer is back within the
/// turn's deadline, so the turn waits for it and is served.
#[test]
fn a_chat_turn_within_its_deadline_waits_for_the_rest_then_is_served() {
    run_on_engine_stack("caller-deadline-chat-rest-within", || async {
        let served = served(Vec::new(), Reply::text(SERVED)).await;
        for door in Door::CHAT {
            assert_served_after_the_rest(&served, door).await;
        }
        served.host.shutdown().await;
    });
}

/// Test (2) on the role door: the offer is back within the call's
/// deadline, so the call waits for it and is served.
#[test]
fn a_role_call_within_its_deadline_waits_for_the_rest_then_is_served() {
    run_on_engine_stack("caller-deadline-role-rest-within", || async {
        let served = served(Vec::new(), Reply::text(SERVED)).await;
        pin_every_role(&served.vault);
        assert_served_after_the_rest(&served, Door::Role).await;
        served.host.shutdown().await;
    });
}

/// Test (3) on chat, whole and streamed: a reply still going at the turn's
/// deadline is cut there with `timeout`.
#[test]
fn a_chat_turn_the_deadline_cuts_answers_timeout() {
    run_on_engine_stack("caller-deadline-chat-cut", || async {
        let served = served(
            Vec::new(),
            Reply::Hold {
                text: "never sent".into(),
            },
        )
        .await;
        for door in Door::CHAT {
            assert_cut_with_timeout(&served, door).await;
        }
        assert!(!served.fake.seen().is_empty(), "the held send went out");
        served.fake.release();
        served.host.shutdown().await;
    });
}

/// Test (3) on the role door: a send still out at the call's deadline is
/// cut there with `timeout` (504).
#[test]
fn a_role_call_the_deadline_cuts_answers_timeout() {
    run_on_engine_stack("caller-deadline-role-cut", || async {
        let served = served(
            Vec::new(),
            Reply::Hold {
                text: "never sent".into(),
            },
        )
        .await;
        pin_every_role(&served.vault);
        assert_cut_with_timeout(&served, Door::Role).await;
        assert!(!served.fake.seen().is_empty(), "the held send went out");
        served.fake.release();
        served.host.shutdown().await;
    });
}

/// The vault's wait row, and a rest 5 s past it.
fn wait_row_and_a_rest_past_it(served: &Served) -> (u64, u64) {
    let wait_row = served
        .vault
        .provider_cooldown_policy()
        .expect("the vault's cooldown rows")
        .max_wait_secs;
    (wait_row, wait_row + 5)
}

/// Test (4) on chat (RULING RAW-NO-DEADLINE-WAIT = A): with no
/// `deadline_ms` a turn keeps the vault's wait row, so an offer resting past
/// it is answered at once, `rate_limited` with the reset (RULING
/// CHAT-ROLE-DEADLINE-CODES = A), never waited out. The whole turn meets the
/// rest on its own send; the streamed turn after it is refused before its
/// stream starts.
#[test]
fn a_chat_turn_with_no_deadline_keeps_the_wait_row_and_answers_rate_limited() {
    run_on_engine_stack("caller-deadline-chat-none", || async {
        let served = served(Vec::new(), Reply::text(SERVED)).await;
        let (wait_row, rest) = wait_row_and_a_rest_past_it(&served);
        served.fake.push(limited(rest));
        for door in [Door::Chat { stream: false }, Door::Chat { stream: true }] {
            assert_rate_limited(
                &served,
                door,
                None,
                Duration::from_secs(wait_row / 2),
                Duration::from_secs(wait_row),
            )
            .await;
        }
        served.host.shutdown().await;
    });
}

/// Test (4) on the role door: with no `deadline_ms` the call keeps the
/// vault's wait row, so an offer resting past it is answered at once, 429
/// `rate_limited` with the reset, never waited out.
#[test]
fn a_role_call_with_no_deadline_keeps_the_wait_row_and_answers_rate_limited() {
    run_on_engine_stack("caller-deadline-role-none", || async {
        let served = served(Vec::new(), Reply::text(SERVED)).await;
        pin_every_role(&served.vault);
        let (wait_row, rest) = wait_row_and_a_rest_past_it(&served);
        served.fake.push(limited(rest));
        assert_rate_limited(
            &served,
            Door::Role,
            None,
            Duration::from_secs(wait_row / 2),
            Duration::from_secs(wait_row),
        )
        .await;
        served.host.shutdown().await;
    });
}
