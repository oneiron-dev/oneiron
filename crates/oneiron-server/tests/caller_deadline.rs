//! The caller's own deadline on raw calls (census L9-23; ARCH-0036
//! #offers-quota-built: "the caller's own deadline on role, raw and chat
//! calls"). `POST /v1/llm/generate` and `POST /v1/llm/stream` take
//! `deadline_ms`, the memory proxy's field (FIX 8189): milliseconds from when
//! the door takes the call. Its sends, its waits for a resting offer and its
//! fallbacks end by then, and a call it ends answers `timeout`: 504 before a
//! stream starts, or the stream's last line once it has.
//!
//! Red on main: the raw doors read no deadline and run every call open
//! (FIX 8213). On a cooling chain the call answers `rate_limited`, and a
//! send that never answers holds the call past the test's bound.
//!
//! Deterministic but for the bound: in-process vault and router (`oneshot`,
//! no TCP ports), an injected backend, the owner's host-root credential on a
//! profiled install.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test caller_deadline`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::llm::registry::{ModelRegistryRow, ModelWireFormat};
use oneiron::llm::{LlmCatalogCost, LlmCatalogEntry, SingleRouteBackend};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallClass, CallEnvelope, CallPurpose,
    EntityId, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmRequest, LlmResult,
    LlmStream, LlmStreamResult, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    RetryableLlmError, TierPrecedence, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The model every call names: a registered catalog row, served by the
/// injected backend.
const MODEL: &str = "own/model@1";

/// The caller's deadline in each call.
const DEADLINE_MS: u64 = 1_500;

/// How long the test waits for an answer: far past the deadline, far short
/// of the cooling offer's rest.
const ANSWER_BOUND: Duration = Duration::from_secs(20);

/// The rest a refusal names: past both the deadline and the bound.
const REST_SECS: u64 = 30;

/// What the injected backend answers each send.
#[derive(Clone, Copy)]
enum Offer {
    /// A rate limit naming a 30 s rest: a cooling chain.
    Cooling,
    /// Nothing, ever: a send still out at the deadline.
    Silent,
}

struct Backend {
    offer: Offer,
    sends: Arc<AtomicUsize>,
}

fn rate_limited() -> LlmError {
    RetryableLlmError::RateLimited {
        retry_after: Some(REST_SECS),
        resets_at: Vec::new(),
    }
    .into()
}

// One request per call: the raw routes' gate wraps it.
impl SingleRouteBackend for Backend {
    fn preflight(&self, _: &LlmRequest, _: bool) -> LlmResult<()> {
        Ok(())
    }
}

impl LlmBackend for Backend {
    fn generate<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        let offer = self.offer;
        Box::pin(async move {
            match offer {
                Offer::Cooling => Err(rate_limited()),
                Offer::Silent => std::future::pending().await,
            }
        })
    }

    fn stream<'a>(&'a self, _: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        match self.offer {
            Offer::Cooling => Err(rate_limited()),
            Offer::Silent => Ok(LlmStream::new(futures_util::stream::pending())),
        }
    }
}

/// A served vault whose raw routes reach only `offer`, and the owner's
/// host-root credential.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    sends: Arc<AtomicUsize>,
}

fn served(offer: Offer) -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    register_model(&vault);
    let sends = Arc::new(AtomicUsize::new(0));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("caller-deadline".into()),
                ..Default::default()
            },
        )
        .expect("create server")
        .with_llm_backend(
            Arc::new(Backend {
                offer,
                sends: Arc::clone(&sends),
            }),
            BudgetGuard::with_reserve_units(
                "caller-deadline",
                1_000,
                10,
                BudgetExhaustionPolicy::Suspend,
            ),
        ),
    );
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
        server,
        issuer,
        root,
        sends,
    }
}

/// The catalog row a raw call's model needs when no `[models]` names it.
fn register_model(vault: &Vault) {
    vault
        .put_model_registry_row(&ModelRegistryRow {
            version: 1,
            wire: ModelWireFormat::OpenaiCompat,
            catalog: LlmCatalogEntry {
                model: ModelId::new(MODEL).expect("model id"),
                display_name: "model".into(),
                locality: ModelLocality::ThirdParty,
                context_window_tokens: 4096,
                max_output_tokens: Some(100),
                cost: Some(LlmCatalogCost {
                    input_per_million: "1".into(),
                    output_per_million: "1".into(),
                    cache_read_per_million: None,
                    cache_write_per_million: None,
                    currency: None,
                }),
                capabilities: vec![LlmCapability::Streaming],
                metadata: BTreeMap::new(),
            },
            scores: BTreeMap::new(),
            fetched_at: BTreeMap::new(),
            tokens_per_o200k: None,
            stale_since: None,
            source_rows: None,
        })
        .expect("register the model");
}

/// The raw call's body: a request for [`MODEL`] with `deadline_ms` beside
/// it.
fn body(deadline_ms: u64) -> Value {
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
        messages: vec![],
        tools: vec![],
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    };
    let mut body = serde_json::to_value(&request).expect("encode request");
    body["deadline_ms"] = json!(deadline_ms);
    body
}

/// How a raw call ended.
#[derive(Debug)]
enum Ended {
    /// No answer within [`ANSWER_BOUND`].
    Unanswered,
    /// The status and the error code of the refusal or of the stream's last
    /// line (`None` when that line names none).
    Answered {
        status: StatusCode,
        code: Option<String>,
    },
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

    /// The owner's `POST /v1/llm/{verb}` with `deadline_ms`, read whole
    /// within [`ANSWER_BOUND`].
    async fn call(&self, verb: &str, deadline_ms: u64) -> Ended {
        let request = Request::post(format!("/v1/llm/{verb}"))
            .header(
                "authorization",
                format!("Bearer {}", self.root.to_token().expect("root token")),
            )
            .header("x-oneiron-binding", self.owner_binding())
            .header("content-type", "application/json")
            .body(Body::from(body(deadline_ms).to_string()))
            .expect("raw call request");
        let app = build_app(Arc::clone(&self.server));
        let answered = tokio::time::timeout(ANSWER_BOUND, async move {
            let response = app.oneshot(request).await.expect("raw call response");
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 1024 * 1024)
                .await
                .expect("raw call body");
            (status, bytes)
        })
        .await;
        let Ok((status, bytes)) = answered else {
            return Ended::Unanswered;
        };
        let text = String::from_utf8_lossy(&bytes);
        // A refusal is one JSON body; a stream's lines end with its last.
        let last = text
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or_default();
        let code = serde_json::from_str::<Value>(last)
            .ok()
            .and_then(|line| line["error"]["code"].as_str().map(str::to_owned));
        Ended::Answered { status, code }
    }
}

/// Whether `ended` is the caller's deadline ending the call: 504 `timeout`
/// before a stream starts, or a started stream whose last line is
/// `timeout`.
fn timed_out(verb: &str, ended: &Ended) -> bool {
    match ended {
        Ended::Answered { status, code } => {
            code.as_deref() == Some("timeout")
                && (*status == StatusCode::GATEWAY_TIMEOUT
                    || (verb == "stream" && *status == StatusCode::OK))
        }
        Ended::Unanswered => false,
    }
}

#[test]
fn a_raw_call_on_a_cooling_chain_ends_at_its_deadline_with_timeout() {
    run_on_engine_stack("caller-deadline-cooling", || async {
        let served = served(Offer::Cooling);
        for verb in ["generate", "stream"] {
            let ended = served.call(verb, DEADLINE_MS).await;
            assert!(
                timed_out(verb, &ended),
                "{verb}: a call whose one offer rests {REST_SECS} s past its \
                 {DEADLINE_MS} ms deadline ends with timeout, got {ended:?}"
            );
        }
        assert!(
            served.sends.load(Ordering::SeqCst) >= 1,
            "the cooling offer was reached"
        );
    });
}

#[test]
fn a_raw_call_whose_send_never_answers_ends_at_its_deadline_with_timeout() {
    run_on_engine_stack("caller-deadline-silent", || async {
        let served = served(Offer::Silent);
        for verb in ["generate", "stream"] {
            let ended = served.call(verb, DEADLINE_MS).await;
            assert!(
                timed_out(verb, &ended),
                "{verb}: a send still out at the {DEADLINE_MS} ms deadline \
                 is ended there with timeout, got {ended:?}"
            );
        }
        assert_eq!(
            served.sends.load(Ordering::SeqCst),
            2,
            "each call sent once and was ended while out"
        );
    });
}
