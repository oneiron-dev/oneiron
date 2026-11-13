//! The context pack a turn taken in an off-record stretch reads (census row
//! L6-12; ARCH-0052 #e5-read-union-open, ONE-1729: "A route that takes a
//! room's turn should bind the pack too").
//!
//! The owner witnesses one turn into a live stretch, so its MESSAGE is staged
//! in the stretch's overlay and is in no base row. A pack the owner asks for
//! with the stretch named in `x-oneiron-session` reads that MESSAGE, through
//! `POST /v1/core/context-pack` and through `POST /v1/core/context-board`,
//! whose pack is the one a chat turn's board runs. The same pack without the
//! header reads base alone. The pack in the stretch registers its retrieval
//! run through the stretch, never in base.
//!
//! A pack assembled in a stretch finishes after its own filters and cuts
//! (the deferred door). When its run row can no longer land in the stretch,
//! because the stretch flipped on record before the finish, the finish fails
//! and base keeps no run of it.
//!
//! On unmodified main every pack route reads base alone, so the first two
//! cases miss the staged MESSAGE and the third finds a run in base; and the
//! deferred door refuses any pack assembled in a stretch, so the fourth
//! fails at its assembly.
//!
//! Each case drives the real route with the owner's host-root credential (on
//! a profiled install, as a serving start enrols it). Deterministic:
//! in-process vault and router (`oneshot`, no TCP ports, no sleeps, no
//! models).
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support
//! --test off_record_room_context_pack`.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::edge::EdgeActorClass;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::off_record::OffRecordBackendClass;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::stretch_pack_finalize::finish_stretch_pack_after_flip;
use oneiron::{EntityId, ErrorKind, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

/// The live stretch every case stages its MESSAGE in.
const STRETCH: &str = "room-pack-stretch";
/// The stretch the fourth case flips on record before its pack finishes.
const FLIPPED_STRETCH: &str = "room-pack-flipped-stretch";
/// The one word the staged MESSAGE holds, which no base row holds.
const STAGED_WORD: &str = "lanternfish";
const CONTEXT_PACK: &str = "/v1/core/context-pack";
const CONTEXT_BOARD: &str = "/v1/core/context-board";

struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_slip: CapabilitySlip,
    owner_token: String,
    /// The short id of the MESSAGE the owner's turn staged in the stretch.
    staged_message: String,
}

/// Runs `test` on an engine-sized stack and runtime, as the served doors
/// need more than a test thread's default stack.
fn run_on_engine_stack(name: &str, test: impl std::future::Future<Output = ()> + Send + 'static) {
    let run = std::thread::Builder::new()
        .name(name.into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime")
                .block_on(test)
        })
        .expect("spawn the engine-sized test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A host whose vault keeps its retrieval runs, with a live stretch that
/// holds one turn the owner witnessed into it.
fn host() -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    config.dimensions = 4;
    config.retrieval_telemetry_capture = true;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("off-record-room-context-pack".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");

    let stretch = vault
        .off_record_session_vault()
        .enter(STRETCH, OffRecordBackendClass::Local)
        .expect("enter the stretch");
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .witness_into_session(
            &stretch,
            &WitnessTurn {
                conversation_ref: String::new(),
                turn_ref: None,
                thread_audience: None,
                messages: vec![WitnessMessage {
                    id: None,
                    author: WitnessAuthor::User,
                    message_type: "dialogue".to_owned(),
                    content: format!("the stretch says {STAGED_WORD}"),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                    parts: None,
                    quote: None,
                }],
                occurred_at: 900,
                assertions: Default::default(),
            },
            None,
            None,
        )
        .expect("the owner's turn in the stretch");
    let staged_message = receipt
        .message_short_ids
        .first()
        .and_then(|short| short.split(':').next())
        .expect("the turn's MESSAGE")
        .to_owned();
    drop(stretch);

    let app = build_app(server);
    Host {
        _dir: dir,
        vault,
        app,
        issuer,
        owner,
        owner_slip,
        owner_token,
        staged_message,
    }
}

impl Host {
    fn owner_binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = hex(&self
            .issuer
            .binding_proof(&self.owner_slip, challenge.as_bytes())
            .expect("owner holder proof"));
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    /// The owner's call to `route` over actual HTTP, in the stretch when
    /// `in_stretch`; its answer, which must be 200.
    async fn call(&self, route: &str, body: Value, in_stretch: bool) -> Value {
        let mut request = Request::post(route)
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding())
            .header("content-type", "application/json");
        if in_stretch {
            request = request.header("x-oneiron-session", STRETCH);
        }
        let response = self
            .app
            .clone()
            .oneshot(
                request
                    .body(Body::from(body.to_string()))
                    .expect("pack request"),
            )
            .await
            .expect("pack response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("pack response body");
        let answer: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{route} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        assert_eq!(status, StatusCode::OK, "{route} answered {answer}");
        answer
    }

    /// Retrieval runs the vault keeps in base.
    fn base_runs(&self) -> usize {
        self.vault
            .retrieval_runs(64)
            .expect("base retrieval runs")
            .len()
    }
}

/// The pack request every case sends: the staged word, as a text query.
fn pack_request() -> Value {
    json!({"query": STAGED_WORD, "limit": 10})
}

/// Whether any object in `answer` names `short_id` as its `short_id`.
fn names_short_id(answer: &Value, short_id: &str) -> bool {
    match answer {
        Value::Object(fields) => {
            fields.get("short_id").and_then(Value::as_str) == Some(short_id)
                || fields.values().any(|value| names_short_id(value, short_id))
        }
        Value::Array(items) => items.iter().any(|value| names_short_id(value, short_id)),
        _ => false,
    }
}

/// A pack the owner asks for in the stretch returns the MESSAGE the stretch
/// staged; the same pack outside it does not.
#[test]
fn a_context_pack_in_a_stretch_reads_its_staged_message() {
    run_on_engine_stack("stretch-context-pack", async {
        let host = host();
        let outside = host.call(CONTEXT_PACK, pack_request(), false).await;
        assert!(
            !names_short_id(&outside, &host.staged_message),
            "outside the stretch the pack reads base alone: {outside}"
        );
        let inside = host.call(CONTEXT_PACK, pack_request(), true).await;
        assert!(
            names_short_id(&inside["results"], &host.staged_message),
            "the pack in the stretch returns its staged MESSAGE {}: {inside}",
            host.staged_message
        );
    });
}

/// The id of the entity `pack` returned under `short_id`.
fn result_id(pack: &Value, short_id: &str) -> String {
    pack["results"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entity| entity["short_id"].as_str() == Some(short_id))
        .and_then(|entity| entity["id"].as_str())
        .unwrap_or_else(|| panic!("the pack returns {short_id}: {pack}"))
        .to_owned()
}

/// The board a turn reads, asked for in the stretch, carries the MESSAGE the
/// stretch staged among its MEMORIES: a chat turn's board runs this pack.
#[test]
fn the_context_board_in_a_stretch_reads_its_staged_message() {
    run_on_engine_stack("stretch-context-board", async {
        let host = host();
        let pack = host.call(CONTEXT_PACK, pack_request(), true).await;
        let staged = result_id(&pack, &host.staged_message);
        let board = json!({
            "retrieval": pack_request(),
            "memories": {"shared_total": 0},
            "session": {"session_id": host.owner.to_hex()},
        });
        let outside = host.call(CONTEXT_BOARD, board.clone(), false).await;
        assert!(
            !outside.to_string().contains(&staged),
            "outside the stretch the board reads base alone: {outside}"
        );
        let inside = host.call(CONTEXT_BOARD, board, true).await;
        assert!(
            inside.to_string().contains(&staged),
            "the board in the stretch carries its staged MESSAGE {staged}: {inside}"
        );
    });
}

/// The pack in the stretch registers its retrieval run through the stretch,
/// so base keeps no run of it; a pack outside the stretch keeps one there.
#[test]
fn a_stretch_pack_keeps_no_retrieval_run_in_base() {
    run_on_engine_stack("stretch-pack-runs", async {
        let host = host();
        let before = host.base_runs();
        host.call(CONTEXT_PACK, pack_request(), true).await;
        assert_eq!(
            host.base_runs(),
            before,
            "a pack in the stretch keeps no retrieval run in base"
        );
        host.call(CONTEXT_PACK, pack_request(), false).await;
        assert_eq!(
            host.base_runs(),
            before + 1,
            "a pack outside the stretch keeps its run in base, as capture is on"
        );
    });
}

/// A pack assembled in a stretch whose stretch flips on record before the
/// pack finishes fails at the finish: its run row can no longer land in the
/// stretch, and the retrieval fails with it rather than warning past it
/// (ONE-1570 Arm B). Base keeps no run of it.
#[test]
fn a_stretch_pack_whose_run_cannot_land_fails_at_its_finish() {
    run_on_engine_stack("stretch-pack-flipped", async {
        let host = host();
        let owner = host
            .vault
            .authenticate_owner(
                host.owner,
                &host.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the owner's proof");
        let before = host.base_runs();
        let finished =
            finish_stretch_pack_after_flip(&host.vault, &owner, FLIPPED_STRETCH, STAGED_WORD)
                .expect("the pack assembles in the stretch and the stretch flips on record");
        let error = finished.expect_err("a pack whose run cannot land fails at its finish");
        assert_eq!(
            error.kind(),
            ErrorKind::OffRecordOverlayLeaseClosed,
            "the finish answers the stretch's closed overlay: {error:?}"
        );
        assert_eq!(
            host.base_runs(),
            before,
            "base keeps no run of a pack assembled in the stretch"
        );
    });
}
