//! A context pack its rows left empty says so, with the owner's L2 base
//! beside it or not (FIX 22309, E2E RETRIEVAL-06; ARCH-0004 #pre-assembly:
//! "the caller sees an explicit empty result rather than invented recall").
//!
//! The L2 base answers no query. F19 (ARCH-0067 #presence-oracles-built)
//! rules that every pack its rows left empty reads alike, `missing_data` /
//! `filter_matched_none` with `total_in_scope` 0 and one generic hint, so no
//! state tells a reader a match it cannot read from no match. The code-run
//! read already reads an L2-only pack so. The HTTP door kept the empty state
//! only for a pack with no L2 base. A pack whose results and neighbours were
//! empty read `ok` whenever the owner held one base claim.
//!
//! On unmodified main the first case reads `ok`. The second case is the
//! control: a pack with rows reads `ok` beside the same L2 base.
//!
//! Each case drives the real route with the owner's host-root credential (on
//! a profiled install, as a serving start enrols it). Deterministic:
//! in-process vault and router (`oneshot`, no TCP ports, no sleeps, no
//! models, no embedder).
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test context_pack_empty_beside_l2_base`.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::edge::EdgeActorClass;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

const CONTEXT_PACK: &str = "/v1/core/context-pack";
/// When the owner's base claim was learned and holds.
const LEARNED_AT: u64 = 1_780_000_000;
/// The one word the owner's witnessed turn holds, which no claim holds.
const TURN_WORD: &str = "quayside";
/// The owner's base claim's text, which the L2 base renders.
const CLAIM_TEXT: &str = "harbor note quay one";

struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
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

/// A served host whose owner holds one base-reality claim about themself
/// (the L2 base every owner pack carries) and, when `with_turn`, one
/// witnessed turn.
fn host(with_turn: bool) -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    config.dimensions = 4;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    // The base claim is written before the host roots the vault, as a device
    // vault holds it before its first serving start.
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    seed_base_claim(&vault, owner);
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("context-pack-empty-beside-l2-base".into()),
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

    if with_turn {
        witness_turn(&vault, owner);
    }

    let app = build_app(server);
    Host {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
    }
}

/// The owner's base-reality claim about themself: an L2 base row.
fn seed_base_claim(vault: &Vault, owner: EntityId) {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(owner),
        rmpv::Value::from(CLAIM_TEXT),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    let claim = EntityId::from_bytes([0x41; 16]).expect("claim id");
    vault
        .put_claim(
            &claim,
            &body,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
        )
        .expect("the owner's base claim");
}

/// The owner's one turn, holding [`TURN_WORD`].
fn witness_turn(vault: &Vault, owner: EntityId) {
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: String::new(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: format!("the ferry waits at the {TURN_WORD}"),
                metadata: None,
                is_visible: true,
                order: 0,
                parts: None,
                quote: None,
            }],
            occurred_at: 900,
            assertions: Default::default(),
        })
        .expect("the owner's witnessed turn");
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

    /// The owner's context pack for `query` over actual HTTP; its answer,
    /// which must be 200.
    async fn pack(&self, query: &str) -> Value {
        let request = Request::post(CONTEXT_PACK)
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding())
            .header("content-type", "application/json")
            .body(Body::from(json!({"query": query, "limit": 10}).to_string()))
            .expect("pack request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("pack response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("pack response body");
        let answer: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{CONTEXT_PACK} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        assert_eq!(status, StatusCode::OK, "{CONTEXT_PACK} answered {answer}");
        answer
    }
}

/// Whether `pack` carries the owner's L2 base, rendering the base claim.
fn carries_l2_base(pack: &Value) -> bool {
    pack["l2_base"]["body"]
        .as_str()
        .is_some_and(|body| body.contains(CLAIM_TEXT))
}

fn rows(pack: &Value, key: &str) -> usize {
    pack[key].as_array().map_or(0, Vec::len)
}

#[test]
fn a_pack_its_rows_left_empty_says_so_beside_the_l2_base() {
    run_on_engine_stack("pack-empty-beside-l2", async {
        let host = host(false);
        let token = format!("zq{}", EntityId::now().to_hex());
        let pack = host.pack(&token).await;
        let state = &pack["state"];
        assert_eq!(
            (rows(&pack, "results"), rows(&pack, "neighbors")),
            (0, 0),
            "a fresh token matches no row: state {state} pack {pack}",
        );
        assert!(
            carries_l2_base(&pack),
            "the owner's pack carries the L2 base: state {state} pack {pack}",
        );
        assert_eq!(
            state["kind"],
            Value::from("missing_data"),
            "a pack its rows left empty says so beside the L2 base, not ok: state {state}",
        );
        assert_eq!(
            state["reason"],
            Value::from("filter_matched_none"),
            "{state}"
        );
        assert_eq!(state["total_in_scope"], Value::from(0), "{state}");
        assert!(
            state["hint"].as_str().is_some_and(|hint| !hint.is_empty()),
            "{state}",
        );
        assert_eq!(pack["evidence"]["result_ids"], json!([]), "{pack}");
    });
}

#[test]
fn a_pack_with_rows_reads_ok_beside_the_l2_base() {
    run_on_engine_stack("pack-rows-beside-l2", async {
        let host = host(true);
        let pack = host.pack(TURN_WORD).await;
        let state = &pack["state"];
        assert!(
            rows(&pack, "results") > 0,
            "the witnessed turn's word finds it: state {state} pack {pack}",
        );
        assert!(
            carries_l2_base(&pack),
            "the owner's pack carries the L2 base: state {state} pack {pack}",
        );
        assert_eq!(state["kind"], Value::from("ok"), "{state}");
        assert!(state.get("reason").is_none_or(Value::is_null), "{state}");
    });
}
