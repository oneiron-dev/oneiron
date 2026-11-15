//! CROSS-ARCH-0002b #ep-6-2-3 `packetId` on the context call (Engine RULING
//! L10-02-SURFACE = A: rehydration is `POST /v1/core/context-pack`; RULING
//! L10-03-PACKET-STORE = B: the epoch summary is the stored packet). A
//! request that names the epoch summary a `host.compact` minted gets the rows
//! that summary carries first, before the ranked fill, with the pack's
//! working-set accounting in its stats. A malformed id is a 400, and an id
//! that names no epoch summary is a stale packet: today's pack.
//!
//! On unmodified main the route reads no `packet_id`: the carried rows never
//! lead, and a malformed id is answered 200.
//!
//! Each case drives the real route with the owner's host-root credential, on
//! a profiled install, on an engine-sized stack. Deterministic: in-process
//! vault and router (`oneshot`, no TCP ports, no sleeps, no models, no
//! embedder; the compaction backend is a fixture).
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test context_pack_packet_id`.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::compaction::{CompactionCheck, CompactionGatePolicy, CompactionRefusal};
use oneiron::edge::EdgeActorClass;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::runtime_hooks::host_doors::{HostCompactRequest, compact_as_owner};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    CompactionBackend, CompactionProduct, CompactionRequest, CompactionTierClass,
    CompactionWindowMessage, EntityId, FinishReason, SessionMintOutcome, TimeRange, Vault,
    VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const CONTEXT_PACK: &str = "/v1/core/context-pack";
const LEARNED_AT: u64 = 1_780_000_000;
/// The one word the owner's ranked turn holds, which no other row holds.
const TURN_WORD: &str = "quayside";
/// What the fixture backend summarizes each window as.
const SUMMARY_TEXT: &str = "The owner and the host walked through the harbor ledger, agreed \
     which rows stay in view after the swap, and set the next review for the morning shift.";

/// A cheap backend that answers every window with [`SUMMARY_TEXT`] over the
/// window's own span, in the reply schema the gate parses.
struct SummaryBackend;

impl CompactionBackend for SummaryBackend {
    fn backend_key(&self) -> &str {
        "test.cheap.packet"
    }

    fn tier_class(&self) -> CompactionTierClass {
        CompactionTierClass::Cheap
    }

    fn compact(
        &self,
        request: &CompactionRequest,
        _retry: Option<CompactionCheck>,
    ) -> Result<CompactionProduct, CompactionRefusal> {
        let through = request
            .window
            .last()
            .map_or(request.turn_start, |message| message.turn);
        Ok(CompactionProduct {
            summary_text: json!({
                "from": request.turn_start,
                "through": through,
                "summary": SUMMARY_TEXT,
            })
            .to_string(),
            finish: FinishReason::Stop,
            latency: Duration::from_millis(5),
        })
    }
}

struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    /// The two claims the summary carries; no query finds them.
    carried: [EntityId; 2],
    /// The epoch summary `host.compact` minted.
    summary: EntityId,
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
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn fixture_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).expect("valid entity id")
}

fn occurred() -> TimeRange {
    TimeRange {
        start: LEARNED_AT,
        end: LEARNED_AT,
    }
}

fn put_claim(vault: &Vault, subject: EntityId, id: EntityId, value: &str) {
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    vault
        .put_claim(&id, &body, occurred(), LEARNED_AT)
        .expect("fixture claim");
}

/// One witnessed turn holding `content`, in `session` when one is given. A
/// base witness parses its conversation ref as an entity ref.
fn witness(
    vault: &Vault,
    owner: EntityId,
    session: bool,
    turn: Option<EntityId>,
    content: &str,
    at: u64,
) {
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let memory = if session {
        memory.with_session(vault.local_session_key(owner).expect("session key"))
    } else {
        memory
    };
    memory
        .witness(&WitnessTurn {
            conversation_ref: if session {
                fixture_id(0x70).to_hex()
            } else {
                EntityId::now().to_hex()
            },
            turn_ref: turn.map(|turn| turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: content.to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
                parts: None,
                quote: None,
            }],
            occurred_at: at,
            assertions: Default::default(),
        })
        .expect("a witnessed turn");
}

/// A served host: two carried claims about a person, the owner's ranked turn
/// holding [`TURN_WORD`], and one `host.compact` over a two-turn window of
/// the owner's SESSION that carries both claims.
fn host() -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    config.dimensions = 4;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    // The claims are written before the host roots the vault, as a device
    // vault holds them before its first serving start.
    let subject = fixture_id(0x21);
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            occurred(),
            LEARNED_AT,
            b"subject",
        )
        .expect("subject entity");
    let carried = [fixture_id(0x41), fixture_id(0x42)];
    put_claim(&vault, subject, carried[0], "carried berth one");
    put_claim(&vault, subject, carried[1], "carried berth two");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("context-pack-packet-id".into()),
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

    let now = vault.now_recorded_at();
    witness(
        &vault,
        owner,
        false,
        None,
        &format!("the ferry waits at the {TURN_WORD}"),
        now,
    );
    let summary = compact(&vault, owner, &carried, now);
    let app = build_app(server);
    Host {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        carried,
        summary,
    }
}

/// The owner's `host.compact` over turns 1 and 2 of a fresh SESSION,
/// carrying `working_set`; the minted epoch summary.
fn compact(vault: &Vault, owner: EntityId, working_set: &[EntityId], now: u64) -> EntityId {
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let session = match vault
        .mint_session(vault.local_session_key(owner).expect("session key"), now)
        .expect("mint session")
    {
        SessionMintOutcome::Minted(session) | SessionMintOutcome::AlreadyOpen(session) => session,
    };
    let window: Vec<CompactionWindowMessage> = (1..=2_u64)
        .map(|turn| {
            let turn_id = fixture_id(0x80 + u8::try_from(turn).expect("a small turn number"));
            let content = format!(
                "turn {turn}: the owner reads the harbor ledger aloud, row by row, while the \
                 host notes which entries the next shift must keep in view, which ones close \
                 today, and which ones wait on the berth schedule"
            );
            witness(vault, owner, true, Some(turn_id), &content, now + turn);
            CompactionWindowMessage {
                message_id: EntityId::now(),
                turn_id,
                content,
                turn,
                tokens: 40,
            }
        })
        .collect();
    let result = compact_as_owner(
        &vault.memory(owner, EdgeActorClass::Human),
        &proof,
        HostCompactRequest {
            session_ref: session,
            window,
            keep_list: Vec::new(),
            token_ceiling: 400,
            working_set: working_set.to_vec(),
        },
        &SummaryBackend,
        &CompactionGatePolicy::default(),
    )
    .expect("host.compact with a working set");
    assert_eq!(result.carried, 2, "the summary carries both claims");
    result.summary
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

    /// The owner's context pack for `body` over the route; its status and
    /// its JSON answer.
    async fn pack(&self, body: Value) -> (StatusCode, Value) {
        let request = Request::post(CONTEXT_PACK)
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding())
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
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
        (status, answer)
    }

    fn carried_hex(&self) -> Vec<String> {
        self.carried.iter().map(EntityId::to_hex).collect()
    }
}

/// The result ids of `pack`, in pack order.
fn result_ids(pack: &Value) -> Vec<String> {
    pack["results"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn a_packet_id_leads_the_pack_with_the_rows_its_summary_carries() {
    run_on_engine_stack("pack-packet-id-leads", async {
        let host = host();
        let (status, today) = host.pack(json!({"query": TURN_WORD, "limit": 10})).await;
        assert_eq!(status, StatusCode::OK, "{today}");
        let today_ids = result_ids(&today);
        assert!(!today_ids.is_empty(), "the query finds the turn: {today}");
        assert!(
            host.carried_hex().iter().all(|id| !today_ids.contains(id)),
            "no query finds a carried row: {today}"
        );
        assert!(today["stats"].get("working_set").is_none(), "{today}");

        let (status, pack) = host
            .pack(json!({
                "query": TURN_WORD,
                "limit": 10,
                "packetId": host.summary.to_hex(),
            }))
            .await;
        assert_eq!(status, StatusCode::OK, "{pack}");
        let ids = result_ids(&pack);
        assert_eq!(
            ids.get(..2),
            Some(&host.carried_hex()[..]),
            "the carried rows lead, in the host's order: {pack}"
        );
        assert_eq!(&ids[2..], &today_ids[..], "then today's fill: {pack}");
        let working_set = &pack["stats"]["working_set"];
        assert_eq!(working_set["asked"], json!(2), "{pack}");
        assert_eq!(working_set["served"], json!(2), "{pack}");
        assert_eq!(working_set["stale"], json!(false), "{pack}");
    });
}

#[test]
fn a_malformed_packet_id_is_a_bad_request() {
    run_on_engine_stack("pack-packet-id-malformed", async {
        let host = host();
        let (status, answer) = host
            .pack(json!({"query": TURN_WORD, "packet_id": "not-a-packet"}))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    });
}

#[test]
fn a_packet_id_that_names_no_epoch_summary_is_todays_pack() {
    run_on_engine_stack("pack-packet-id-stale", async {
        let host = host();
        let (_, today) = host.pack(json!({"query": TURN_WORD, "limit": 10})).await;
        for packet in [EntityId::now(), host.carried[0]] {
            let (status, pack) = host
                .pack(json!({
                    "query": TURN_WORD,
                    "limit": 10,
                    "packet_id": packet.to_hex(),
                }))
                .await;
            assert_eq!(status, StatusCode::OK, "{pack}");
            assert_eq!(result_ids(&pack), result_ids(&today), "{pack}");
            assert_eq!(pack["stats"]["working_set"]["stale"], json!(true), "{pack}");
            assert_eq!(pack["stats"]["working_set"]["served"], json!(0), "{pack}");
        }
    });
}
