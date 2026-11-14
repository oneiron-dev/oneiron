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
//! A member of a room (ROOM-PACK-MEMBER-BIND; ARCH-0052 #e5-read-union-open
//! = B, the lead's ruling 13 Nov 05:5x): the owner witnesses one turn into a
//! stretch in a Group room that seats the owner and their own agent. The
//! agent, on its own slip, names that room's stretch in `x-oneiron-session`:
//! its pack binds the stretch while the agent is on the roster, so its
//! retrieval run lands in the stretch, never in base, and each staged row is
//! read under the agent's own key. An agent not on the roster reads base
//! alone. The owner's pack in the same stretch is the fixture's control: it
//! returns the staged MESSAGE.
//!
//! The owner cases drive the real route with the owner's host-root
//! credential (on a profiled install, as a serving start enrols it); the
//! member cases with an agent slip signed by the agent's own key.
//! Deterministic:
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
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AgentTier, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::off_record::{OffRecordBackendClass, room_session_key};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::stretch_pack_finalize::finish_stretch_pack_after_flip;
use oneiron::{EntityId, ErrorKind, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
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
/// The stretch the member cases stage their MESSAGE in, in a room.
const ROOM_STRETCH: &str = "room-pack-room-stretch";
/// The one word the room stretch's staged MESSAGE holds, which no base row
/// and no other stretch holds.
const ROOM_WORD: &str = "kingfisher";

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
            &owner_turn(format!("the stretch says {STAGED_WORD}"), 900),
            None,
            None,
        )
        .expect("the owner's turn in the stretch");
    let staged_message = first_message(&receipt);
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

/// The owner's one-message turn saying `content` at `occurred_at`.
fn owner_turn(content: String, occurred_at: u64) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: String::new(),
        turn_ref: None,
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content,
            metadata: None,
            is_visible: true,
            order: 0,
            parts: None,
            quote: None,
        }],
        occurred_at,
        assertions: Default::default(),
    }
}

/// The short id of the first MESSAGE a witness receipt names.
fn first_message(receipt: &oneiron::memory::WitnessReceipt) -> String {
    receipt
        .message_short_ids
        .first()
        .and_then(|short| short.split(':').next())
        .expect("the turn's MESSAGE")
        .to_owned()
}

/// One of the vault's own agents on its own slip, signed by its own key.
struct Principal {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// Who sends a request: the owner on the host root, or a principal.
#[derive(Clone, Copy)]
enum Caller<'a> {
    Owner,
    Principal(&'a Principal),
}

/// A live stretch in a Group room that seats the owner and their agent
/// `member`, holding one turn the owner witnessed into it. `stranger` is
/// another of the vault's agents, not on the room's roster.
struct RoomStretch {
    /// The key `x-oneiron-session` names the stretch by.
    key: String,
    member: Principal,
    stranger: Principal,
    /// The short id of the MESSAGE the owner's turn staged in the stretch.
    staged_message: String,
}

impl Host {
    fn owner_proof(&self) -> AuthenticatedOwner {
        self.vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the owner's proof")
    }

    /// `agent`'s slip: the vault's own agent, reading on its own key.
    fn agent_slip(&self, agent: EntityId, seed: u8) -> Principal {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.owner_slip.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = agent.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("agent".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
        claims.slip_id = [seed; 32];
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("mint the agent's slip");
        Principal { slip, key }
    }

    /// A Group room seating the owner and their agent, with a stretch the
    /// owner entered there and one turn they witnessed into it.
    fn room_stretch(&self) -> RoomStretch {
        let vault = &self.vault;
        let proof = self.owner_proof();
        let by_owner = || WriteActor::new(self.owner, EdgeActorClass::Human);
        let member = vault
            .ensure_agent_principal("yuki")
            .expect("the member agent");
        let stranger = vault
            .ensure_agent_principal("owen")
            .expect("the stranger agent");
        for agent in [member, stranger] {
            vault
                .bind_and_grant_agent_principal(
                    &self.issuer,
                    &proof,
                    agent,
                    AgentTier::ReadOnly.ceiling(),
                )
                .expect("bind the vault's own agent");
        }
        let room = EntityId::now();
        vault
            .create_conversation(
                room,
                &ConversationBody {
                    kind: ConversationKind::Group,
                    member_ids: vec![self.owner],
                    ..Default::default()
                },
                by_owner(),
                vault.now_recorded_at(),
            )
            .expect("create the room");
        vault
            .join_member(
                room,
                member,
                by_owner(),
                vault.now_recorded_at(),
                HistoryChoice::Share,
            )
            .expect("seat the member agent");
        let stretch = vault
            .off_record_session_vault()
            .enter_in_room_as(ROOM_STRETCH, OffRecordBackendClass::Local, room, &proof)
            .expect("enter the room stretch");
        let receipt = vault
            .memory(self.owner, EdgeActorClass::Human)
            .witness_into_session_as(
                &proof,
                &stretch,
                &owner_turn(
                    format!("the room says {ROOM_WORD}"),
                    vault.now_recorded_at(),
                ),
                None,
                None,
            )
            .expect("the owner's turn in the room stretch");
        RoomStretch {
            key: room_session_key(room, ROOM_STRETCH),
            member: self.agent_slip(member, 0x71),
            stranger: self.agent_slip(stranger, 0x72),
            staged_message: first_message(&receipt),
        }
    }

    /// The owner's call to `route` over actual HTTP, in the stretch when
    /// `in_stretch`; its answer, which must be 200.
    async fn call(&self, route: &str, body: Value, in_stretch: bool) -> Value {
        self.send(Caller::Owner, route, body, in_stretch.then_some(STRETCH))
            .await
    }

    /// `caller`'s call to `route` over actual HTTP, in the stretch `session`
    /// names, if any; its answer, which must be 200.
    async fn send(
        &self,
        caller: Caller<'_>,
        route: &str,
        body: Value,
        session: Option<&str>,
    ) -> Value {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let (token, signature) = match caller {
            Caller::Owner => (
                self.owner_token.clone(),
                hex(&self
                    .issuer
                    .binding_proof(&self.owner_slip, &challenge)
                    .expect("owner holder proof")),
            ),
            Caller::Principal(principal) => (
                principal.slip.to_token().expect("agent slip token"),
                hex(&principal
                    .key
                    .sign(
                        &principal
                            .slip
                            .binding_transcript(&challenge)
                            .expect("agent binding transcript"),
                    )
                    .to_bytes()),
            ),
        };
        let binding =
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string();
        let mut request = Request::post(route)
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding)
            .header("content-type", "application/json");
        if let Some(session) = session {
            request = request.header("x-oneiron-session", session);
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

/// The short ids of the rows a pack returned, for a failure message.
fn result_short_ids(pack: &Value) -> Vec<&str> {
    pack["results"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entity| entity["short_id"].as_str())
        .collect()
}

/// The room request a member case sends: the room stretch's word.
fn room_pack_request() -> Value {
    json!({"query": ROOM_WORD, "limit": 10})
}

/// The owner's pack in the room's stretch returns the MESSAGE they staged
/// there: the fixture's control, so a member case that misses that MESSAGE
/// misses it by the member's read, not by the fixture.
#[test]
fn the_owners_pack_in_a_room_stretch_reads_its_staged_message() {
    run_on_engine_stack("room-stretch-owner-pack", async {
        let host = host();
        let room = host.room_stretch();
        let inside = host
            .send(
                Caller::Owner,
                CONTEXT_PACK,
                room_pack_request(),
                Some(room.key.as_str()),
            )
            .await;
        assert!(
            names_short_id(&inside["results"], &room.staged_message),
            "the owner's pack in the room stretch returns {} among {:?}",
            room.staged_message,
            result_short_ids(&inside)
        );
    });
}

/// A member's pack in the room's stretch binds it: its retrieval run lands
/// in the stretch, so base keeps none of it. The same pack with no stretch
/// named keeps its run in base. On main the member's pack reads base alone,
/// so base keeps its run either way.
#[test]
fn a_members_pack_in_a_room_keeps_no_retrieval_run_in_base() {
    run_on_engine_stack("room-stretch-member-runs", async {
        let host = host();
        let room = host.room_stretch();
        let before = host.base_runs();
        host.send(
            Caller::Principal(&room.member),
            CONTEXT_PACK,
            room_pack_request(),
            None,
        )
        .await;
        let outside = host.base_runs();
        assert_eq!(
            outside,
            before + 1,
            "the member's pack outside the stretch keeps its run in base, as capture is on"
        );
        host.send(
            Caller::Principal(&room.member),
            CONTEXT_PACK,
            room_pack_request(),
            Some(room.key.as_str()),
        )
        .await;
        assert_eq!(
            host.base_runs(),
            outside,
            "the member's pack in the room stretch keeps no retrieval run in base"
        );
    });
}

/// An agent not on the room's roster names the room's stretch and reads base
/// alone: no staged MESSAGE, and its run lands in base.
#[test]
fn a_strangers_pack_in_a_room_reads_base_alone() {
    run_on_engine_stack("room-stretch-stranger-pack", async {
        let host = host();
        let room = host.room_stretch();
        let before = host.base_runs();
        let inside = host
            .send(
                Caller::Principal(&room.stranger),
                CONTEXT_PACK,
                room_pack_request(),
                Some(room.key.as_str()),
            )
            .await;
        assert!(
            !names_short_id(&inside, &room.staged_message),
            "a stranger's pack reads none of the room stretch: {:?}",
            result_short_ids(&inside)
        );
        assert_eq!(
            host.base_runs(),
            before + 1,
            "a stranger's pack reads base, and keeps its run there"
        );
    });
}
