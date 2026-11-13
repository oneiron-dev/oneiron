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
//! A staged row hangs under the stretch's own conversation shell, not under
//! the room, so a member's pack that names the room (`conversation_id`)
//! meets the room's rules only once the read maps that shell to its room:
//! the member reads the staged turn, a member who joined with no history
//! reads nothing staged before the join, a member who left reads base alone,
//! and a private thread the member is out of stays out of their pack and its
//! counts. The owner's pack that names the room reads the staged turn while
//! the owner's agent in the room, a peer of that read, holds a grant to the
//! room's messages, and not without one.
//!
//! A stretch's staged rows are its live overlay's, which the disclosure
//! clamp's Tier-A rule 1 withholds from every reader but the owner alone.
//! ARCH-0052 D5 rule 1 (ROOM-PACK-STRETCH-TIER-A = A, the lead 14 Nov 05:3x,
//! from the owner's OFFRECORD-WORDS = A, ARCH-0052:18: "the agent in the room
//! sees both the room and outside. but the room itself is sealed from
//! outside. one-way mirror"): a pack bound to the stretch, whose every
//! interlocutor is seated in its room, reads the stretch's own rows past
//! rule 1. A pack that names a contact outside the room still withholds
//! them, though that contact's clearance would admit them, and a member's
//! pack in one room's stretch reads no row another live room's stretch
//! staged.
//!
//! The owner cases that name no room drive the real route with the owner's
//! host-root credential (on a profiled install, as a serving start enrols
//! it). A room proves its reader the owner only by a slip naming the owner's
//! PERSON, which a bare host credential does not, so the owner cases that
//! name the room read on the owner's own full slip, signed by its own key;
//! the member cases on an agent slip signed by the agent's own key.
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
use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::authority::{
    AgentTier, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::disclosure::DisclosureScope;
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
/// The word of a turn the room stretch staged before a late joiner's join.
const EARLY_WORD: &str = "heron";
/// The word of a private thread's root the member is out of.
const THREAD_WORD: &str = "plover";
/// The stretch of a second room that also seats the member.
const OTHER_ROOM_STRETCH: &str = "room-pack-other-room-stretch";
/// The one word the second room's stretch staged, which no base row and no
/// other stretch holds.
const OTHER_ROOM_WORD: &str = "wagtail";

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
    room: EntityId,
    member_id: EntityId,
    member: Principal,
    stranger: Principal,
    /// The short id of the MESSAGE the owner's turn staged in the stretch.
    staged_message: String,
    /// With [`RoomPlan::late_joiner`], the MESSAGE staged before the join.
    early_message: Option<String>,
    /// With [`RoomPlan::private_thread`], the thread root's MESSAGE.
    thread_message: Option<String>,
}

/// How [`Host::room_stretch_planned`] seats the member and what it stages.
#[derive(Clone, Copy, Default)]
struct RoomPlan {
    /// Seat the member with no history after a first staged turn
    /// ([`EARLY_WORD`]), then stage the room's turn ([`ROOM_WORD`]).
    late_joiner: bool,
    /// Open a private thread on the room's turn whose audience is the owner
    /// alone, its root saying [`THREAD_WORD`].
    private_thread: bool,
    /// Give the member a grant to read the room's messages.
    member_reads_messages: bool,
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

    /// The owner's own full slip, held by the owner's PERSON as a human and
    /// signed by its own key: the credential a room proves its owner reader
    /// by, which the bare host root is not.
    fn owner_full_slip(&self, seed: u8) -> Principal {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.owner_slip.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = self.owner.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = Scope::top();
        claims.slip_id = [seed; 32];
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("mint the owner's own slip");
        Principal { slip, key }
    }

    /// A second Group room seating the owner and `room`'s member, with a
    /// stretch the owner entered there and one turn saying
    /// [`OTHER_ROOM_WORD`] they witnessed into it, live beside `room`'s:
    /// the key `x-oneiron-session` names it by, the room, and the short id
    /// of its staged MESSAGE.
    fn other_room_stretch(&self, room: &RoomStretch) -> (String, EntityId, String) {
        let vault = &self.vault;
        let proof = self.owner_proof();
        let by_owner = || WriteActor::new(self.owner, EdgeActorClass::Human);
        let now = vault.now_recorded_at();
        let other = EntityId::now();
        vault
            .create_conversation(
                other,
                &ConversationBody {
                    kind: ConversationKind::Group,
                    member_ids: vec![self.owner],
                    ..Default::default()
                },
                by_owner(),
                now.saturating_sub(100),
            )
            .expect("create the second room");
        vault
            .join_member(
                other,
                room.member_id,
                by_owner(),
                now.saturating_sub(100),
                HistoryChoice::Share,
            )
            .expect("seat the member in the second room");
        let stretch = vault
            .off_record_session_vault()
            .enter_in_room_as(
                OTHER_ROOM_STRETCH,
                OffRecordBackendClass::Local,
                other,
                &proof,
            )
            .expect("enter the second room's stretch");
        let receipt = vault
            .memory(self.owner, EdgeActorClass::Human)
            .witness_into_session_as(
                &proof,
                &stretch,
                &owner_turn(format!("the other room says {OTHER_ROOM_WORD}"), now),
                None,
                None,
            )
            .expect("the owner's turn in the second room's stretch");
        (
            room_session_key(other, OTHER_ROOM_STRETCH),
            other,
            first_message(&receipt),
        )
    }

    /// A Group room seating the owner and their agent, with a stretch the
    /// owner entered there and one turn they witnessed into it.
    fn room_stretch(&self) -> RoomStretch {
        self.room_stretch_planned(RoomPlan::default())
    }

    /// [`Self::room_stretch`] as `plan` seats the member and stages. Every
    /// time is at or before now, as the roster is read at now: the room is
    /// made 100 s back, an early turn staged 50 s back, a late join 10 s back.
    fn room_stretch_planned(&self, plan: RoomPlan) -> RoomStretch {
        let vault = &self.vault;
        let proof = self.owner_proof();
        let by_owner = || WriteActor::new(self.owner, EdgeActorClass::Human);
        let now = vault.now_recorded_at();
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
                now.saturating_sub(100),
            )
            .expect("create the room");
        if !plan.late_joiner {
            vault
                .join_member(
                    room,
                    member,
                    by_owner(),
                    now.saturating_sub(100),
                    HistoryChoice::Share,
                )
                .expect("seat the member agent");
        }
        let stretch = vault
            .off_record_session_vault()
            .enter_in_room_as(ROOM_STRETCH, OffRecordBackendClass::Local, room, &proof)
            .expect("enter the room stretch");
        let witness = |turn: WitnessTurn| {
            vault
                .memory(self.owner, EdgeActorClass::Human)
                .witness_into_session_as(&proof, &stretch, &turn, None, None)
                .expect("the owner's turn in the room stretch")
        };
        let early_message = plan.late_joiner.then(|| {
            let early = witness(owner_turn(
                format!("the room said {EARLY_WORD}"),
                now.saturating_sub(50),
            ));
            vault
                .join_member(
                    room,
                    member,
                    by_owner(),
                    now.saturating_sub(10),
                    HistoryChoice::None,
                )
                .expect("seat the member agent with no history");
            first_message(&early)
        });
        let receipt = witness(owner_turn(format!("the room says {ROOM_WORD}"), now));
        let thread_message = plan.private_thread.then(|| {
            let mut root = owner_turn(format!("between us, {THREAD_WORD}"), now);
            root.thread_audience = Some(BTreeSet::from([self.owner]));
            root.messages[0].metadata = Some(json!({"room_thread_of": receipt.turn_id.to_hex()}));
            first_message(&witness(root))
        });
        if plan.member_reads_messages {
            grant_room_messages(vault, room, member);
        }
        RoomStretch {
            key: room_session_key(room, ROOM_STRETCH),
            room,
            member_id: member,
            member: self.agent_slip(member, 0x71),
            stranger: self.agent_slip(stranger, 0x72),
            staged_message: first_message(&receipt),
            early_message,
            thread_message,
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

/// `principal` reads `room`'s MESSAGEs under an active grant.
fn grant_room_messages(vault: &Vault, room: EntityId, principal: EntityId) {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault
        .create_access_grant(
            &EntityId::now(),
            &AccessGrant {
                authority_scope,
                principal_ref: principal,
                scope: AccessGrantScope::ConversationMessages {
                    conversation_ref: room,
                },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: vault.now_recorded_at(),
                revoked_at: None,
                expires_at: None,
                companion_bounds: None,
            },
        )
        .expect("grant the room's messages");
}

/// A contact on no room's roster whose clearance is the top of the lattice,
/// so the clearance it meets admits every row the room's own read does.
fn top_cleared_contact(vault: &Vault) -> EntityId {
    let contact = EntityId::now();
    let record = CounterpartyContactRecord::user_introduction(
        EntityId::now(),
        "owen@example.com",
        vault.now_recorded_at(),
    )
    .expect("the contact's record");
    vault
        .create_counterparty_contact(&contact, &record)
        .expect("create the contact");
    vault
        .set_counterparty_disclosure_scope(
            &contact,
            &DisclosureScope::new(Scope::top(), "outside the room", vault.now_recorded_at())
                .expect("the contact's clearance"),
        )
        .expect("clear the contact to the top");
    contact
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

/// A pack request for `query` that names `room`'s room as its conversation,
/// so the room's audience resolves its reader.
fn room_request(room: &RoomStretch, query: &str) -> Value {
    json!({"query": query, "limit": 10, "conversation_id": room.room.to_hex()})
}

/// What a pack says about its rows withheld: its narrowing's and its
/// access block's suppressed counts, each 0 when absent.
fn suppressed_counts(pack: &Value) -> (u64, u64) {
    (
        pack["narrowing"]["suppressed_count"].as_u64().unwrap_or(0),
        pack["access"]["accessLimited"]["suppressedCount"]
            .as_u64()
            .unwrap_or(0),
    )
}

/// `caller`'s pack in `room`'s stretch for `request`.
async fn room_pack(host: &Host, caller: Caller<'_>, room: &RoomStretch, request: Value) -> Value {
    host.send(caller, CONTEXT_PACK, request, Some(room.key.as_str()))
        .await
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

/// A member of the room, the owner's own agent on its own slip, reads in its
/// pack the stretch's MESSAGE its key may read, the pack naming the room as
/// its conversation, so the room's audience resolves the member as the
/// vault's own agent. On main a member's pack reads base alone.
#[test]
fn a_members_pack_naming_the_room_reads_the_rows_it_can_read() {
    run_on_engine_stack("room-stretch-member-pack-room", async {
        let host = host();
        let room = host.room_stretch();
        let inside = room_pack(
            &host,
            Caller::Principal(&room.member),
            &room,
            room_request(&room, ROOM_WORD),
        )
        .await;
        assert!(
            names_short_id(&inside["results"], &room.staged_message),
            "the member's pack naming the room returns {} among {:?}; narrowing {}; access {}",
            room.staged_message,
            result_short_ids(&inside),
            inside["narrowing"],
            inside["access"]
        );
    });
}

/// A member who joined with no history reads, in a pack naming the room,
/// the turn the stretch staged after the join and none staged before it.
/// The owner's pack reads that earlier turn: the member's own windows keep
/// it out, not the fixture.
#[test]
fn a_late_joiners_pack_reads_nothing_staged_before_the_join() {
    run_on_engine_stack("room-stretch-late-joiner", async {
        let host = host();
        let room = host.room_stretch_planned(RoomPlan {
            late_joiner: true,
            ..RoomPlan::default()
        });
        let early = room
            .early_message
            .clone()
            .expect("the early turn's MESSAGE");
        let member = Caller::Principal(&room.member);
        let after = room_pack(&host, member, &room, room_request(&room, ROOM_WORD)).await;
        assert!(
            names_short_id(&after["results"], &room.staged_message),
            "the late joiner's pack returns {}, staged after the join, among {:?}; narrowing {}; access {}",
            room.staged_message,
            result_short_ids(&after),
            after["narrowing"],
            after["access"]
        );
        let before = room_pack(&host, member, &room, room_request(&room, EARLY_WORD)).await;
        assert!(
            !names_short_id(&before, &early),
            "the late joiner's pack holds no turn staged before the join: {:?}",
            result_short_ids(&before)
        );
        assert_eq!(
            suppressed_counts(&before),
            (0, 0),
            "the late joiner's pack counts no turn staged before the join"
        );
        let owner = room_pack(
            &host,
            Caller::Owner,
            &room,
            json!({"query": EARLY_WORD, "limit": 10}),
        )
        .await;
        assert!(
            names_short_id(&owner["results"], &early),
            "the owner's pack returns the early turn {early} among {:?}",
            result_short_ids(&owner)
        );
    });
}

/// A member reads the room's stretch while on its roster; once they leave
/// it, their pack reads base alone.
#[test]
fn a_former_members_pack_reads_the_room_stretch_no_more() {
    run_on_engine_stack("room-stretch-former-member", async {
        let host = host();
        let room = host.room_stretch();
        let member = Caller::Principal(&room.member);
        let seated = room_pack(&host, member, &room, room_request(&room, ROOM_WORD)).await;
        assert!(
            names_short_id(&seated["results"], &room.staged_message),
            "the seated member's pack returns {} among {:?}; narrowing {}; access {}",
            room.staged_message,
            result_short_ids(&seated),
            seated["narrowing"],
            seated["access"]
        );
        host.vault
            .leave_member(
                room.room,
                room.member_id,
                WriteActor::new(host.owner, EdgeActorClass::Human),
                host.vault.now_recorded_at(),
            )
            .expect("the member leaves the room");
        let before = host.base_runs();
        let left = room_pack(&host, member, &room, room_pack_request()).await;
        assert!(
            !names_short_id(&left, &room.staged_message),
            "a former member's pack reads none of the room stretch: {:?}",
            result_short_ids(&left)
        );
        assert_eq!(
            host.base_runs(),
            before + 1,
            "a former member's pack reads base, and keeps its run there"
        );
    });
}

/// A private thread the member is out of stays out of their pack, and out
/// of its counts, while they read the room's turn the thread hangs on. The
/// owner, in the thread's audience, reads its root.
#[test]
fn a_members_pack_reads_no_private_thread_it_is_out_of() {
    run_on_engine_stack("room-stretch-private-thread", async {
        let host = host();
        let room = host.room_stretch_planned(RoomPlan {
            private_thread: true,
            ..RoomPlan::default()
        });
        let thread = room
            .thread_message
            .clone()
            .expect("the thread root's MESSAGE");
        let member = Caller::Principal(&room.member);
        let trunk = room_pack(&host, member, &room, room_request(&room, ROOM_WORD)).await;
        assert!(
            names_short_id(&trunk["results"], &room.staged_message),
            "the member's pack returns the room's turn {} among {:?}; narrowing {}; access {}",
            room.staged_message,
            result_short_ids(&trunk),
            trunk["narrowing"],
            trunk["access"]
        );
        let hidden = room_pack(&host, member, &room, room_request(&room, THREAD_WORD)).await;
        assert!(
            !names_short_id(&hidden, &thread),
            "the member's pack holds no row of a thread it is out of: {:?}",
            result_short_ids(&hidden)
        );
        assert_eq!(
            suppressed_counts(&hidden),
            (0, 0),
            "the member's pack counts no row of a thread it is out of"
        );
        let owner = room_pack(
            &host,
            Caller::Owner,
            &room,
            json!({"query": THREAD_WORD, "limit": 10}),
        )
        .await;
        assert!(
            names_short_id(&owner["results"], &thread),
            "the owner's pack returns the thread root {thread} among {:?}",
            result_short_ids(&owner)
        );
    });
}

/// The owner's pack naming the room reads its staged turn while their agent
/// in the room, a peer of that read, holds a grant to the room's messages:
/// the peer reads the staged MESSAGE as one of the room's.
#[test]
fn the_owners_pack_naming_the_room_reads_its_staged_message_beside_a_granted_agent() {
    run_on_engine_stack("room-stretch-owner-names-room", async {
        let host = host();
        let room = host.room_stretch_planned(RoomPlan {
            member_reads_messages: true,
            ..RoomPlan::default()
        });
        let owner = host.owner_full_slip(0x73);
        let pack = room_pack(
            &host,
            Caller::Principal(&owner),
            &room,
            room_request(&room, ROOM_WORD),
        )
        .await;
        assert!(
            names_short_id(&pack["results"], &room.staged_message),
            "the owner's pack naming the room returns {} among {:?}; narrowing {}; access {}",
            room.staged_message,
            result_short_ids(&pack),
            pack["narrowing"],
            pack["access"]
        );
    });
}

/// The same pack naming, beside the room, a contact on no roster of it holds
/// none of the stretch's rows: the room is sealed from outside, though the
/// contact's clearance is the top and admits each of them. Without the
/// contact the same pack reads the staged turn, so the contact keeps it out.
#[test]
fn the_owners_pack_beside_a_contact_outside_the_room_reads_no_staged_row() {
    run_on_engine_stack("room-stretch-owner-outside-contact", async {
        let host = host();
        let room = host.room_stretch_planned(RoomPlan {
            member_reads_messages: true,
            ..RoomPlan::default()
        });
        let contact = top_cleared_contact(&host.vault);
        let owner = host.owner_full_slip(0x74);
        let seated = room_pack(
            &host,
            Caller::Principal(&owner),
            &room,
            room_request(&room, ROOM_WORD),
        )
        .await;
        assert!(
            names_short_id(&seated["results"], &room.staged_message),
            "the owner's pack with every interlocutor seated returns {} among {:?}; narrowing {}; access {}",
            room.staged_message,
            result_short_ids(&seated),
            seated["narrowing"],
            seated["access"]
        );
        let mut request = room_request(&room, ROOM_WORD);
        request["interlocutors"] = json!({"third_parties": [{"contact_ref": contact.to_hex()}]});
        let outside = room_pack(&host, Caller::Principal(&owner), &room, request).await;
        assert!(
            !names_short_id(&outside, &room.staged_message),
            "the owner's pack beside a contact outside the room holds none of the stretch's rows: {:?}",
            result_short_ids(&outside)
        );
    });
}

/// A member seated in two rooms, each with a live stretch, reads in its pack
/// bound to one room's stretch no row the other room's stretch staged; bound
/// to the other room's stretch, the same member reads that row.
#[test]
fn a_members_pack_in_one_room_reads_no_row_of_another_live_room() {
    run_on_engine_stack("room-stretch-other-live-room", async {
        let host = host();
        let room = host.room_stretch();
        let (other_key, other_room, other_message) = host.other_room_stretch(&room);
        let member = Caller::Principal(&room.member);
        let here = room_pack(&host, member, &room, room_request(&room, OTHER_ROOM_WORD)).await;
        assert!(
            !names_short_id(&here, &other_message),
            "the member's pack in one room's stretch holds no row of another live room: {:?}",
            result_short_ids(&here)
        );
        assert_eq!(
            suppressed_counts(&here),
            (0, 0),
            "the member's pack in one room's stretch counts no row of another live room"
        );
        let there = host
            .send(
                member,
                CONTEXT_PACK,
                json!({"query": OTHER_ROOM_WORD, "limit": 10, "conversation_id": other_room.to_hex()}),
                Some(other_key.as_str()),
            )
            .await;
        assert!(
            names_short_id(&there["results"], &other_message),
            "the member's pack in the other room's stretch returns {other_message} among {:?}; narrowing {}; access {}",
            result_short_ids(&there),
            there["narrowing"],
            there["access"]
        );
    });
}

/// The same pack beside an agent with no grant to the room's messages holds
/// no MESSAGE that agent cannot read: mapping the stretch to its room opens
/// no grant.
#[test]
fn the_owners_pack_naming_the_room_reads_no_message_an_ungranted_agent_cannot() {
    run_on_engine_stack("room-stretch-owner-ungranted-peer", async {
        let host = host();
        let room = host.room_stretch();
        let owner = host.owner_full_slip(0x75);
        let pack = room_pack(
            &host,
            Caller::Principal(&owner),
            &room,
            room_request(&room, ROOM_WORD),
        )
        .await;
        assert!(
            !names_short_id(&pack, &room.staged_message),
            "the owner's pack beside an ungranted agent holds none of its MESSAGEs: {:?}",
            result_short_ids(&pack)
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
