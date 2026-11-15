//! Promise tests for the off-record session doors a stretch's manager calls
//! (ruling L4-23 = A: each test proves a promise at its door; DOOR-127):
//! `vault.off_record.start`, `.status`, `.witness`, `.discard`, `.recall`,
//! `.notes.create`, `.claims.upsert` and `.artifacts.save`, each entered at
//! its generated HTTP facade route, `POST /v1/core/facade/<verb>`.
//!
//! The promises, one test each:
//! - Close drops the overlay (ARCH-0052 §2): a discarded stretch stops
//!   resolving, and nothing it held is in base.
//! - Off-record bytes never enter vault storage (ARCH-0052 D1): no file under
//!   the vault's directory holds a byte of what the stretch was told, while
//!   it is live and after it is discarded.
//! - A stretch entered alone answers only its creator and the owner (the door
//!   module's rule: WILL-PLAN L13 row 03, Engine ruling 2026-10-19; FIX 4597):
//!   another principal gets the 404 a stretch that does not exist gets, and
//!   may take the same name for a stretch of its own.
//! - A room's stretch keeps its members' bounded acts and refuses whole-room
//!   management (Engine ruling 2026-10-19; `room_management`).
//! - An outsider gets the same 404 as for a stretch that does not exist
//!   (ARCH-0052 D5, outsiders).
//! - No session door keeps a wire receipt (ARCH-0052 D5): every reply states
//!   `x-oneiron-receipt-ref: none; no-record`.
//!
//! The owner calls on the host-root credential of a profiled install, as a
//! serving start enrols it; each agent on its own slip, signed by its own
//! key. Deterministic: an in-process vault and router (`oneshot`), no TCP
//! port, no sleep, no model.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support
//! --test vault_off_record_doors`.

#![cfg(unix)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    AgentTier, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge,
};
use oneiron::claim::{base_world_id, default_project_id};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput, WitnessAuthor,
    WitnessMessage, WitnessReceipt, WitnessTurn,
};
use oneiron::off_record::{OffRecordBackendClass, room_session_key};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The reply header that states a call's receipt.
const RECEIPT_REF_HEADER: &str = "x-oneiron-receipt-ref";
/// What that header states for a call no wire receipt may record.
const NO_RECORD: &str = "none; no-record";
/// The code a whole-room management refusal carries.
const ROOM_MANAGEMENT: &str = "OFF_RECORD_ROOM_MANAGEMENT_CONSENT_UNAVAILABLE";
/// The name the room cases' stretch is entered under.
const ROOM_STRETCH: &str = "doors-room-stretch";

/// One served vault: the owner on the host root of a profiled install.
struct Host {
    dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_slip: CapabilitySlip,
    owner_token: String,
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

/// One reply: its status, its `x-oneiron-receipt-ref` header and its JSON.
struct Reply {
    status: StatusCode,
    receipt_ref: Option<String>,
    body: Value,
}

impl Reply {
    /// The body of a 200, or a failure naming the verb and the reply.
    fn ok(self, verb: &str) -> Value {
        assert_eq!(self.status, StatusCode::OK, "{verb} answered {}", self.body);
        self.body
    }

    /// The refusal's `error.code`.
    fn code(&self) -> &str {
        self.body["error"]["code"].as_str().unwrap_or("")
    }

    /// The refusal as a caller can compare it: status, code, message with
    /// `named` replaced, and suggestions. The request id differs per call.
    fn refusal_naming(&self, named: &str) -> Value {
        let error = &self.body["error"];
        json!({
            "status": self.status.as_u16(),
            "code": error["code"],
            "message": error["message"].as_str().unwrap_or("").replace(named, "<session>"),
            "suggestions": error["suggestions"],
        })
    }
}

/// A host whose vault serves the facade; its owner is the vault's embedded
/// owner, on the host root.
fn host() -> Host {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    config.dimensions = 4;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-off-record-doors".into()),
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
    Host {
        dir,
        vault,
        app: build_app(server),
        issuer,
        owner,
        owner_slip,
        owner_token,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One user message saying `content`, as a turn with no conversation named.
fn turn(content: &str, occurred_at: u64) -> Value {
    serde_json::to_value(WitnessTurn {
        conversation_ref: String::new(),
        turn_ref: None,
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
        occurred_at,
        assertions: Default::default(),
    })
    .expect("witness turn JSON")
}

/// Whether any file under `root` holds the bytes of `word`.
fn storage_holds(root: &Path, word: &str) -> bool {
    let needle = word.as_bytes();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("read a vault directory") {
            let path = entry.expect("vault directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if let Ok(bytes) = std::fs::read(&path)
                && bytes.windows(needle.len()).any(|window| window == needle)
            {
                return true;
            }
        }
    }
    false
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

    /// The vault's own agent `name`, bound with full access, on its own
    /// read-and-write slip.
    fn agent(&self, name: &str, seed: u8) -> (EntityId, Principal) {
        let agent = self
            .vault
            .ensure_agent_principal(name)
            .expect("the vault's own agent");
        self.vault
            .bind_and_grant_agent_principal(
                &self.issuer,
                &self.owner_proof(),
                agent,
                AgentTier::FullAccess.ceiling(),
            )
            .expect("bind the vault's own agent");
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.owner_slip.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = agent.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("agent".to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        claims.slip_id = [seed; 32];
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("mint the agent's slip");
        (agent, Principal { slip, key })
    }

    /// A live stretch in a Group room that seats the owner and `member`,
    /// entered by the owner; the key later calls name it by.
    fn room_stretch(&self, member: EntityId) -> String {
        let vault = &self.vault;
        let by_owner = || WriteActor::new(self.owner, EdgeActorClass::Human);
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
        vault
            .off_record_session_vault()
            .enter_in_room_as(
                ROOM_STRETCH,
                OffRecordBackendClass::Local,
                room,
                &self.owner_proof(),
            )
            .expect("enter the room stretch");
        room_session_key(room, ROOM_STRETCH)
    }

    /// `caller`'s call to `verb` at its facade route.
    async fn send(&self, caller: Caller<'_>, verb: &str, input: Value) -> Reply {
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
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding)
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("facade request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("facade response");
        let status = response.status();
        let receipt_ref = response
            .headers()
            .get(RECEIPT_REF_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("facade response body");
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{verb} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        Reply {
            status,
            receipt_ref,
            body,
        }
    }

    /// `caller` starts a stretch alone under `name`, off record; the handle
    /// later calls name it by.
    async fn start(&self, caller: Caller<'_>, name: &str) -> String {
        let view = self
            .send(
                caller,
                "vault.off_record.start",
                json!({"session_ref": name, "mode": "off_record", "backend": "local"}),
            )
            .await
            .ok("vault.off_record.start");
        view["session_ref"]
            .as_str()
            .expect("the stretch's handle")
            .to_owned()
    }

    /// `caller` witnesses one turn saying `content` into `session`; the
    /// turn's id.
    async fn witness(&self, caller: Caller<'_>, session: &str, content: &str) -> EntityId {
        let receipt = self
            .send(
                caller,
                "vault.off_record.witness",
                json!({
                    "session_ref": session,
                    "turn": turn(content, self.vault.now_recorded_at()),
                }),
            )
            .await
            .ok("vault.off_record.witness");
        serde_json::from_value::<WitnessReceipt>(receipt)
            .expect("a witness receipt")
            .turn_id
    }

    /// `caller` writes one research NOTE saying `markdown` into `session`;
    /// the note's id.
    async fn note(&self, caller: Caller<'_>, session: &str, markdown: &str) -> EntityId {
        let receipt = self
            .send(
                caller,
                "vault.off_record.notes.create",
                json!({
                    "session_ref": session,
                    "note": {"kind": "research", "markdown": markdown},
                }),
            )
            .await
            .ok("vault.off_record.notes.create");
        EntityId::from_hex(receipt["id_hex"].as_str().expect("the note's id")).expect("note id")
    }

    /// One owner claim about the owner whose value is `value`, in the base
    /// world's default position.
    fn claim(&self, value: &str) -> ScopedClaimInput {
        ScopedClaimInput {
            id: Some(EntityId::now().to_hex()),
            predicate: "profile.preference".to_owned(),
            subject_ref: self.owner.to_hex(),
            value: json!(value),
            confidence: 1.0,
            source: "user_stated".to_owned(),
            scope: ClaimScope {
                world_id: base_world_id().to_hex(),
                scope_facet_id: self
                    .vault
                    .default_facet()
                    .expect("owner default facet")
                    .to_hex(),
                scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
                scope_project_id: default_project_id().to_hex(),
            },
            sensitivity: None,
            evidence_turn_refs: Vec::new(),
            valid_from: None,
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        }
    }

    /// Whether the vault's base store holds `id`.
    fn in_base(&self, id: &EntityId) -> bool {
        self.vault.get_raw(id).expect("base get").is_some()
    }
}

/// Close drops the overlay: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:43`, "Close
/// drops the overlay unless someone persisted from the middle." For the owner
/// and for an agent that entered its own stretch: a turn and a NOTE written
/// into the stretch read back through `vault.off_record.recall` and are in no
/// base row; `vault.off_record.discard` drops the turn and keeps none
/// promoted; after it the handle names no stretch for any session door, and
/// base still holds neither row.
#[test]
fn discard_drops_the_overlay_and_the_handle_stops_resolving() {
    run_on_engine_stack("off-record-discard", || async {
        let host = host();
        let (_, agent) = host.agent("discard-agent", 0x41);
        for (who, caller) in [
            ("owner", Caller::Owner),
            ("agent", Caller::Principal(&agent)),
        ] {
            let word = format!("marrowquill{who}");
            let session = host.start(caller, &format!("discard-{who}")).await;
            let turn_id = host
                .witness(caller, &session, &format!("the stretch says {word}"))
                .await;
            let note = host
                .note(caller, &session, &format!("a note that says {word}"))
                .await;
            assert!(
                !host.in_base(&turn_id) && !host.in_base(&note),
                "{who}: a live stretch's turn and note are in no base row"
            );
            let pack = host
                .send(
                    caller,
                    "vault.off_record.recall",
                    json!({"session_ref": session, "query": word, "limit": 10}),
                )
                .await
                .ok("vault.off_record.recall");
            assert!(
                pack["items"].to_string().contains(&word),
                "{who}: recall in the stretch reads what it holds: {pack}"
            );

            let closed = host
                .send(
                    caller,
                    "vault.off_record.discard",
                    json!({"session_ref": session}),
                )
                .await
                .ok("vault.off_record.discard");
            assert!(
                closed["turns_dropped"].as_u64() >= Some(1),
                "{who}: discard drops the stretch's turn: {closed}"
            );
            assert_eq!(
                closed["promoted_turns_kept"], 0,
                "{who}: nothing was saved from the middle, so nothing is kept: {closed}"
            );

            for (verb, input) in [
                ("vault.off_record.status", json!({"session_ref": session})),
                (
                    "vault.off_record.recall",
                    json!({"session_ref": session, "query": word, "limit": 10}),
                ),
                (
                    "vault.off_record.witness",
                    json!({
                        "session_ref": session,
                        "turn": turn("after the close", host.vault.now_recorded_at()),
                    }),
                ),
                ("vault.off_record.discard", json!({"session_ref": session})),
            ] {
                let reply = host.send(caller, verb, input).await;
                assert_eq!(
                    reply.status,
                    StatusCode::NOT_FOUND,
                    "{who}: {verb} after discard finds no stretch: {}",
                    reply.body
                );
            }
            assert!(
                !host.in_base(&turn_id) && !host.in_base(&note),
                "{who}: a discarded stretch leaves its turn and note in no base row"
            );
        }
    });
}

/// Off-record bytes never enter vault storage: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:80`,
/// "off-record bytes never enter vault storage at all." The owner tells a
/// live stretch one word through `vault.off_record.witness`,
/// `vault.off_record.notes.create` and `vault.off_record.claims.upsert`; no
/// file under the vault's directory holds that word, while the stretch is
/// live and after `vault.off_record.discard`. The control: a NOTE the owner
/// writes on record through `vault.notes.create` is found by the same scan,
/// so the scan reads the store's bytes as they are written.
#[test]
fn session_writes_leave_no_byte_in_vault_storage() {
    run_on_engine_stack("off-record-storage", || async {
        let host = host();
        const STAGED: &str = "quillmarrowsealed";
        const ON_RECORD: &str = "lanternmothrecorded";
        let session = host.start(Caller::Owner, "storage-stretch").await;
        host.witness(
            Caller::Owner,
            &session,
            &format!("the stretch says {STAGED}"),
        )
        .await;
        host.note(
            Caller::Owner,
            &session,
            &format!("a note that says {STAGED}"),
        )
        .await;
        host.send(
            Caller::Owner,
            "vault.off_record.claims.upsert",
            json!({"session_ref": session, "claim": host.claim(STAGED)}),
        )
        .await
        .ok("vault.off_record.claims.upsert");

        host.send(
            Caller::Owner,
            "vault.notes.create",
            json!({"kind": "research", "markdown": format!("an on-record note: {ON_RECORD}")}),
        )
        .await
        .ok("vault.notes.create");
        assert!(
            storage_holds(host.dir.path(), ON_RECORD),
            "the control: an on-record note's words are in vault storage"
        );
        assert!(
            !storage_holds(host.dir.path(), STAGED),
            "a live stretch's words are in no file of vault storage"
        );

        host.send(
            Caller::Owner,
            "vault.off_record.discard",
            json!({"session_ref": session}),
        )
        .await
        .ok("vault.off_record.discard");
        assert!(
            !storage_holds(host.dir.path(), STAGED),
            "a discarded stretch's words are in no file of vault storage"
        );
    });
}

/// A stretch entered alone answers only its creator and the owner: the door
/// module's rule (`crates/oneiron-server/src/api/facade/off_record_doors.rs`,
/// WILL-PLAN L13 row 03, Engine ruling 2026-10-19; FIX 4597), "Each creator
/// names their stretches in their own space ... no answer says that a name
/// someone else holds is taken." Another agent may start a stretch under the
/// same name and gets a handle of its own; naming the first agent's handle,
/// every session door answers it the 404 a stretch that does not exist gets.
/// The owner manages the first agent's stretch by its handle.
#[test]
fn a_stretch_entered_alone_answers_only_its_creator_and_the_owner() {
    run_on_engine_stack("off-record-creator", || async {
        let host = host();
        let (_, creator) = host.agent("creator-agent", 0x51);
        let (_, other) = host.agent("other-agent", 0x52);
        let first = host.start(Caller::Principal(&creator), "shared-name").await;
        let second = host.start(Caller::Principal(&other), "shared-name").await;
        assert_ne!(
            first, second,
            "a name another principal holds is not taken: each gets its own stretch"
        );
        let own = host
            .send(
                Caller::Principal(&creator),
                "vault.off_record.status",
                json!({"session_ref": "shared-name"}),
            )
            .await
            .ok("vault.off_record.status");
        assert_eq!(
            own["session_ref"], first,
            "the creator's own name resolves to its own stretch"
        );

        const NEVER: &str = "never-entered-stretch";
        for verb in [
            "vault.off_record.status",
            "vault.off_record.witness",
            "vault.off_record.recall",
            "vault.off_record.notes.create",
            "vault.off_record.artifacts.save",
            "vault.off_record.discard",
        ] {
            let input = |session: &str| match verb {
                "vault.off_record.witness" => json!({
                    "session_ref": session,
                    "turn": turn("not mine to speak in", host.vault.now_recorded_at()),
                }),
                "vault.off_record.recall" => {
                    json!({"session_ref": session, "query": "anything", "limit": 5})
                }
                "vault.off_record.notes.create" => json!({
                    "session_ref": session,
                    "note": {"kind": "research", "markdown": "not mine to write in"},
                }),
                "vault.off_record.artifacts.save" => {
                    json!({"session_ref": session, "artifact_ref": EntityId::now().to_hex()})
                }
                _ => json!({"session_ref": session}),
            };
            let held = host
                .send(Caller::Principal(&other), verb, input(&first))
                .await;
            let none = host
                .send(Caller::Principal(&other), verb, input(NEVER))
                .await;
            assert_eq!(
                held.status,
                StatusCode::NOT_FOUND,
                "{verb}: another principal's stretch is a 404: {}",
                held.body
            );
            assert_eq!(
                held.refusal_naming(&first),
                none.refusal_naming(NEVER),
                "{verb}: another principal's stretch answers as one that does not exist"
            );
        }

        let managed = host
            .send(
                Caller::Owner,
                "vault.off_record.status",
                json!({"session_ref": first}),
            )
            .await
            .ok("vault.off_record.status");
        assert_eq!(
            managed["session_ref"], first,
            "the owner reads it by its handle"
        );
        host.send(
            Caller::Owner,
            "vault.off_record.discard",
            json!({"session_ref": first}),
        )
        .await
        .ok("vault.off_record.discard");
        let gone = host
            .send(
                Caller::Principal(&creator),
                "vault.off_record.status",
                json!({"session_ref": first}),
            )
            .await;
        assert_eq!(
            gone.status,
            StatusCode::NOT_FOUND,
            "the owner's discard closed the creator's stretch: {}",
            gone.body
        );
        host.send(
            Caller::Principal(&other),
            "vault.off_record.status",
            json!({"session_ref": second}),
        )
        .await
        .ok("vault.off_record.status");
    });
}

/// A room's stretch keeps its members' bounded acts and refuses whole-room
/// management: the door module's rule (Engine ruling 2026-10-19;
/// `room_management` in `off_record_doors.rs`), "Recalling everyone's overlay
/// at once, running in it, and discarding it for the room answer
/// `OFF_RECORD_ROOM_MANAGEMENT_CONSENT_UNAVAILABLE` to a caller on its
/// roster". A seated agent reads the stretch through `vault.off_record.status`;
/// its `vault.off_record.recall` and `vault.off_record.discard`, and the
/// owner's discard, are refused with that code; the stretch stays live.
#[test]
fn a_room_stretch_refuses_whole_room_management_to_its_members() {
    run_on_engine_stack("off-record-room-management", || async {
        let host = host();
        let (member_id, member) = host.agent("member-agent", 0x61);
        let key = host.room_stretch(member_id);

        let view = host
            .send(
                Caller::Principal(&member),
                "vault.off_record.status",
                json!({"session_ref": key}),
            )
            .await
            .ok("vault.off_record.status");
        assert_eq!(
            view["session_ref"], key,
            "a member reads the room's stretch"
        );

        for (who, caller, verb, input) in [
            (
                "member",
                Caller::Principal(&member),
                "vault.off_record.recall",
                json!({"session_ref": key, "query": "anything", "limit": 5}),
            ),
            (
                "member",
                Caller::Principal(&member),
                "vault.off_record.discard",
                json!({"session_ref": key}),
            ),
            (
                "owner",
                Caller::Owner,
                "vault.off_record.discard",
                json!({"session_ref": key}),
            ),
        ] {
            let reply = host.send(caller, verb, input).await;
            assert_eq!(
                (reply.status, reply.code()),
                (StatusCode::FORBIDDEN, ROOM_MANAGEMENT),
                "{who}: {verb} would manage the room's whole stretch: {}",
                reply.body
            );
        }
        host.send(
            Caller::Owner,
            "vault.off_record.status",
            json!({"session_ref": key}),
        )
        .await
        .ok("vault.off_record.status");
    });
}

/// An outsider gets the same 404 as for a stretch that does not exist: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:194`, "A
/// caller not on the room's roster gets the same 404 as for a stretch that
/// does not exist". An agent of the vault that the room does not seat names
/// the room's stretch, and a room key no stretch holds, at every session door
/// that binds one; each pair of answers is the same refusal.
#[test]
fn an_outsider_gets_the_same_404_as_a_stretch_that_does_not_exist() {
    run_on_engine_stack("off-record-outsider", || async {
        let host = host();
        let (member_id, _member) = host.agent("seated-agent", 0x71);
        let (_, outsider) = host.agent("outsider-agent", 0x72);
        let key = host.room_stretch(member_id);
        let ghost = room_session_key(EntityId::now(), ROOM_STRETCH);
        for verb in [
            "vault.off_record.status",
            "vault.off_record.witness",
            "vault.off_record.recall",
            "vault.off_record.notes.create",
            "vault.off_record.claims.upsert",
            "vault.off_record.artifacts.save",
            "vault.off_record.discard",
        ] {
            let input = |session: &str| match verb {
                "vault.off_record.witness" => json!({
                    "session_ref": session,
                    "turn": turn("an outsider speaks", host.vault.now_recorded_at()),
                }),
                "vault.off_record.recall" => {
                    json!({"session_ref": session, "query": "anything", "limit": 5})
                }
                "vault.off_record.notes.create" => json!({
                    "session_ref": session,
                    "note": {"kind": "research", "markdown": "an outsider writes"},
                }),
                "vault.off_record.claims.upsert" => {
                    json!({"session_ref": session, "claim": host.claim("an outsider claims")})
                }
                "vault.off_record.artifacts.save" => {
                    json!({"session_ref": session, "artifact_ref": EntityId::now().to_hex()})
                }
                _ => json!({"session_ref": session}),
            };
            let held = host
                .send(Caller::Principal(&outsider), verb, input(&key))
                .await;
            let none = host
                .send(Caller::Principal(&outsider), verb, input(&ghost))
                .await;
            assert_eq!(
                held.status,
                StatusCode::NOT_FOUND,
                "{verb}: the room's stretch is a 404 to an outsider: {}",
                held.body
            );
            assert_eq!(
                held.refusal_naming(&key),
                none.refusal_naming(&ghost),
                "{verb}: the room's stretch answers an outsider as one that does not exist"
            );
        }
    });
}

/// No session door keeps a wire receipt: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:192`, "So no
/// wire receipt records that a session ran." Every reply of a session door,
/// answer or refusal, states `x-oneiron-receipt-ref: none; no-record`. The
/// control: the same NOTE written on record through `vault.notes.create`
/// states a receipt ref.
#[test]
fn no_session_door_keeps_a_wire_receipt() {
    run_on_engine_stack("off-record-no-receipt", || async {
        let host = host();
        let control = host
            .send(
                Caller::Owner,
                "vault.notes.create",
                json!({"kind": "research", "markdown": "an on-record note"}),
            )
            .await;
        let control_ref = control.receipt_ref.clone();
        control.ok("vault.notes.create");
        assert!(
            control_ref
                .as_deref()
                .is_some_and(|value| !value.is_empty() && value != NO_RECORD),
            "the control: an on-record write states its receipt ref, got {control_ref:?}"
        );

        let start = host
            .send(
                Caller::Owner,
                "vault.off_record.start",
                json!({"session_ref": "receipt-stretch", "mode": "off_record", "backend": "local"}),
            )
            .await;
        let start_ref = start.receipt_ref.clone();
        let session = start.ok("vault.off_record.start")["session_ref"]
            .as_str()
            .expect("the stretch's handle")
            .to_owned();
        let mut stated = vec![("vault.off_record.start", start_ref)];
        for (verb, input) in [
            ("vault.off_record.status", json!({"session_ref": session})),
            (
                "vault.off_record.witness",
                json!({
                    "session_ref": session,
                    "turn": turn("the stretch says nothing", host.vault.now_recorded_at()),
                }),
            ),
            (
                "vault.off_record.notes.create",
                json!({
                    "session_ref": session,
                    "note": {"kind": "research", "markdown": "an off-record note"},
                }),
            ),
            (
                "vault.off_record.claims.upsert",
                json!({"session_ref": session, "claim": host.claim("an off-record claim")}),
            ),
            (
                "vault.off_record.recall",
                json!({"session_ref": session, "query": "nothing", "limit": 5}),
            ),
            ("vault.off_record.discard", json!({"session_ref": session})),
            // A refusal: the stretch is closed now.
            ("vault.off_record.status", json!({"session_ref": session})),
        ] {
            let reply = host.send(Caller::Owner, verb, input).await;
            stated.push((verb, reply.receipt_ref));
        }
        for (verb, receipt_ref) in stated {
            assert_eq!(
                receipt_ref.as_deref(),
                Some(NO_RECORD),
                "{verb}: a session door's reply keeps no wire receipt"
            );
        }
    });
}
