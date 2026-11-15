//! Promise tests for the off-record doors a room's participants call (ruling
//! L4-23 = A: each test proves a promise at its door; DOOR-127):
//! `vault.off_record.rooms.start`, `.status`, `.witness`, `.save`,
//! `.save_from_here`, `.suggest_save`, `.confirm_save`, `.decline_save` and
//! `.export`, each entered at its generated HTTP facade route,
//! `POST /v1/core/facade/<verb>`, and the participant root route
//! `GET /v1/core/off-record`, which no test named before.
//!
//! The promises (ARCH-0052 D5: the notice model, the save grant and
//! STRETCH-START), one test each:
//! - Notice, not consent: each save or export posts a notice to the room,
//!   naming who did what and when, never the talk. The root route reads the
//!   view the status door reads.
//! - Own vault only: a guest's save writes no vault; the guest takes an
//!   export file.
//! - Saving takes the save grant; asking does not: an agent without the grant
//!   suggests, everyone sees the suggestion wait, and a holder declines or
//!   confirms it.
//! - Any holder starts and saves, an agent holder too; only a person exports.
//! - From here on saves later turns only.
//! - An outsider gets the same 404 as for a stretch that does not exist, at
//!   every room door and at the root route.
//! - No room door keeps a wire receipt: every reply states
//!   `x-oneiron-receipt-ref: none; no-record`.
//!
//! Every participant calls on its own slip, signed by its own key: the owner
//! and Mina, a guest person with no vault here, on human slips; the keeper,
//! the vault's own agent, on its own write slip, so it holds the save grant;
//! the asker, the vault's own agent, on a read-and-propose slip, so it holds
//! none. Deterministic: an in-process vault and router (`oneshot`), no TCP
//! port, no sleep, no model.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support
//! --test vault_off_record_rooms_doors`.

#![cfg(unix)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, request::Builder},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    AgentTier, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessReceipt, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The reply header that states a call's receipt.
const RECEIPT_REF_HEADER: &str = "x-oneiron-receipt-ref";
/// What that header states for a call no wire receipt may record.
const NO_RECORD: &str = "none; no-record";
/// The name the room's stretch is started under.
const STRETCH: &str = "rooms-doors-stretch";
/// A name no stretch in the room holds.
const NO_STRETCH: &str = "rooms-doors-unheld";
/// The name a refused start would have taken.
const REFUSED_STRETCH: &str = "rooms-doors-refused";
/// What the talk says, which no notice, view or vault file may hold until a
/// holder saves it.
const SECRET: &str = "the lighthouse key is under the blue stone";
/// A second thing said in the talk.
const REPLY: &str = "noted, the boat leaves at dawn";

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

/// A participant on its own slip, signed by its own key.
struct Principal {
    id: EntityId,
    slip: CapabilitySlip,
    key: SigningKey,
}

/// Who sends a request: the owner on the host root, or a participant.
#[derive(Clone, Copy)]
enum Caller<'a> {
    HostRoot,
    As(&'a Principal),
}

/// One reply: its status, its `x-oneiron-receipt-ref` header and its JSON.
struct Reply {
    status: StatusCode,
    receipt_ref: Option<String>,
    body: Value,
}

impl Reply {
    /// The body of a 200, or a failure naming the call and the reply.
    fn ok(self, call: &str) -> Value {
        assert_eq!(self.status, StatusCode::OK, "{call} answered {}", self.body);
        self.body
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

/// A Group room and the four participants it seats.
struct Room {
    id: EntityId,
    /// The vault's owner, on a human slip of their own.
    owner: Principal,
    /// A guest person this vault knows, who has no vault here.
    mina: Principal,
    /// The vault's own agent on its own write slip: a holder of the grant.
    keeper: Principal,
    /// The vault's own agent on a read-and-propose slip: no holder.
    asker: Principal,
}

impl Room {
    /// The input that names the stretch `session_ref` in this room.
    fn stretch(&self, session_ref: &str) -> Value {
        json!({"room": self.id.to_hex(), "session_ref": session_ref})
    }

    /// The start input for the stretch `session_ref` in this room.
    fn start_input(&self, session_ref: &str) -> Value {
        let mut input = self.stretch(session_ref);
        input["backend"] = json!("local");
        input
    }

    /// The witness input that says `content` into the stretch `session_ref`.
    fn witness_input(&self, session_ref: &str, content: &str, occurred_at: u64) -> Value {
        let mut input = self.stretch(session_ref);
        input["turn"] = turn(content, occurred_at);
        input
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
                auth_secret: Some("vault-off-record-rooms-doors".into()),
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

/// The `(act, by)` of each notice `view` lists. Each notice names who did
/// what and when, and nothing more.
fn notices(view: &Value) -> Vec<(String, String)> {
    view["notices"]
        .as_array()
        .unwrap_or_else(|| panic!("the view lists its notices: {view}"))
        .iter()
        .map(|notice| {
            let fields: BTreeSet<&str> = notice
                .as_object()
                .unwrap_or_else(|| panic!("a notice is an object: {notice}"))
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                fields,
                BTreeSet::from(["act", "at", "by"]),
                "a notice names who did what and when, nothing more: {notice}"
            );
            (
                notice["act"].as_str().expect("the notice's act").to_owned(),
                notice["by"]
                    .as_str()
                    .expect("who the notice names")
                    .to_owned(),
            )
        })
        .collect()
}

/// Who has a save suggestion waiting, as `view` shows the room.
fn waiting(view: &Value) -> Vec<String> {
    view["waiting_suggestions"]
        .as_array()
        .unwrap_or_else(|| panic!("the view lists its waiting suggestions: {view}"))
        .iter()
        .map(|suggestion| suggestion["by"].as_str().expect("who suggested").to_owned())
        .collect()
}

/// The turns a save's answer says it wrote into this vault.
fn saved_turns(saved: &Value) -> Vec<String> {
    saved["saved"]
        .as_array()
        .unwrap_or_else(|| panic!("a save answers the turns it wrote: {saved}"))
        .iter()
        .map(|turn| turn["turn"].as_str().expect("a saved turn's id").to_owned())
        .collect()
}

/// The content of every message an export file holds, in turn order.
fn exported_words(file: &Value) -> Vec<String> {
    file["turns"]
        .as_array()
        .unwrap_or_else(|| panic!("an export file holds its turns: {file}"))
        .iter()
        .flat_map(|turn| {
            turn["messages"]
                .as_array()
                .unwrap_or_else(|| panic!("an exported turn holds its messages: {turn}"))
                .iter()
                .map(|message| {
                    message["content"]
                        .as_str()
                        .expect("an exported message's content")
                        .to_owned()
                })
        })
        .collect()
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

    /// `holder`'s own slip as a `class` participant, signed by the key
    /// `seed` makes. It allows `verbs`, or every verb when `None`.
    fn principal(
        &self,
        holder: EntityId,
        class: &str,
        seed: u8,
        verbs: Option<&[&str]>,
    ) -> Principal {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.owner_slip.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = holder.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some(class.to_owned());
        claims.scope = Scope::top();
        if let Some(verbs) = verbs {
            claims.scope.verbs =
                ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
        }
        claims.slip_id = [seed; 32];
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("mint the participant's slip");
        Principal {
            id: holder,
            slip,
            key,
        }
    }

    /// A person named `name` whom this vault knows and who has no vault
    /// here, on a read-and-write human slip of their own.
    fn guest(&self, name: &str, seed: u8) -> Principal {
        let id = EntityId::now();
        let now = self.vault.now_recorded_at();
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
        )
        .expect("the guest's PERSON body");
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )
            .expect("the guest's PERSON row");
        self.principal(id, "human", seed, Some(&["core:read", "core:write"]))
    }

    /// The vault's own agent `name`, bound at `tier`, on its own slip that
    /// allows `verbs`.
    fn agent(&self, name: &str, seed: u8, tier: AgentTier, verbs: &[&str]) -> Principal {
        let agent = self
            .vault
            .ensure_agent_principal(name)
            .expect("the vault's own agent");
        self.vault
            .bind_and_grant_agent_principal(
                &self.issuer,
                &self.owner_proof(),
                agent,
                tier.ceiling(),
            )
            .expect("bind the vault's own agent");
        self.principal(agent, "agent", seed, Some(verbs))
    }

    /// A Group room seating the owner, Mina, the keeper and the asker.
    fn room(&self) -> Room {
        let owner = self.principal(self.owner, "human", 0x41, None);
        let mina = self.guest("Mina", 0x42);
        let keeper = self.agent(
            "keeper-agent",
            0x43,
            AgentTier::FullAccess,
            &["core:read", "core:write"],
        );
        let asker = self.agent(
            "asker-agent",
            0x44,
            AgentTier::ProposeOnly,
            &["core:read", "core:propose"],
        );
        let by_owner = WriteActor::new(self.owner, EdgeActorClass::Human);
        let id = EntityId::now();
        self.vault
            .create_conversation(
                id,
                &ConversationBody {
                    kind: ConversationKind::Group,
                    member_ids: vec![self.owner],
                    ..Default::default()
                },
                by_owner,
                self.vault.now_recorded_at(),
            )
            .expect("create the room");
        for member in [mina.id, keeper.id, asker.id] {
            self.vault
                .join_member(
                    id,
                    member,
                    by_owner,
                    self.vault.now_recorded_at(),
                    HistoryChoice::Share,
                )
                .expect("seat a participant");
        }
        Room {
            id,
            owner,
            mina,
            keeper,
            asker,
        }
    }

    /// `builder` carrying `caller`'s bearer slip and a fresh holder proof.
    fn signed(&self, caller: Caller<'_>, builder: Builder) -> Builder {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let (token, signature) = match caller {
            Caller::HostRoot => (
                self.owner_token.clone(),
                hex(&self
                    .issuer
                    .binding_proof(&self.owner_slip, &challenge)
                    .expect("owner holder proof")),
            ),
            Caller::As(principal) => (
                principal.slip.to_token().expect("participant slip token"),
                hex(&principal
                    .key
                    .sign(
                        &principal
                            .slip
                            .binding_transcript(&challenge)
                            .expect("participant binding transcript"),
                    )
                    .to_bytes()),
            ),
        };
        let binding =
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string();
        builder
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding)
    }

    /// The reply `request` gets from the app.
    async fn answer(&self, call: &str, request: Request<Body>) -> Reply {
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("the app's response");
        let status = response.status();
        let receipt_ref = response
            .headers()
            .get(RECEIPT_REF_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the response body");
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{call} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        Reply {
            status,
            receipt_ref,
            body,
        }
    }

    /// `caller`'s call to `verb` at its facade route.
    async fn send(&self, caller: Caller<'_>, verb: &str, input: Value) -> Reply {
        let request = self
            .signed(caller, Request::post(format!("/v1/core/facade/{verb}")))
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("facade request");
        self.answer(verb, request).await
    }

    /// `caller`'s read of the stretch `session_ref` in `room` at the
    /// participant root route, `GET /v1/core/off-record`.
    async fn read_root(&self, caller: Caller<'_>, room: EntityId, session_ref: &str) -> Reply {
        let uri = format!(
            "/v1/core/off-record?room={}&session_ref={session_ref}",
            room.to_hex()
        );
        let request = self
            .signed(caller, Request::get(uri))
            .body(Body::empty())
            .expect("root route request");
        self.answer("GET /v1/core/off-record", request).await
    }

    /// `who` calls the room door `vault.off_record.rooms.<act>` on the
    /// stretch `session_ref` in `room`.
    async fn act(&self, who: &Principal, act: &str, room: &Room, session_ref: &str) -> Reply {
        self.send(
            Caller::As(who),
            &format!("vault.off_record.rooms.{act}"),
            room.stretch(session_ref),
        )
        .await
    }

    /// `who` starts the stretch `session_ref` in `room`; its view.
    async fn start(&self, who: &Principal, room: &Room, session_ref: &str) -> Value {
        self.send(
            Caller::As(who),
            "vault.off_record.rooms.start",
            room.start_input(session_ref),
        )
        .await
        .ok("vault.off_record.rooms.start")
    }

    /// `who` says `content` into the stretch `session_ref` in `room`; the
    /// turn's id.
    async fn say(
        &self,
        who: &Principal,
        room: &Room,
        session_ref: &str,
        content: &str,
    ) -> EntityId {
        let receipt = self
            .send(
                Caller::As(who),
                "vault.off_record.rooms.witness",
                room.witness_input(session_ref, content, self.vault.now_recorded_at()),
            )
            .await
            .ok("vault.off_record.rooms.witness");
        serde_json::from_value::<WitnessReceipt>(receipt)
            .expect("a witness receipt")
            .turn_id
    }

    /// Whether the vault's base store holds `id`.
    fn in_base(&self, id: &EntityId) -> bool {
        self.vault.get_raw(id).expect("base get").is_some()
    }
}

/// Notice, not consent: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:149`, "Each
/// save or export posts a notice to the room, for example “Mina saved this
/// talk.” Saving needs no prior OK from the others." The owner starts a
/// stretch and says something into it. Mina takes an export file at
/// `vault.off_record.rooms.export`, and the owner saves the whole talk at
/// `vault.off_record.rooms.save`, with nobody's OK asked. The room's view at
/// `vault.off_record.rooms.status` then lists two notices, `exported` by Mina
/// and `saved_talk` by the owner, each naming who did what and when alone. No
/// view quotes the talk. The root route, `GET /v1/core/off-record`
/// (`off_record_rooms.rs:60`), answers Mina the same view.
#[test]
fn every_save_and_export_posts_a_notice_that_never_quotes_the_talk() {
    run_on_engine_stack("rooms-notices", || async {
        let host = host();
        let room = host.room();
        let started = host.start(&room.owner, &room, STRETCH).await;
        assert!(
            notices(&started).is_empty(),
            "a fresh stretch has heard of nothing: {started}"
        );
        let said = host.say(&room.owner, &room, STRETCH, SECRET).await;

        let file = host
            .act(&room.mina, "export", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.export");
        assert_eq!(
            exported_words(&file),
            [SECRET],
            "Mina's export file holds the talk: {file}"
        );
        let saved = host
            .act(&room.owner, "save", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.save");
        assert_eq!(
            saved_turns(&saved),
            [said.to_hex()],
            "the owner's save keeps the turn, with no OK asked: {saved}"
        );

        let view = host
            .act(&room.mina, "status", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.status");
        assert_eq!(
            notices(&view),
            [
                ("exported".to_owned(), room.mina.id.to_hex()),
                ("saved_talk".to_owned(), room.owner.id.to_hex()),
            ],
            "the room hears of the export and of the save: {view}"
        );
        let root = host
            .read_root(Caller::As(&room.mina), room.id, STRETCH)
            .await
            .ok("GET /v1/core/off-record");
        assert_eq!(
            root, view,
            "the root route reads the view the status door reads"
        );
        for (what, answer) in [
            ("start", &started),
            ("status", &view),
            ("root route", &root),
        ] {
            assert!(
                !answer.to_string().contains(SECRET),
                "the {what} view never quotes the talk: {answer}"
            );
        }
    });
}

/// Own vault only: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:147`, "A
/// member saves into their own vault. A guest who is a person downloads an
/// export file.", and `:148`, "Nobody saves into another person's vault." Mina,
/// who has no vault here, and the owner each say one thing into the owner's
/// stretch. Mina's whole-talk save and her save from here are refused 403;
/// her export file holds both turns. Neither turn is in base or in any file
/// of the vault, and the stretch stays off record. The control: the owner's
/// own save then lands both turns in base.
#[test]
fn a_guest_saves_into_no_vault_and_takes_an_export_file() {
    run_on_engine_stack("rooms-guest", || async {
        let host = host();
        let room = host.room();
        host.start(&room.owner, &room, STRETCH).await;
        let said = [
            host.say(&room.mina, &room, STRETCH, SECRET).await,
            host.say(&room.owner, &room, STRETCH, REPLY).await,
        ];

        for act in ["save", "save_from_here"] {
            let refused = host.act(&room.mina, act, &room, STRETCH).await;
            assert_eq!(
                refused.status,
                StatusCode::FORBIDDEN,
                "a guest's {act} into this vault is refused: {}",
                refused.body
            );
        }
        let file = host
            .act(&room.mina, "export", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.export");
        assert_eq!(
            exported_words(&file),
            [SECRET, REPLY],
            "the guest's copy is an export file of the talk: {file}"
        );
        for turn in said {
            assert!(
                !host.in_base(&turn),
                "a guest's save and export land no turn {} in base",
                turn.to_hex()
            );
        }
        assert!(
            !storage_holds(host.dir.path(), SECRET),
            "no file of the vault holds the talk the guest tried to save"
        );
        let view = host
            .act(&room.owner, "status", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.status");
        assert_eq!(
            view["mode"], "off_record",
            "the guest's refused save from here leaves the stretch off record: {view}"
        );

        let saved = host
            .act(&room.owner, "save", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.save");
        assert_eq!(
            saved_turns(&saved),
            said.map(|turn| turn.to_hex()),
            "the control: the owner's save keeps both turns: {saved}"
        );
        for turn in said {
            assert!(
                host.in_base(&turn),
                "the control: the owner's save lands turn {} in base",
                turn.to_hex()
            );
        }
    });
}

/// Saving takes the save grant; asking does not: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:151`, "An
/// agent without the grant may ask, for example “this felt important, keep
/// it?” Everyone present sees the suggestion, and any holder of the grant
/// confirms or declines." The asker, an agent on a read-and-propose slip, is
/// refused a save. Its `suggest_save` saves nothing and waits in the room,
/// where Mina sees it too. The owner declines it: nothing lands and nothing
/// waits, and a second decline answers 409, as nothing waits. The asker asks
/// again and the owner confirms: the owner's own save, which keeps the turn.
#[test]
fn an_agent_without_the_grant_asks_and_a_holder_answers() {
    run_on_engine_stack("rooms-suggestion", || async {
        let host = host();
        let room = host.room();
        host.start(&room.owner, &room, STRETCH).await;
        let said = host.say(&room.owner, &room, STRETCH, SECRET).await;
        let asker = room.asker.id.to_hex();

        let refused = host.act(&room.asker, "save", &room, STRETCH).await;
        assert_eq!(
            refused.status,
            StatusCode::FORBIDDEN,
            "an agent without the grant does not save: {}",
            refused.body
        );
        let asked = host
            .act(&room.asker, "suggest_save", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.suggest_save");
        assert_eq!(
            waiting(&asked),
            [asker.clone()],
            "the suggestion waits: {asked}"
        );
        let seen = host
            .act(&room.mina, "status", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.status");
        assert_eq!(
            waiting(&seen),
            [asker.clone()],
            "everyone present sees the suggestion: {seen}"
        );
        assert!(
            !host.in_base(&said),
            "neither the refused save nor the suggestion lands the turn"
        );

        let declined = host
            .act(&room.owner, "decline_save", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.decline_save");
        assert!(
            waiting(&declined).is_empty(),
            "a decline answers the suggestion: {declined}"
        );
        assert!(!host.in_base(&said), "a decline lands nothing");
        let again = host.act(&room.owner, "decline_save", &room, STRETCH).await;
        assert_eq!(
            again.status,
            StatusCode::CONFLICT,
            "no suggestion waits to be declined: {}",
            again.body
        );

        let asked = host
            .act(&room.asker, "suggest_save", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.suggest_save");
        assert_eq!(
            waiting(&asked),
            [asker],
            "the new suggestion waits: {asked}"
        );
        let confirmed = host
            .act(&room.owner, "confirm_save", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.confirm_save");
        assert_eq!(
            saved_turns(&confirmed),
            [said.to_hex()],
            "a holder's confirm is their own save of the talk: {confirmed}"
        );
        assert!(host.in_base(&said), "the confirmed save lands the turn");
        let after = host
            .act(&room.owner, "status", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.status");
        assert!(
            waiting(&after).is_empty(),
            "the confirm answered the suggestion: {after}"
        );
    });
}

/// Any holder starts and saves, an agent holder too; only a person exports:
/// canon `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:146`,
/// "An agent holding its own vault write permission may start one too. Only
/// a person exports.", and `:151`, "Any holder may save: a person, or an
/// agent that holds the grant." The keeper, the vault's own agent on its own
/// write slip, starts a stretch as itself, and the owner says one thing into
/// it. The keeper's export is refused 403; its save keeps the turn in base.
/// The asker, on no write slip, starts no stretch.
#[test]
fn a_holder_agent_starts_and_saves_and_only_a_person_exports() {
    run_on_engine_stack("rooms-holder-agent", || async {
        let host = host();
        let room = host.room();
        let started = host.start(&room.keeper, &room, STRETCH).await;
        assert_eq!(
            (started["started_by"].clone(), started["mode"].clone()),
            (json!(room.keeper.id.to_hex()), json!("off_record")),
            "the keeper starts the stretch as itself: {started}"
        );
        let said = host.say(&room.owner, &room, STRETCH, SECRET).await;

        let refused = host.act(&room.keeper, "export", &room, STRETCH).await;
        assert_eq!(
            refused.status,
            StatusCode::FORBIDDEN,
            "an agent takes no export file: {}",
            refused.body
        );
        let saved = host
            .act(&room.keeper, "save", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.save");
        assert_eq!(
            saved_turns(&saved),
            [said.to_hex()],
            "the agent holder's save keeps the turn: {saved}"
        );
        assert!(
            host.in_base(&said),
            "the agent holder's save lands the turn"
        );

        let refused = host
            .send(
                Caller::As(&room.asker),
                "vault.off_record.rooms.start",
                room.start_input(REFUSED_STRETCH),
            )
            .await;
        assert_eq!(
            refused.status,
            StatusCode::FORBIDDEN,
            "an agent on no write slip starts no stretch: {}",
            refused.body
        );
        let none = host
            .act(&room.owner, "status", &room, REFUSED_STRETCH)
            .await;
        assert_eq!(
            none.status,
            StatusCode::NOT_FOUND,
            "the refused start left no stretch: {}",
            none.body
        );
    });
}

/// From here on saves later turns only: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:137`, "From
/// here on saves later turns only." The owner says one thing off record, then
/// saves from here at `vault.off_record.rooms.save_from_here`: the stretch is
/// on record and the room hears of it. Mina's next turn lands in base as it is
/// said; the earlier turn stays out of base.
#[test]
fn saving_from_here_keeps_only_later_turns() {
    run_on_engine_stack("rooms-from-here", || async {
        let host = host();
        let room = host.room();
        host.start(&room.owner, &room, STRETCH).await;
        let earlier = host.say(&room.owner, &room, STRETCH, SECRET).await;

        let flipped = host
            .act(&room.owner, "save_from_here", &room, STRETCH)
            .await
            .ok("vault.off_record.rooms.save_from_here");
        assert_eq!(
            flipped["mode"], "on_record",
            "saving from here puts the stretch on record: {flipped}"
        );
        assert_eq!(
            notices(&flipped),
            [("saving_from_here".to_owned(), room.owner.id.to_hex())],
            "the room hears who saves from here: {flipped}"
        );
        let later = host.say(&room.mina, &room, STRETCH, REPLY).await;
        assert!(
            host.in_base(&later),
            "a turn said after the flip lands in base as it is said"
        );
        assert!(
            !host.in_base(&earlier),
            "a turn said before the flip stays out of base"
        );
    });
}

/// An outsider gets the same 404 as for a stretch that does not exist: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:194`, "A
/// caller not on the room's roster gets the same 404 as for a stretch that
/// does not exist". Two callers the room does not seat, Olu (a person) and
/// the vault's own agent on its own write slip, each name the room's live
/// stretch and a name no stretch in the room holds, at every room door their
/// class may call and at the root route: each pair of answers is the same
/// 404. Neither starts a stretch in the room either.
#[test]
fn an_outsider_gets_the_same_404_at_every_room_door() {
    run_on_engine_stack("rooms-outsider", || async {
        let host = host();
        let room = host.room();
        host.start(&room.owner, &room, STRETCH).await;
        host.say(&room.owner, &room, STRETCH, SECRET).await;
        let olu = host.guest("Olu", 0x51);
        let stranger = host.agent(
            "stranger-agent",
            0x52,
            AgentTier::FullAccess,
            &["core:read", "core:write"],
        );

        for (who, outsider) in [("person", &olu), ("agent", &stranger)] {
            for act in [
                "status",
                "witness",
                "save",
                "save_from_here",
                "confirm_save",
                "decline_save",
                "export",
                "suggest_save",
            ] {
                // Only a person exports and only an agent suggests: the other
                // class is refused for what it is, before the roster.
                if (act, who) == ("export", "agent") || (act, who) == ("suggest_save", "person") {
                    continue;
                }
                let verb = format!("vault.off_record.rooms.{act}");
                let input = |session_ref: &str| match act {
                    "witness" => room.witness_input(
                        session_ref,
                        "an outsider speaks",
                        host.vault.now_recorded_at(),
                    ),
                    _ => room.stretch(session_ref),
                };
                let held = host.send(Caller::As(outsider), &verb, input(STRETCH)).await;
                let none = host
                    .send(Caller::As(outsider), &verb, input(NO_STRETCH))
                    .await;
                assert_eq!(
                    held.status,
                    StatusCode::NOT_FOUND,
                    "{who}: {verb}: the room's stretch is a 404 to an outsider: {}",
                    held.body
                );
                assert_eq!(
                    held.refusal_naming(STRETCH),
                    none.refusal_naming(NO_STRETCH),
                    "{who}: {verb}: the room's stretch answers an outsider as one that does not exist"
                );
            }

            let held = host.read_root(Caller::As(outsider), room.id, STRETCH).await;
            let none = host
                .read_root(Caller::As(outsider), room.id, NO_STRETCH)
                .await;
            assert_eq!(
                held.status,
                StatusCode::NOT_FOUND,
                "{who}: the root route answers an outsider 404: {}",
                held.body
            );
            assert_eq!(
                held.refusal_naming(STRETCH),
                none.refusal_naming(NO_STRETCH),
                "{who}: the root route answers an outsider as for no stretch"
            );

            let refused = host
                .send(
                    Caller::As(outsider),
                    "vault.off_record.rooms.start",
                    room.start_input(REFUSED_STRETCH),
                )
                .await;
            assert_eq!(
                refused.status,
                StatusCode::NOT_FOUND,
                "{who}: an outsider starts no stretch in the room: {}",
                refused.body
            );
            let none = host
                .act(&room.owner, "status", &room, REFUSED_STRETCH)
                .await;
            assert_eq!(
                none.status,
                StatusCode::NOT_FOUND,
                "{who}: the outsider's refused start left no stretch: {}",
                none.body
            );
        }
    });
}

/// No room door keeps a wire receipt: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:192`, "So no
/// wire receipt records that a session ran." Every reply of a room door,
/// answer or refusal, states `x-oneiron-receipt-ref: none; no-record`. The
/// control: an on-record NOTE written through `vault.notes.create` states a
/// receipt ref.
#[test]
fn no_room_door_keeps_a_wire_receipt() {
    run_on_engine_stack("rooms-no-receipt", || async {
        let host = host();
        let control = host
            .send(
                Caller::HostRoot,
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

        let room = host.room();
        let stretch = room.stretch(STRETCH);
        let calls = [
            (
                &room.owner,
                "start",
                room.start_input(STRETCH),
                StatusCode::OK,
            ),
            (
                &room.owner,
                "witness",
                room.witness_input(STRETCH, SECRET, host.vault.now_recorded_at()),
                StatusCode::OK,
            ),
            (&room.mina, "status", stretch.clone(), StatusCode::OK),
            (&room.mina, "export", stretch.clone(), StatusCode::OK),
            (&room.asker, "suggest_save", stretch.clone(), StatusCode::OK),
            (&room.owner, "decline_save", stretch.clone(), StatusCode::OK),
            // A refusal: nothing waits now.
            (
                &room.owner,
                "decline_save",
                stretch.clone(),
                StatusCode::CONFLICT,
            ),
            (&room.asker, "suggest_save", stretch.clone(), StatusCode::OK),
            (&room.owner, "confirm_save", stretch.clone(), StatusCode::OK),
            (&room.owner, "save", stretch.clone(), StatusCode::OK),
            // A refusal: the asker holds no grant.
            (&room.asker, "save", stretch.clone(), StatusCode::FORBIDDEN),
            (&room.owner, "save_from_here", stretch, StatusCode::OK),
        ];
        for (who, act, input, expected) in calls {
            let verb = format!("vault.off_record.rooms.{act}");
            let reply = host.send(Caller::As(who), &verb, input).await;
            assert_eq!(reply.status, expected, "{verb} answered {}", reply.body);
            assert_eq!(
                reply.receipt_ref.as_deref(),
                Some(NO_RECORD),
                "{verb} ({}): a room door's reply keeps no wire receipt",
                reply.status
            );
        }
    });
}
