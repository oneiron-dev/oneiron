//! Promise tests for the doors of a session-bound code run (ruling L4-23 =
//! A: each test proves a promise at its door; DOOR-127, FIX 4284):
//! `self.off_record.execute`, `.results.list`, `.results.read`,
//! `.waits.get` and `.waits.answer`, each entered at its generated HTTP
//! facade route, `POST /v1/core/facade/<verb>`, and the anonymous chat route
//! `POST /v1/ai/anonymous-chat`, which no Rust test named before.
//!
//! The promises, one test each:
//! - No run acts in a room through these doors (ND-026, the refusal it
//!   waits on; the door module's rule, Engine ruling 2026-10-19): a room
//!   member and the owner get `OFF_RECORD_ROOM_MANAGEMENT_CONSENT_UNAVAILABLE`
//!   at every run door, and the stretch stays live.
//! - An outsider gets the same 404 as for a stretch that does not exist
//!   (ARCH-0052 D5, outsiders), at every run door.
//! - A stretch entered alone runs only for its creator and the owner (the
//!   door module's rule: WILL-PLAN L13 row 03; FIX 4597): another principal
//!   gets the 404 a stretch that does not exist gets.
//! - No run door keeps a wire receipt (ARCH-0052 D5): every reply states
//!   `x-oneiron-receipt-ref: none; no-record`.
//! - Anonymous chat keeps no memory at all (ARCH-0052 D5): a second turn's
//!   model call holds nothing of the first, and no file of the vault holds a
//!   word of either.
//! - A run keeps its rows in its stretch until the discard (ARCH-0052
//!   code-run artifacts): its result shows through the stretch, base holds
//!   no replay record of it, and after the discard no door and no file of
//!   the vault shows it.
//! - A run writes nothing durable (ARCH-0052 code-run artifacts): a durable
//!   memory write in a run is refused as talk-only.
//!
//! The owner calls on the host-root credential of a profiled install, as a
//! serving start enrols it; each agent on its own slip, signed by its own
//! key. The first four tests serve no code-mode host, so `execute` stops
//! at the host once its stretch is bound, and a run read binds the stretch
//! and finds no run by the name. The anonymous chat test serves a scripted
//! local model on a loopback port (`support/fake_llm.rs`). The two run tests
//! serve the checked-in QuickJS component as the code-mode host, its model
//! a script that answers each call with the next program.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support
//! --test self_off_record_doors`.

#![cfg(unix)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::collections::{BTreeSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};

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
use oneiron::code_run::CodeRunDeterminism;
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use oneiron::edge::EdgeActorClass;
use oneiron::engine_executor::{EngineExecutorConfig, EngineExecutorLimits};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::SingleRouteBackend;
use oneiron::off_record::{OffRecordBackendClass, room_session_key};
use oneiron::store::GateDecisionId;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, ContentPart, EntityId, FatalLlmError,
    FinishReason, LlmBackend, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest,
    LlmResponse, LlmResult, LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, Vault,
    VaultConfig, WriteActor,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::mcp::{CodeRunLimits, McpQuickJsProvider, checked_in_quickjs_runtime};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

use fake_llm::{FakeLlm, Reply as ModelReply};

/// The reply header that states a call's receipt.
const RECEIPT_REF_HEADER: &str = "x-oneiron-receipt-ref";
/// What that header states for a call no wire receipt may record.
const NO_RECORD: &str = "none; no-record";
/// The code a whole-room management refusal carries.
const ROOM_MANAGEMENT: &str = "OFF_RECORD_ROOM_MANAGEMENT_CONSENT_UNAVAILABLE";
/// The code of `execute`'s answer on a server with no code-mode host.
const MODEL_UNAVAILABLE: &str = "MODEL_UNAVAILABLE";
/// The name the room cases' stretch is entered under.
const ROOM_STRETCH: &str = "self-doors-room-stretch";
/// The runner's handle for the run every call names.
const RUN: &str = "self-doors-run";
/// A name no stretch was ever entered under.
const NEVER: &str = "self-doors-never-entered";
/// The five doors of a session-bound run.
const RUN_DOORS: [&str; 5] = [
    "self.off_record.execute",
    "self.off_record.results.list",
    "self.off_record.results.read",
    "self.off_record.waits.get",
    "self.off_record.waits.answer",
];
/// The first anonymous turn: nothing may keep a word of it.
const FIRST_TURN: &str = "anonfirst the spare key sits under the heron statue";
/// The model's answer to the first anonymous turn.
const FIRST_ANSWER: &str = "anonanswerone the heron keeps it safe";
/// The second anonymous turn.
const SECOND_TURN: &str = "anonsecond what did I tell you a moment ago";
/// The model's answer to the second anonymous turn.
const SECOND_ANSWER: &str = "anonanswertwo nothing from before reached me";
/// The on-record control NOTE's words, which vault storage does keep.
const ON_RECORD: &str = "selfdoors on-record control note words";
/// The name the stretch a run keeps its result in is entered under.
const KEPT_STRETCH: &str = "self-doors-kept-stretch";
/// The name the run binds its result under.
const KEPT_NAME: &str = "kept";
/// The run's result: once its stretch is discarded, no door and no file of
/// the vault may show these words.
const KEPT_WORDS: &str = "selfdoorsrun the lighthouse ledger sits in drawer nine";
/// The name the stretch a run tries a durable write in is entered under.
const WRITE_STRETCH: &str = "self-doors-write-stretch";
/// What the refusal of a durable write in an off-record stretch says.
const TALK_ONLY: &str = "is talk-only";

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
    cache_control: Option<String>,
    body: Value,
}

impl Reply {
    /// The body of a 200, or a failure naming the call and the reply.
    fn ok(self, call: &str) -> Value {
        assert_eq!(self.status, StatusCode::OK, "{call} answered {}", self.body);
        self.body
    }

    /// The refusal's `error.code`.
    fn code(&self) -> &str {
        self.body["error"]["code"].as_str().unwrap_or("")
    }

    /// The refusal's `error.message`.
    fn message(&self) -> &str {
        self.body["error"]["message"].as_str().unwrap_or("")
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

/// A vault in a fresh directory, its keys in memory.
fn open_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.embedding_model = None;
    config.dimensions = 4;
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    (dir, vault)
}

/// A server on `vault` with no model and no code-mode host.
fn bare_server(vault: &Arc<Vault>) -> SyncServer {
    SyncServer::new(
        Arc::clone(vault),
        SyncServerConfig {
            auth_secret: Some("self-off-record-doors".into()),
            ..Default::default()
        },
    )
    .expect("create server")
}

/// `server` serving the facade, its owner the vault's embedded owner, on the
/// host root of a profiled install.
fn serve(dir: tempfile::TempDir, vault: Arc<Vault>, server: SyncServer) -> Host {
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
        app: build_app(Arc::new(server)),
        issuer,
        owner,
        owner_slip,
        owner_token,
    }
}

/// A host with no model and no code-mode host.
fn host() -> Host {
    let (dir, vault) = open_vault();
    let server = bare_server(&vault);
    serve(dir, vault, server)
}

/// The model of a code host: each call answers with the next scripted
/// program, and a call past the last one with a program that throws.
struct ScriptedModel {
    programs: Mutex<VecDeque<String>>,
}

impl SingleRouteBackend for ScriptedModel {
    fn preflight(&self, _request: &LlmRequest, _stream: bool) -> LlmResult<()> {
        Ok(())
    }
}

impl LlmBackend for ScriptedModel {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let text = self
            .programs
            .lock()
            .expect("the scripted programs")
            .pop_front()
            .unwrap_or_else(|| {
                "throw new Error('the scripted model has no program left');".to_owned()
            });
        Box::pin(async move {
            Ok(LlmResponse {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text,
                        signature: None,
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// A host whose server runs the checked-in QuickJS component as its
/// code-mode host, its model answering each call with the next of
/// `programs`. The vault holds no model manifest, so a run takes the
/// configured model with no seat.
fn code_host(programs: &[&str]) -> Host {
    let (dir, vault) = open_vault();
    // The component compiles and passes its readiness probe: blocking work,
    // kept off the runtime's other tasks.
    let runtime = tokio::task::block_in_place(checked_in_quickjs_runtime)
        .expect("the checked-in QuickJS component passes its readiness probe");
    let model = Arc::new(ScriptedModel {
        programs: Mutex::new(
            programs
                .iter()
                .map(|program| (*program).to_owned())
                .collect(),
        ),
    });
    let provider = McpQuickJsProvider::new(
        Arc::new(runtime),
        model,
        BudgetGuard::new(
            "self-off-record-doors",
            1_000_000,
            BudgetExhaustionPolicy::Suspend,
        ),
        EngineExecutorConfig {
            run_id: EntityId::now(),
            task: "template".to_owned(),
            prompt_package_root: oneiron::prompt::workspace_test_prompt_package_root()
                .expect("the workspace test prompt package"),
            model: ModelId::new("fixture/self-doors@v1").expect("a model id"),
            model_locality: ModelLocality::OnDevice,
            seat_effort: None,
            global_tier: ModelTierRef("fixture".to_owned()),
            determinism: CodeRunDeterminism::new(1_719_000_001_000, [0x5d; 32]),
            limits: EngineExecutorLimits::default(),
            wake: None,
        },
    )
    .expect("the QuickJS code-mode provider");
    let server = bare_server(&vault).with_mcp_quickjs_provider(provider, CodeRunLimits::default());
    serve(dir, vault, server)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The input of `verb`, one of [`RUN_DOORS`], for the run [`RUN`] in the
/// stretch `session`.
fn run_input(verb: &str, session: &str) -> Value {
    match verb {
        "self.off_record.execute" => json!({
            "session_ref": session,
            "run_ref": RUN,
            "task": "list what this stretch holds",
        }),
        "self.off_record.results.read" => json!({
            "session_ref": session,
            "run_ref": RUN,
            "ref": "summary",
        }),
        "self.off_record.waits.answer" => json!({
            "session_ref": session,
            "run_ref": RUN,
            "reply": {"approved": true},
        }),
        _ => json!({"session_ref": session, "run_ref": RUN}),
    }
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

    /// `caller`'s POST of `input` to `uri`.
    async fn post(&self, caller: Caller<'_>, uri: &str, input: Value) -> Reply {
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
        let request = Request::post(uri)
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding)
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("the app's response");
        let status = response.status();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let receipt_ref = header(RECEIPT_REF_HEADER);
        let cache_control = header("cache-control");
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the response body");
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{uri} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        Reply {
            status,
            receipt_ref,
            cache_control,
            body,
        }
    }

    /// `caller`'s call to `verb` at its facade route.
    async fn send(&self, caller: Caller<'_>, verb: &str, input: Value) -> Reply {
        self.post(caller, &format!("/v1/core/facade/{verb}"), input)
            .await
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
}

/// No run acts in a room through these doors: NO-DOOR row ND-026, whose
/// waiting tests (`crates/oneiron/src/code_run/tests_room_saver.rs`) wait on
/// the room-consented run door, "test today's refusal through execute_code";
/// the door module's rule (Engine ruling 2026-10-19; `room_management` in
/// `off_record_doors.rs`), "Recalling everyone's overlay at once, running in
/// it, and discarding it for the room answer
/// `OFF_RECORD_ROOM_MANAGEMENT_CONSENT_UNAVAILABLE` to a caller on its
/// roster". A seated agent and the owner each call all five run doors on the
/// room's stretch; each answers 403 with that code, so no run enters it and
/// none of a run's rows is read. The stretch stays live for the member.
#[test]
fn a_room_stretch_runs_nothing_through_the_run_doors() {
    run_on_engine_stack("self-off-record-room", || async {
        let host = host();
        let (member_id, member) = host.agent("member-agent", 0x61);
        let key = host.room_stretch(member_id);

        for verb in RUN_DOORS {
            for (who, caller) in [
                ("member", Caller::Principal(&member)),
                ("owner", Caller::Owner),
            ] {
                let reply = host.send(caller, verb, run_input(verb, &key)).await;
                assert_eq!(
                    (reply.status, reply.code()),
                    (StatusCode::FORBIDDEN, ROOM_MANAGEMENT),
                    "{who}: {verb} would run in the room's whole stretch: {}",
                    reply.body
                );
            }
        }
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
            "the refused runs left the room's stretch live"
        );
    });
}

/// An outsider gets the same 404 as for a stretch that does not exist: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:194`, "A
/// caller not on the room's roster gets the same 404 as for a stretch that
/// does not exist". An agent of the vault that the room does not seat names
/// the room's stretch, and a room key no stretch holds, at every run door;
/// each pair of answers is the same 404.
#[test]
fn an_outsider_gets_the_same_404_as_a_stretch_that_does_not_exist() {
    run_on_engine_stack("self-off-record-outsider", || async {
        let host = host();
        let (member_id, _member) = host.agent("seated-agent", 0x71);
        let (_, outsider) = host.agent("outsider-agent", 0x72);
        let key = host.room_stretch(member_id);
        let ghost = room_session_key(EntityId::now(), ROOM_STRETCH);
        for verb in RUN_DOORS {
            let held = host
                .send(Caller::Principal(&outsider), verb, run_input(verb, &key))
                .await;
            let none = host
                .send(Caller::Principal(&outsider), verb, run_input(verb, &ghost))
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

/// A stretch entered alone runs only for its creator and the owner: the door
/// module's rule (`crates/oneiron-server/src/api/facade/off_record_doors.rs`,
/// WILL-PLAN L13 row 03, Engine ruling 2026-10-19; FIX 4597), "a stretch
/// entered alone is managed by the person or agent who entered it ... and by
/// the vault's live owner on their proof", and `run_reads.rs`, "Each admits
/// the session's manager as the run's entries do". An agent enters a stretch
/// alone; another agent enters one under the same name. At every run door
/// that names the first agent's handle, the creator and the owner reach the
/// run (a run read: no run by that name in the stretch; `execute`: no
/// code-mode host on this server), while the other agent gets the answer a
/// name never entered gets.
#[test]
fn a_stretch_entered_alone_runs_only_for_its_creator_and_the_owner() {
    run_on_engine_stack("self-off-record-creator", || async {
        let host = host();
        let (_, creator) = host.agent("creator-agent", 0x51);
        let (_, other) = host.agent("other-agent", 0x52);
        let first = host.start(Caller::Principal(&creator), "shared-name").await;
        let second = host.start(Caller::Principal(&other), "shared-name").await;
        assert_ne!(
            first, second,
            "a name another principal holds is not taken: each gets its own stretch"
        );

        for verb in RUN_DOORS {
            for (who, caller) in [
                ("creator", Caller::Principal(&creator)),
                ("owner", Caller::Owner),
            ] {
                let reply = host.send(caller, verb, run_input(verb, &first)).await;
                if verb == "self.off_record.execute" {
                    assert_eq!(
                        (reply.status, reply.code()),
                        (StatusCode::SERVICE_UNAVAILABLE, MODEL_UNAVAILABLE),
                        "{who}: {verb} binds the stretch and stops at the code-mode host: {}",
                        reply.body
                    );
                } else {
                    assert!(
                        reply.status == StatusCode::NOT_FOUND
                            && reply.message().starts_with(&format!("no run {RUN} ")),
                        "{who}: {verb} binds the stretch and finds no run by the name: {} {}",
                        reply.status,
                        reply.body
                    );
                }
            }

            let held = host
                .send(Caller::Principal(&other), verb, run_input(verb, &first))
                .await;
            let none = host
                .send(Caller::Principal(&other), verb, run_input(verb, NEVER))
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
                "{verb}: another principal's stretch answers as one never entered"
            );
        }
    });
}

/// No run door keeps a wire receipt: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:192`, "So no
/// wire receipt records that a session ran." Every reply of a run door,
/// whatever it answers, states `x-oneiron-receipt-ref: none; no-record`: the
/// creator's and the owner's on its own stretch, another principal's 404, a
/// room member's 403 and an outsider's 404. The control: an on-record NOTE
/// written through `vault.notes.create` states a receipt ref.
#[test]
fn no_run_door_keeps_a_wire_receipt() {
    run_on_engine_stack("self-off-record-no-receipt", || async {
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

        let (_, creator) = host.agent("receipt-creator", 0x81);
        let (_, other) = host.agent("receipt-other", 0x82);
        let (member_id, member) = host.agent("receipt-member", 0x83);
        let own = host
            .start(Caller::Principal(&creator), "receipt-stretch")
            .await;
        let room = host.room_stretch(member_id);
        let calls = [
            ("creator", Caller::Principal(&creator), own.clone()),
            ("owner", Caller::Owner, own.clone()),
            ("another principal", Caller::Principal(&other), own),
            ("room member", Caller::Principal(&member), room.clone()),
            ("outsider", Caller::Principal(&other), room),
        ];
        for (who, caller, session) in calls {
            for verb in RUN_DOORS {
                let reply = host.send(caller, verb, run_input(verb, &session)).await;
                assert_eq!(
                    reply.receipt_ref.as_deref(),
                    Some(NO_RECORD),
                    "{who}: {verb} ({}): a run door's reply keeps no wire receipt: {}",
                    reply.status,
                    reply.body
                );
                assert_ne!(
                    reply.status,
                    StatusCode::OK,
                    "{who}: {verb}: no run exists here to answer: {}",
                    reply.body
                );
            }
        }
    });
}

/// The models config of a server whose every role is the local model at
/// `base_url`, with no background model work.
fn models(base_url: &str) -> ModelsConfig {
    let toml = format!(
        "default = \"local:test-model\"\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n"
    );
    ModelsConfig::from_toml(&toml, None).expect("models config")
}

/// Whether the model call `body` holds `word` anywhere.
fn call_holds(body: &Value, word: &str) -> bool {
    body.to_string().contains(word)
}

/// Anonymous chat keeps no memory at all: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:143`,
/// "Anonymous chat mode means default chat for anonymous requests. Anonymous
/// chat mode keeps no memory at all." The owner chats twice at
/// `POST /v1/ai/anonymous-chat` with the house mind, a scripted local model.
/// Each turn answers the model's reply, `cache-control: no-store` and
/// `x-oneiron-receipt-ref: none; no-record`. From the second turn's first
/// model call on, no call holds a word of the first turn or its answer. No file under the vault's directory
/// holds a word of either turn or answer. The control: an on-record NOTE's
/// words are in vault storage, so the scan sees what a vault keeps.
#[test]
fn anonymous_chat_keeps_no_memory_at_all() {
    run_on_engine_stack("anonymous-chat-no-memory", || async {
        let answer = |body: &Value| {
            let text = body.to_string();
            if text.contains(SECOND_TURN) {
                SECOND_ANSWER.to_owned()
            } else if text.contains(FIRST_TURN) {
                FIRST_ANSWER.to_owned()
            } else {
                "a call no anonymous turn made".to_owned()
            }
        };
        let fake = FakeLlm::start(Vec::new(), Some(ModelReply::Computed(Arc::new(answer)))).await;
        let (dir, vault) = open_vault();
        let (server, ai) = AiHost::attach(bare_server(&vault), Some(&models(&fake.base_url))).await;
        let host = serve(dir, vault, server);

        for (turn, expected) in [(FIRST_TURN, FIRST_ANSWER), (SECOND_TURN, SECOND_ANSWER)] {
            let reply = host
                .post(
                    Caller::Owner,
                    "/v1/ai/anonymous-chat",
                    json!({"text": turn, "target": "house_mind"}),
                )
                .await;
            assert_eq!(
                reply.receipt_ref.as_deref(),
                Some(NO_RECORD),
                "an anonymous turn keeps no wire receipt"
            );
            assert_eq!(
                reply.cache_control.as_deref(),
                Some("no-store"),
                "an anonymous turn's answer is not to be stored"
            );
            let body = reply.ok("POST /v1/ai/anonymous-chat");
            assert_eq!(
                (body["type"].as_str(), body["content"].as_str()),
                (Some("reply"), Some(expected)),
                "the anonymous turn answers the model's reply: {body}"
            );
        }

        let seen = fake.seen();
        assert!(
            seen.iter().any(|call| call_holds(&call.body, FIRST_TURN)),
            "the model saw the first turn"
        );
        let second_calls = seen
            .iter()
            .position(|call| call_holds(&call.body, SECOND_TURN))
            .expect("the model saw the second turn");
        for (index, call) in seen.iter().enumerate().skip(second_calls) {
            for word in [FIRST_TURN, FIRST_ANSWER] {
                assert!(
                    !call_holds(&call.body, word),
                    "model call {index} ({}) holds the earlier anonymous words {word:?}",
                    call.path
                );
            }
        }

        host.send(
            Caller::Owner,
            "vault.notes.create",
            json!({"kind": "research", "markdown": ON_RECORD}),
        )
        .await
        .ok("vault.notes.create");
        assert!(
            storage_holds(host.dir.path(), ON_RECORD),
            "the control: an on-record NOTE's words are in vault storage"
        );
        for word in [FIRST_TURN, FIRST_ANSWER, SECOND_TURN, SECOND_ANSWER] {
            assert!(
                !storage_holds(host.dir.path(), word),
                "vault storage keeps the anonymous words {word:?}"
            );
        }
        ai.shutdown().await;
    });
}

/// A run keeps its rows in its stretch until the discard: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:237`,
/// "session-bound replay/raw-output rows land in the overlay". The owner
/// enters a stretch alone and runs one program in it that binds a result by
/// name. The run's own doors show the result through the stretch, and base
/// holds no replay record of the run. Once the stretch is discarded, no run
/// door shows the run, base still holds no record of it, and no file of the
/// vault holds the result's words. The control: an on-record NOTE's words
/// are in vault storage.
#[test]
fn a_run_keeps_its_rows_in_its_stretch_until_the_discard() {
    run_on_engine_stack("self-off-record-kept-rows", || async {
        let program = format!("await store({KEPT_WORDS:?}, {KEPT_NAME:?});\nfinish(\"kept\");");
        let host = code_host(&[program.as_str()]);
        let session = host.start(Caller::Owner, KEPT_STRETCH).await;
        let ran = host
            .send(
                Caller::Owner,
                "self.off_record.execute",
                json!({
                    "session_ref": session,
                    "run_ref": RUN,
                    "task": "keep one result by name",
                }),
            )
            .await
            .ok("self.off_record.execute");
        assert_eq!(
            ran["status"], "complete",
            "the run ends in its one step: {ran}"
        );
        let run_id = EntityId::from_hex(ran["run_id"].as_str().expect("the run's id"))
            .expect("the run's id is 32 hex");
        let list_input = json!({"session_ref": session, "run_ref": RUN});
        let read_input = json!({"session_ref": session, "run_ref": RUN, "ref": KEPT_NAME});

        let listed = host
            .send(
                Caller::Owner,
                "self.off_record.results.list",
                list_input.clone(),
            )
            .await
            .ok("self.off_record.results.list");
        assert_eq!(
            listed["run_id"], ran["run_id"],
            "the list reads the run: {listed}"
        );
        assert!(
            listed["count"].as_u64() >= Some(1),
            "the stretch shows the run's bound name: {listed}"
        );
        if listed["withheld"] != json!(true) {
            assert!(
                listed["cards"]
                    .as_array()
                    .is_some_and(|cards| cards.iter().any(|card| card["name"] == KEPT_NAME)),
                "the stretch shows the result's card by its name: {listed}"
            );
        }
        host.send(
            Caller::Owner,
            "self.off_record.results.read",
            read_input.clone(),
        )
        .await
        .ok("self.off_record.results.read");
        assert!(
            host.vault
                .get_code_run_replay_record(&run_id)
                .expect("read base's replay records")
                .is_none(),
            "base holds no replay record of a run in a live stretch"
        );

        host.send(
            Caller::Owner,
            "vault.off_record.discard",
            json!({"session_ref": session}),
        )
        .await
        .ok("vault.off_record.discard");
        for (verb, input) in [
            ("self.off_record.results.list", list_input),
            ("self.off_record.results.read", read_input),
        ] {
            let reply = host.send(Caller::Owner, verb, input).await;
            assert_ne!(
                reply.status,
                StatusCode::OK,
                "{verb} shows nothing of a discarded stretch's run: {}",
                reply.body
            );
            assert!(
                !reply.body.to_string().contains(KEPT_WORDS),
                "{verb} quotes the discarded run's result: {}",
                reply.body
            );
        }
        assert!(
            host.vault
                .get_code_run_replay_record(&run_id)
                .expect("read base's replay records")
                .is_none(),
            "base holds no replay record of the run after the discard"
        );
        host.send(
            Caller::Owner,
            "vault.notes.create",
            json!({"kind": "research", "markdown": ON_RECORD}),
        )
        .await
        .ok("vault.notes.create");
        assert!(
            storage_holds(host.dir.path(), ON_RECORD),
            "the control: an on-record NOTE's words are in vault storage"
        );
        assert!(
            !storage_holds(host.dir.path(), KEPT_WORDS),
            "vault storage keeps the discarded run's result"
        );
    });
}

/// A run writes nothing durable: canon
/// `oneiron/core/oneiron-arch-0052-off-record-branch-store-v1.md:237`,
/// "Off-record runs still reject durable memory writes and guest-supplied
/// turn refs." The owner's run in a stretch entered alone supersedes one
/// claim with another, a durable memory write: the door refuses the run
/// with the talk-only refusal. A guest has no carrier for a turn ref: each
/// speech input of the guest SDK is a closed object whose order and time the
/// host stamps, and the executor's witness entry refuses a supplied turn ref
/// before it builds a turn (`crates/oneiron/src/off_record/lifecycle/executor.rs`,
/// the branch-store oracle's `guest_supplied_turn_ref_rejected`), so this
/// test proves the durable-write half at the door.
#[test]
fn a_run_writes_nothing_durable() {
    run_on_engine_stack("self-off-record-no-durable-write", || async {
        let program = format!(
            "await vault.claims.supersede({{newId: {:?}, oldId: {:?}, now: 1719000000}});\nfinish(\"superseded\");",
            EntityId::now().to_hex(),
            EntityId::now().to_hex(),
        );
        let host = code_host(&[program.as_str()]);
        let session = host.start(Caller::Owner, WRITE_STRETCH).await;
        let reply = host
            .send(
                Caller::Owner,
                "self.off_record.execute",
                json!({
                    "session_ref": session,
                    "run_ref": RUN,
                    "task": "supersede one claim with another",
                }),
            )
            .await;
        assert!(
            reply.status != StatusCode::OK && reply.message().contains(TALK_ONLY),
            "the run's durable write is refused as talk-only: {} {}",
            reply.status,
            reply.body
        );
    });
}
