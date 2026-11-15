//! A transferred slip of one of the vault's own agents is not the room's
//! proven own-agent reader (ROOM-READER-TRANSFERRED-SLIP).
//!
//! The room reader — the owner or one of the vault's own agents reading on
//! its own credential — adds no clearance term, since its own read bounds it
//! (ARCH-0067 S8). A slip the agent handed to another holder key reads as
//! another holder acting on the agent's word, not as the agent reading on
//! its own, as the inquiry and guest-document doors already hold it. So the
//! room's owner and agents meet as clearance terms again, and the pack's
//! interlocutor stamps name them.
//!
//! Two cases drive the real route with real credentials (on a profiled
//! install, as a serving start enrols it): the member agent's slip handed to
//! another key names the room, and the stamps name the owner and the member;
//! the unhanded member slip is the control and still reads as the room's
//! own-agent reader, with empty stamps. Deterministic: in-process vault and
//! router (`oneshot`, no TCP ports, no sleeps, no models).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test room_reader_transferred_slip`.

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    AgentTier, CapabilitySlip, HostSlipIssuer, MachineRole, SlipCaveat, holder_proof_challenge,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt;

const CONTEXT_PACK: &str = "/v1/core/context-pack";

struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_slip: CapabilitySlip,
}

/// One of the vault's own agents on a slip, signed by `key`.
struct Principal {
    slip: CapabilitySlip,
    key: SigningKey,
}

/// A Group room seating the owner and their agent `member`.
struct Room {
    id: EntityId,
    member: EntityId,
    principal: Principal,
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
                auth_secret: Some("room-reader-transferred-slip".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let app = build_app(server);
    Host {
        _dir: dir,
        vault,
        app,
        issuer,
        owner,
        owner_slip,
    }
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

    /// A Group room seating the owner and their agent, and the agent's own
    /// slip.
    fn room(&self) -> Room {
        let vault = &self.vault;
        let proof = self.owner_proof();
        let by_owner = || WriteActor::new(self.owner, EdgeActorClass::Human);
        let member = vault
            .ensure_agent_principal("yuki")
            .expect("the member agent");
        vault
            .bind_and_grant_agent_principal(
                &self.issuer,
                &proof,
                member,
                AgentTier::ReadOnly.ceiling(),
            )
            .expect("bind the vault's own agent");
        let id = EntityId::now();
        vault
            .create_conversation(
                id,
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
                id,
                member,
                by_owner(),
                vault.now_recorded_at(),
                HistoryChoice::Share,
            )
            .expect("seat the member agent");
        Room {
            id,
            member,
            principal: self.agent_slip(member, 0x71),
        }
    }

    /// `principal`'s pack in `room`; the answer, which must be 200.
    async fn pack(&self, principal: &Principal, room: EntityId) -> Value {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let token = principal.slip.to_token().expect("agent slip token");
        let signature = hex(&principal
            .key
            .sign(
                &principal
                    .slip
                    .binding_transcript(&challenge)
                    .expect("agent binding transcript"),
            )
            .to_bytes());
        let binding =
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string();
        let response = self
            .app
            .clone()
            .oneshot(
                Request::post(CONTEXT_PACK)
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-oneiron-binding", binding)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "query": "harborlight",
                            "limit": 10,
                            "conversation_id": room.to_hex(),
                        })
                        .to_string(),
                    ))
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
                "{CONTEXT_PACK} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        assert_eq!(status, StatusCode::OK, "{CONTEXT_PACK} answered {answer}");
        answer
    }
}

/// The pack's interlocutor stamps as `(speaker, class)` pairs.
fn stamps(pack: &Value) -> Vec<(String, String)> {
    pack["interlocutors"]
        .as_array()
        .unwrap_or_else(|| panic!("the pack echoes its interlocutor stamps: {pack}"))
        .iter()
        .map(|stamp| {
            (
                stamp["speaker"].as_str().unwrap_or_default().to_owned(),
                stamp["class"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

/// The member agent's slip handed to another holder key: a transfer alone,
/// with no narrowing caveat.
fn handed_to(principal: &Principal, seed: u8) -> Principal {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let mut slip = principal.slip.clone();
    slip.attenuate_to(
        SlipCaveat::default(),
        &principal.key,
        key.verifying_key().to_bytes(),
    )
    .expect("hand the member slip to another holder key");
    Principal { slip, key }
}

/// A transferred slip of the room's member agent is not the room's proven
/// own-agent reader: the pack's stamps name the owner and the member as the
/// clearance terms they are again.
#[test]
fn a_transferred_agent_slip_is_not_the_rooms_own_agent_reader() {
    run_on_engine_stack("transferred-slip-room-reader", async {
        let host = host();
        let room = host.room();
        let handed = handed_to(&room.principal, 0x77);
        let pack = host.pack(&handed, room.id).await;
        let stamps = stamps(&pack);
        let speakers: Vec<&str> = stamps.iter().map(|(speaker, _)| speaker.as_str()).collect();
        let owner = host.owner.to_hex();
        let member = room.member.to_hex();
        assert!(
            speakers.contains(&owner.as_str()),
            "a transferred agent slip meets the room owner as a clearance term: {pack}"
        );
        assert!(
            speakers.contains(&member.as_str()),
            "a transferred agent slip meets the member agent as a clearance term: {pack}"
        );
        assert!(
            stamps.iter().all(|(_, class)| class == "unknown"),
            "a transferred agent slip reads no owner session: {pack}"
        );
    });
}

/// The member agent's own slip still reads as the room's own-agent reader:
/// its own read bounds it, so the pack's stamps stay empty.
#[test]
fn an_untransferred_agent_slip_still_reads_as_the_rooms_own_agent_reader() {
    run_on_engine_stack("own-slip-room-reader", async {
        let host = host();
        let room = host.room();
        let pack = host.pack(&room.principal, room.id).await;
        assert_eq!(
            stamps(&pack),
            Vec::<(String, String)>::new(),
            "the member agent on its own slip is the room's proven reader: {pack}"
        );
    });
}
