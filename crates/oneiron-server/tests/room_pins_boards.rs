//! Room-scoped shared pins through the real signed HTTP board route.
//! Run on a build host with `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test room_pins_boards`.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof_challenge};
use oneiron::conversation::{ConversationBody, ConversationKind, RoomPin};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{ProjectRecord, RoomPinRequest};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Credential {
    slip: CapabilitySlip,
    key: SigningKey,
}

struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    credential: Credential,
    member: EntityId,
    room_a: EntityId,
    room_b: EntityId,
    pin_a: RoomPin,
    pin_b: RoomPin,
    short_ref_a: String,
    deleted: Option<EntityId>,
    _directory: tempfile::TempDir,
}

/// Each of `principals` reads `room`'s MESSAGEs under an active grant.
fn grant_room_messages(vault: &Vault, room: EntityId, principals: &[EntityId]) -> TestResult {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    for &principal in principals {
        vault.create_access_grant(
            &EntityId::now(),
            &AccessGrant {
                authority_scope: authority_scope.clone(),
                principal_ref: principal,
                scope: AccessGrantScope::ConversationMessages {
                    conversation_ref: room,
                },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at,
                revoked_at: None,
                expires_at: None,
                companion_bounds: None,
            },
        )?;
    }
    Ok(())
}

impl Fixture {
    fn new(delete_second_pin: bool) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(directory.path(), config)?);
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));

        // An ordinary human principal is added as Unknown by the HTTP audience
        // resolver, even if its PERSON has a contact. Use the embedded owner
        // as the member/caller, still distinct from the project's leader.
        // The owner's full signed human slip proves that room reader. The
        // leader's public contact is owner-precleared below; own pen agents
        // add no disclosure term and keep their manifest read ceilings.
        let member = vault.ensure_embedded_owner_actor()?;
        let proof = vault
            .memory(member, EdgeActorClass::Human)
            .embedded_owner("vault.agents.create")?;
        let leader = EntityId::now();
        let now = vault.now_recorded_at();
        vault.put_entity(
            &leader,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"owen",
        )?;

        let mut agents = Vec::new();
        for (agent_id, person) in [("owen", leader), ("yuki", member)] {
            let agent = EntityId::now();
            let definition: AgentDefinitionSpec = serde_json::from_value(json!({
                "agent_id": agent_id,
                "display_name": "yuki",
                "desc": "yuki",
                "version": "1",
                "ceiling": "auto"
            }))?;
            oneiron::verbs::create_agent_definition_as(
                &vault,
                &proof,
                AgentDefinitionCreateRequest {
                    agent_def_ref: agent,
                    definition,
                },
            )?;
            oneiron::subject_model::anchor_actor_subject(
                &vault,
                agent,
                person,
                WriteActor::new(member, EdgeActorClass::Human),
                vault.now_recorded_at(),
            )?;
            agents.push(agent);
        }

        let view =
            policy_manifests_as_owner(&vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
        let default = view
            .manifests
            .iter()
            .find(|entry| entry.manifest_ref == view.default_manifest_ref)
            .ok_or("default policy manifest missing")?;
        let mut manifest = default.manifest.clone();
        let mut grants = manifest.scoped_grants.clone().unwrap_or_default();
        for agent in &agents {
            manifest.actor_ceilings.push(ActorCeiling {
                actor_class: "agent".into(),
                actor_ref: Some(agent.to_hex()),
                ceiling: PolicyCeiling::Auto,
            });
        }
        for actor in [leader, member].into_iter().chain(agents.iter().copied()) {
            grants.push(PolicyScopedGrantRow {
                actor_class: None,
                actor_ref: Some(actor.to_hex()),
                effector: "core:read".into(),
                scope: Scope::top(),
                selectors: None,
                budget: None,
                receipt_required: false,
            });
        }
        manifest.scoped_grants = Some(grants);
        put_policy_manifest_as_owner(
            &vault,
            &proof,
            PolicyManifestPut {
                manifest_ref: Some(default.manifest_ref.clone()),
                expected_body_hash: Some(default.body_hash.clone()),
                manifest,
            },
        )?;

        // identity_ref is the public contact's link to the leader PERSON.
        // Public discovery is not public disclosure: grant real standing
        // clearance through the owner's public door, not a test-only setter.
        let contact = EntityId::now();
        vault.create_counterparty_contact(
            &contact,
            &CounterpartyContactRecord::public(
                leader,
                "owen@example.com",
                vault.now_recorded_at(),
            )?,
        )?;
        vault.preclear_contact_disclosure(&proof, "owen", &[contact], Scope::top())?;

        let root_project = vault.root_project()?;
        let project_id = EntityId::now();
        let mut project = ProjectRecord::new(project_id, Some(root_project), root_project, leader)?;
        project.roster.push(member.to_hex());
        project.roster.extend(agents.iter().map(EntityId::to_hex));
        vault.put_project(project_id, &project, vault.now_recorded_at())?;
        let room_a = EntityId::from_hex(&project.home_room)?;
        let room_b = EntityId::now();
        vault.create_conversation(
            room_b,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![leader, member],
                ..Default::default()
            },
            WriteActor::new(member, EdgeActorClass::Human),
            vault.now_recorded_at(),
        )?;
        // A room read admits a row only when every reader of its audience
        // may: each seated non-owner reads the room's MESSAGEs under a grant.
        // Room B seats no agent.
        let mut room_a_readers = vec![leader];
        room_a_readers.extend(agents.iter().copied());
        grant_room_messages(&vault, room_a, &room_a_readers)?;
        grant_room_messages(&vault, room_b, &[leader])?;

        let (target_a, short_ref_a) = speak_trunk(&vault, leader, room_a)?;
        let (target_b, _) = speak_trunk(&vault, leader, room_b)?;
        let pin_a = vault
            .memory(leader, EdgeActorClass::Human)
            .rooms_pins_pin(&RoomPinRequest {
                room: room_a,
                target: target_a,
            })?
            .pin;
        let pin_b = vault
            .memory(member, EdgeActorClass::Human)
            .rooms_pins_pin(&RoomPinRequest {
                room: room_b,
                target: target_b,
            })?
            .pin;
        let deleted = if delete_second_pin {
            let (target, _) = speak_trunk(&vault, leader, room_a)?;
            vault
                .memory(leader, EdgeActorClass::Human)
                .rooms_pins_pin(&RoomPinRequest {
                    room: room_a,
                    target,
                })?;
            assert!(vault.delete_entity(&target)?);
            Some(target)
        } else {
            None
        };

        // Keep Scope::top(): attenuating to a read-only scope would remove
        // owner-grade standing and turn this human reader back into Unknown.
        let issuer = HostSlipIssuer::from_secret(b"owen")?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let key = SigningKey::from_bytes(&[0x65; 32]);
        let mut claims = root.claims;
        claims.parent_id = None;
        claims.holder_ref = member.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some("human".into());
        claims.scope = Scope::top();
        claims.slip_id = [0x65; 32];
        let credential = Credential {
            slip: vault.mint_capability_slip(&issuer, claims)?,
            key,
        };
        let server = Arc::new(SyncServer::new(vault.clone(), SyncServerConfig::default())?);
        Ok(Self {
            app: build_app(server),
            vault,
            credential,
            member,
            room_a,
            room_b,
            pin_a,
            pin_b,
            short_ref_a,
            deleted,
            _directory: directory,
        })
    }

    fn request(&self, room: Option<EntityId>, retrieval: bool) -> Value {
        let mut request = json!({
            "memories": {"shared_total": 0},
            "session": {"session_id": self.member.to_hex()}
        });
        if let Some(room) = room {
            request["room"] = json!({"conversation_id": room.to_hex()});
            if retrieval {
                request["retrieval"] = json!({
                    "query": "yuki", "limit": 1, "conversation_id": room.to_hex()
                });
            }
        }
        request
    }

    async fn board(&self, input: Value) -> TestResult<Value> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = self
            .credential
            .key
            .sign(&self.credential.slip.binding_transcript(&challenge)?)
            .to_bytes();
        let request = Request::post("/v1/core/context-board")
            .header(
                "authorization",
                format!("Bearer {}", self.credential.slip.to_token()?),
            )
            .header(
                "x-oneiron-binding",
                json!({
                    "timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)
                })
                .to_string(),
            )
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(status, StatusCode::OK, "board request {input}: {body}");
        Ok(body)
    }
}

/// A public trunk witness returns the MESSAGE id and its engine-issued short ref.
fn speak_trunk(vault: &Vault, leader: EntityId, room: EntityId) -> TestResult<(EntityId, String)> {
    let message = EntityId::now();
    let receipt = vault
        .memory(leader, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "yuki".into(),
                parts: None,
                metadata: Some(json!({})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    let reference = receipt
        .message_short_ids
        .into_iter()
        .next()
        .ok_or("a trunk MESSAGE has an engine-issued short ref")?;
    assert!(
        reference.contains(':'),
        "expected a short ref, not a hex fallback: {reference}"
    );
    Ok((message, reference))
}

fn memory_rows(board: &Value) -> &[Value] {
    match board.get("memories") {
        None => &[],
        Some(memories) => memories["rows"].as_array().expect("MEMORIES rows"),
    }
}

fn memory_row(board: &Value, target: EntityId) -> &Value {
    memory_rows(board)
        .iter()
        .find(|row| row["id"] == target.to_hex())
        .unwrap_or_else(|| panic!("missing MESSAGE {} in MEMORIES: {board}", target.to_hex()))
}

fn assert_absent(board: &Value, target: EntityId) {
    assert!(
        memory_rows(board)
            .iter()
            .all(|row| row["id"] != target.to_hex()),
        "another room's MESSAGE {} reached MEMORIES: {board}",
        target.to_hex()
    );
}

fn assert_room_pin(board: &Value, pin: &RoomPin) {
    let row = memory_row(board, pin.target);
    assert_eq!(row["tier"], "pinned", "{board}");
    assert_eq!(row["room_pin"]["target"], pin.target.to_hex(), "{board}");
    assert_eq!(
        row["room_pin"]["pinned_by"],
        pin.pinned_by.to_hex(),
        "{board}"
    );
    assert_eq!(
        row["room_pin"].get("acting_agent"),
        Some(&Value::Null),
        "{board}"
    );
    assert_eq!(
        row["room_pin"]["pinned_at"],
        json!(pin.pinned_at),
        "{board}"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Both the driver and runtime workers need the server's engine-sized stack.
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Engine 00:05 rule 4: without retrieval, only the rendered room's pins join
/// MEMORIES; explicit pins still work independently of that shared list.
#[test]
fn no_retrieval_board_pins_only_its_room() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new(false)?;
        // Control first, under B's room audience: both rooms seat the same
        // people. T belongs to A, so explicitly pinning T in B cannot attach
        // A's room_pin, even on P2b. No retrieval/query hit can supply T.
        let mut control = fixture.request(Some(fixture.room_b), false);
        control["memories"]["pinned_refs"] = json!([fixture.short_ref_a]);
        let board = fixture.board(control).await?;
        let row = memory_row(&board, fixture.pin_a.target);
        assert_eq!(row["tier"], "pinned", "explicit-pin control: {board}");
        assert!(
            row.get("room_pin").is_none(),
            "explicit-pin control: {board}"
        );

        let board = fixture
            .board(fixture.request(Some(fixture.room_a), false))
            .await?;
        assert_room_pin(&board, &fixture.pin_a);
        assert_absent(&board, fixture.pin_b.target);
        let board = fixture
            .board(fixture.request(Some(fixture.room_b), false))
            .await?;
        assert_room_pin(&board, &fixture.pin_b);
        assert_absent(&board, fixture.pin_a.target);
        let board = fixture.board(fixture.request(None, false)).await?;
        assert_absent(&board, fixture.pin_a.target);
        assert_absent(&board, fixture.pin_b.target);
        Ok(())
    })
}

/// Engine 00:05 rule 4: retrieval cannot import another room's shared pins;
/// admitted room pins survive a zero shared MEMORIES budget as PINNED rows.
#[test]
fn retrieval_board_pins_only_its_room() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new(false)?;
        let board = fixture
            .board(fixture.request(Some(fixture.room_a), true))
            .await?;
        assert_room_pin(&board, &fixture.pin_a);
        assert_absent(&board, fixture.pin_b.target);
        let board = fixture
            .board(fixture.request(Some(fixture.room_b), true))
            .await?;
        assert_room_pin(&board, &fixture.pin_b);
        assert_absent(&board, fixture.pin_a.target);
        Ok(())
    })
}

/// Engine 00:05 rule 4: a deleted pin target leaves no ROOM row or page count;
/// the admitted pin keeps its PERSON, acting-agent and time attribution.
#[test]
fn board_room_page_counts_admitted_pins() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new(true)?;
        let deleted = fixture.deleted.ok_or("fixture deleted a pinned MESSAGE")?;
        let board = fixture
            .board(fixture.request(Some(fixture.room_a), false))
            .await?;
        assert_eq!(board["room_page"]["pins_total"], 1, "{board}");
        let rows = board["room"].as_array().expect("ROOM rows");
        let pin = &fixture.pin_a;
        let target_prefix = format!("pin: {} pinned_by=", pin.target.to_hex());
        let attribution = format!(" acting_agent=none pinned_at={}", pin.pinned_at);
        // ROOM uses PEOPLE handles for pinned_by, not necessarily its hex id.
        assert!(
            rows.iter().any(|row| row.as_str().is_some_and(|row| {
                row.starts_with(&target_prefix) && row.contains(&attribution)
            })),
            "admitted pin missing from ROOM: {board}"
        );
        assert!(
            rows.iter().all(|row| !row
                .as_str()
                .expect("ROOM row text")
                .contains(&deleted.to_hex())),
            "deleted pin target reached ROOM: {board}"
        );
        Ok(())
    })
}
