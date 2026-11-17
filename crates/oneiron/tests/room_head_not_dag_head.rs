//! `Memory::room_head` is the room's selected DAG HEAD, not its newest
//! trunk row (FIX-LIST 23504, [ROOM-HEAD-NOT-DAG-HEAD]).
//!
//! Every trunk TURN keeps a room row, and the room index files each such
//! row by time alone. A trunk TURN appended with `advance: false` and a
//! trunk TURN left behind by an explicit HEAD move are therefore the
//! newest trunk rows without being the head. In a room that keeps DAG
//! topology `room_head` reads the DAG HEAD; it falls back to the newest
//! trunk row only for a room with no DAG topology.
//!
//! Fixture: owen, the vault's owner, and one agent made through the
//! agent-definition door, seated in a project's home room, each reading
//! the vault's records under the default policy manifest and the agent
//! reading the room's MESSAGEs under a grant. As
//! `tests/room_thread_task_parity.rs` builds its home room.
//!
//! Public paths only; no test door.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test room_head_not_dag_head`.

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{Memory, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A project's home room seating owen and the agent.
struct Fixture {
    vault: Vault,
    owen: EntityId,
    room: EntityId,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn owen(&self) -> Memory<'_> {
        self.vault.memory(self.owen, EdgeActorClass::Human)
    }

    /// The turn id `room_head` serves owen, as hex.
    fn room_head_id(&self) -> TestResult<Option<String>> {
        Ok(self.owen().room_head(self.room)?.map(|turn| turn.turn_id))
    }
}

/// An agent made through the agent-definition door, as the owner.
fn create_agent(vault: &Vault, owner: EntityId, name: &str) -> TestResult<EntityId> {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
        "agent_id": name,
        "display_name": name,
        "desc": name,
        "version": "1",
        "ceiling": "auto",
    }))?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    oneiron::verbs::create_agent_definition_as(
        vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )?;
    Ok(agent)
}

/// The agent asks under its own Auto ceiling, and owen and the agent read
/// the vault's records: rows added to the default policy manifest, the
/// shipped rows kept.
fn grant_reads(vault: &Vault, owen: EntityId, agent: EntityId) -> TestResult {
    let proof = vault
        .memory(owen, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let view =
        policy_manifests_as_owner(vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    manifest.actor_ceilings.push(ActorCeiling {
        actor_class: "agent".into(),
        actor_ref: Some(agent.to_hex()),
        ceiling: PolicyCeiling::Auto,
    });
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for actor in [owen, agent] {
        rows.push(PolicyScopedGrantRow {
            // Bare census keys carry no actor class.
            actor_class: None,
            actor_ref: Some(actor.to_hex()),
            effector: "core:read".into(),
            scope: Scope::top(),
            selectors: None,
            budget: None,
            receipt_required: false,
        });
    }
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    Ok(())
}

/// `principal` reads `room`'s MESSAGEs under an active grant.
fn grant_messages(vault: &Vault, room: EntityId, principal: EntityId) -> TestResult {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            authority_scope,
            principal_ref: principal,
            scope: AccessGrantScope::ConversationMessages {
                conversation_ref: room,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    Ok(())
}

fn open_fixture() -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owen = vault.ensure_embedded_owner_actor()?;
    let agent = create_agent(&vault, owen, "yuki")?;
    grant_reads(&vault, owen, agent)?;
    let root = vault.root_project()?;
    let project = EntityId::now();
    let mut record = ProjectRecord::new(project, Some(root), root, owen)?;
    record.roster.push(agent.to_hex());
    vault.put_project(project, &record, vault.now_recorded_at())?;
    let room = EntityId::from_hex(&record.home_room)?;
    grant_messages(&vault, room, agent)?;
    Ok(Fixture {
        vault,
        owen,
        room,
        _directory: directory,
    })
}

/// owen's plain broadcast TURN for the DAG's append door.
fn plain_turn(fixture: &Fixture) -> TestResult<AppendRecord> {
    let now = fixture.vault.now_recorded_at();
    Ok(AppendRecord {
        conversation: fixture.room,
        parent: None,
        reply_to: None,
        quote: None,
        address: AddressMode::Broadcast,
        recipients: vec![],
        advance: false,
        kind: ENTITY_TYPE_TURN,
        containing_turn: None,
        occurred: TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
        body: rmp_serde::to_vec_named(&serde_json::json!({"txt": "owen"}))?,
        text: vec![],
        session: None,
        actor: WriteActor::new(fixture.owen, EdgeActorClass::Human),
        thread_audience: None,
    })
}

/// owen's DAG TURN on the room's trunk under `parent`; `advance` is its
/// own word on whether HEAD moves to it. Returns the TURN.
fn append_trunk(
    fixture: &Fixture,
    parent: Option<EntityId>,
    advance: bool,
) -> TestResult<EntityId> {
    let mut input = plain_turn(fixture)?;
    input.parent = parent;
    input.advance = advance;
    Ok(fixture.vault.append_dag_record(&fixture.owen(), &input)?.id)
}

/// owen's witness turn on the room's trunk, one MESSAGE, through the room
/// speech door. Returns the TURN.
fn speak_trunk(fixture: &Fixture) -> TestResult<EntityId> {
    let turn = EntityId::now();
    fixture.owen().rooms_speak(&WitnessTurn {
        conversation_ref: fixture.room.to_hex(),
        turn_ref: Some(turn.to_hex()),
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: Some(EntityId::now().to_hex()),
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: "owen".into(),
            parts: None,
            metadata: Some(serde_json::json!({})),
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: fixture.vault.now_recorded_at(),
        assertions: Default::default(),
    })?;
    Ok(turn)
}

/// A trunk TURN appended without advancing HEAD keeps a trunk room row,
/// so it is the newest trunk row; the room's head stays on the DAG HEAD.
#[test]
fn room_head_stays_on_dag_head_after_non_advancing_append() -> TestResult {
    let fixture = open_fixture()?;
    let first = append_trunk(&fixture, fixture.vault.head(&fixture.room)?, true)?;
    assert_eq!(fixture.vault.head(&fixture.room)?, Some(first));
    assert_eq!(fixture.room_head_id()?, Some(first.to_hex()));

    let beside = append_trunk(&fixture, Some(first), false)?;
    let beside_row = fixture
        .owen()
        .rooms_messages(fixture.room)?
        .into_iter()
        .find(|row| row.turn_id == beside.to_hex())
        .ok_or("the non-advancing turn keeps no room row")?;
    assert_eq!(beside_row.thread_of, None, "the turn is on the trunk");
    assert_eq!(
        fixture.vault.head(&fixture.room)?,
        Some(first),
        "a non-advancing append leaves the DAG HEAD where it was"
    );
    assert_eq!(
        fixture.room_head_id()?,
        Some(first.to_hex()),
        "the room head is the DAG HEAD, not the newest trunk row {}",
        beside.to_hex()
    );
    Ok(())
}

/// An explicit HEAD move back to an earlier trunk TURN moves the room
/// head with it, though the TURN it leaves is the newest trunk row.
#[test]
fn room_head_follows_explicit_dag_head_move() -> TestResult {
    let fixture = open_fixture()?;
    let first = append_trunk(&fixture, fixture.vault.head(&fixture.room)?, true)?;
    let second = append_trunk(&fixture, Some(first), true)?;
    assert_eq!(fixture.vault.head(&fixture.room)?, Some(second));
    assert_eq!(fixture.room_head_id()?, Some(second.to_hex()));

    fixture.vault.move_head(&fixture.room, &first)?;
    assert_eq!(fixture.vault.head(&fixture.room)?, Some(first));
    assert_eq!(
        fixture.room_head_id()?,
        Some(first.to_hex()),
        "the room head follows the HEAD move, not the newest trunk row {}",
        second.to_hex()
    );
    Ok(())
}

/// Control: a witness trunk turn is the room's head, as it was before
/// the DAG HEAD read.
#[test]
fn room_head_returns_witness_trunk_turn() -> TestResult {
    let fixture = open_fixture()?;
    let turn = speak_trunk(&fixture)?;
    assert_eq!(fixture.room_head_id()?, Some(turn.to_hex()));
    Ok(())
}
