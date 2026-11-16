//! An owner-grade generic batch states the agent definition switches it puts (R2d review
//! finding 4).
//!
//! The served owner `vault.batch` route commits at owner grade through the core lane. A batch
//! that turns a revoked definition back on states its switches in the vault's recorded owner's
//! name before it applies, as the owner's update door does, so the row reaches his other
//! installs.
#![cfg(all(feature = "sync", feature = "test-support"))]
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::core_write::{
    AnnouncementAuthority, CoreBatchCommit, CoreBatchEntityInput, CoreBatchWriteInput,
    CoreWriteLane,
};
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::sync::FederationAdmissionRole;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::temporal::TimeRange;
use oneiron::test_support::provision_act_carrier;
use oneiron::{EdgeActorClass, EntityId, ErrorKind, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

const T0: u64 = 1_773_532_800;
const SHARED: u64 = 42;

fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn running_definition() -> AgentDefinition {
    AgentDefinition::new(
        "custom.revocable",
        "Owner batch fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("owner batch fixture"),
        )]),
        None,
        true,
        None,
    )
}

fn next(
    definition: &AgentDefinition,
    version: &str,
    edit: impl FnOnce(&mut AgentDefinition),
) -> AgentDefinition {
    let mut next = definition.clone();
    next.version = version.to_owned();
    edit(&mut next);
    next
}

fn replay(
    vault: &Vault,
    id: &EntityId,
    definition: &AgentDefinition,
    tier: ImportTier,
) -> oneiron::Result<()> {
    let body = encode_agent_definition(definition).unwrap();
    replay_entity(
        vault,
        ReplicatedEntity {
            id: *id,
            entity_type: ENTITY_TYPE_AGENT_DEF,
            occurred: at(T0),
            learned_at: T0,
            row_version: 0,
            body: &body,
        },
        tier,
    )
}

fn owner_proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .unwrap()
}

/// The definition seeded running at `id`, then turned off by a federation member (a peer's
/// restrictive move lands).
fn revoked_at(vault: &Vault, id: EntityId) -> AgentDefinition {
    let running = running_definition();
    vault
        .put_agent_definition(&id, &running, at(T0), T0)
        .unwrap();
    let revoked = next(&running, "1.0.1", |def| {
        def.enabled = false;
        def.approval_status = ClaimApprovalStatus::Rejected;
        def.lifecycle_status = ClaimLifecycleStatus::Retracted;
    });
    replay(
        vault,
        &id,
        &revoked,
        ImportTier::Federated(FederationAdmissionRole::Member),
    )
    .expect("a peer turns a definition off");
    revoked
}

fn turned_on(revoked: &AgentDefinition) -> AgentDefinition {
    next(revoked, "1.0.2", |def| {
        def.enabled = true;
        def.approval_status = ClaimApprovalStatus::Approved;
        def.lifecycle_status = ClaimLifecycleStatus::Active;
    })
}

fn authority_entries(vault: &Vault) -> u64 {
    vault
        .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
        .unwrap()
}

fn json_of(value: &RmpValue) -> Value {
    match value {
        RmpValue::Nil => Value::Null,
        RmpValue::Boolean(flag) => Value::Bool(*flag),
        RmpValue::Integer(int) => int
            .as_u64()
            .map(Value::from)
            .or_else(|| int.as_i64().map(Value::from))
            .expect("an integer fits i64 or u64"),
        RmpValue::F32(float) => json!(f64::from(*float)),
        RmpValue::F64(float) => json!(*float),
        RmpValue::String(text) => Value::String(text.as_str().expect("UTF-8").to_owned()),
        RmpValue::Array(items) => Value::Array(items.iter().map(json_of).collect()),
        RmpValue::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.as_str().expect("string key").to_owned(), json_of(value)))
                .collect(),
        ),
        other => panic!("an AGENT_DEF body holds no {other:?}"),
    }
}

/// The definition as a core batch body: its encoded bytes read back as JSON.
fn agent_body(definition: &AgentDefinition) -> Value {
    let bytes = encode_agent_definition(definition).unwrap();
    let value = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap();
    json_of(&value)
}

/// One AGENT_DEF put of `definition` at `id`, as `vault.batch` takes it.
fn batch_input(id: &EntityId, definition: &AgentDefinition) -> CoreBatchWriteInput {
    CoreBatchWriteInput {
        entities: vec![CoreBatchEntityInput {
            id: Some(id.to_hex()),
            entity_type: ENTITY_TYPE_AGENT_DEF,
            occurred_start: Some(T0),
            occurred_end: Some(T0),
            learned_at: Some(T0),
            body: agent_body(definition),
            text: None,
        }],
    }
}

/// An install of a fresh vault with its keystore and signing loaded, and no machine profile
/// in the vault's roster: it carries no act.
fn plain_install(dir: &std::path::Path) -> Vault {
    let vault = Vault::open(dir, VaultConfig::device()).unwrap();
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    vault.prepare_install_signing().unwrap();
    vault
}

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

/// `owner` shares the vault as its Owner and invites each of `invited` at its role.
fn share(vault: &Vault, owner: EntityId, invited: &[(EntityId, Role)]) {
    let mut members = vec![InitialSharedMember {
        member_ref: owner,
        role: Some(Role::Owner),
    }];
    members.extend(invited.iter().map(|(member, role)| InitialSharedMember {
        member_ref: *member,
        role: Some(*role),
    }));
    vault
        .initialize_shared_vault(
            &owner_proof(vault, owner),
            SHARED,
            None,
            &members,
            vault.now_recorded_at(),
        )
        .expect("a shared vault");
}

/// `member` accepts its founding invitation at `role`.
fn accept(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = owner_proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

/// Catches an owner-grade generic batch turning a definition back on without stating its
/// switches: the batch lands here, no act is written, and the replicated row never reaches
/// the owner's other installs.
#[test]
fn an_owner_batch_turn_on_states_its_switches() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let (_issuer, person) = provision_act_carrier(&vault);
    let _owner = owner_proof(&vault, person);
    let id = EntityId::now();
    let on = turned_on(&revoked_at(&vault, id));
    let entries = authority_entries(&vault);
    let body = encode_agent_definition(&on).unwrap();
    vault
        .batch()
        .put(&id, ENTITY_TYPE_AGENT_DEF, at(T0), T0, &body)
        .commit_in_core_lane(&CoreWriteLane::Unbound, CoreBatchCommit::Owner, |_| Ok(()))
        .expect("the owner batch turns the definition back on");
    assert!(
        authority_entries(&vault) > entries,
        "the batch states the switches on the authority log"
    );
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(on.clone()));

    let off = next(&on, "1.0.3", |def| def.enabled = false);
    replay(
        &vault,
        &id,
        &off,
        ImportTier::Federated(FederationAdmissionRole::Member),
    )
    .expect("a peer turns the definition off again");
    replay(&vault, &id, &on, ImportTier::OwnDevice).expect("the stated row lands on replay");
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(on));
}

/// Catches the no-lane owner batch never stating its switches: `write_core_batch` at owner
/// grade turns a revoked definition back on but appends no act, so the owner's other
/// installs wait.
#[test]
fn a_no_lane_owner_batch_turn_on_states_its_switches() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let (_issuer, person) = provision_act_carrier(&vault);
    let _owner = owner_proof(&vault, person);
    let id = EntityId::now();
    let on = turned_on(&revoked_at(&vault, id));
    let entries = authority_entries(&vault);
    vault
        .write_core_batch(
            &batch_input(&id, &on),
            CoreBatchCommit::Owner,
            AnnouncementAuthority::Owner,
        )
        .expect("the no-lane owner batch turns the definition back on");
    assert!(
        authority_entries(&vault) > entries,
        "the batch states the switches on the authority log"
    );
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(on));
}

/// Catches the owner-batch local-only answer carrying no notice: on an install with no
/// carrier the turn-on lands here alone with no act, and the receipt's row says so.
#[test]
fn a_no_carrier_owner_batch_turn_on_lands_here_alone_with_a_notice() {
    let dir = tempfile::tempdir().unwrap();
    let vault = plain_install(dir.path());
    let person = vault.ensure_embedded_owner_actor().unwrap();
    let _owner = owner_proof(&vault, person);
    let id = EntityId::now();
    let on = turned_on(&revoked_at(&vault, id));
    let entries = authority_entries(&vault);
    let receipt = vault
        .write_core_batch(
            &batch_input(&id, &on),
            CoreBatchCommit::Owner,
            AnnouncementAuthority::Owner,
        )
        .expect("the owner's turn-on lands here");
    assert_eq!(authority_entries(&vault), entries, "no act is written");
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(on));
    let notice = &serde_json::to_value(&receipt).unwrap()["entities"][0]["notice"];
    assert!(
        notice
            .as_str()
            .is_some_and(|notice| notice.contains("this device only")),
        "the receipt's row carries the notice: {notice:?}"
    );
}

/// Catches an owner-grade batch stating the requested switches instead of the row it writes:
/// a Base author's All child is stored Proposed, and an own-device replay of the requested
/// Approved switches must not land.
#[test]
fn an_authored_owner_batch_states_the_written_switches() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let (_issuer, person) = provision_act_carrier(&vault);
    let owner = owner_proof(&vault, person);
    let author = EntityId::now();
    let mut author_def = running_definition();
    author_def.agent_id = "custom.author".to_owned();
    author_def.scope = AgentScope::Base;
    vault
        .create_agent_definition_as(&owner, &author, &author_def, at(T0), T0)
        .expect("the owner creates the Base author");
    let child = EntityId::now();
    let mut requested = running_definition();
    requested.agent_id = "custom.child".to_owned();
    vault
        .write_core_batch_in_lane_as(
            &batch_input(&child, &requested),
            CoreBatchCommit::Owner,
            AnnouncementAuthority::Owner,
            &CoreWriteLane::Unbound,
            Some(&WriteActor::new(author, EdgeActorClass::Agent)),
            "vault.batch",
        )
        .expect("the author's owner-grade batch creates the child");
    let stored = vault
        .get_agent_definition(&child)
        .unwrap()
        .expect("the child row");
    assert_eq!(
        stored.approval_status,
        ClaimApprovalStatus::Proposed,
        "the author writer stores the out-of-slice child as a proposal"
    );
    let replayed = replay(&vault, &child, &requested, ImportTier::OwnDevice);
    assert_eq!(
        replayed.as_ref().err().map(oneiron::Error::kind),
        Some(ErrorKind::InvalidAgentDefBody),
        "the requested Approved row waits: {replayed:?}"
    );
    assert_eq!(
        vault.get_agent_definition(&child).unwrap(),
        Some(stored),
        "the stored child stays as the batch wrote it"
    );
}

/// Catches a named co-owner's batch stating nothing: on a shared vault with two live Owners,
/// O1's owner-grade batch in O1's name states the turn-on it writes.
#[test]
fn a_co_owner_batch_states_in_the_named_owner_name() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let (_issuer, owner) = provision_act_carrier(&vault);
    let o1 = EntityId::now();
    person(&vault, o1);
    share(&vault, owner, &[(o1, Role::Owner)]);
    accept(&vault, o1, Role::Owner);
    let id = EntityId::now();
    let on = turned_on(&revoked_at(&vault, id));
    let entries = authority_entries(&vault);
    vault
        .write_core_batch_in_lane_as(
            &batch_input(&id, &on),
            CoreBatchCommit::Owner,
            AnnouncementAuthority::Owner,
            &CoreWriteLane::Unbound,
            Some(&WriteActor::new(o1, EdgeActorClass::Human)),
            "vault.batch",
        )
        .expect("O1's owner-grade batch turns the definition back on");
    assert!(
        authority_entries(&vault) > entries,
        "the batch states the switches in O1's name"
    );
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(on));
}

/// Catches the owner batch failing when its install key is available but not loaded: an
/// enrolled carrying vault reopened with its keystore attached and its signer not loaded
/// still states the turn-on it writes.
#[test]
fn an_owner_batch_loads_its_available_install_key() {
    let dir = tempfile::tempdir().unwrap();
    let keystore = Arc::new(MemoryKeystore::default());
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    vault.install_device_keystore(Arc::clone(&keystore));
    vault.prepare_install_signing().unwrap();
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, oneiron::authority::MachineRole::Unanswered)
        .expect("this install's live machine profile, to carry acts");
    let person = vault.ensure_embedded_owner_actor().unwrap();
    oneiron::test_support::bind_host_owner(&vault, &issuer, person).expect("owner binding");
    let id = EntityId::now();
    let on = turned_on(&revoked_at(&vault, id));
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    vault.install_device_keystore(Arc::clone(&keystore));
    let _owner = owner_proof(&vault, person);
    let entries = authority_entries(&vault);
    vault
        .write_core_batch_in_lane(
            &batch_input(&id, &on),
            CoreBatchCommit::Owner,
            AnnouncementAuthority::Owner,
            &CoreWriteLane::Unbound,
        )
        .expect("the owner batch turns the definition back on");
    assert!(
        authority_entries(&vault) > entries,
        "the batch states the switches on the authority log"
    );
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(on));
}
