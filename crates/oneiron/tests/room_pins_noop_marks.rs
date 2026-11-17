//! A pin door that changes nothing marks nothing (FIX ROOM-PINS-NOOP-MARKS-DIRTY):
//! a pin of a target the room has pinned already, and a pin policy set to
//! the value it holds, write no body, so they run no room-cell refresh and
//! queue no room-fact flush, as an unpin of a target that is not pinned
//! already does. A change still runs it. The refresh with no handle marks
//! the room's host-pin cell (`sync/room_facts.rs`
//! `refresh_room_cell_in_live_window`), which the tests read.
//!
//! Fixture (trimmed from `room_pins.rs`): a project whose home room seats
//! its leader, a PERSON who is not the vault's owner and holds one public
//! contact the owner precleared, a `core:read` row and a grant over the
//! room's MESSAGEs. The leader speaks one trunk turn; its MESSAGE is the pin
//! target. The vault runs no live window, so a room-cell refresh marks the
//! room's host-pin cell; the door `test_doors::room_fact_marks` reads and
//! clears that mark.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test room_pins_noop_marks`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::conversation::RoomPinPolicy;
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::room_fact_marks::{
    clear_room_host_pin_cell_mark, room_host_pin_cell_marked,
};
use oneiron::workspace_roster::{ProjectRecord, RoomPinPolicySet, RoomPinRequest};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    leader: EntityId,
    room: EntityId,
    target: EntityId,
    _directory: tempfile::TempDir,
}

fn put_person(vault: &Vault) -> TestResult<EntityId> {
    let person = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        b"owen",
    )?;
    Ok(person)
}

/// `principal` reads `room`'s MESSAGEs under an active grant.
fn grant_room_messages(vault: &Vault, room: EntityId, principal: EntityId) -> TestResult {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
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
            created_at,
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    Ok(())
}

/// The leader's trunk turn in the home room `room`, one MESSAGE; returns the
/// MESSAGE id.
fn speak_trunk(vault: &Vault, leader: EntityId, room: EntityId) -> TestResult<EntityId> {
    let message = EntityId::now();
    vault
        .memory(leader, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(serde_json::Value::Object(serde_json::Map::new())),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: Some(vault.now_recorded_at()),
            assertions: Default::default(),
        })?;
    Ok(message)
}

fn open_fixture() -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let leader = put_person(&vault)?;
    // One public contact, precleared at top through the owner's door: a
    // PERSON with no contact clearance reads only public rows, and a room's
    // MESSAGEs are born Sensitive.
    let contact = EntityId::now();
    vault.create_counterparty_contact(
        &contact,
        &CounterpartyContactRecord::public(leader, "owen@example.com", vault.now_recorded_at())?,
    )?;
    vault.preclear_contact_disclosure(&proof, "owen", &[contact], Scope::top())?;
    // The leader reads the vault's records. The shipped rows stay.
    let view =
        policy_manifests_as_owner(&vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    rows.push(PolicyScopedGrantRow {
        actor_class: None,
        actor_ref: Some(leader.to_hex()),
        effector: "core:read".into(),
        scope: Scope::top(),
        selectors: None,
        budget: None,
        receipt_required: false,
    });
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        &vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    let root_project = vault.root_project()?;
    let project_id = EntityId::now();
    let project = ProjectRecord::new(project_id, Some(root_project), root_project, leader)?;
    vault.put_project(project_id, &project, vault.now_recorded_at())?;
    let room = EntityId::from_hex(&project.home_room)?;
    grant_room_messages(&vault, room, leader)?;
    let target = speak_trunk(&vault, leader, room)?;
    Ok(Fixture {
        vault,
        leader,
        room,
        target,
        _directory: directory,
    })
}

/// A pin of a target pinned already keeps its first record and marks
/// nothing; the first pin, a change, marked the cell. Red on main: the
/// repeated pin refreshed the cell and marked it again.
#[test]
fn a_repeated_pin_marks_no_room_dirty() -> TestResult {
    let fx = open_fixture()?;
    let leader = fx.vault.memory(fx.leader, EdgeActorClass::Human);
    let request = RoomPinRequest {
        room: fx.room,
        target: fx.target,
    };

    let first = leader.rooms_pins_pin(&request)?;
    assert!(
        room_host_pin_cell_marked(&fx.vault, fx.room)?,
        "a new pin changes the room's pins and runs the room-cell refresh"
    );
    clear_room_host_pin_cell_mark(&fx.vault, fx.room)?;
    assert!(!room_host_pin_cell_marked(&fx.vault, fx.room)?);

    let again = leader.rooms_pins_pin(&request)?;
    assert_eq!(again.pin, first.pin, "the pin keeps its first record");
    assert!(
        !room_host_pin_cell_marked(&fx.vault, fx.room)?,
        "a pin that changes nothing marks no room cell"
    );
    Ok(())
}

/// A pin policy set to the value it holds marks nothing; the set that
/// changed it marked the cell. Red on main: the unchanged set refreshed
/// the cell and marked it again.
#[test]
fn an_unchanged_pin_policy_marks_no_room_dirty() -> TestResult {
    let fx = open_fixture()?;
    let leader = fx.vault.memory(fx.leader, EdgeActorClass::Human);
    let managers = RoomPinPolicySet {
        room: fx.room,
        policy: RoomPinPolicy::Managers,
    };

    let set = leader.rooms_pins_policy_set(&managers)?;
    assert_eq!(set.policy, RoomPinPolicy::Managers);
    assert!(
        room_host_pin_cell_marked(&fx.vault, fx.room)?,
        "a policy change runs the room-cell refresh"
    );
    clear_room_host_pin_cell_mark(&fx.vault, fx.room)?;

    let again = leader.rooms_pins_policy_set(&managers)?;
    assert_eq!(again.policy, RoomPinPolicy::Managers);
    assert!(
        !room_host_pin_cell_marked(&fx.vault, fx.room)?,
        "a policy set to its own value marks no room cell"
    );
    Ok(())
}
