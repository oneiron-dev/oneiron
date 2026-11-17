//! A room's shared pins merge record by record between a vault's machines
//! (ROOM-PINS-LWW-MERGE; RULED ROOM-PIN-CONCURRENT-UNPIN = A, Engine 17 Nov
//! 00:02: add-wins, an observed-remove set). Two machines that pin or unpin
//! in one room while apart both keep their changes once they sync: an unpin
//! removes only the pin records it saw.
//!
//! Fixture: one vault with a group room, a seated member and two of the
//! member's room MESSAGEs as pin targets, copied to a second directory while
//! closed, so both machines hold the same rows. As the testkit's fixture
//! copy, it refuses a seed that left anything beside the vault directory
//! (key custody or a page seal), which a copy would share. Each machine runs
//! its own live window manager over the room's base window; the tests carry
//! the window between the two docs both ways, as a sync connection does,
//! until both machines store the expected pins.
//!
//! On main one room body wins whole: the first, second and fourth tests fail
//! there; the third guards an unpin both machines saw.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test room_pins_concurrent_merge`.
#![cfg(feature = "sync")]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::conversation::{ConversationBody, ConversationKind, RoomPin};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::policy_model::SecretScanMode;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::types::WindowKey;
use oneiron::workspace_roster::RoomPinRequest;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The room's base window: it is learned in March 2026.
const WINDOW: &str = "2026-03";
/// The vault's directory inside each machine's temp dir.
const VAULT_DIR: &str = "vault";
/// 2026-03-15 00:00 UTC, inside [`WINDOW`].
const LEARNED_AT: u64 = 1_773_532_800;
/// How long a machine's live mirror, or the two machines' sync, may take.
const WAIT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(20);

/// The room both machines hold, the member who pins in it, and its two pin
/// targets.
struct Room {
    room: EntityId,
    member: EntityId,
    first: EntityId,
    second: EntityId,
}

/// One machine of the vault: its vault, its live window manager and the
/// room's window doc. The doc and the manager drop before the vault, and
/// the vault before its directory.
struct Machine {
    doc: LoroDoc,
    _manager: Arc<WindowManager>,
    vault: Arc<Vault>,
    _dir: tempfile::TempDir,
}

/// The member's trunk MESSAGE `message` in `room`, witnessed as the room's
/// member writes it.
fn say(vault: &Vault, member: EntityId, room: EntityId, message: EntityId) -> TestResult {
    vault
        .memory(member, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(EntityId::now().to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "yuki".into(),
                parts: None,
                metadata: Some(serde_json::Value::Object(serde_json::Map::new())),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    Ok(())
}

/// The vault both machines start from, in `dir`: a group room learned in
/// [`WINDOW`] that seats a member, who reads its MESSAGEs and has said two
/// of them.
fn seed_vault(dir: &Path) -> TestResult<Room> {
    let vault = Vault::open_owned(dir, VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let authenticated =
        vault.authenticate_owner(owner, "owen@example.com", true, GateDecisionId::now())?;
    vault.set_secret_scan_mode(&authenticated, SecretScanMode::Off, LEARNED_AT)?;
    let member = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &member,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        b"yuki",
    )?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let contact = EntityId::now();
    vault.create_counterparty_contact(
        &contact,
        &CounterpartyContactRecord::public(member, "yuki@example.com", now)?,
    )?;
    vault.preclear_contact_disclosure(&proof, "yuki", &[contact], Scope::top())?;
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
        actor_ref: Some(member.to_hex()),
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
    let room = EntityId::now();
    vault.create_conversation(
        room,
        &ConversationBody {
            kind: ConversationKind::Group,
            member_ids: vec![member],
            ..Default::default()
        },
        WriteActor::new(owner, EdgeActorClass::Human),
        LEARNED_AT,
    )?;
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            authority_scope,
            principal_ref: member,
            scope: AccessGrantScope::ConversationMessages {
                conversation_ref: room,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: now,
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    let first = EntityId::now();
    say(&vault, member, room, first)?;
    let second = EntityId::now();
    say(&vault, member, room, second)?;
    assert!(
        vault.conversation_body(room)?.pins.is_empty(),
        "the room starts with no pins"
    );
    Ok(Room {
        room,
        member,
        first,
        second,
    })
}

/// Copies the closed vault directory `from` into `to`, file by file, as the
/// testkit's fixture copy does. The lock file goes too: the root preflight
/// refuses a data file without one. The seed vault was closed with no live
/// transaction, so the copy holds no reader that LMDB would wait on.
fn copy_vault_dir(from: &Path, to: &Path) -> TestResult {
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            std::fs::create_dir_all(&target)?;
            copy_vault_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// The machine on `dir`, its live window manager running as `user`, with the
/// room's window open.
fn open_machine(dir: tempfile::TempDir, user: &str) -> TestResult<Machine> {
    let vault = Arc::new(Vault::open_owned(
        dir.path().join(VAULT_DIR),
        VaultConfig::default(),
    )?);
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(Materializer::new()),
        user,
    ));
    let doc = manager.open_window(&WindowKey::new(WINDOW))?.doc.clone();
    Ok(Machine {
        doc,
        _manager: manager,
        vault,
        _dir: dir,
    })
}

/// Two machines of one vault that hold the same room and have synced its
/// window once.
fn two_machines() -> TestResult<(Machine, Machine, Room)> {
    let first_dir = tempfile::tempdir()?;
    let first_vault = first_dir.path().join(VAULT_DIR);
    std::fs::create_dir_all(&first_vault)?;
    let room = seed_vault(&first_vault)?;
    let mut beside = Vec::new();
    for entry in std::fs::read_dir(first_dir.path())? {
        let name = entry?.file_name();
        if name != VAULT_DIR {
            beside.push(name);
        }
    }
    if !beside.is_empty() {
        return Err(format!(
            "the seed left {beside:?} beside the vault (key custody or a page seal): a copy would share those keys"
        )
        .into());
    }
    let second_dir = tempfile::tempdir()?;
    let second_vault = second_dir.path().join(VAULT_DIR);
    std::fs::create_dir_all(&second_vault)?;
    copy_vault_dir(&first_vault, &second_vault)?;
    let first = open_machine(first_dir, "machine-a")?;
    let second = open_machine(second_dir, "machine-b")?;
    exchange(&first.doc, &second.doc)?;
    Ok((first, second, room))
}

/// Carries the window between the two docs both ways until both hold the
/// same operations.
fn exchange(a: &LoroDoc, b: &LoroDoc) -> TestResult {
    for _ in 0..5 {
        if a.oplog_vv() == b.oplog_vv() {
            return Ok(());
        }
        let to_b = a
            .export(ExportMode::updates(&b.oplog_vv()))
            .map_err(|error| format!("{error:?}"))?;
        let to_a = b
            .export(ExportMode::updates(&a.oplog_vv()))
            .map_err(|error| format!("{error:?}"))?;
        b.import(&to_b).map_err(|error| format!("{error:?}"))?;
        a.import(&to_a).map_err(|error| format!("{error:?}"))?;
    }
    Ok(())
}

/// The room body bytes `doc` carries for `room`, if any.
fn carrier(doc: &LoroDoc, room: EntityId) -> Option<Vec<u8>> {
    match doc.get_map("entities").get(&room.to_hex())? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

/// Waits until `machine`'s live mirror has carried its stored room row into
/// its window, so each pin door write rides the window on its own.
fn settle(machine: &Machine, room: EntityId) -> TestResult {
    let deadline = Instant::now() + WAIT;
    loop {
        let stored = machine.vault.get_raw(&room)?.ok_or("room row missing")?;
        if carrier(&machine.doc, room).as_deref() == Some(stored.as_slice()) {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err("the live mirror did not carry the room body into the window".into());
        }
        std::thread::sleep(POLL);
    }
}

fn pin(machine: &Machine, room: &Room, target: EntityId) -> TestResult<RoomPin> {
    let reply = machine
        .vault
        .memory(room.member, EdgeActorClass::Human)
        .rooms_pins_pin(&RoomPinRequest {
            room: room.room,
            target,
        })?;
    settle(machine, room.room)?;
    Ok(reply.pin)
}

fn unpin(machine: &Machine, room: &Room, target: EntityId) -> TestResult {
    machine
        .vault
        .memory(room.member, EdgeActorClass::Human)
        .rooms_pins_unpin(&RoomPinRequest {
            room: room.room,
            target,
        })?;
    settle(machine, room.room)
}

/// One pin record: its target, PERSON, acting agent and time.
type Record = (EntityId, EntityId, Option<EntityId>, u64);

fn record(pin: &RoomPin) -> Record {
    (pin.target, pin.pinned_by, pin.acting_agent, pin.pinned_at)
}

/// The pin records `machine` stores for the room, as a set.
fn stored_pins(machine: &Machine, room: &Room) -> TestResult<BTreeSet<Record>> {
    Ok(machine
        .vault
        .conversation_body(room.room)?
        .pins
        .iter()
        .map(record)
        .collect())
}

fn records(pins: &[&RoomPin]) -> BTreeSet<Record> {
    pins.iter().map(|pin| record(pin)).collect()
}

/// Syncs the two machines until both store exactly `expected`, or fails
/// with what each stores after [`WAIT`].
fn converge(a: &Machine, b: &Machine, room: &Room, expected: &[&RoomPin]) -> TestResult {
    let expected = records(expected);
    let deadline = Instant::now() + WAIT;
    loop {
        exchange(&a.doc, &b.doc)?;
        let (on_a, on_b) = (stored_pins(a, room)?, stored_pins(b, room)?);
        if on_a == expected && on_b == expected {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!(
                "the machines did not settle on the expected pins {expected:?}: machine A stores {on_a:?}, machine B stores {on_b:?}"
            )
            .into());
        }
        std::thread::sleep(POLL);
    }
}

#[test]
fn two_replicas_pinning_offline_keep_both_pins() -> TestResult {
    let (a, b, room) = two_machines()?;
    // Apart: A pins the first MESSAGE, B the second.
    let on_a = pin(&a, &room, room.first)?;
    let on_b = pin(&b, &room, room.second)?;
    assert_eq!(on_a.pinned_by, room.member);
    assert_eq!(on_b.pinned_by, room.member);
    // Synced: each machine keeps its own pin and takes the other's.
    converge(&a, &b, &room, &[&on_a, &on_b])
}

#[test]
fn an_offline_unpin_does_not_drop_a_pin_it_never_saw() -> TestResult {
    let (a, b, room) = two_machines()?;
    let seen = pin(&a, &room, room.first)?;
    converge(&a, &b, &room, &[&seen])?;
    // Apart: B unpins the first MESSAGE and pins it again, a new record.
    unpin(&b, &room, room.first)?;
    let repinned = pin(&b, &room, room.first)?;
    assert_ne!(
        repinned, seen,
        "a pin after an unpin is a new record, never the unpinned one"
    );
    // A unpins the record it saw, then pins and unpins the second MESSAGE,
    // so A's room body is the window's later write.
    unpin(&a, &room, room.first)?;
    for _ in 0..3 {
        pin(&a, &room, room.second)?;
        unpin(&a, &room, room.second)?;
    }
    // Synced: A's unpin removed only the record it saw; B's new record stays
    // on both machines, and the second MESSAGE stays unpinned.
    converge(&a, &b, &room, &[&repinned])
}

#[test]
fn an_unpin_seen_by_both_replicas_stays_removed() -> TestResult {
    let (a, b, room) = two_machines()?;
    let pinned = pin(&a, &room, room.first)?;
    converge(&a, &b, &room, &[&pinned])?;
    // B saw the pin and unpins it: the unpin reaches A and stays.
    unpin(&b, &room, room.first)?;
    converge(&a, &b, &room, &[])?;
    // A later write on A, whose room body now holds the unpinned record,
    // brings it back on neither machine.
    let later = pin(&a, &room, room.second)?;
    converge(&a, &b, &room, &[&later])?;
    for _ in 0..10 {
        exchange(&a.doc, &b.doc)?;
        std::thread::sleep(POLL);
    }
    let expected = records(&[&later]);
    assert!(
        stored_pins(&a, &room)? == expected && stored_pins(&b, &room)? == expected,
        "a later sync brought an unpinned record back"
    );
    // No reader is served the records an unpin removed: the member's read
    // of the room carries neither its pins nor them.
    let read = a
        .vault
        .memory(room.member, EdgeActorClass::Human)
        .get_entity(&room.room.to_hex())?;
    let served = serde_json::to_value(&read.value)?.to_string();
    assert!(
        !served.contains("\"pins\"") && !served.contains("\"unpinned\""),
        "a served room body names no pin record: {served}"
    );
    Ok(())
}

#[test]
fn an_unpin_holds_against_a_later_write_that_still_holds_the_record() -> TestResult {
    let (a, b, room) = two_machines()?;
    let seen = pin(&a, &room, room.first)?;
    converge(&a, &b, &room, &[&seen])?;
    // Apart: B unpins the record. A, which still holds it, pins the second
    // MESSAGE and changes that pin twice more, so A's room body is the
    // window's later write and still carries the record B unpinned.
    unpin(&b, &room, room.first)?;
    let mut kept = pin(&a, &room, room.second)?;
    for _ in 0..2 {
        unpin(&a, &room, room.second)?;
        kept = pin(&a, &room, room.second)?;
    }
    // Synced: B's unpin holds on both machines, and A's last pin stays.
    converge(&a, &b, &room, &[&kept])
}
