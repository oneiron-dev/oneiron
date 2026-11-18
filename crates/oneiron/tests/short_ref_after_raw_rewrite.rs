//! The short ref `vault.get` issues for a row that a raw rewrite changed
//! resolves through `vault.refs.resolve` and reads back through `vault.get`
//! (FIX RAW-REWRITE-SHORT-ID-STALE). A read issues the ref with the content
//! hash of the row it serves. Two writers put a new body in place without the
//! batch writer's short-id step, so the index kept the old body's hash and the
//! issued ref answered NOT_FOUND:
//! - a Habit TASK's derived streak counters, which the batch tail writes after
//!   every put of the habit and every check-in that changes them;
//! - a connector key's record, which its suspension and revocation rewrite.
//!
//! Each case reads the rewrite back through a second door (the habit's body
//! at `vault.get`, the key's status at `Vault::get_connector_key`), so a case
//! never passes on a body that did not change. The verbs are called by name
//! through the embedded door, and their output is read as JSON.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test short_ref_after_raw_rewrite`
#![cfg(feature = "test-support")]

use std::sync::Arc;

use oneiron::connector_key::{ConnectorKeyRecord, ConnectorKeyStatus};
use oneiron::habit::TaskRole;
use oneiron::memory::Memory;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

/// The UTC day the habit is created on and first checked in on.
const HABIT_DAY: u64 = 20_601;
const DAY_SECS: u64 = 86_400;

fn fresh_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    bind_host_owner(&vault, &test_host_issuer(), owner).expect("owner host binding");
    (directory, vault)
}

fn owner_memory(vault: &Vault) -> Memory<'_> {
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    vault.memory(owner, EdgeActorClass::Human)
}

fn field<'a>(output: &'a Value, pointer: &str, what: &str) -> &'a Value {
    output
        .pointer(pointer)
        .unwrap_or_else(|| panic!("{what}: no {pointer} in {output}"))
}

fn read_by_id(memory: &Memory<'_>, entity: &EntityId) -> Value {
    oneiron::task_verb::sdk::invoke(
        memory,
        "vault.get",
        json!({ "entity_ref": entity.to_hex() }),
    )
    .expect("the owner reads the row by its id")
}

/// The ref `vault.get` issues for `entity` must name it at
/// `vault.refs.resolve` and read it back at `vault.get`.
fn assert_issued_short_ref_resolves(memory: &Memory<'_>, entity: &EntityId) {
    let read = read_by_id(memory, entity);
    let reference = field(&read, "/value/short_ref", "vault.get by id")
        .as_str()
        .unwrap_or_else(|| panic!("vault.get issued no short ref: {read}"))
        .to_owned();

    let resolved = oneiron::task_verb::sdk::invoke(
        memory,
        "vault.refs.resolve",
        json!({ "reference": reference }),
    )
    .unwrap_or_else(|error| {
        panic!("the short ref {reference} that vault.get issued does not resolve: {error:?}")
    });
    assert_eq!(
        field(&resolved, "/value/record/id", "vault.refs.resolve")
            .as_str()
            .map(str::to_ascii_lowercase),
        Some(entity.to_hex().to_ascii_lowercase()),
        "the issued short ref {reference} resolves to its own row: {resolved}"
    );

    let reread =
        oneiron::task_verb::sdk::invoke(memory, "vault.get", json!({ "entity_ref": reference }))
            .unwrap_or_else(|error| {
                panic!("vault.get by the issued ref {reference} fails: {error:?}")
            });
    assert!(
        !field(&reread, "/value", "vault.get by short ref").is_null(),
        "vault.get reads the row back by the ref it issued ({reference}): {reread}"
    );
}

fn task_body(role: TaskRole) -> Vec<u8> {
    let value = rmpv::Value::Map(vec![(
        rmpv::Value::from("role"),
        rmpv::Value::from(role.role_byte()),
    )]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value).expect("encode the TASK body");
    bytes
}

/// Puts a Habit-role TASK as a public put does; the batch tail writes its
/// derived streak counters into the stored body in the same commit.
fn put_habit(vault: &Vault) -> EntityId {
    let habit = EntityId::now();
    let created = HABIT_DAY * DAY_SECS;
    vault
        .put_entity(
            &habit,
            ENTITY_TYPE_TASK,
            TimeRange {
                start: created,
                end: created,
            },
            created,
            &task_body(TaskRole::Habit),
        )
        .expect("the owner puts a habit");
    habit
}

fn check_in(vault: &Vault, habit: &EntityId, day: u64) {
    let occurred = day * DAY_SECS + 100;
    vault
        .put_habit_checkin(
            habit,
            &EntityId::now(),
            TimeRange {
                start: occurred,
                end: occurred,
            },
            occurred,
            &task_body(TaskRole::HabitCheckin),
        )
        .expect("the owner checks in on the habit");
}

/// The habit's stored counters as `vault.get` serves them.
fn served_streak(memory: &Memory<'_>, habit: &EntityId) -> (u64, u64) {
    let read = read_by_id(memory, habit);
    let counter = |key: &str| {
        field(&read, &format!("/value/body/{key}"), "the habit body")
            .as_u64()
            .unwrap_or_else(|| panic!("{key} is not a count: {read}"))
    };
    (counter("currentStreak"), counter("longestStreak"))
}

#[test]
fn a_new_habit_resolves_by_its_issued_short_ref() {
    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    let habit = put_habit(&vault);
    assert_eq!(
        served_streak(&memory, &habit),
        (0, 0),
        "the batch tail wrote the empty streak into the new habit's body"
    );

    assert_issued_short_ref_resolves(&memory, &habit);
}

#[test]
fn a_habit_after_a_check_in_resolves_by_its_issued_short_ref() {
    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    let habit = put_habit(&vault);
    check_in(&vault, &habit, HABIT_DAY);
    assert_eq!(
        served_streak(&memory, &habit),
        (1, 1),
        "the check-in rewrote the habit's streak"
    );

    assert_issued_short_ref_resolves(&memory, &habit);
}

#[test]
fn a_habit_after_check_ins_on_two_days_resolves_by_its_issued_short_ref() {
    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    let habit = put_habit(&vault);
    check_in(&vault, &habit, HABIT_DAY);
    check_in(&vault, &habit, HABIT_DAY + 1);
    assert_eq!(
        served_streak(&memory, &habit),
        (2, 2),
        "each check-in rewrote the habit's streak"
    );

    assert_issued_short_ref_resolves(&memory, &habit);
}

/// A vault with a device keystore and install signing, and one Active
/// connector key for a person, as `tests/gate_receipt_rows.rs` registers one.
struct ConnectorKeyFixture {
    vault: Vault,
    key: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl ConnectorKeyFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary vault");
        let vault =
            Vault::open_owned(directory.path(), VaultConfig::device()).expect("owned vault");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.prepare_install_signing().expect("install signing");
        vault
            .ensure_embedded_owner_actor()
            .expect("the embedded owner");
        let person = EntityId::now();
        let body =
            rmp_serde::to_vec_named(&json!({ "name": "connector person" })).expect("a person body");
        vault
            .put_entity(
                &person,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &body,
            )
            .expect("put the person");
        let key = EntityId::now();
        vault
            .register_connector_key(
                &key,
                ConnectorKeyRecord::active("email", Some(person), Vec::new(), 10),
            )
            .expect("register the connector key");
        Self {
            vault,
            key,
            _directory: directory,
        }
    }

    fn status(&self) -> ConnectorKeyStatus {
        self.vault
            .get_connector_key(&self.key)
            .expect("read the key")
            .expect("the key exists")
            .status
    }
}

#[test]
fn a_suspended_connector_key_resolves_by_its_issued_short_ref() {
    let fixture = ConnectorKeyFixture::new();
    let memory = owner_memory(&fixture.vault);
    // The registered key's ref resolves before any rewrite.
    assert_issued_short_ref_resolves(&memory, &fixture.key);

    fixture
        .vault
        .suspend_connector_key(&fixture.key, "the owner pauses the key", 20)
        .expect("the owner suspends the key");
    assert_eq!(fixture.status(), ConnectorKeyStatus::Suspended);

    assert_issued_short_ref_resolves(&memory, &fixture.key);
}

#[test]
fn a_revoked_connector_key_resolves_by_its_issued_short_ref() {
    let fixture = ConnectorKeyFixture::new();
    let memory = owner_memory(&fixture.vault);
    assert_issued_short_ref_resolves(&memory, &fixture.key);

    fixture
        .vault
        .revoke_connector_key(&fixture.key, 20)
        .expect("the owner revokes the key");
    assert_eq!(fixture.status(), ConnectorKeyStatus::Revoked);

    assert_issued_short_ref_resolves(&memory, &fixture.key);
}
