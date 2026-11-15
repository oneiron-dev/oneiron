//! A TASK authority fact proves itself to every install but the one whose door wrote it
//! (Fable pass 28 R5, DESIGN 3.2). Its carrier, the machine that ran the door, signs the
//! fact's row with its install key; another install counts the fact only when that signature
//! verifies and its fold admitted the carrier. A row that proves nothing is skipped, never an
//! error. Before R5 any sender's fact was believed, a federation peer's included (until
//! #8576), and a malformed or foreign role-6 row failed the task's read.
//!
//! Red on the base (main d9371998 with R0 87b4b0cc): the forged cancel counts in
//! `a_replayed_unsigned_cancel_leaves_the_task_open`; the forged signed cancel fails the read
//! in `a_cancel_signed_by_a_key_the_fold_never_admitted_leaves_the_task_open`; the forged
//! second owner forks the owner in `a_fact_the_hosts_machine_signed_counts_on_the_device`;
//! the ask record and the malformed fact fail the read in their tests. Green on the head.
//! `a_row_replaced_under_an_indexed_id_does_not_count` is red on the base when the replay
//! door lands the new body (the forger owns the task), and a guard when it refuses it.
//! `an_unrooted_vault_counts_the_facts_its_own_door_wrote` passes on both: this install's own
//! facts count here with no carrier.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test task_fact_carrier_proof`.
#![cfg(feature = "sync")]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::habit::TaskRole;
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::{
    EdgeActorClass, EdgeKind, EntityId, TASK_AUTHORITY_FACT_SCHEMA_VERSION,
    TASK_AUTHORITY_FACT_SUBKIND, TaskAuthorityFactKind, TimeRange, Vault, VaultConfig,
};
use oneiron_authority::authority::carrier_transcript;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use rmpv::Value;

/// The carrier transcript domain of a TASK fact (`task_authority::fact_proof`).
const TASK_FACT_CARRIER_DOMAIN: &[u8] = b"oneiron/task-fact/v2";
/// The stored weight of a `scoped_to` edge (contracts.ts `edgeKinds.pprWeight`).
const SCOPED_TO_WEIGHT: f32 = 0.7;

fn encode(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).expect("encode fixture");
    bytes
}

/// The keys of one current-schema fact about `task`, without a carrier, in the order the
/// engine's encoder writes them.
fn fact_entries(
    task: EntityId,
    kind: TaskAuthorityFactKind,
    actor: EntityId,
    at: u64,
) -> Vec<(Value, Value)> {
    vec![
        (
            Value::from("role"),
            Value::from(TaskRole::AuthorityFact.role_byte()),
        ),
        (
            Value::from("schema_version"),
            Value::from(TASK_AUTHORITY_FACT_SCHEMA_VERSION),
        ),
        (
            Value::from("subkind"),
            Value::from(TASK_AUTHORITY_FACT_SUBKIND),
        ),
        (Value::from("task_ref"), Value::from(task.to_hex())),
        (Value::from("kind"), Value::from(kind.as_byte())),
        (Value::from("actor_ref"), Value::from(actor.to_hex())),
        (Value::from("occurred_at"), Value::from(at)),
    ]
}

/// One fact signed by `key` as machine `machine`'s carrier signature over the fact row
/// `row` of the vault `vault_id`: a valid signature, whoever holds the key.
fn signed_fact_body(
    vault_id: &[u8; 32],
    row: EntityId,
    machine: EntityId,
    key: &SigningKey,
    entries: Vec<(Value, Value)>,
) -> Vec<u8> {
    let unsigned = encode(entries.clone());
    let transcript = carrier_transcript(
        TASK_FACT_CARRIER_DOMAIN,
        vault_id,
        &row,
        &machine,
        &unsigned,
    );
    let mut entries = entries;
    entries.extend([
        (
            Value::from("carrier_machine"),
            Value::from(machine.to_hex()),
        ),
        (
            Value::from("carrier_key"),
            Value::Binary(key.verifying_key().to_bytes().to_vec()),
        ),
        (
            Value::from("carrier_signature"),
            Value::Binary(key.sign(&transcript).to_bytes().to_vec()),
        ),
    ]);
    encode(entries)
}

/// Lands one TASK row as another of the owner's devices sends it: the own-device replay
/// door admits role 6 like any other TASK row.
fn replay_task_row(vault: &Vault, row: EntityId, body: &[u8]) -> oneiron::Result<()> {
    let now = vault.now_recorded_at();
    replay_entity(
        vault,
        ReplicatedEntity {
            id: row,
            entity_type: ENTITY_TYPE_TASK,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            row_version: 0,
            body,
        },
        ImportTier::OwnDevice,
    )
}

/// [`replay_task_row`], and the row's `ScopedTo` link to `task`.
fn land_replicated_fact(vault: &Vault, row: EntityId, task: EntityId, body: &[u8]) {
    replay_task_row(vault, row, body).expect("the own-device replay door lands the row");
    vault
        .batch()
        .edge(&row, EdgeKind::ScopedTo, &task, SCOPED_TO_WEIGHT)
        .commit()
        .expect("the row's link to its task");
}

/// A TASK `owner` creates through the task door, which writes its Owner fact.
fn owner_task(vault: &Vault, owner: EntityId, label: &str) -> EntityId {
    vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            Value::Nil,
            Some(label.into()),
            Some(owner),
            Some(vault.now_recorded_at()),
        ))
        .expect("the task door")
        .task_ref
        .expect("the TASK creation took effect")
}

/// The authority fact rows linked to `task`, as `(id, body)`.
fn fact_rows(vault: &Vault, task: EntityId) -> Vec<(EntityId, Vec<u8>)> {
    vault
        .edges_in(&task)
        .expect("the task's links")
        .into_iter()
        .filter(|edge| edge.kind == EdgeKind::ScopedTo)
        .filter_map(|edge| {
            let raw = vault.get_raw(&edge.target).expect("the linked row")?;
            let body = raw[ENTITY_METADATA_HEADER_LEN..].to_vec();
            let text = String::from_utf8_lossy(&body);
            text.contains(TASK_AUTHORITY_FACT_SUBKIND)
                .then_some((edge.target, body))
        })
        .collect()
}

/// A rooted vault on a hosted node: its install's profile stands in its own fold, its
/// install signer is loaded, and its owner is bound, so its doors sign every fact.
struct Host {
    _dir: tempfile::TempDir,
    vault: Vault,
    _issuer: HostSlipIssuer,
    owner: EntityId,
    vault_id: [u8; 32],
}

fn host() -> Host {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the host's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    vault
        .prepare_install_signing()
        .expect("the host's install signer");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
        .expect("the hosted node's live machine profile");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let vault_id = vault
        .authority_fold()
        .expect("the host's fold")
        .vault_id
        .expect("a rooted vault");
    Host {
        _dir: dir,
        vault,
        _issuer: issuer,
        owner,
        vault_id,
    }
}

/// The owner's device: its own install, which the owner enrols as his on the host, holding
/// the vault's authority history as sync gives it.
struct Device {
    _dir: tempfile::TempDir,
    vault: Vault,
}

fn device(host: &Host) -> Device {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the device's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = vault
        .machine_encryption_key(host.vault_id)
        .expect("the device's encryption key");
    let request = vault
        .machine_enrolment_request(host.vault_id, key)
        .expect("the device's enrolment request");
    let owner = host
        .vault
        .authenticate_owner(
            host.owner,
            &host.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("the owner's proof");
    host.vault
        .enroll_machine(
            &owner,
            ActSurface::HostedConsole,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner enrols the device as his");
    let history = host
        .vault
        .export_signed_authority_history()
        .expect("the host's history");
    vault
        .import_signed_authority_history(&history)
        .expect("the device takes the history");
    Device { _dir: dir, vault }
}

#[test]
fn a_replayed_unsigned_cancel_leaves_the_task_open() {
    let host = host();
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let forged = EntityId::now();
    land_replicated_fact(
        &host.vault,
        forged,
        task,
        &encode(fact_entries(
            task,
            TaskAuthorityFactKind::Cancelled,
            host.owner,
            host.vault.now_recorded_at(),
        )),
    );
    let state = host
        .vault
        .task_authority_state(task)
        .expect("the task's authority reads")
        .expect("the owner's own Owner fact counts");
    assert_eq!(state.owner_ref, host.owner);
    assert!(
        !state.cancelled,
        "a cancel no carrier signed is not a fact here"
    );
}

#[test]
fn a_cancel_signed_by_a_key_the_fold_never_admitted_leaves_the_task_open() {
    let host = host();
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let forged = EntityId::now();
    let stranger = SigningKey::from_bytes(&[0x5a; 32]);
    land_replicated_fact(
        &host.vault,
        forged,
        task,
        &signed_fact_body(
            &host.vault_id,
            forged,
            EntityId::now(),
            &stranger,
            fact_entries(
                task,
                TaskAuthorityFactKind::Cancelled,
                host.owner,
                host.vault.now_recorded_at(),
            ),
        ),
    );
    let state = host
        .vault
        .task_authority_state(task)
        .expect("the task's authority reads")
        .expect("the owner's own Owner fact counts");
    assert!(
        !state.cancelled,
        "a cancel signed by a machine the fold never admitted is not a fact here"
    );
}

#[test]
fn a_fact_the_hosts_machine_signed_counts_on_the_device() {
    let host = host();
    let device = device(&host);
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let rows = fact_rows(&host.vault, task);
    assert!(
        !rows.is_empty(),
        "the task door wrote the task's Owner fact"
    );
    for (row, body) in &rows {
        land_replicated_fact(&device.vault, *row, task, body);
    }
    // A second Owner fact naming another actor, with no carrier: were it a fact, the owner
    // would fork and nobody would stand.
    let forged = EntityId::now();
    land_replicated_fact(
        &device.vault,
        forged,
        task,
        &encode(fact_entries(
            task,
            TaskAuthorityFactKind::Owner,
            EntityId::now(),
            host.vault.now_recorded_at(),
        )),
    );
    let state = device
        .vault
        .task_authority_state(task)
        .expect("the task's authority reads on the device")
        .expect("the Owner fact the host's machine signed counts on the device");
    assert_eq!(state.owner_ref, host.owner);
}

#[test]
fn a_row_replaced_under_an_indexed_id_does_not_count() {
    let host = host();
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let rows = fact_rows(&host.vault, task);
    let (owner_fact, _) = rows
        .first()
        .expect("the task door wrote the task's Owner fact");
    // Another device sends a new body under the id of the Owner fact this install wrote: an
    // Owner fact naming someone else, with no carrier. The door may refuse the row; if it
    // lands, the written-here mark no longer names its bytes, so it must prove itself.
    let forger = EntityId::now();
    let _landed = replay_task_row(
        &host.vault,
        *owner_fact,
        &encode(fact_entries(
            task,
            TaskAuthorityFactKind::Owner,
            forger,
            host.vault.now_recorded_at(),
        )),
    );
    let state = host
        .vault
        .task_authority_state(task)
        .expect("the task's authority reads");
    assert_ne!(
        state.map(|state| state.owner_ref),
        Some(forger),
        "a row replaced under a fact's id is not the fact this install wrote"
    );
}

#[test]
fn an_ask_record_linked_to_a_task_does_not_fail_its_read() {
    let host = host();
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let record = EntityId::now();
    land_replicated_fact(
        &host.vault,
        record,
        task,
        &encode(vec![
            (
                Value::from("role"),
                Value::from(TaskRole::AuthorityFact.role_byte()),
            ),
            (Value::from("subkind"), Value::from("tasks.ask_group")),
            (Value::from("task_ref"), Value::from(task.to_hex())),
        ]),
    );
    let state = host
        .vault
        .task_authority_state(task)
        .expect("an ask record is not a fact, so the read stands")
        .expect("the owner's own Owner fact counts");
    assert_eq!(state.owner_ref, host.owner);
}

#[test]
fn a_malformed_fact_from_another_install_does_not_fail_its_read() {
    let host = host();
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let forged = EntityId::now();
    let mut entries = fact_entries(
        task,
        TaskAuthorityFactKind::Cancelled,
        host.owner,
        host.vault.now_recorded_at(),
    );
    entries.push((Value::from("unknown_key"), Value::from(1)));
    land_replicated_fact(&host.vault, forged, task, &encode(entries));
    let state = host
        .vault
        .task_authority_state(task)
        .expect("a row that proves nothing is skipped, never an error")
        .expect("the owner's own Owner fact counts");
    assert!(!state.cancelled);
}

#[test]
fn an_unrooted_vault_counts_the_facts_its_own_door_wrote() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("an unrooted vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let task = owner_task(&vault, owner, "the owner's task");
    let state = vault
        .task_authority_state(task)
        .expect("the task's authority reads")
        .expect("the Owner fact this install's door wrote counts with no carrier");
    assert_eq!(state.owner_ref, owner);
    assert!(!state.cancelled);
}
