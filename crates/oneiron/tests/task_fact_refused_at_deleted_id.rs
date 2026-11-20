//! A task authority fact refused because its id was deleted here first is judged when its
//! task is read, as the fold judges any fact (blind reviews of #9365 and #9438). The device
//! keeps the refused row under its task; the read fails closed once the fold would count it.
//!
//! - `a_refused_stranger_ack_leaves_its_task_readable` (REVIEW-9365 P1): an Acked fact by an
//!   actor who is not the task's owner, signed by a carrier the device admitted, is refused
//!   at a deleted id. The fold's actor rule never counts it, so the task stays readable. Red
//!   at the pin opus-task-proof/restore-counts-live-task-facts-red-refused (refusal marked
//!   the task on carrier proof alone, and every read of it failed); green on the head. Its
//!   second half, a refused owner's cancel still fails its task's read, is a guard.
//! - `a_stranger_ack_refused_before_the_owner_fact_leaves_its_task_readable`: the same Ack
//!   refused before the task's Owner fact reached the device. Red at the pin as above.
//! - `a_refused_cancel_counts_once_its_carrier_is_admitted` (REVIEW-9438 P1): the owner's
//!   signed cancel is refused before the device holds its carrier's profile; once the
//!   authority history arrives, the task reads as a refusal. Red at the pin (the refusal
//!   found no proof, kept nothing, and the task read with no cancel); green on the head.
//! - `a_forged_replay_of_a_refused_cancel_keeps_its_refusal` (REVIEW-9438 round 2 P1): the
//!   owner's signed cancel is refused at a deleted id, then its row comes again with another
//!   time under the original signature. Red at the pin
//!   opus-task-proof/restore-counts-live-task-facts-red-forged-replay (the replay replaced
//!   the kept body, and the task read with no cancel); green on the head.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test task_fact_refused_at_deleted_id`.
#![cfg(oneiron_test_support)]
#![cfg(feature = "sync")]

use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::task_fact_actor::{mint_fact, note_refused_fact, write_unjudged_fact};
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::{
    EdgeActorClass, EdgeKind, EntityId, Error, TASK_AUTHORITY_FACT_SUBKIND, TaskAuthorityFactKind,
    TimeRange, Vault, VaultConfig,
};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use rmpv::Value;

/// The stored weight of a `scoped_to` edge (contracts.ts `edgeKinds.pprWeight`).
const SCOPED_TO_WEIGHT: f32 = 0.7;

/// Lands one fact row and its `ScopedTo` link to `task` as another of the owner's devices
/// sends them: the own-device replay door admits role 6 like any other TASK row.
fn land_replicated_fact(vault: &Vault, row: EntityId, task: EntityId, body: &[u8]) {
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
    .expect("the own-device replay door lands the row");
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

/// The body of the fact row `row` linked to `task` on `vault`.
fn fact_body(vault: &Vault, task: EntityId, row: EntityId) -> Vec<u8> {
    fact_rows(vault, task)
        .into_iter()
        .find_map(|(id, body)| (id == row).then_some(body))
        .expect("the fact row is linked to its task")
}

fn reads_suppressed(vault: &Vault, task: EntityId) -> bool {
    matches!(
        vault.task_authority_state(task),
        Err(Error::InvariantViolation("task authority fact suppressed"))
    )
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

/// The owner's device: its own install, which holds nothing of the vault until it takes
/// the vault's authority history ([`take_history`]).
struct Device {
    _dir: tempfile::TempDir,
    vault: Vault,
}

fn bare_device() -> Device {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the device's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    Device { _dir: dir, vault }
}

/// The owner enrols `device` as his on the host, and the device takes the vault's authority
/// history as sync gives it: the host's machine, the carrier of its facts, is admitted there.
fn take_history(host: &Host, device: &Device) {
    let key = device
        .vault
        .machine_encryption_key(host.vault_id)
        .expect("the device's encryption key");
    let request = device
        .vault
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
    device
        .vault
        .import_signed_authority_history(&history)
        .expect("the device takes the history");
}

fn device(host: &Host) -> Device {
    let device = bare_device();
    take_history(host, &device);
    device
}

/// Lands every fact row the host holds about `task` on the device, in row order.
fn sync_facts(host: &Host, device: &Device, task: EntityId) {
    for (row, body) in fact_rows(&host.vault, task) {
        land_replicated_fact(&device.vault, row, task, &body);
    }
}

/// An Acked fact about `task` by an actor who is not its owner, signed by the host's own
/// carrier as a member machine whose door lacks the actor check would carry it: its row id
/// and body.
fn stranger_ack(host: &Host, task: EntityId) -> (EntityId, Vec<u8>) {
    let ack = write_unjudged_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Acked,
        EntityId::now(),
        None,
    )
    .expect("the host's carrier signs a stranger's ack");
    (ack, fact_body(&host.vault, task, ack))
}

#[test]
fn a_refused_stranger_ack_leaves_its_task_readable() {
    let host = host();
    let device = device(&host);
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    sync_facts(&host, &device, task);
    let (ack, ack_body) = stranger_ack(&host, task);
    note_refused_fact(&device.vault, ack, &ack_body)
        .expect("the device refuses the ack's row, deleted there");
    let state = device
        .vault
        .task_authority_state(task)
        .expect("a refused fact the actor rule refuses fails no read")
        .expect("the owner's fact counts on the device");
    assert_eq!(state.owner_ref, host.owner);
    assert!(!state.acked, "the stranger's ack does not count");

    // A refused fact the fold counts still fails its task's read.
    let cancelled = owner_task(&host.vault, host.owner, "a task the owner cancels");
    sync_facts(&host, &device, cancelled);
    let cancel = mint_fact(
        &host.vault,
        cancelled,
        TaskAuthorityFactKind::Cancelled,
        host.owner,
        None,
    )
    .expect("the host's door writes the owner's cancel");
    let cancel_body = fact_body(&host.vault, cancelled, cancel);
    note_refused_fact(&device.vault, cancel, &cancel_body)
        .expect("the device refuses the cancel's row, deleted there");
    assert!(
        reads_suppressed(&device.vault, cancelled),
        "a refused cancel the device would count fails its task's read"
    );
    assert!(
        !reads_suppressed(&device.vault, task),
        "the refusal stays on the cancelled task"
    );
}

#[test]
fn a_stranger_ack_refused_before_the_owner_fact_leaves_its_task_readable() {
    let host = host();
    let device = device(&host);
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let (ack, ack_body) = stranger_ack(&host, task);
    note_refused_fact(&device.vault, ack, &ack_body)
        .expect("the device refuses the ack's row, deleted there");
    for (row, body) in fact_rows(&host.vault, task) {
        if row != ack {
            land_replicated_fact(&device.vault, row, task, &body);
        }
    }
    let state = device
        .vault
        .task_authority_state(task)
        .expect("the ack, judged once the owner's fact is in, fails no read")
        .expect("the owner's fact counts on the device");
    assert_eq!(state.owner_ref, host.owner);
    assert!(!state.acked, "the stranger's ack does not count");
}

#[test]
fn a_refused_cancel_counts_once_its_carrier_is_admitted() {
    let host = host();
    let device = bare_device();
    let task = owner_task(&host.vault, host.owner, "a task the owner cancels");
    let cancel = mint_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Cancelled,
        host.owner,
        None,
    )
    .expect("the host's door writes the owner's cancel");
    let cancel_body = fact_body(&host.vault, task, cancel);
    note_refused_fact(&device.vault, cancel, &cancel_body)
        .expect("the device refuses the cancel's row before it holds its carrier's profile");
    assert!(
        !reads_suppressed(&device.vault, task),
        "a refused fact that proves nothing yet fails no read"
    );
    take_history(&host, &device);
    assert!(
        reads_suppressed(&device.vault, task),
        "once its carrier is admitted, the refused cancel fails its task's read"
    );
}

/// `body` with its `occurred_at` moved by one second and every other byte kept, its
/// carrier signature included: a replay of the row that no carrier signed.
fn with_moved_time(body: &[u8]) -> Vec<u8> {
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut &body[..]).expect("the fact body decodes")
    else {
        panic!("a fact body is a map");
    };
    for (key, value) in &mut entries {
        if key.as_str() == Some("occurred_at") {
            *value = Value::from(value.as_u64().expect("the fact's time") + 1);
        }
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries)).expect("encode fixture");
    bytes
}

#[test]
fn a_forged_replay_of_a_refused_cancel_keeps_its_refusal() {
    let host = host();
    let device = device(&host);
    let task = owner_task(&host.vault, host.owner, "a task the owner cancels");
    sync_facts(&host, &device, task);
    let cancel = mint_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Cancelled,
        host.owner,
        None,
    )
    .expect("the host's door writes the owner's cancel");
    let cancel_body = fact_body(&host.vault, task, cancel);
    note_refused_fact(&device.vault, cancel, &cancel_body)
        .expect("the device refuses the cancel's row, deleted there");
    assert!(
        reads_suppressed(&device.vault, task),
        "a refused cancel the device would count fails its task's read"
    );
    let forged = with_moved_time(&cancel_body);
    assert_ne!(forged, cancel_body, "the replay carries another body");
    note_refused_fact(&device.vault, cancel, &forged)
        .expect("the device refuses the replayed row, deleted there");
    assert!(
        reads_suppressed(&device.vault, task),
        "a replay its carrier never signed does not replace the refused cancel"
    );
}
