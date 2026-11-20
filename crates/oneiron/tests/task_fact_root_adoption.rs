//! The root adopts the TASK authority facts written before it (pass 28 R5; Engine RULING
//! 16 Nov 03:18, TASK-FACT-RULING-CROSSED-OPTION-D = B). An unrooted vault's doors write
//! their facts unsigned, since there is no vault id to sign under, and those facts count on
//! that install alone. When the vault is rooted, each unsigned fact gets a twin that this
//! install's carrier signs, so a task cancelled before the root stays cancelled on every
//! device of the vault.
//!
//! Red on branch `opus-task-proof/task-fact-carrier-signature-red-no-adoption` (this head
//! with the two root doors' adoption calls taken out): the device counts no fact the vault
//! wrote before its root, so no owner stands there. Green on the head.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test task_fact_root_adoption`.
#![cfg(oneiron_test_support)]
#![cfg(feature = "sync")]

use std::sync::Arc;

use oneiron::authority::{ActSurface, LocalOpenProfile, MachineOwnership, MachineRole};
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::{
    EdgeActorClass, EdgeKind, EntityId, TASK_AUTHORITY_FACT_SUBKIND, TimeRange, Vault, VaultConfig,
};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;

/// The stored weight of a `scoped_to` edge (contracts.ts `edgeKinds.pprWeight`).
const SCOPED_TO_WEIGHT: f32 = 0.7;

/// A TASK `owner` creates through the task door, which writes its Owner fact.
fn owner_task(vault: &Vault, owner: EntityId) -> EntityId {
    vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some("cancelled before the root".into()),
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
            String::from_utf8_lossy(&body)
                .contains(TASK_AUTHORITY_FACT_SUBKIND)
                .then_some((edge.target, body))
        })
        .collect()
}

/// Lands one fact row and its `ScopedTo` link to `task` as the vault's own machine sends
/// them to another device.
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

#[test]
fn a_task_cancelled_before_the_root_stays_cancelled_on_a_second_device() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("a new vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let task = owner_task(&vault, owner);
    oneiron::test_doors::inquiry::cancel_task(&vault, task, owner).expect("the owner cancels");
    let before = vault
        .task_authority_state(task)
        .expect("the task's authority reads")
        .expect("the unrooted vault counts its own Owner fact");
    assert!(before.cancelled, "the unrooted vault counts its own cancel");

    assert_eq!(
        vault
            .profile_local_open(Some(b"task-fact-root-adoption"), true)
            .expect("the root door"),
        LocalOpenProfile::RootedAndProfiled,
    );
    let here = vault
        .task_authority_state(task)
        .expect("the task's authority reads after the root")
        .expect("the vault still counts its Owner fact");
    assert_eq!(here.owner_ref, owner);
    assert!(here.cancelled, "the vault still counts its cancel");

    let vault_id = vault
        .authority_fold()
        .expect("the vault's fold")
        .vault_id
        .expect("a rooted vault");
    let device_dir = tempfile::tempdir().expect("tempdir");
    let device =
        Vault::open(device_dir.path(), VaultConfig::device()).expect("the device's install");
    device.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = device
        .machine_encryption_key(vault_id)
        .expect("the device's encryption key");
    let request = device
        .machine_enrolment_request(vault_id, key)
        .expect("the device's enrolment request");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner's proof");
    vault
        .enroll_machine(
            &proof,
            ActSurface::ThisInstall,
            &request,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the owner enrols the device as his");
    let history = vault
        .export_signed_authority_history()
        .expect("the vault's history");
    device
        .import_signed_authority_history(&history)
        .expect("the device takes the history");
    for (row, body) in fact_rows(&vault, task) {
        land_replicated_fact(&device, row, task, &body);
    }

    let there = device
        .task_authority_state(task)
        .expect("the task's authority reads on the device")
        .expect("the signed twin of the Owner fact counts on the device");
    assert_eq!(there.owner_ref, owner);
    assert!(
        there.cancelled,
        "the signed twin of the pre-root cancel counts on the device"
    );
    assert_eq!(
        vault
            .adopt_unsigned_task_facts()
            .expect("a second adoption pass"),
        0,
        "the root adopted every fact written before it, so a second pass adopts none"
    );
}
