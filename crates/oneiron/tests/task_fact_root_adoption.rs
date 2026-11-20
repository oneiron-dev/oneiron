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

/// A fact the task door writes unsigned after the root, on a start with no signer
/// loaded, is adopted on the next profiling open: it counts nowhere else before, and on
/// a second device after, and a further adoption pass finds nothing left.
#[test]
fn a_fact_written_unsigned_after_the_root_is_adopted_on_the_next_profiling_open() {
    // One keystore held across opens: the adopting reopen must load the same machine's
    // seed. A fresh empty keystore with `prepare_install_signing` would forget the machine
    // and join as new.
    let keystore = Arc::new(oneiron_keystore::MemoryKeystore::default());
    let dir = tempfile::tempdir().expect("tempdir");
    let device_dir = tempfile::tempdir().expect("tempdir");
    let device =
        Vault::open(device_dir.path(), VaultConfig::device()).expect("the device's install");
    device.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));

    // Root the vault with the signer loaded, enrol the device, then drop the vault so the
    // same path can reopen.
    let owner = {
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("a new vault");
        vault.install_device_keystore(Arc::clone(&keystore));
        assert_eq!(
            vault
                .profile_local_open(Some(b"task-fact-post-root-adoption"), true)
                .expect("the root door"),
            LocalOpenProfile::RootedAndProfiled,
        );
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("the embedded owner");
        let vault_id = vault
            .authority_fold()
            .expect("the vault's fold")
            .vault_id
            .expect("a rooted vault");
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
        owner
    };

    // Reopen the same path with no keystore and no signer: a start with no signer
    // loaded. The task door still succeeds, and its Owner fact stores unsigned.
    let (task, landed) = {
        let vault =
            Vault::open(dir.path(), VaultConfig::device()).expect("reopen without a keystore");
        let task = owner_task(&vault, owner);
        let here = vault
            .task_authority_state(task)
            .expect("the task reads here")
            .expect("the unproved fact still counts where it was written");
        assert_eq!(here.owner_ref, owner);
        let rows = fact_rows(&vault, task);
        for (row, body) in &rows {
            land_replicated_fact(&device, *row, task, body);
        }
        assert_eq!(
            device
                .task_authority_state(task)
                .expect("the task reads on the device"),
            None,
            "the unsigned post-root fact proves nothing on another device"
        );
        let landed: Vec<EntityId> = rows.into_iter().map(|(row, _)| row).collect();
        (task, landed)
    };

    // Reopen with the same keystore and profile again: the non-rooted branch adopts
    // what is left. The profile already stands, so this reports carrying, not rooting.
    {
        let vault =
            Vault::open(dir.path(), VaultConfig::device()).expect("reopen with the keystore");
        vault.install_device_keystore(Arc::clone(&keystore));
        let profile = vault
            .profile_local_open(Some(b"task-fact-post-root-adoption"), false)
            .expect("the profiling open");
        assert!(
            matches!(
                profile,
                LocalOpenProfile::AlreadyCarrying { wrong_root: false }
            ),
            "reopen profiles under the settled root, then adopts: {profile:?}"
        );
        assert_eq!(
            vault
                .adopt_unsigned_task_facts()
                .expect("a second adoption pass"),
            0,
            "the profiling open adopted the post-root fact, so a second pass adopts none"
        );
        // The device already holds the unsigned row: only the twin crosses now.
        for (row, body) in fact_rows(&vault, task) {
            if !landed.contains(&row) {
                land_replicated_fact(&device, row, task, &body);
            }
        }
        let there = device
            .task_authority_state(task)
            .expect("the task's authority reads on the device")
            .expect("the twin of the post-root Owner fact counts on the device");
        assert_eq!(
            there.owner_ref, owner,
            "the adopted fact names the true owner on the device"
        );
    }
}
