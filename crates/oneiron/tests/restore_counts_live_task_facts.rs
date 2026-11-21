//! A restore over the live vault weighs a task fact only as the live fold counts it
//! (FIX TASK-FACT-RESTORE-BELIEVES-ROWS). The restore refuses to roll back task authority
//! that moved since the checkpoint: an owner, cancellation or human assignment fact the live
//! vault added to a task the checkpoint holds. Since R5 the fold counts a fact row only when
//! this install's door wrote it with that body, or its carrier's signature proves it. A row
//! that proves nothing, such as another install's unsigned replica, changes no task; before
//! this fix the restore compare still read it as moved authority and refused every restore of
//! that task.
//!
//! Red on the base (#9424's head bb07bb984497): the restore in
//! `an_unproved_replicated_cancel_does_not_refuse_the_restore` is refused for "task
//! authority". Green on the head.
//! `a_cancel_this_install_wrote_since_the_checkpoint_still_refuses_the_restore` is a guard on
//! both: a counted fact still holds the restore.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test restore_counts_live_task_facts`.
#![cfg(all(oneiron_test_support, feature = "sync", feature = "test-support"))]

use std::path::PathBuf;
use std::sync::Arc;

use oneiron::habit::TaskRole;
use oneiron::recovery::checkpoint::CheckpointKey;
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::{
    EdgeActorClass, EdgeKind, EntityId, TASK_AUTHORITY_FACT_SCHEMA_VERSION,
    TASK_AUTHORITY_FACT_SUBKIND, TaskAuthorityFactKind, TimeRange, Vault, VaultConfig,
};
use rmpv::Value;

/// The stored weight of a `scoped_to` edge (contracts.ts `edgeKinds.pprWeight`).
const SCOPED_TO_WEIGHT: f32 = 0.7;

/// A live vault with one task its owner made, and a checkpoint of it that holds the task.
struct Checkpointed {
    directory: tempfile::TempDir,
    live: Vault,
    owner: EntityId,
    task: EntityId,
    image: PathBuf,
    key: CheckpointKey,
}

fn checkpointed() -> Checkpointed {
    let directory = oneiron::test_support::restore_tempdir();
    let live = Vault::open(directory.path().join("vault"), VaultConfig::device())
        .expect("open a fresh device vault");
    live.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    live.ensure_vault_key().expect("mint the vault data key");
    let owner = live
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let task = live
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            Value::Nil,
            Some("the owner's task".into()),
            Some(owner),
            Some(live.now_recorded_at()),
        ))
        .expect("the task door")
        .task_ref
        .expect("the TASK creation took effect");
    let key = live.checkpoint_key().expect("derive the checkpoint key");
    let image = directory.path().join("image");
    live.snapshot_checkpoint(&image, 100)
        .expect("snapshot the vault with its task");
    Checkpointed {
        directory,
        live,
        owner,
        task,
        image,
        key,
    }
}

impl Checkpointed {
    fn cancelled(&self) -> bool {
        self.live
            .task_authority_state(self.task)
            .expect("the task's authority reads")
            .expect("the owner's own Owner fact counts")
            .cancelled
    }

    fn restore(&self) -> oneiron::Result<()> {
        Vault::restore_checkpoint_keeping_authority(
            &self.image,
            &self.key,
            &self.directory.path().join("restored"),
            VaultConfig::device(),
            &self.live,
            200,
        )
        .map(|_| ())
    }
}

/// A current-schema Cancelled fact about `task` by `actor`, with no carrier, in the order
/// the engine's encoder writes its keys.
fn unsigned_cancel(task: EntityId, actor: EntityId, at: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(
        &mut bytes,
        &Value::Map(vec![
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
            (
                Value::from("kind"),
                Value::from(TaskAuthorityFactKind::Cancelled.as_byte()),
            ),
            (Value::from("actor_ref"), Value::from(actor.to_hex())),
            (Value::from("occurred_at"), Value::from(at)),
        ]),
    )
    .expect("encode the fact");
    bytes
}

/// Lands one TASK row as another of the owner's devices sends it, through the own-device
/// replay door, and its `ScopedTo` link to `task`.
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
fn an_unproved_replicated_cancel_does_not_refuse_the_restore() {
    let vault = checkpointed();
    land_replicated_fact(
        &vault.live,
        EntityId::now(),
        vault.task,
        &unsigned_cancel(vault.task, vault.owner, vault.live.now_recorded_at()),
    );
    assert!(
        !vault.cancelled(),
        "a cancel no carrier signed and no door here wrote is not a fact in the live fold"
    );
    if let Err(error) = vault.restore() {
        panic!(
            "a fact row the live fold does not count moved no task authority, \
             so the restore goes ahead; it was refused: {error}"
        );
    }
}

#[test]
fn a_cancel_this_install_wrote_since_the_checkpoint_still_refuses_the_restore() {
    let vault = checkpointed();
    oneiron::test_doors::inquiry::cancel_task(&vault.live, vault.task, vault.owner)
        .expect("the owner's cancel through the fact door");
    assert!(
        vault.cancelled(),
        "the cancel this install's door wrote counts"
    );
    let Err(error) = vault.restore() else {
        panic!("restoring the checkpoint would bring the cancelled task back open");
    };
    let message = error.to_string();
    assert!(
        message.contains("would roll back") && message.contains("task authority"),
        "{message}"
    );
}
