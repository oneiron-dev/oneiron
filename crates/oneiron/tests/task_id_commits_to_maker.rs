//! A TASK's id commits to its maker and its owner (FIX TASK-ID-COMMITS-TO-MAKER; Engine
//! RULING 16 Nov 04:34, TASK-ID-MAKER-SHAPE = A). Every door that writes an Owner fact mints
//! its TASK at `derive(TASK_MAKER, maker, owner, nonce)`, and the Owner fact carries the maker
//! and the nonce. The fold counts an Owner fact only when they and the owner it names derive
//! its task's id. A second Owner fact that names the true maker and nonce but another owner,
//! signed by a machine the fold admitted, therefore does not count: the true owner stands on
//! the host and on the device, and the mint door refuses to write it (Fable pass 28 SR-1).
//!
//! Red at the pin opus-task-proof/task-id-commits-to-maker-red (this head with
//! `TaskAuthorityFact::commits_to_its_task` answering true for every Owner fact): the second
//! owner forks the task's read on the host and on the device, and the mint door writes it.
//! `the_owner_fact_commits_to_its_maker_and_owner` and `a_nominated_owner_counts` pass there
//! too: the door mints at the derived id either way. Green on the head.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test task_id_commits_to_maker`.
#![cfg(oneiron_test_support)]
#![cfg(feature = "sync")]

use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::task_fact_actor::{
    mint_owner_fact, task_ref_of_maker, write_unjudged_owner_fact,
};
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::{
    EdgeActorClass, EdgeKind, EntityId, TASK_AUTHORITY_FACT_SUBKIND, TaskAuthorityFactKind,
    TimeRange, Vault, VaultConfig,
};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use rmpv::Value;

/// The stored weight of a `scoped_to` edge (contracts.ts `edgeKinds.pprWeight`).
const SCOPED_TO_WEIGHT: f32 = 0.7;

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

/// Lands every fact row the host holds about `task` on the device, in row order.
fn sync_facts(host: &Host, device: &Device, task: EntityId) {
    for (row, body) in fact_rows(&host.vault, task) {
        land_replicated_fact(&device.vault, row, task, &body);
    }
}

/// The Owner fact a task's door wrote, read from its body: the owner it names, and its
/// maker commitment `(maker, nonce)`.
struct OwnerCommitment {
    owner: EntityId,
    maker: EntityId,
    nonce: EntityId,
}

fn owner_commitment(vault: &Vault, task: EntityId) -> OwnerCommitment {
    let owners: Vec<OwnerCommitment> = fact_rows(vault, task)
        .into_iter()
        .filter_map(|(_, body)| {
            let Value::Map(entries) =
                rmpv::decode::read_value(&mut body.as_slice()).expect("a fact body decodes")
            else {
                panic!("a fact body is a map");
            };
            let field = |name: &str| {
                entries
                    .iter()
                    .find(|(key, _)| key.as_str() == Some(name))
                    .map(|(_, value)| value.clone())
            };
            let entity = |name: &str| {
                field(name)
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .map(|hex| EntityId::from_hex(&hex).expect("an entity ref"))
            };
            (field("kind").and_then(|kind| kind.as_u64())
                == Some(u64::from(TaskAuthorityFactKind::Owner.as_byte())))
            .then(|| OwnerCommitment {
                owner: entity("actor_ref").expect("an Owner fact names its owner"),
                maker: entity("maker_ref").expect("an Owner fact names its maker"),
                nonce: entity("nonce").expect("an Owner fact names its nonce"),
            })
        })
        .collect();
    let [owner] = <[OwnerCommitment; 1]>::try_from(owners)
        .unwrap_or_else(|_| panic!("the task door wrote exactly one Owner fact"));
    owner
}

/// A task the host's owner made, and a second Owner fact about it, signed by the host's own
/// carrier as a member machine whose door lacks the check would carry it: the true maker and
/// nonce, and another owner.
fn task_with_a_second_owner(host: &Host) -> (EntityId, EntityId) {
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let made = owner_commitment(&host.vault, task);
    let other = EntityId::now();
    write_unjudged_owner_fact(&host.vault, task, other, made.maker, made.nonce)
        .expect("the host's carrier signs a second owner");
    (task, other)
}

#[test]
fn the_owner_fact_commits_to_its_maker_and_owner() {
    let host = host();
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let made = owner_commitment(&host.vault, task);
    assert_eq!(made.owner, host.owner);
    assert_eq!(made.maker, host.owner, "the owner made its own task");
    assert_eq!(
        task_ref_of_maker(made.maker, made.owner, made.nonce).expect("the id derives"),
        task,
        "the task's id derives from its maker, its owner and its nonce"
    );
}

#[test]
fn a_second_owner_naming_the_true_maker_does_not_count_on_the_host() {
    let host = host();
    let (task, other) = task_with_a_second_owner(&host);
    let state = host
        .vault
        .task_authority_state(task)
        .expect("the second owner is skipped, not a fork")
        .expect("the true owner's fact counts");
    assert_eq!(state.owner_ref, host.owner);
    assert_ne!(state.owner_ref, other);
}

#[test]
fn a_second_owner_naming_the_true_maker_does_not_count_on_the_device() {
    let host = host();
    let device = device(&host);
    let (task, _) = task_with_a_second_owner(&host);
    sync_facts(&host, &device, task);
    let state = device
        .vault
        .task_authority_state(task)
        .expect("the second owner is skipped on the device, not a fork")
        .expect("the true owner's fact counts on the device");
    assert_eq!(state.owner_ref, host.owner);
}

#[test]
fn the_mint_door_refuses_a_second_owner_naming_the_true_maker() {
    let host = host();
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let made = owner_commitment(&host.vault, task);
    assert!(
        mint_owner_fact(&host.vault, task, EntityId::now(), made.maker, made.nonce).is_err(),
        "the door writes no Owner fact whose maker commitment derives another task"
    );
    mint_owner_fact(&host.vault, task, made.owner, made.maker, made.nonce)
        .expect("the door writes the true Owner fact again: a set duplicate");
    let state = host
        .vault
        .task_authority_state(task)
        .expect("the task's authority reads")
        .expect("the true owner's fact counts");
    assert_eq!(state.owner_ref, host.owner);
}

#[test]
fn a_nominated_owner_counts() {
    let host = host();
    let nominee = EntityId::now();
    let task = host
        .vault
        .memory(host.owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            Value::Nil,
            Some("a task for another owner".into()),
            Some(nominee),
            Some(host.vault.now_recorded_at()),
        ))
        .expect("the task door")
        .task_ref
        .expect("the TASK creation took effect");
    let made = owner_commitment(&host.vault, task);
    assert_eq!(made.owner, nominee);
    assert_eq!(made.maker, host.owner, "the caller made the task");
    let state = host
        .vault
        .task_authority_state(task)
        .expect("the task's authority reads")
        .expect("the nominated owner's fact counts");
    assert_eq!(state.owner_ref, nominee);
}
