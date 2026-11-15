//! A proved TASK authority fact counts only when its actor may make it (Fable pass 28 R5
//! part 2, DESIGN 2.2 and 3.2 point 3). The fold reads Owner facts first, then the facts
//! whose rule reads the owner, then those whose rule reads the assignee, so no arrival order
//! changes the answer; the mint door asks the same rule before it writes. Each fact here is
//! signed by the host's own carrier, as a member machine whose door lacks the actor check
//! would carry it, so it proves itself on every device: only the actor rule refuses it.
//!
//! Red at 5d987ffd4f68 (part 1, the PR's base) with this file and the test door laid in: the stranger's ack
//! counts on the host and the device; the stranger's assignment forks the owner's and fails
//! the task's read; the stranger's take counts; the mint door writes the stranger's ack.
//! `the_owner_taking_its_own_task_counts` passes on both: the owner reclaims or takes over
//! its own task. `a_cancel_lands_on_a_task_whose_facts_fail_the_read` passes there too,
//! since part 1's door reads no fact; it is red at 256f9a3d012a (part 2 before its door
//! skipped the read for the kinds that count from any actor): the failed read refuses the
//! cancel. Green on the head. (Before FIX TASK-ID-COMMITS-TO-MAKER that test failed the read
//! with a second Owner fact naming another owner, a fork; now such a fact is skipped, so it
//! fails the read with an Owner fact this install wrote with no maker commitment.)
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test task_fact_actor_rule`.
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
    ProvedStanding, mint_fact, proved_standing, write_unjudged_fact,
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

fn standing(vault: &Vault, task: EntityId) -> ProvedStanding {
    proved_standing(vault, task)
        .expect("the task's facts read")
        .expect("the owner's Owner fact counts")
}

#[test]
fn an_ack_its_carrier_signed_for_another_actor_counts_on_no_device() {
    let host = host();
    let device = device(&host);
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let stranger = EntityId::now();
    write_unjudged_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Acked,
        stranger,
        None,
    )
    .expect("the host's carrier signs the stranger's ack");
    sync_facts(&host, &device, task);
    for (name, vault) in [("host", &host.vault), ("device", &device.vault)] {
        let state = vault
            .task_authority_state(task)
            .expect("the task's authority reads")
            .expect("the owner's Owner fact counts");
        assert!(
            !state.acked,
            "an ack by an actor that does not own the task is not a fact on the {name}"
        );
    }
}

#[test]
fn an_assignment_from_another_actor_does_not_fork_the_owners() {
    let host = host();
    let device = device(&host);
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let (agent, stranger, strangers_agent) = (EntityId::now(), EntityId::now(), EntityId::now());
    write_unjudged_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Assigned,
        host.owner,
        Some(agent),
    )
    .expect("the owner's assignment");
    write_unjudged_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Assigned,
        stranger,
        Some(strangers_agent),
    )
    .expect("the host's carrier signs the stranger's assignment");
    sync_facts(&host, &device, task);
    for vault in [&host.vault, &device.vault] {
        assert_eq!(
            standing(vault, task).assignee,
            Some(agent),
            "only the owner's assignment counts, so it stands alone"
        );
    }
}

#[test]
fn a_take_by_an_actor_the_task_is_not_addressed_to_does_not_count() {
    let host = host();
    let device = device(&host);
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let (agent, stranger) = (EntityId::now(), EntityId::now());
    // The stranger's take is written before the assignment: the fold judges a take only
    // after every assignment, whatever order the rows come in.
    write_unjudged_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Accepted,
        stranger,
        None,
    )
    .expect("the host's carrier signs the stranger's take");
    write_unjudged_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Assigned,
        host.owner,
        Some(agent),
    )
    .expect("the owner's assignment");
    sync_facts(&host, &device, task);
    for vault in [&host.vault, &device.vault] {
        assert_eq!(
            standing(vault, task).taker,
            None,
            "a take by an actor the task is not addressed to is not a fact"
        );
    }
    write_unjudged_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Accepted,
        agent,
        None,
    )
    .expect("the assignee's take");
    assert_eq!(standing(&host.vault, task).taker, Some(agent));
}

#[test]
fn the_owner_taking_its_own_task_counts() {
    let host = host();
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let agent = EntityId::now();
    mint_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Assigned,
        host.owner,
        Some(agent),
    )
    .expect("the owner assigns its task");
    mint_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Accepted,
        host.owner,
        None,
    )
    .expect("the owner takes over its own task");
    assert_eq!(standing(&host.vault, task).taker, Some(host.owner));
}

#[test]
fn a_cancel_lands_on_a_task_whose_facts_fail_the_read() {
    let host = host();
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    // An Owner fact with no maker commitment, written past the door: this install reads
    // the facts its own door wrote strictly, so the task's read fails.
    write_unjudged_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Owner,
        EntityId::now(),
        None,
    )
    .expect("the host's carrier signs an Owner fact with no maker");
    assert!(
        host.vault.task_authority_state(task).is_err(),
        "a malformed fact this install wrote fails the task's read"
    );
    // The vault owner's force cancel writes this fact once it stops a branch, whatever
    // the task's facts read.
    mint_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Cancelled,
        host.owner,
        None,
    )
    .expect("the door writes a cancel on a task whose facts fail the read");
}

#[test]
fn the_mint_door_refuses_a_fact_its_actor_may_not_make() {
    let host = host();
    let task = owner_task(&host.vault, host.owner, "the owner's task");
    let stranger = EntityId::now();
    assert!(
        mint_fact(
            &host.vault,
            task,
            TaskAuthorityFactKind::Acked,
            stranger,
            None
        )
        .is_err(),
        "the door writes no ack the fold would not count"
    );
    mint_fact(
        &host.vault,
        task,
        TaskAuthorityFactKind::Acked,
        host.owner,
        None,
    )
    .expect("the owner's own ack");
    let state = host
        .vault
        .task_authority_state(task)
        .expect("the task's authority reads")
        .expect("the owner's Owner fact counts");
    assert!(state.acked);
}
