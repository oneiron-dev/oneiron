//! A removed machine's signature proves only the TASK facts its removal saw (row
//! TASK-FACT-REMOVED-CARRIER-NEW-FACTS; lead ruling REMOVED-CARRIER-NEW-FACTS = A, 21 Nov:
//! "a removal does not unmake facts made BEFORE it, and cannot be used to make new ones
//! after"). Before the fix the fold admitted a removed machine's carrier with no check, so a
//! cancel the machine signed after its removal, relayed to the host, cancelled the task there
//! (blind review round 2 P1, REVIEW-10064).
//!
//! - `a_cancel_the_removed_machine_signs_after_its_removal_does_not_count`: the machine's
//!   cancel of one task reaches the host before the owner removes the machine there, and
//!   counts; its cancel of another task, signed after the removal, does not, and the host
//!   counts it as one fact that arrived after the removal. Red on the base (#10064's head
//!   770193f08af3): the late cancel cancels its task. Green on the head.
//! - `cancels_the_removal_never_saw_do_not_count_and_the_host_counts_them`: two cancels the
//!   machine signed before its removal reach the host only after it. The remover never saw
//!   them, so they do not count, the narrow loss the ruling accepts, and the host counts them.
//!   Red on the base (both cancels count). Green on the head.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test task_fact_removed_carrier`.
#![cfg(oneiron_test_support)]
#![cfg(feature = "sync")]

use std::sync::Arc;

use oneiron::authority::{
    ActSurface, HostSlipIssuer, LastDeviceKeyConfirmation, MachineOwnership, MachineRemoval,
    MachineRole,
};
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::store::GateDecisionId;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::task_authority::task_facts_not_counted_text;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::task_fact_actor::write_unjudged_fact;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::{
    EdgeActorClass, EdgeKind, EntityId, TaskAuthorityFactKind, TimeRange, Vault, VaultConfig,
};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use rmpv::Value;

/// The stored weight of a `scoped_to` edge (contracts.ts `edgeKinds.pprWeight`).
const SCOPED_TO_WEIGHT: f32 = 0.7;

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

/// Whether `vault` reads `task` as cancelled.
fn cancelled(vault: &Vault, task: EntityId) -> bool {
    vault
        .task_authority_state(task)
        .expect("the task's authority reads")
        .expect("the task has its owner")
        .cancelled
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

/// Another machine of the owner's: its install, which signs the facts its doors write.
struct Machine {
    _dir: tempfile::TempDir,
    vault: Vault,
    id: EntityId,
}

/// A machine the owner enrolled on the host as a work or school machine of theirs, so its
/// carrier counts there, holding the vault's history as it stood then. An `Owned(Yours)`
/// answer needs an owner-key proof this hosted vault cannot give: it would land held.
fn enrolled_machine(host: &Host) -> Machine {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the machine's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let key = vault
        .machine_encryption_key(host.vault_id)
        .expect("the machine's encryption key");
    let request = vault
        .machine_enrolment_request(host.vault_id, key)
        .expect("the machine's enrolment request");
    let landing = host
        .vault
        .enroll_machine(
            &owner_proof(host),
            ActSurface::HostedConsole,
            &request,
            MachineRole::Owned(MachineOwnership::WorkSchool),
            None,
        )
        .expect("the owner enrols the machine as theirs");
    assert!(
        landing.held().is_none(),
        "FIXTURE: the machine's enrolment lands, so the host admits its carrier"
    );
    let history = host
        .vault
        .export_signed_authority_history()
        .expect("the host's history");
    vault
        .import_signed_authority_history(&history)
        .expect("the machine takes the history");
    vault
        .prepare_install_signing()
        .expect("the machine's install signer");
    Machine {
        _dir: dir,
        vault,
        id: request.machine,
    }
}

fn owner_proof(host: &Host) -> oneiron::consent::AuthenticatedOwner {
    host.vault
        .authenticate_owner(
            host.owner,
            &host.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("the owner's proof")
}

impl Machine {
    /// The owner's cancel of `task`, which this machine's carrier signs. The machine never
    /// learns of its removal, as a lost or stolen device does not.
    fn cancel(&self, host: &Host, task: EntityId) -> EntityId {
        write_unjudged_fact(
            &self.vault,
            task,
            TaskAuthorityFactKind::Cancelled,
            host.owner,
            None,
        )
        .expect("the machine's carrier signs the owner's cancel")
    }

    /// This machine's fact row `fact` as sync brings it to the host: the row through the
    /// own-device replay door, then its link to `task`.
    fn deliver(&self, host: &Host, fact: EntityId, task: EntityId) {
        let raw = self
            .vault
            .get_raw(&fact)
            .expect("read the fact")
            .expect("the machine holds its fact");
        let now = host.vault.now_recorded_at();
        replay_entity(
            &host.vault,
            ReplicatedEntity {
                id: fact,
                entity_type: ENTITY_TYPE_TASK,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                row_version: 0,
                body: &raw[ENTITY_METADATA_HEADER_LEN..],
            },
            ImportTier::OwnDevice,
        )
        .expect("the own-device replay door lands the row");
        host.vault
            .batch()
            .edge(&fact, EdgeKind::ScopedTo, &task, SCOPED_TO_WEIGHT)
            .commit()
            .expect("the row's link to its task");
    }
}

/// The owner removes `machine` on the host, and the removal stands there.
fn remove(host: &Host, machine: &Machine) {
    match host
        .vault
        .remove_machine(
            &owner_proof(host),
            ActSurface::HostedConsole,
            machine.id,
            None,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the owner removes the machine")
    {
        MachineRemoval::Written(receipt) => assert!(
            receipt.landing.held().is_none(),
            "FIXTURE: the removal stands on the host"
        ),
        MachineRemoval::LastDeviceKey(remaining) => {
            panic!("FIXTURE: the machine holds no owner key: {remaining:?}")
        }
    }
}

/// The host counts `count` facts of `machine` that arrived after its removal, and the
/// machine's answer says so in the ruled words.
fn assert_host_counts(host: &Host, machine: &Machine, count: u64, words: Option<&str>) {
    let counted = host
        .vault
        .task_facts_not_counted_after_removal(machine.id)
        .expect("the host counts the machine's facts");
    assert_eq!(
        counted, count,
        "the facts of the machine that arrived after its removal"
    );
    assert_eq!(task_facts_not_counted_text(counted).as_deref(), words);
}

#[test]
fn a_cancel_the_removed_machine_signs_after_its_removal_does_not_count() {
    let host = host();
    let before = owner_task(&host.vault, host.owner, "cancelled before the removal");
    let after = owner_task(&host.vault, host.owner, "cancelled after the removal");
    let machine = enrolled_machine(&host);
    let early = machine.cancel(&host, before);
    machine.deliver(&host, early, before);
    assert!(
        cancelled(&host.vault, before),
        "FIXTURE: the machine's cancel counts on the host while the machine stands"
    );
    assert_host_counts(&host, &machine, 0, None);

    remove(&host, &machine);
    assert!(
        cancelled(&host.vault, before),
        "a removal does not unmake the cancel the machine carried before it"
    );
    let late = machine.cancel(&host, after);
    machine.deliver(&host, late, after);
    assert!(
        !cancelled(&host.vault, after),
        "a cancel the removed machine signs after its removal does not count"
    );
    assert_host_counts(
        &host,
        &machine,
        1,
        Some("1 fact from this machine arrived after its removal and was not counted"),
    );
}

#[test]
fn cancels_the_removal_never_saw_do_not_count_and_the_host_counts_them() {
    let host = host();
    let first = owner_task(&host.vault, host.owner, "the first task");
    let second = owner_task(&host.vault, host.owner, "the second task");
    let machine = enrolled_machine(&host);
    let unseen = [
        (machine.cancel(&host, first), first),
        (machine.cancel(&host, second), second),
    ];

    remove(&host, &machine);
    for (fact, task) in unseen {
        machine.deliver(&host, fact, task);
        assert!(
            !cancelled(&host.vault, task),
            "a cancel the removal never saw does not count, though the machine signed it before"
        );
    }
    assert_host_counts(
        &host,
        &machine,
        2,
        Some("2 facts from this machine arrived after its removal and were not counted"),
    );
}
