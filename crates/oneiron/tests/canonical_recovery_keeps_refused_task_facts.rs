//! A canonical capture carries each signed task authority fact its vault keeps refused under
//! a window TASK (its id was deleted there first), so the recovered vault judges it as the
//! source would, at each read (FIX TASK-FACT-REFUSED-PENDING-NOT-CAPTURED). Before the fix
//! the capture carried only a mark for a task whose refused fact counted at the capture; a
//! fact whose carrier's profile had not reached the source yet was dropped, and the
//! recovered vault read the task as never cancelled once that profile arrived.
//!
//! - `a_refused_cancel_counts_after_the_recovery_once_its_carrier_is_enrolled`: the owner's
//!   cancel from a machine the owner had not enrolled yet is refused on the host; the host
//!   captures the window; a device recovers it; then the machine's enrolment reaches the
//!   device. Red on the base (#9807's head c66acd41d143): the device reads the task with no
//!   refusal. Green on the head.
//! - `a_window_recovers_into_a_vault_whose_fold_already_admits_the_carrier`: the same window
//!   recovered into a device that took the enrolment first. The recovery's recapture must
//!   match the artifact (the capture marks no task by what its own fold admitted), and the
//!   task reads as a refusal at once. Red on the base (the task reads with no refusal).
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test canonical_recovery_keeps_refused_task_facts`.
#![cfg(oneiron_test_support)]
#![cfg(feature = "sync")]

use std::collections::BTreeSet;
use std::sync::Arc;

use loro::LoroDoc;
use oneiron::authority::{ActSurface, HostSlipIssuer, MachineOwnership, MachineRole};
use oneiron::recovery::{
    CanonicalSnapshot, RecoveryBudget, capture_canonical_window, recover_vault_window,
};
use oneiron::store::GateDecisionId;
use oneiron::sync::WindowKey;
use oneiron::sync::bridge::Materializer;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::task_fact_actor::{note_refused_fact, write_unjudged_fact};
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::{EdgeActorClass, EntityId, Error, TaskAuthorityFactKind, Vault, VaultConfig};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use rmpv::Value;

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

/// Another install of the owner's, holding the rows of the vault's authority history it
/// took so far.
struct Device {
    _dir: tempfile::TempDir,
    vault: Vault,
    held: BTreeSet<Vec<u8>>,
}

fn bare_device() -> Device {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the device's install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    Device {
        _dir: dir,
        vault,
        held: BTreeSet::new(),
    }
}

impl Device {
    /// Takes the rows of the host's authority history this device does not hold yet, as
    /// sync gives them.
    fn take_history(&mut self, host: &Host) {
        let new: Vec<Vec<u8>> = host
            .vault
            .export_signed_authority_history()
            .expect("the host's history")
            .into_iter()
            .filter(|row| !self.held.contains(row))
            .collect();
        self.vault
            .import_signed_authority_history(&new)
            .expect("the device takes the rows");
        self.held.extend(new);
    }
}

/// The owner enrols `device` as theirs on the host.
fn enrol(host: &Host, device: &Device) {
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
        .expect("the owner enrols the device as theirs");
}

/// A device the owner enrolled, holding the vault's history as it stands now.
fn enrolled_device(host: &Host) -> Device {
    let mut device = bare_device();
    enrol(host, &device);
    device.take_history(host);
    device
}

/// The host, its task, and the owner's cancel of it from a new machine of the owner's,
/// signed by that machine's own carrier before the owner enrolled the machine. The host
/// refused the cancel's row because its id was deleted there first; its fold has not
/// admitted the machine, so the refusal fails no read yet.
struct RefusedCancel {
    host: Host,
    machine: Device,
    task: EntityId,
}

fn refused_cancel() -> RefusedCancel {
    let host = host();
    let task = owner_task(
        &host.vault,
        host.owner,
        "a task cancelled from a new machine",
    );
    let mut machine = bare_device();
    machine.take_history(&host);
    machine
        .vault
        .prepare_install_signing()
        .expect("the machine's install signer");
    let cancel = write_unjudged_fact(
        &machine.vault,
        task,
        TaskAuthorityFactKind::Cancelled,
        host.owner,
        None,
    )
    .expect("the machine's carrier signs the owner's cancel");
    let raw = machine
        .vault
        .get_raw(&cancel)
        .expect("read the cancel")
        .expect("the machine holds its cancel");
    note_refused_fact(&host.vault, cancel, &raw[ENTITY_METADATA_HEADER_LEN..])
        .expect("the host refuses the cancel's row at its deleted id");
    assert!(
        !reads_suppressed(&host.vault, task),
        "a refused cancel whose carrier the host's fold has not admitted fails no read yet"
    );
    RefusedCancel {
        host,
        machine,
        task,
    }
}

impl RefusedCancel {
    /// The host's capture of the window holding the task's row.
    fn capture(&self) -> CanonicalSnapshot {
        let raw = self
            .host
            .vault
            .get_raw(&self.task)
            .expect("read the task")
            .expect("the host holds its task");
        let learned_at = u64::from_be_bytes(raw[17..25].try_into().expect("the header's time"));
        let doc = LoroDoc::new();
        doc.get_map("entities")
            .insert(&self.task.to_hex(), raw.as_slice())
            .expect("the window's task row");
        doc.commit();
        capture_canonical_window(
            &self.host.vault,
            WindowKey::from_timestamp(learned_at).as_str(),
            &doc,
        )
        .expect("the host captures the window")
    }

    /// The owner enrols the machine; the host's fold admits its carrier.
    fn enrol_the_machine(&self) {
        enrol(&self.host, &self.machine);
        assert!(
            reads_suppressed(&self.host.vault, self.task),
            "on the host, the refused cancel fails its task's read once its carrier is enrolled"
        );
    }
}

fn recover(device: &Device, snapshot: &CanonicalSnapshot) {
    let manifest_dir = tempfile::tempdir().expect("manifest dir");
    recover_vault_window(
        &device.vault,
        &Materializer::new(),
        manifest_dir.path().join("manifest"),
        snapshot,
        RecoveryBudget::default(),
    )
    .expect("the device recovers the window");
}

#[test]
fn a_refused_cancel_counts_after_the_recovery_once_its_carrier_is_enrolled() {
    let refused = refused_cancel();
    let snapshot = refused.capture();
    let mut device = enrolled_device(&refused.host);
    recover(&device, &snapshot);
    assert!(
        !reads_suppressed(&device.vault, refused.task),
        "before the machine's enrolment reaches the device, the cancel proves nothing there"
    );
    refused.enrol_the_machine();
    device.take_history(&refused.host);
    assert!(
        reads_suppressed(&device.vault, refused.task),
        "the recovered device keeps the refused cancel, and it counts once its carrier is \
         enrolled, as on the host"
    );
}

#[test]
fn a_window_recovers_into_a_vault_whose_fold_already_admits_the_carrier() {
    let refused = refused_cancel();
    let snapshot = refused.capture();
    refused.enrol_the_machine();
    let device = enrolled_device(&refused.host);
    recover(&device, &snapshot);
    assert!(
        reads_suppressed(&device.vault, refused.task),
        "the recovered device judges the refused cancel as the host does now"
    );
}
