//! [KIT-ACTIVATION-DOORS-READY-THIS-INSTALLS-SIGNING-KEYS-BEFORE-THE-CONFIRM]
//! A declined confirm at each kit activation door and the restored join
//! leaves this install's machine unchanged, even with an empty keystore.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test owner_presence_before_install_signing`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{
    ActAuthority, ActSurface, HostSlipIssuer, MachineOwnership, MachineRole, RootChange,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{OwnerPresenceRefusal, RecordError};
use oneiron::recovery::{CodeKeeping, KitIssue, PassphraseCost, PieceHome};
use oneiron::store::{GateDecisionId, ports::ManualClock};
use oneiron::test_support::{
    bind_host_owner, provision_engine_machines, restore_tempdir, test_host_issuer,
};
use oneiron::world_keys::{PreparedRoot, RootMaterial, RootWorkDone};
use oneiron::{EntityId, Error, Vault, VaultConfig};
use oneiron_keystore::{
    ManualPresenceClock, MemoryKeystore, PresenceError, PresenceGate, PresenceWindow,
    ScriptedPresence,
};

/// A rooted self-hosted vault with a live serving profile and an authenticated owner.
struct ServedVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    keystore: Arc<MemoryKeystore>,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    /// Opens and profiles the serving install under the test host root.
    fn self_host(clock: &Arc<ManualClock>, role: MachineRole) -> Self {
        let (vault, dir) = open_vault(clock);
        let keystore = Arc::new(MemoryKeystore::default());
        vault.install_device_keystore(keystore.clone());
        let issuer = provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, role)
            .expect("this install's machine profile under the host root");
        let person = vault.ensure_embedded_owner_actor().expect("the owner");
        bind_host_owner(&vault, &issuer, person).expect("the owner's host binding");
        let owner = owner_proof(&vault, person);
        Self {
            vault,
            issuer,
            owner,
            keystore,
            _dir: dir,
        }
    }
}

/// The device configuration, with a fixed clock and a shared ID sequence for related installs.
fn device_config(clock: &Arc<ManualClock>) -> VaultConfig {
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    config
}

/// Opens a fresh self-hosted vault and keeps its directory alive.
fn open_vault(clock: &Arc<ManualClock>) -> (Vault, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let vault = Vault::open(dir.path(), device_config(clock)).expect("vault");
    (vault, dir)
}

/// Authenticates the owner on this install without a bound credential.
fn owner_proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(
            person,
            &person.to_hex(),
            true,
            GateDecisionId::from_bytes([2; 16]),
        )
        .expect("the owner's proof")
}

/// Enrols and holds this install's own owner signing key as a predecessor.
fn enrol_owner_key(vault: &Vault, owner: &AuthenticatedOwner, issuer: &HostSlipIssuer) {
    let authority = ActAuthority::Owner(owner.clone(), ActSurface::ThisInstall);
    vault
        .enrol_device_owner_signing_key(&authority, issuer)
        .expect("this install holds its enrolled owner signing key");
}

/// A serving install with a held predecessor and a root prepared but not activated.
fn prepared_activation() -> (ServedVault, PreparedRoot) {
    let served = ServedVault::self_host(&ManualClock::new(1_790_000_000), MachineRole::Unanswered);
    enrol_owner_key(&served.vault, &served.owner, &served.issuer);
    let prepared = served
        .vault
        .prepare_owner_root(&served.owner)
        .expect("a prepared root");
    (served, prepared)
}

/// The kit places all three pieces away from this install's keystore.
fn kit_issue(vault_id: [u8; 32]) -> KitIssue<'static> {
    KitIssue {
        vault_id,
        homes: [
            PieceHome::RecoveryCode(CodeKeeping::Paper),
            PieceHome::TrustedPerson,
            PieceHome::SecurityKey,
        ],
        passphrase: None,
        cost: PassphraseCost::FLOOR,
        only_machine: false,
    }
}

/// This install's machine under the keystore that is on the handle now.
fn machine(vault: &Vault) -> EntityId {
    vault
        .prepare_install_signing()
        .expect("this install's machine")
}

/// Drops the loaded install signing keys and leaves no seed in their slot.
fn install_empty_keystore(vault: &Vault) {
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
}

/// Reads the machine by readying the keys after its own keystore is back on the handle.
fn machine_under_own_keystore(vault: &Vault, keystore: &Arc<MemoryKeystore>) -> EntityId {
    vault.install_device_keystore(keystore.clone());
    machine(vault)
}

/// Puts a fresh prompt gate on the handle and returns the device that counts prompts.
fn scripted_gate(
    vault: &Vault,
    answers: impl IntoIterator<Item = Result<(), PresenceError>>,
) -> Arc<ScriptedPresence> {
    let presence = Arc::new(ScriptedPresence::new(answers));
    let window = PresenceWindow::new(ManualPresenceClock::new(1_000_000, 1_000_000));
    let gate = PresenceGate::new(presence.clone(), window);
    vault.install_presence_gate(Arc::new(gate));
    presence
}

/// Asserts that the door returned the refusal from the declined prompt.
fn assert_declined<T: std::fmt::Debug>(refused: &oneiron::Result<T>, what: &str) {
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a declined confirm refuses {what}: {refused:?}"
    );
}

/// A declined root activation does not replace the machine.
#[test]
fn a_declined_confirm_at_the_root_activation_leaves_this_installs_machine_unchanged() {
    let (served, prepared) = prepared_activation();
    let before = machine(&served.vault);
    install_empty_keystore(&served.vault);
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let refused = served
        .vault
        .activate_owner_root(&served.owner, prepared, &BTreeSet::new());
    assert_declined(&refused, "root activation");
    assert_eq!(
        presence.prompts(),
        1,
        "root activation did not prompt exactly once"
    );
    assert_eq!(
        machine_under_own_keystore(&served.vault, &served.keystore),
        before,
        "root activation readied signing keys and replaced the machine before confirmation"
    );
}

/// A declined confirm of a pending kit does not replace the machine.
#[test]
fn a_declined_confirm_at_the_kit_confirm_leaves_this_installs_machine_unchanged() {
    let served = ServedVault::self_host(&ManualClock::new(1_790_000_000), MachineRole::Unanswered);
    enrol_owner_key(&served.vault, &served.owner, &served.issuer);
    let vault_id = served
        .vault
        .authority_vault_id()
        .expect("the vault's authority")
        .expect("the vault is rooted");
    let kit = served
        .vault
        .issue_world_kit(&served.owner, &kit_issue(vault_id))
        .expect("a pending world kit");
    let pieces: Vec<_> = kit.pieces.iter().take(2).collect();
    let before = machine(&served.vault);
    install_empty_keystore(&served.vault);
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let refused = served
        .vault
        .confirm_world_kit(&served.owner, &pieces, None, &BTreeSet::new());
    assert_declined(&refused, "world kit confirmation");
    assert_eq!(
        presence.prompts(),
        1,
        "world kit confirmation did not prompt exactly once"
    );
    assert_eq!(
        machine_under_own_keystore(&served.vault, &served.keystore),
        before,
        "world kit confirmation readied signing keys and replaced the machine before confirmation"
    );
}

/// A declined kit confirm on the target of a root request does not replace its machine.
#[test]
fn a_declined_confirm_at_the_kit_confirm_of_a_root_request_leaves_this_installs_machine_unchanged()
{
    let clock = ManualClock::new(1_790_000_000);
    let recorder = ServedVault::self_host(&clock, MachineRole::HostedNode);
    enrol_owner_key(&recorder.vault, &recorder.owner, &recorder.issuer);
    let vault_id = recorder
        .vault
        .authority_vault_id()
        .expect("the vault's authority")
        .expect("the vault is rooted");

    let (target, _target_dir) = open_vault(&clock);
    let keystore = Arc::new(MemoryKeystore::default());
    target.install_device_keystore(keystore.clone());
    let key = target
        .machine_encryption_key(vault_id)
        .expect("the target's encryption key");
    let enrolment = target
        .machine_enrolment_request(vault_id, key)
        .expect("the target's enrolment request");
    recorder
        .vault
        .enroll_machine(
            &recorder.owner,
            ActSurface::HostedConsole,
            &enrolment,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("the recorder links the target");
    let receipt = recorder
        .vault
        .request_root_change(
            &recorder.owner,
            ActSurface::HostedConsole,
            enrolment.machine,
            RootChange::Activate,
        )
        .expect("record a root activation request");
    let person = target
        .ensure_embedded_owner_actor()
        .expect("the owner on the target");
    let history = recorder
        .vault
        .export_signed_authority_history()
        .expect("the recorder's authority history");
    target
        .import_signed_authority_history(&history, &std::collections::BTreeMap::new())
        .expect("the target takes the request and its authority history");
    let owner = owner_proof(&target, person);
    enrol_owner_key(&target, &owner, &recorder.issuer);
    let authority = ActAuthority::Owner(owner.clone(), ActSurface::ThisInstall);
    let request = target
        .pending_root_requests(&owner)
        .expect("the target's pending root requests")
        .into_iter()
        .find_map(|(hash, change, pending)| {
            (matches!(change, RootChange::Activate) && pending.request == receipt.request)
                .then_some(hash)
        })
        .expect("the recorded activation request is pending on this target");
    let issued = target
        .run_root_request_as(
            &authority,
            request,
            RootMaterial::IssueKit(&kit_issue(vault_id)),
        )
        .expect("issue the kit for this root request");
    let RootWorkDone::KitIssued(kit) = issued else {
        panic!("the root request did not issue a pending kit: {issued:?}");
    };
    let pieces: Vec<_> = kit.pieces.iter().take(2).collect();
    let before = machine(&target);
    install_empty_keystore(&target);
    let presence = scripted_gate(&target, [Err(PresenceError::Declined)]);
    let refused = target.run_root_request_as(
        &authority,
        request,
        RootMaterial::ConfirmKit {
            pieces: &pieces,
            passphrase: None,
            carry: &BTreeSet::new(),
        },
    );
    assert_declined(&refused, "kit confirmation of a root request");
    assert_eq!(
        presence.prompts(),
        1,
        "the root request's kit confirmation did not prompt exactly once"
    );
    assert_eq!(
        machine_under_own_keystore(&target, &keystore),
        before,
        "the root request's kit confirmation readied signing keys and replaced the machine before confirmation"
    );
}

/// A declined join of a restored copy does not replace the copy's machine.
#[test]
fn a_declined_confirm_at_the_restored_join_leaves_this_installs_machine_unchanged() {
    let clock = ManualClock::new(1_790_000_000);
    let host = ServedVault::self_host(&clock, MachineRole::Unanswered);
    host.vault
        .ensure_vault_key()
        .expect("the source vault's checkpoint needs a data key");
    let backups = restore_tempdir();
    let image = backups.path().join("image");
    host.vault
        .snapshot_checkpoint(&image, 100)
        .expect("the source vault's checkpoint");
    let key = host.vault.checkpoint_key().expect("the checkpoint key");
    let origin = host
        .vault
        .side_restore_source()
        .expect("the beside restore source");
    let (copy, _) = Vault::restore_checkpoint_beside(
        &image,
        &key,
        &backups.path().join("copy"),
        device_config(&clock),
        &origin,
        200,
    )
    .expect("a copy restored beside the source vault");
    let keystore = Arc::new(MemoryKeystore::default());
    copy.install_device_keystore(keystore.clone());
    let person = copy
        .ensure_embedded_owner_actor()
        .expect("the owner on the copy");
    let proof = owner_proof(&copy, person);
    let issuer = host.issuer;
    drop(host.vault);
    copy.hold_checkpoint_root_signer(Arc::new(test_host_issuer()));

    let before = machine(&copy);
    install_empty_keystore(&copy);
    let presence = scripted_gate(&copy, [Err(PresenceError::Declined)]);
    let refused = copy.join_restored_install(&issuer, &proof, MachineRole::Unanswered);
    assert_declined(&refused, "restored install join");
    assert_eq!(
        presence.prompts(),
        1,
        "the restored install join did not prompt exactly once"
    );
    assert_eq!(
        machine_under_own_keystore(&copy, &keystore),
        before,
        "the restored install join readied signing keys and replaced the machine before confirmation"
    );
}

/// Readying install signing under an empty keystore replaces the machine the test reads.
#[test]
fn under_an_empty_keystore_readying_the_signing_keys_forgets_this_installs_machine() {
    let (served, _prepared) = prepared_activation();
    let before = machine(&served.vault);
    install_empty_keystore(&served.vault);
    served
        .vault
        .prepare_install_signing()
        .expect("ready signing keys under the empty keystore");
    assert_ne!(
        machine_under_own_keystore(&served.vault, &served.keystore),
        before,
        "readying signing keys under an empty keystore did not replace the machine"
    );
}
