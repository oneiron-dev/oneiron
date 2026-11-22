//! The two removal doors read before they ask (row OWNER-CONFIRM-SHEET, PR 4b-3b).
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    ActAuthority, ActSurface, HostSlipIssuer, LastDeviceKeyConfirmation, MachineEnrolmentRequest,
    MachineOwnership, MachineRemoval, MachineRole, OwnerKeyEnrollment, OwnerKeyRemoval,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{DevicePinRefusal, OwnerPresenceRefusal, RecordError, SecretError};
use oneiron::recovery::{
    KitIssue, KitSecretKind, PassphraseCost, PieceHome, issue_recovery_root_kit, restore_kit,
};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::owner_key_release::release_owner_keys;
use oneiron::test_doors::owner_presence_between::{
    remove_machine_between, remove_owner_key_between,
};
use oneiron::test_support::provision_engine_machines;
use oneiron::world_keys::{DevicePin, RecoveryRootSeed};
use oneiron::{EntityId, Error, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_keystore::{
    ManualPresenceClock, MemoryKeystore, PresenceError, PresenceGate, PresenceWindow,
    ScriptedPresence,
};
use oneiron_store::ports::manual_clock::ManualClock;

/// One vault as a managed host serves it: the Hosted posture, rooted under the test host,
/// this install profiled `Unanswered`, and the embedded owner authenticated.
struct RemovalVault {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl RemovalVault {
    fn hosted() -> Self {
        Self::with_keystore(Arc::new(MemoryKeystore::default()))
    }

    fn with_keystore(keystore: Arc<MemoryKeystore>) -> Self {
        let (vault, dir) = open_vault(HostingPrivacyPosture::Hosted);
        vault.install_device_keystore(keystore);
        let issuer = provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let owner = embedded_owner(&vault)
            .expect("authenticated embedded owner")
            .1;
        Self {
            vault,
            issuer,
            owner,
            _dir: dir,
        }
    }

    /// This install's MACHINE row.
    fn install(&self) -> EntityId {
        self.vault
            .local_machine()
            .expect("read this install")
            .expect("this install is profiled")
            .id
    }

    /// The signed authority history.
    fn history(&self) -> Vec<Vec<u8>> {
        self.vault
            .export_signed_authority_history()
            .expect("the signed history")
    }

    /// The owner enrols this install's owner signing key; its public half.
    fn enrol_owner_key(&self) -> [u8; 32] {
        self.vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall),
                &self.issuer,
            )
            .expect("the owner enrols this install's owner signing key")
            .public_key
    }

    /// The owner enrols a second machine as his and a second owner key whose enrolment names
    /// it, from `second_signing_key`'s proof of possession.
    fn enrol_second_machine_and_key(
        &self,
        second_signing_key: &SigningKey,
    ) -> (EntityId, [u8; 32]) {
        let request = second_install_request(&self.vault);
        let landing = self
            .vault
            .enroll_machine(
                &self.owner,
                ActSurface::ThisInstall,
                &request,
                MachineRole::Owned(MachineOwnership::Yours),
                None,
            )
            .expect("the owner enrols the second machine");
        assert!(
            landing.held().is_none(),
            "the second machine stands with the owner's key"
        );
        let second_key = second_signing_key.verifying_key().to_bytes();
        let authority = ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall);
        let challenge = self
            .vault
            .owner_key_enrollment_challenge_as(&authority, request.machine, &second_key)
            .expect("the second key's challenge");
        let receipt = self
            .vault
            .enrol_owner_signing_key_as_host(
                &authority,
                OwnerKeyEnrollment {
                    machine: request.machine,
                    public_key: second_key,
                    proof: second_signing_key.sign(&challenge).to_bytes().to_vec(),
                },
                &self.issuer,
            )
            .expect("the owner enrols the second key on the second machine");
        assert_eq!(
            receipt.public_key, second_key,
            "the receipt names the second key"
        );
        (request.machine, second_key)
    }

    /// The owner enrols the recovery root's authority key on this install's machine, from a
    /// fresh kit.
    fn enrol_recovery_root_key(&self) -> [u8; 32] {
        let vault_id = self
            .vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("a rooted vault");
        let machine = self.install();
        let authority = ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall);
        let seed = RecoveryRootSeed::generate().expect("a root seed");
        let other_a = EntityId::from_bytes([0x51; 16]).expect("a fixed other machine");
        let other_b = EntityId::from_bytes([0x52; 16]).expect("a fixed other machine");
        let pieces = issue_recovery_root_kit(
            &KitIssue {
                vault_id,
                homes: [
                    PieceHome::ThisMachine,
                    PieceHome::OtherMachine(other_a),
                    PieceHome::OtherMachine(other_b),
                ],
                passphrase: None,
                cost: PassphraseCost::FLOOR,
                only_machine: false,
            },
            &seed.kit_bytes(),
        )
        .expect("the kit")
        .into_pieces();
        let restored = restore_kit(
            vault_id,
            KitSecretKind::RecoveryRoot,
            &[&pieces[0], &pieces[1]],
            None,
        )
        .expect("two stored pieces restore the seed");
        self.vault
            .enrol_recovery_authority_key_as_host(
                &authority,
                machine,
                &RecoveryRootSeed::from_restored_kit(restored).expect("the seed"),
                &self.issuer,
            )
            .expect("the owner enrols the root's authority key")
            .public_key
    }
}

fn open_vault(posture: HostingPrivacyPosture) -> (Vault, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.privacy.posture = posture;
    config.store_clock = ManualClock::new(1_790_000_000).bundle();
    let vault = Vault::open(dir.path(), config).expect("vault");
    (vault, dir)
}

/// A scripted device prompt on `vault`: `answers` in order, a prompt past the script
/// declined.
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

/// Another install's request to join `vault`, made by a throwaway second install over its
/// own keys.
fn second_install_request(vault: &Vault) -> MachineEnrolmentRequest {
    let vault_id = vault
        .authority_fold()
        .expect("authority fold")
        .vault_id
        .expect("the vault is rooted");
    let (install, _dir) = open_vault(HostingPrivacyPosture::SelfHostLocal);
    install.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let key = install
        .machine_encryption_key(vault_id)
        .expect("the second install's encryption key");
    install
        .machine_enrolment_request(vault_id, key)
        .expect("the second install's enrolment request")
}

/// The machine's roster role.
fn machine_role(vault: &Vault, machine: EntityId) -> MachineRole {
    vault
        .authority_fold()
        .expect("authority fold")
        .machine(machine)
        .and_then(|folded| folded.roster.as_ref())
        .expect("a roster revision names the machine")
        .profile
        .role
}

/// Whether `key` is enrolled and live.
fn key_is_live(vault: &Vault, key: [u8; 32]) -> bool {
    vault
        .enrolled_owner_keys()
        .expect("enrolled owner keys")
        .iter()
        .any(|enrolled| enrolled.public_key == key && enrolled.live)
}

fn assert_pin_required<T: std::fmt::Debug>(refused: &oneiron::Result<T>, what: &str) {
    assert!(
        matches!(
            refused,
            Err(Error::Secret(SecretError::DevicePin(
                DevicePinRefusal::Required
            )))
        ),
        "{what} answers PIN required: {refused:?}"
    );
}

/// One vault with a device PIN set, over a process-memory keystore, on a clock the test
/// moves.
struct PinDevice {
    removal: RemovalVault,
    pin: Arc<DevicePin>,
}

/// The device PIN: a passphrase, since nothing counts wrong tries but this process.
const PIN: &[u8] = b"quiet harbour lantern";

impl PinDevice {
    fn with_pin_set() -> Self {
        let keystore = Arc::new(MemoryKeystore::new());
        let removal = RemovalVault::with_keystore(Arc::clone(&keystore));
        let pin = DevicePin::with_clock_and_cost(
            keystore,
            ManualPresenceClock::new(1_000_000, 1_000_000),
            PassphraseCost::FLOOR,
        )
        .expect("device PIN over the vault's keystore");
        removal
            .vault
            .install_device_pin(pin.clone())
            .expect("install device PIN");
        let authority = ActAuthority::Owner(removal.owner.clone(), ActSurface::ThisInstall);
        removal
            .vault
            .set_device_pin_as(&authority, PIN, false)
            .expect("set the device PIN as the owner");
        Self { removal, pin }
    }
}

/// The key door asks its last-device-key question with no prompt and stores nothing.
#[test]
fn the_last_device_key_question_at_the_key_door_raises_no_prompt() {
    let removal_vault = RemovalVault::hosted();
    let first_key = removal_vault.enrol_owner_key();
    let presence = scripted_gate(&removal_vault.vault, []);
    let history = removal_vault.history();
    let asked = removal_vault
        .vault
        .remove_owner_key(
            &removal_vault.owner,
            first_key,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the door asks first");
    match asked {
        OwnerKeyRemoval::LastDeviceKey(remaining) => {
            assert_eq!(remaining.device_keys, 0, "no device key would remain");
            assert!(remaining.needs_recovery(), "a later change needs recovery");
        }
        OwnerKeyRemoval::Removed { ended, remaining } => {
            panic!("the last device key asks first: {ended:?} {remaining:?}")
        }
    }
    assert_eq!(presence.prompts(), 0, "the question shows no prompt");
    assert_eq!(
        removal_vault.history(),
        history,
        "the log holds the entries it held before"
    );
    assert!(
        key_is_live(&removal_vault.vault, first_key),
        "the ask stores nothing: the key stays live"
    );
}

/// The machine door asks its last-device-key question with no prompt and stores nothing.
#[test]
fn the_last_device_key_question_at_the_machine_door_raises_no_prompt() {
    let removal_vault = RemovalVault::hosted();
    let first_key = removal_vault.enrol_owner_key();
    let machine = removal_vault.install();
    let presence = scripted_gate(&removal_vault.vault, []);
    let history = removal_vault.history();
    for seen in [None, Some([9; 32])] {
        let asked = removal_vault
            .vault
            .remove_machine(
                &removal_vault.owner,
                ActSurface::ThisInstall,
                machine,
                seen,
                LastDeviceKeyConfirmation::NotGiven,
            )
            .expect("the last-device-key question comes before the seen check");
        match asked {
            MachineRemoval::LastDeviceKey(remaining) => {
                assert_eq!(remaining.device_keys, 0, "no device key would remain");
            }
            MachineRemoval::Written(receipt) => {
                panic!("the last device key asks first: {receipt:?}")
            }
        }
    }
    assert_eq!(presence.prompts(), 0, "the question shows no prompt");
    assert_eq!(
        removal_vault.history(),
        history,
        "the log holds the entries it held before"
    );
    assert!(
        key_is_live(&removal_vault.vault, first_key),
        "the ask stores nothing: the key stays live"
    );
    assert_ne!(
        machine_role(&removal_vault.vault, machine),
        MachineRole::Removed,
        "the machine still stands"
    );
}

/// A key removal the read refuses raises no prompt, and a keyless install is asked first.
#[test]
fn a_key_removal_refused_on_its_read_raises_no_prompt() {
    let removal_vault = RemovalVault::hosted();
    let first_key = removal_vault.enrol_owner_key();
    let root_key = removal_vault.enrol_recovery_root_key();
    let second_signing_key = SigningKey::from_bytes(&[72; 32]);
    let (_, second_key) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    removal_vault
        .vault
        .remove_owner_key(
            &removal_vault.owner,
            second_key,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the setup removal lands without a gate");
    assert!(!key_is_live(&removal_vault.vault, second_key));
    let unknown_key = SigningKey::from_bytes(&[0x5A; 32])
        .verifying_key()
        .to_bytes();
    let presence = scripted_gate(&removal_vault.vault, []);
    let history = removal_vault.history();
    for key in [unknown_key, root_key, second_key] {
        let refused = removal_vault.vault.remove_owner_key(
            &removal_vault.owner,
            key,
            LastDeviceKeyConfirmation::NotGiven,
        );
        assert!(
            matches!(
                refused,
                Err(Error::Record(RecordError::AuthorityRefused(_)))
            ),
            "the key is refused: {refused:?}"
        );
        assert_eq!(presence.prompts(), 0, "the refusal shows no prompt");
        assert_eq!(removal_vault.history(), history);
    }
    assert!(key_is_live(&removal_vault.vault, root_key));

    release_owner_keys(&removal_vault.vault);
    let presence = scripted_gate(&removal_vault.vault, [Ok(())]);
    let refused = removal_vault.vault.remove_owner_key(
        &removal_vault.owner,
        first_key,
        LastDeviceKeyConfirmation::Given,
    );
    assert!(
        matches!(refused, Err(Error::Record(RecordError::OwnerKeyRequired))),
        "an install that holds no owner key is asked first, then required: {refused:?}"
    );
    assert_eq!(
        presence.prompts(),
        1,
        "the door asked once before it answered"
    );
    assert_eq!(removal_vault.history(), history);
    assert!(key_is_live(&removal_vault.vault, first_key));
}

/// A machine removal the read refuses raises no prompt.
#[test]
fn a_machine_removal_refused_on_its_read_raises_no_prompt() {
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[72; 32]);
    let (machine_b, _) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    let presence = scripted_gate(&removal_vault.vault, []);
    let history = removal_vault.history();
    let refused = removal_vault.vault.remove_machine(
        &removal_vault.owner,
        ActSurface::ThisInstall,
        machine_b,
        Some([9; 32]),
        LastDeviceKeyConfirmation::NotGiven,
    );
    assert!(
        matches!(refused, Err(Error::ConcurrentWrite(_))),
        "a stale seen is a conflict: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "the conflict shows no prompt");
    assert_eq!(
        removal_vault.history(),
        history,
        "the log holds the entries it held before"
    );
    assert_ne!(
        machine_role(&removal_vault.vault, machine_b),
        MachineRole::Removed,
        "the machine still stands"
    );

    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let presence = scripted_gate(&removal_vault.vault, []);
    let history = removal_vault.history();
    let unknown = EntityId::from_bytes([9; 16]).expect("a valid unknown machine id");
    let refused = removal_vault.vault.remove_machine(
        &removal_vault.owner,
        ActSurface::ThisInstall,
        unknown,
        None,
        LastDeviceKeyConfirmation::NotGiven,
    );
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::InvalidAuthorityLogBody(_)))
        ),
        "a machine no revision names is refused: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "the refusal shows no prompt");
    assert_eq!(
        removal_vault.history(),
        history,
        "the log holds the entries it held before"
    );

    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[72; 32]);
    let (machine_b, second_key) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    let removed = removal_vault
        .vault
        .remove_machine(
            &removal_vault.owner,
            ActSurface::ThisInstall,
            machine_b,
            None,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the setup removal lands without a gate");
    assert!(
        matches!(removed, MachineRemoval::Written(_)),
        "guard: the setup removal lands: {removed:?}"
    );
    assert!(
        !key_is_live(&removal_vault.vault, second_key),
        "guard: the setup removal ended the key"
    );
    assert_eq!(
        machine_role(&removal_vault.vault, machine_b),
        MachineRole::Removed,
        "guard: the machine stands removed"
    );
    let presence = scripted_gate(&removal_vault.vault, []);
    let history = removal_vault.history();
    let refused = removal_vault.vault.remove_machine(
        &removal_vault.owner,
        ActSurface::ThisInstall,
        machine_b,
        None,
        LastDeviceKeyConfirmation::NotGiven,
    );
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::InvalidAuthorityLogBody(_)))
        ),
        "a removed machine no live key names is refused: {refused:?}"
    );
    assert_eq!(presence.prompts(), 0, "the refusal shows no prompt");
    assert_eq!(
        removal_vault.history(),
        history,
        "the log holds the entries it held before"
    );
}

/// A declined confirm refuses both removals and stores nothing.
#[test]
fn a_declined_confirm_refuses_both_removals_and_stores_nothing() {
    let removal_vault = RemovalVault::hosted();
    let first_key = removal_vault.enrol_owner_key();
    let machine = removal_vault.install();
    let history = removal_vault.history();
    let presence = scripted_gate(&removal_vault.vault, [Err(PresenceError::Declined)]);
    let refused = removal_vault.vault.remove_owner_key(
        &removal_vault.owner,
        first_key,
        LastDeviceKeyConfirmation::Given,
    );
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a declined confirm refuses the key removal: {refused:?}"
    );
    assert_eq!(presence.prompts(), 1, "the key door showed one prompt");
    assert_eq!(
        removal_vault.history(),
        history,
        "the log holds the entries it held before"
    );
    assert!(
        key_is_live(&removal_vault.vault, first_key),
        "the key stays live"
    );

    let presence = scripted_gate(&removal_vault.vault, [Err(PresenceError::Declined)]);
    let refused = removal_vault.vault.remove_machine(
        &removal_vault.owner,
        ActSurface::ThisInstall,
        machine,
        None,
        LastDeviceKeyConfirmation::Given,
    );
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "a declined confirm refuses the machine removal: {refused:?}"
    );
    assert_eq!(presence.prompts(), 1, "the machine door showed one prompt");
    assert_eq!(
        removal_vault.history(),
        history,
        "the log holds the entries it held before"
    );
    assert!(
        key_is_live(&removal_vault.vault, first_key),
        "the key stays live"
    );
    assert_ne!(
        machine_role(&removal_vault.vault, machine),
        MachineRole::Removed,
        "the machine still stands"
    );
}

/// A key that became the last on a device since the door asked gets the question.
#[test]
fn a_key_that_became_the_last_on_a_device_since_the_door_asked_gets_the_question() {
    let removal_vault = RemovalVault::hosted();
    let first_key = removal_vault.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[72; 32]);
    let (_, second_key) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    let _presence = scripted_gate(&removal_vault.vault, [Ok(()), Ok(())]);
    let mut after_between = None;
    let asked = remove_owner_key_between(
        &removal_vault.vault,
        &removal_vault.owner,
        first_key,
        LastDeviceKeyConfirmation::NotGiven,
        || {
            removal_vault
                .vault
                .remove_owner_key(
                    &removal_vault.owner,
                    second_key,
                    LastDeviceKeyConfirmation::NotGiven,
                )
                .expect("between ends the second key");
            after_between = Some(removal_vault.history());
        },
    )
    .expect("the outer call answers");
    match asked {
        OwnerKeyRemoval::LastDeviceKey(remaining) => {
            assert_eq!(remaining.device_keys, 0, "no device key would remain");
        }
        OwnerKeyRemoval::Removed { ended, remaining } => {
            panic!("the key that became the last gets the question: {ended:?} {remaining:?}")
        }
    }
    assert_eq!(
        removal_vault.history(),
        after_between.expect("the intervening removal ran"),
        "the outer removal stores nothing"
    );
    assert!(
        key_is_live(&removal_vault.vault, first_key),
        "the first key is still live"
    );
    assert!(
        !key_is_live(&removal_vault.vault, second_key),
        "between ended the second key"
    );
}

/// A machine removal whose keys changed since the door asked is a conflict.
#[test]
fn a_machine_removal_whose_keys_changed_since_the_door_asked_is_a_conflict() {
    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[72; 32]);
    let (machine_b, second_key) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    let _presence = scripted_gate(&removal_vault.vault, [Ok(()), Ok(())]);
    let mut after_between = None;
    let conflict = remove_machine_between(
        &removal_vault.vault,
        &removal_vault.owner,
        ActSurface::ThisInstall,
        machine_b,
        None,
        LastDeviceKeyConfirmation::NotGiven,
        || {
            removal_vault
                .vault
                .remove_owner_key(
                    &removal_vault.owner,
                    second_key,
                    LastDeviceKeyConfirmation::NotGiven,
                )
                .expect("between ends the machine's key");
            after_between = Some(removal_vault.history());
        },
    );
    assert!(
        matches!(
            conflict,
            Err(Error::ConcurrentWrite(
                "the owner keys this removal ends changed since the owner was asked"
            ))
        ),
        "the keys changed since the door asked: {conflict:?}"
    );
    assert_eq!(
        removal_vault.history(),
        after_between.expect("the intervening removal ran"),
        "the outer removal stores nothing"
    );
    assert_ne!(
        machine_role(&removal_vault.vault, machine_b),
        MachineRole::Removed,
        "the machine still stands"
    );
    assert!(
        !key_is_live(&removal_vault.vault, second_key),
        "between ended the key"
    );
}

/// A confirmed removal asks once and lands.
#[test]
fn a_confirmed_removal_asks_once_and_lands() {
    let removal_vault = RemovalVault::hosted();
    let first_key = removal_vault.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[72; 32]);
    let (machine_b, second_key) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    let presence = scripted_gate(&removal_vault.vault, [Ok(())]);
    let removed = removal_vault
        .vault
        .remove_owner_key(
            &removal_vault.owner,
            second_key,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the confirmed removal lands");
    match removed {
        OwnerKeyRemoval::Removed { ended, remaining } => {
            assert_eq!(
                ended.public_key, second_key,
                "the removal ends the named key"
            );
            assert_eq!(
                ended.machine, machine_b,
                "the ended key names the second machine"
            );
            assert_eq!(remaining.device_keys, 1, "one device key remains");
        }
        OwnerKeyRemoval::LastDeviceKey(remaining) => {
            panic!("another key remains, so no ask: {remaining:?}")
        }
    }
    assert_eq!(presence.prompts(), 1, "the key door showed one prompt");
    assert!(
        !key_is_live(&removal_vault.vault, second_key),
        "the key ended"
    );
    assert!(
        key_is_live(&removal_vault.vault, first_key),
        "the other key stays live"
    );

    let removal_vault = RemovalVault::hosted();
    removal_vault.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[72; 32]);
    let (machine_b, second_key) = removal_vault.enrol_second_machine_and_key(&second_signing_key);
    let presence = scripted_gate(&removal_vault.vault, [Ok(())]);
    let removed = removal_vault
        .vault
        .remove_machine(
            &removal_vault.owner,
            ActSurface::ThisInstall,
            machine_b,
            None,
            LastDeviceKeyConfirmation::NotGiven,
        )
        .expect("the confirmed removal lands");
    match removed {
        MachineRemoval::Written(receipt) => {
            assert!(
                receipt.landing.held().is_none(),
                "the removal stands with the owner's key"
            );
            assert_eq!(
                receipt.ended_keys,
                vec![second_key],
                "the removal ends the machine's key"
            );
            assert!(
                receipt.live_keys.is_empty(),
                "no key of the machine stays live"
            );
        }
        MachineRemoval::LastDeviceKey(remaining) => {
            panic!("another key remains, so no ask: {remaining:?}")
        }
    }
    assert_eq!(presence.prompts(), 1, "the machine door showed one prompt");
    assert_eq!(
        machine_role(&removal_vault.vault, machine_b),
        MachineRole::Removed,
        "the machine stands removed"
    );
    assert!(
        !key_is_live(&removal_vault.vault, second_key),
        "the key ended"
    );
}

/// A removal on a device whose PIN window ended answers PIN required.
#[test]
fn a_removal_on_a_device_whose_pin_window_ended_answers_pin_required() {
    let device = PinDevice::with_pin_set();
    let first_key = device.removal.enrol_owner_key();
    let second_signing_key = SigningKey::from_bytes(&[72; 32]);
    let (machine_b, second_key) = device
        .removal
        .enrol_second_machine_and_key(&second_signing_key);
    device.pin.end_window();
    let presence = scripted_gate(&device.removal.vault, [Ok(()), Ok(()), Ok(()), Ok(())]);
    let history = device.removal.history();
    let refused = device.removal.vault.remove_owner_key(
        &device.removal.owner,
        second_key,
        LastDeviceKeyConfirmation::NotGiven,
    );
    assert_pin_required(&refused, "the key door");
    assert_eq!(
        device.removal.history(),
        history,
        "the log holds the entries it held before"
    );
    let refused = device.removal.vault.remove_machine(
        &device.removal.owner,
        ActSurface::ThisInstall,
        machine_b,
        None,
        LastDeviceKeyConfirmation::NotGiven,
    );
    assert_pin_required(&refused, "the machine door");
    assert_eq!(
        device.removal.history(),
        history,
        "the log holds the entries it held before"
    );
    let unknown_key = SigningKey::from_bytes(&[0x5A; 32])
        .verifying_key()
        .to_bytes();
    let refused = device.removal.vault.remove_owner_key(
        &device.removal.owner,
        unknown_key,
        LastDeviceKeyConfirmation::NotGiven,
    );
    assert_pin_required(&refused, "the key door with a key no enrolment names");
    assert_eq!(
        device.removal.history(),
        history,
        "the log holds the entries it held before"
    );
    let refused = device.removal.vault.remove_machine(
        &device.removal.owner,
        ActSurface::ThisInstall,
        machine_b,
        Some([9; 32]),
        LastDeviceKeyConfirmation::NotGiven,
    );
    assert_pin_required(&refused, "the machine door with a stale seen");
    assert_eq!(
        device.removal.history(),
        history,
        "the log holds the entries it held before"
    );
    assert_eq!(presence.prompts(), 0, "the PIN answers before any prompt");
    assert!(
        key_is_live(&device.removal.vault, first_key),
        "the first key stays live"
    );
    assert!(
        key_is_live(&device.removal.vault, second_key),
        "the second key stays live"
    );
    assert_ne!(
        machine_role(&device.removal.vault, machine_b),
        MachineRole::Removed,
        "the machine still stands"
    );
}
