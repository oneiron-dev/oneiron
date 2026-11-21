//! Recovery preset doors check owner presence before drawing or readying signing keys,
//! and after every refusal they give with nothing held.
#![cfg(oneiron_test_support)]

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use oneiron::authority::{ActAuthority, ActSurface, EnrolledOwnerKeyKind, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{DevicePinRefusal, GateError, OwnerPresenceRefusal, RecordError, SecretError};
use oneiron::recovery::{
    CodeKeeping, KitIssue, KitPiece, KitSecretKind, PassphraseCost, PieceHome, restore_kit,
};
use oneiron::store::{GateDecisionId, ports::ManualClock};
use oneiron::test_doors::owner_key_release::release_owner_keys;
use oneiron::test_doors::recovery_box_kit_only_fact::append_recovery_box_kit_only_fact;
use oneiron::test_doors::recovery_preset_between::set_recovery_preset_any_two_with_kit_between;
use oneiron::test_support::bind_host_owner;
use oneiron::world_keys::{
    DevicePin, NoRecoveryBox, RecoveryAuthoritySigner, RecoveryBoxHold, RecoveryBoxKitOnlyFact,
    RecoveryPreset, RecoveryPresetChange,
};
use oneiron::{Error, Vault, VaultConfig};
use oneiron_keystore::{
    DeviceKeystore, KeystoreLocality, KeystoreSlot, ManualPresenceClock, MemoryKeystore,
    PresenceError, PresenceGate, PresenceWindow, ScriptedPresence, SlotKind,
};
use zeroize::Zeroizing;

const PIN: &[u8] = b"quiet harbour lantern";

/// A self-hosted vault with an owner-held data key and an enrolled device owner key.
struct Fixture {
    vault: Vault,
    owner: AuthenticatedOwner,
    keystore: Arc<MemoryKeystore>,
    authority_vault_id: [u8; 32],
    pieces: Vec<KitPiece>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new(activate_kit: bool) -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.store_clock = ManualClock::new(1_790_000_000).bundle();
        let vault = Vault::open(dir.path(), config).expect("vault");
        let keystore = Arc::new(MemoryKeystore::default());
        vault.install_device_keystore(keystore.clone());
        let issuer = vault.bootstrap_host_slip_issuer().expect("the host seed");
        vault.ensure_host_root_slip(&issuer).expect("the host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machines");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::HostedNode)
            .expect("this install's live machine profile");
        let actor = vault.ensure_embedded_owner_actor().expect("the owner");
        bind_host_owner(&vault, &issuer, actor).expect("the owner's binding");
        let owner = vault
            .authenticate_owner(
                actor,
                &actor.to_hex(),
                true,
                GateDecisionId::from_bytes([2; 16]),
            )
            .expect("authenticated owner");
        vault.ensure_vault_key().expect("the data key");
        let authority_vault_id = vault
            .authority_vault_id()
            .expect("read authority id")
            .expect("rooted vault");
        let mut fixture = Self {
            vault,
            owner,
            keystore,
            authority_vault_id,
            pieces: Vec::new(),
            _dir: dir,
        };
        if activate_kit {
            fixture.pieces = fixture
                .vault
                .issue_world_kit(&fixture.owner, &kit_issue(authority_vault_id))
                .expect("issue the world kit")
                .pieces;
            fixture
                .vault
                .confirm_world_kit(&fixture.owner, &fixture.kit_refs(), None, &BTreeSet::new())
                .expect("activate the world kit");
        }
        // The device key is the only held signer, so a closed PIN window passes over it.
        release_owner_keys(&fixture.vault);
        fixture
            .vault
            .enrol_device_owner_signing_key(&fixture.authority(), &issuer)
            .expect("enrol and hold this install's owner signing key");
        fixture
    }

    fn authority(&self) -> ActAuthority {
        ActAuthority::Owner(self.owner.clone(), ActSurface::ThisInstall)
    }

    fn kit_refs(&self) -> Vec<&KitPiece> {
        self.pieces.iter().take(2).collect()
    }

    fn preset(&self) -> RecoveryPreset {
        self.vault.recovery_preset().expect("read the preset")
    }

    fn fact(&self) -> Option<RecoveryBoxKitOnlyFact> {
        self.vault
            .recovery_box_kit_only_fact()
            .expect("read the fact")
    }

    fn history(&self) -> Vec<Vec<u8>> {
        self.vault
            .export_signed_authority_history()
            .expect("signed history")
    }

    fn live_recovery_keys(&self) -> Vec<[u8; 32]> {
        self.vault
            .enrolled_owner_keys()
            .expect("read owner keys")
            .into_iter()
            .filter(|key| key.kind == EnrolledOwnerKeyKind::RecoveryAuthority && key.live)
            .map(|key| key.public_key)
            .collect()
    }

    fn assert_live_generation(&self, generation: u32) {
        let secret = restore_kit(
            self.authority_vault_id,
            KitSecretKind::RecoveryRoot,
            &self.kit_refs(),
            None,
        )
        .expect("restore the world kit");
        let signer = RecoveryAuthoritySigner::from_restored_kit(
            secret,
            &self.authority_vault_id,
            generation,
        )
        .expect("derive the recovery authority key");
        assert_eq!(self.live_recovery_keys(), [signer.public_key()]);
    }

    fn switch_with_kit(&self, hold: &dyn RecoveryBoxHold) -> oneiron::Result<RecoveryPresetChange> {
        self.vault.set_recovery_preset_with_kit_as(
            &self.authority(),
            RecoveryPreset::NobodyButMe,
            &self.kit_refs(),
            None,
            |_| Ok(()),
            hold,
        )
    }

    fn switch(
        &self,
        preset: RecoveryPreset,
        hold: &dyn RecoveryBoxHold,
    ) -> oneiron::Result<RecoveryPresetChange> {
        self.vault
            .set_recovery_preset_as(&self.owner, preset, |_| Ok(()), hold)
    }

    fn set_pin(&self) -> Arc<DevicePin> {
        let pin = DevicePin::with_clock_and_cost(
            self.keystore.clone(),
            ManualPresenceClock::new(1_000_000, 1_000_000),
            PassphraseCost::FLOOR,
        )
        .expect("device PIN over this install's keystore");
        self.vault
            .install_device_pin(pin.clone())
            .expect("install the device PIN");
        self.vault
            .set_device_pin_as(&self.authority(), PIN, false)
            .expect("set the PIN as the owner");
        pin
    }
}

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

fn scripted_gate(
    vault: &Vault,
    answers: impl IntoIterator<Item = Result<(), PresenceError>>,
) -> Arc<ScriptedPresence> {
    let presence = Arc::new(ScriptedPresence::new(answers));
    let window = PresenceWindow::new(ManualPresenceClock::new(1_000_000, 1_000_000));
    vault.install_presence_gate(Arc::new(PresenceGate::new(presence.clone(), window)));
    presence
}

#[derive(Default)]
struct RecordingBoxHold(RefCell<Vec<bool>>);

impl RecoveryBoxHold for RecordingBoxHold {
    fn hold_kit_only(&self, kit_only: bool) -> oneiron::Result<()> {
        self.0.borrow_mut().push(kit_only);
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SwitchState {
    preset: RecoveryPreset,
    live_keys: Vec<[u8; 32]>,
    history: Vec<Vec<u8>>,
}

impl SwitchState {
    fn read(fixture: &Fixture) -> Self {
        Self {
            preset: fixture.preset(),
            live_keys: fixture.live_recovery_keys(),
            history: fixture.history(),
        }
    }

    fn assert_unchanged(&self, fixture: &Fixture, hold: &RecordingBoxHold) {
        assert_eq!(&Self::read(fixture), self);
        assert!(
            fixture
                .vault
                .recovery_box_hold_pending()
                .expect("read pending hold")
                .is_none()
        );
        assert!(hold.0.borrow().is_empty(), "there was no box-hold call");
    }
}

fn assert_declined<T: std::fmt::Debug>(answer: &oneiron::Result<T>) {
    assert!(
        matches!(
            answer,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined
            }))
        ),
        "expected a declined confirm, got {answer:?}"
    );
}

fn assert_another_vaults_proof<T: std::fmt::Debug>(answer: &oneiron::Result<T>) {
    assert!(
        matches!(
            answer,
            Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(_)))
        ),
        "expected another vault's owner proof to be refused, got {answer:?}"
    );
}

fn assert_pin_required(answer: &oneiron::Result<RecoveryPresetChange>) {
    assert!(
        matches!(
            answer,
            Err(Error::Secret(SecretError::DevicePin(
                DevicePinRefusal::Required
            )))
        ),
        "expected the device PIN to be required, got {answer:?}"
    );
}

/// Rotation and the signed kit-only fact share one prompt.
#[test]
fn a_kit_switch_that_rotates_asks_once() {
    let fixture = Fixture::new(true);
    fixture.assert_live_generation(0);
    let presence = scripted_gate(&fixture.vault, [Ok(())]);
    let change = fixture
        .switch_with_kit(&NoRecoveryBox)
        .expect("the confirmed switch");
    assert_eq!(change.previous, RecoveryPreset::Standard);
    assert_eq!(change.preset, RecoveryPreset::NobodyButMe);
    assert_eq!(presence.prompts(), 1);
    fixture.assert_live_generation(1);
    assert!(fixture.fact().expect("the signed kit-only fact").kit_only);
}

/// A declined confirm ends the rotating switch before any effect.
#[test]
fn a_declined_confirm_refuses_a_rotating_switch_and_stores_nothing() {
    let fixture = Fixture::new(true);
    fixture.assert_live_generation(0);
    let presence = scripted_gate(&fixture.vault, [Err(PresenceError::Declined)]);
    let before = SwitchState::read(&fixture);
    let hold = RecordingBoxHold::default();
    assert_declined(&fixture.switch_with_kit(&hold));
    assert_eq!(presence.prompts(), 1);
    before.assert_unchanged(&fixture, &hold);
}

/// A rotating switch asks even when this handle holds no proving owner key.
#[test]
fn a_switch_on_an_install_no_owner_key_proves_on_is_asked() {
    let fixture = Fixture::new(true);
    release_owner_keys(&fixture.vault);
    fixture.assert_live_generation(0);
    let presence = scripted_gate(&fixture.vault, [Err(PresenceError::Declined)]);
    let before = SwitchState::read(&fixture);
    let hold = RecordingBoxHold::default();
    assert_declined(&fixture.switch_with_kit(&hold));
    assert_eq!(presence.prompts(), 1);
    before.assert_unchanged(&fixture, &hold);
}

/// The closed PIN window blocks both fact directions and a rotation, and the right PIN permits them.
#[test]
fn a_switch_on_a_device_whose_pin_window_ended_answers_pin_required() {
    let fixture = Fixture::new(false);
    assert!(fixture.live_recovery_keys().is_empty());
    let pin = fixture.set_pin();
    let presence = scripted_gate(&fixture.vault, []);
    for (target, kit_only) in [
        (RecoveryPreset::NobodyButMe, true),
        (RecoveryPreset::Standard, false),
    ] {
        pin.end_window();
        let before = SwitchState::read(&fixture);
        let hold = RecordingBoxHold::default();
        assert_pin_required(&fixture.switch(target, &hold));
        before.assert_unchanged(&fixture, &hold);
        fixture
            .vault
            .confirm_device_pin(PIN)
            .expect("the right PIN opens the window");
        let change = fixture
            .switch(target, &hold)
            .expect("the switch in the PIN window");
        assert_eq!(change.preset, target);
        assert_eq!(
            fixture.fact().expect("signed in the PIN window").kit_only,
            kit_only
        );
    }
    assert_eq!(
        presence.prompts(),
        0,
        "the PIN takes precedence over the platform prompt"
    );

    let fixture = Fixture::new(true);
    let pin = fixture.set_pin();
    pin.end_window();
    fixture.assert_live_generation(0);
    let before = SwitchState::read(&fixture);
    let hold = RecordingBoxHold::default();
    assert_pin_required(&fixture.switch_with_kit(&hold));
    before.assert_unchanged(&fixture, &hold);
    fixture
        .vault
        .confirm_device_pin(PIN)
        .expect("the right PIN opens the window");
    fixture
        .switch_with_kit(&hold)
        .expect("the rotation in the PIN window");
    fixture.assert_live_generation(1);
    assert!(fixture.fact().expect("the signed kit-only fact").kit_only);
}

/// Repeating the same settled kit-only preset needs no new prompt outside the window.
#[test]
fn a_switch_that_changes_no_fact_and_rotates_nothing_asks_nothing() {
    let fixture = Fixture::new(true);
    let presence = scripted_gate(&fixture.vault, [Ok(())]);
    fixture
        .switch_with_kit(&NoRecoveryBox)
        .expect("the confirmed switch");
    assert_eq!(presence.prompts(), 1);
    let fact = fixture.fact().expect("the signed kit-only fact");
    fixture
        .vault
        .presence_gate()
        .expect("the installed gate")
        .end_window();
    let same = fixture
        .switch_with_kit(&NoRecoveryBox)
        .expect("the repeated preset stands");
    assert_eq!(presence.prompts(), 1);
    assert_eq!(same.previous, RecoveryPreset::NobodyButMe);
    assert_eq!(same.preset, same.previous);
    assert!(same.sheet.is_none());
    assert_eq!(fixture.fact(), Some(fact));
    fixture.assert_live_generation(1);
}

/// Each any-two rotating attempt prompts once, and only the confirmed attempt makes changes.
#[test]
fn the_any_two_kit_switch_that_rotates_asks_once() {
    let fixture = Fixture::new(true);
    fixture.assert_live_generation(0);
    let presence = scripted_gate(&fixture.vault, [Err(PresenceError::Declined), Ok(())]);
    let before = SwitchState::read(&fixture);
    let hold = RecordingBoxHold::default();
    let issue = kit_issue(fixture.vault.vault_key_vault_id());
    let switch = || {
        fixture.vault.set_recovery_preset_any_two_with_kit_as(
            &fixture.authority(),
            &issue,
            None,
            &fixture.kit_refs(),
            None,
            |_| Ok(()),
            &hold,
        )
    };
    assert_declined(&switch());
    assert_eq!(presence.prompts(), 1);
    before.assert_unchanged(&fixture, &hold);
    let change = switch().expect("the confirmed any-two switch");
    assert_eq!(presence.prompts(), 2);
    assert_eq!(change.change.preset, RecoveryPreset::NobodyButMeAnyTwo);
    fixture.assert_live_generation(1);
    assert!(fixture.fact().expect("the signed kit-only fact").kit_only);
}

/// A concurrent switch back to Standard cannot turn an unasked any-two switch into a rotation.
/// The switch back signs no fact here, so the fact in force never moves and only the rotation
/// is left unasked.
#[test]
fn a_switch_that_would_rotate_unasked_is_a_conflict() {
    let fixture = Fixture::new(true);
    let presence = scripted_gate(&fixture.vault, [Ok(()), Ok(())]);
    fixture
        .switch_with_kit(&NoRecoveryBox)
        .expect("the first rotation");
    fixture.assert_live_generation(1);
    assert!(fixture.fact().expect("the signed kit-only fact").kit_only);
    fixture
        .vault
        .presence_gate()
        .expect("the installed gate")
        .end_window();
    let issue = kit_issue(fixture.vault.vault_key_vault_id());
    let answer = set_recovery_preset_any_two_with_kit_between(
        &fixture.vault,
        &fixture.authority(),
        &issue,
        None,
        &fixture.kit_refs(),
        None,
        |_| Ok(()),
        &NoRecoveryBox,
        || {
            assert_eq!(presence.prompts(), 1, "the outer door did not prompt");
            release_owner_keys(&fixture.vault);
            fixture
                .switch(RecoveryPreset::Standard, &NoRecoveryBox)
                .expect("the concurrent switch back");
            assert_eq!(presence.prompts(), 2, "only the switch back prompted again");
            assert!(
                fixture.fact().expect("the fact in force").kit_only,
                "with no proving key the switch back signed no fact"
            );
        },
    );
    assert!(
        matches!(answer, Err(Error::ConcurrentWrite(_))),
        "expected a conflict, got {answer:?}"
    );
    fixture.assert_live_generation(1);
    assert_eq!(fixture.preset(), RecoveryPreset::Standard);
}

/// A kit-only fact switched off after the door's read cannot be switched on again unasked.
/// No rotation is in reach here: the preset never leaves kit-only.
#[test]
fn a_switch_that_would_change_the_fact_unasked_is_a_conflict() {
    let fixture = Fixture::new(true);
    let presence = scripted_gate(&fixture.vault, [Ok(())]);
    fixture
        .switch_with_kit(&NoRecoveryBox)
        .expect("the first rotation");
    fixture.assert_live_generation(1);
    assert!(fixture.fact().expect("the signed kit-only fact").kit_only);
    fixture
        .vault
        .presence_gate()
        .expect("the installed gate")
        .end_window();
    let issue = kit_issue(fixture.vault.vault_key_vault_id());
    let answer = set_recovery_preset_any_two_with_kit_between(
        &fixture.vault,
        &fixture.authority(),
        &issue,
        None,
        &fixture.kit_refs(),
        None,
        |_| Ok(()),
        &NoRecoveryBox,
        || {
            append_recovery_box_kit_only_fact(&fixture.vault, &fixture.owner, false)
                .expect("the fact is switched off after the outer door's read");
        },
    );
    assert!(
        matches!(answer, Err(Error::ConcurrentWrite(_))),
        "expected a conflict, got {answer:?}"
    );
    assert_eq!(presence.prompts(), 1, "the outer door did not prompt");
    assert!(!fixture.fact().expect("the fact signed in between").kit_only);
    assert_eq!(fixture.preset(), RecoveryPreset::NobodyButMe);
    fixture.assert_live_generation(1);
}

/// An owner proof of another vault is refused on the door's read and never raises the prompt.
#[test]
fn an_owner_proof_of_another_vault_never_raises_the_prompt() {
    let served = Fixture::new(true);
    let other = Fixture::new(false);
    let foreign = other.authority();
    let presence = scripted_gate(&served.vault, []);
    let before = SwitchState::read(&served);
    let hold = RecordingBoxHold::default();
    let sheet_door = served.vault.set_recovery_preset_with_kit_as(
        &foreign,
        RecoveryPreset::NobodyButMe,
        &served.kit_refs(),
        None,
        |_| Ok(()),
        &hold,
    );
    assert_another_vaults_proof(&sheet_door);
    let issue = kit_issue(served.vault.vault_key_vault_id());
    let any_two_door = served.vault.set_recovery_preset_any_two_with_kit_as(
        &foreign,
        &issue,
        None,
        &served.kit_refs(),
        None,
        |_| Ok(()),
        &hold,
    );
    assert_another_vaults_proof(&any_two_door);
    assert_eq!(presence.prompts(), 0, "neither door showed a prompt");
    before.assert_unchanged(&served, &hold);
}

/// A switch the sheet door refuses of its own is refused before the ask.
#[test]
fn a_switch_the_sheet_door_refuses_raises_no_prompt() {
    let fixture = Fixture::new(false);
    let presence = scripted_gate(&fixture.vault, []);
    let before = SwitchState::read(&fixture);
    let hold = RecordingBoxHold::default();
    let refusal = fixture
        .switch(RecoveryPreset::NobodyButMeAnyTwo, &hold)
        .expect_err("\"any 2 pieces\" is turned on with its kit");
    assert!(refusal.to_string().contains("issues the kit"), "{refusal}");
    assert_eq!(presence.prompts(), 0, "the door showed no prompt");
    before.assert_unchanged(&fixture, &hold);
}

/// A kit-only fact that already agrees does not exempt an otherwise required rotation from prompting.
#[test]
fn a_switch_that_only_rotates_is_asked() {
    let fixture = Fixture::new(true);
    fixture.assert_live_generation(0);
    let entry = append_recovery_box_kit_only_fact(&fixture.vault, &fixture.owner, true)
        .expect("sign kit-only without switching the preset");
    assert_eq!(fixture.preset(), RecoveryPreset::Standard);
    let presence = scripted_gate(&fixture.vault, [Ok(())]);
    fixture
        .switch_with_kit(&NoRecoveryBox)
        .expect("the confirmed rotation");
    assert_eq!(presence.prompts(), 1);
    fixture.assert_live_generation(1);
    assert_eq!(
        fixture.fact(),
        Some(RecoveryBoxKitOnlyFact {
            kit_only: true,
            entry
        })
    );
}

/// An empty keystore that records creation of a signing seed even if a new machine names the slot.
#[derive(Default)]
struct RecordingSigningKeystore {
    inner: MemoryKeystore,
    signing_created: AtomicBool,
}

impl DeviceKeystore for RecordingSigningKeystore {
    fn get(&self, slot: &KeystoreSlot) -> oneiron_keystore::Result<Option<Zeroizing<[u8; 32]>>> {
        self.inner.get(slot)
    }

    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> oneiron_keystore::Result<()> {
        self.inner.create(slot, secret)?;
        if slot.kind == SlotKind::DeviceSigning {
            self.signing_created.store(true, Ordering::Relaxed);
        }
        Ok(())
    }

    fn delete(&self, slot: &KeystoreSlot) -> oneiron_keystore::Result<()> {
        self.inner.delete(slot)
    }

    fn locality(&self) -> KeystoreLocality {
        self.inner.locality()
    }
}

/// Declining either answered switch leaves this install's machine and empty signing slot alone.
#[test]
fn a_declined_confirm_at_an_answered_switch_leaves_this_installs_machine_unchanged() {
    let observations = [false, true].map(|with_kit| {
        let fixture = Fixture::new(with_kit);
        let before = fixture
            .vault
            .prepare_install_signing()
            .expect("this install's machine");
        let empty = Arc::new(RecordingSigningKeystore::default());
        fixture.vault.install_device_keystore(empty.clone());
        let presence = scripted_gate(&fixture.vault, [Err(PresenceError::Declined)]);
        let answer = if with_kit {
            fixture.vault.set_recovery_preset_answered_with_kit_as(
                &fixture.authority(),
                RecoveryPreset::NobodyButMe,
                &fixture.kit_refs(),
                None,
                &NoRecoveryBox,
            )
        } else {
            fixture.vault.set_recovery_preset_answered_as(
                &fixture.owner,
                RecoveryPreset::NobodyButMe,
                &NoRecoveryBox,
            )
        };
        fixture
            .vault
            .install_device_keystore(fixture.keystore.clone());
        let after = fixture
            .vault
            .prepare_install_signing()
            .expect("machine under the original keystore");
        (
            with_kit,
            answer,
            presence.prompts(),
            before,
            after,
            empty.signing_created.load(Ordering::Relaxed),
        )
    });
    for (with_kit, answer, prompts, before, after, signing_created) in observations {
        assert_declined(&answer);
        assert_eq!(prompts, 1, "with kit: {with_kit}");
        assert_eq!(after, before, "with kit: {with_kit}");
        assert!(
            !signing_created,
            "a signing seed was created; with kit: {with_kit}"
        );
    }
}
