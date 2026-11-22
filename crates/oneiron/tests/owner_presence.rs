//! The vault's owner presence check on its public paths, without a platform prompt.
#![cfg(feature = "test-support")]

use std::sync::Arc;

use oneiron::authority::{ActAuthority, ActSurface, MachineRole};
use oneiron::error::{DevicePinRefusal, OwnerPresenceRefusal, RecordError, SecretError};
use oneiron::memory::MemoryError;
use oneiron::recovery::PassphraseCost;
use oneiron::store::GateDecisionId;
use oneiron::test_support::provision_engine_machines;
use oneiron::world_keys::{DevicePin, OwnerActImportance, OwnerPresenceBasis};
use oneiron::{Error, ErrorKind, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_keystore::{
    ManualPresenceClock, MemoryKeystore, NoPromptPresence, PresenceError, PresenceGate,
    PresenceWindow, ScriptedPresence,
};
use oneiron_store::ports::manual_clock::ManualClock;
use tempfile::TempDir;

const REASON: &str = "Confirm a change to your vault";
const PIN: &[u8] = b"quiet harbour lantern";

fn open_vault(posture: HostingPrivacyPosture) -> (Vault, TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.privacy.posture = posture;
    config.store_clock = ManualClock::new(1_790_000_000).bundle();
    let vault = Vault::open(dir.path(), config).expect("vault");
    (vault, dir)
}

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

struct PinDevice {
    vault: Vault,
    keystore: Arc<MemoryKeystore>,
    pin: Arc<DevicePin>,
    _dir: TempDir,
}

impl PinDevice {
    fn with_pin_set() -> Self {
        let (vault, dir) = open_vault(HostingPrivacyPosture::Hosted);
        let keystore = Arc::new(MemoryKeystore::new());
        vault.install_device_keystore(keystore.clone());
        let issuer = provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("install's machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let proof = vault
            .authenticate_owner(
                owner,
                &owner.to_hex(),
                true,
                GateDecisionId::from_bytes([1; 16]),
            )
            .expect("authenticated owner");
        let pin = DevicePin::with_clock_and_cost(
            keystore.clone(),
            ManualPresenceClock::new(1_000_000, 1_000_000),
            PassphraseCost::FLOOR,
        )
        .expect("device PIN over the vault's keystore");
        vault
            .install_device_pin(pin.clone())
            .expect("install device PIN");
        let authority = ActAuthority::Owner(proof, ActSurface::ThisInstall);
        vault
            .set_device_pin_as(&authority, PIN, false)
            .expect("set the device PIN as the owner");
        Self {
            vault,
            keystore,
            pin,
            _dir: dir,
        }
    }
}

/// An ordinary act asks no prompt and records its importance in the witness.
#[test]
fn an_ordinary_act_asks_nothing() {
    let (vault, _dir) = open_vault(HostingPrivacyPosture::SelfHostLocal);
    let presence = scripted_gate(&vault, [Ok(())]);
    let witness = vault
        .owner_presence(OwnerActImportance::Ordinary, REASON)
        .expect("presence witness");
    assert_eq!(witness.importance(), OwnerActImportance::Ordinary);
    assert_eq!(witness.basis(), OwnerPresenceBasis::NotAsked);
    assert_eq!(presence.prompts(), 0);
}

/// An important act passes its reason to the prompt, whose window serves the next act.
#[test]
fn an_important_act_prompts_once_and_a_second_act_inside_the_window_does_not() {
    let (vault, _dir) = open_vault(HostingPrivacyPosture::SelfHostLocal);
    let presence = scripted_gate(&vault, [Ok(())]);
    let first = vault
        .owner_presence(OwnerActImportance::Important, REASON)
        .expect("presence witness");
    let second = vault
        .owner_presence(OwnerActImportance::Important, "Confirm another change")
        .expect("presence witness");
    assert_eq!(first.basis(), OwnerPresenceBasis::Prompted);
    assert_eq!(second.basis(), OwnerPresenceBasis::WithinWindow);
    assert_eq!(presence.prompts(), 1);
    assert_eq!(presence.reasons(), [REASON]);
}

/// A declined prompt refuses the act and makes the next important act ask again.
#[test]
fn a_declined_prompt_refuses_and_opens_no_window() {
    let (vault, _dir) = open_vault(HostingPrivacyPosture::SelfHostLocal);
    let presence = scripted_gate(&vault, [Err(PresenceError::Declined), Ok(())]);
    assert!(matches!(
        vault.owner_presence(OwnerActImportance::Important, REASON),
        Err(Error::Record(RecordError::OwnerPresenceRequired {
            here: OwnerPresenceRefusal::Declined
        }))
    ));
    let next = vault
        .owner_presence(OwnerActImportance::Important, REASON)
        .expect("presence witness");
    assert_eq!(next.basis(), OwnerPresenceBasis::Prompted);
    assert_eq!(presence.prompts(), 2);
}

/// An unanswered prompt is a typed refusal distinct from a decline.
#[test]
fn an_unanswered_prompt_refuses() {
    let (vault, _dir) = open_vault(HostingPrivacyPosture::SelfHostLocal);
    scripted_gate(&vault, [Err(PresenceError::NoAnswer)]);
    assert!(matches!(
        vault.owner_presence(OwnerActImportance::Important, REASON),
        Err(Error::Record(RecordError::OwnerPresenceRequired {
            here: OwnerPresenceRefusal::NoAnswer
        }))
    ));
}

/// A locked screen refuses an important act inside an open window without showing a prompt.
#[test]
fn a_locked_screen_refuses_inside_an_open_window() {
    let (vault, _dir) = open_vault(HostingPrivacyPosture::SelfHostLocal);
    let presence = scripted_gate(&vault, [Ok(())]);
    let first = vault
        .owner_presence(OwnerActImportance::Important, REASON)
        .expect("presence witness");
    assert_eq!(first.basis(), OwnerPresenceBasis::Prompted);
    presence.set_screen_locked(true);
    assert!(matches!(
        vault.owner_presence(OwnerActImportance::Important, REASON),
        Err(Error::Record(RecordError::OwnerPresenceRequired {
            here: OwnerPresenceRefusal::ScreenLocked
        }))
    ));
    assert_eq!(presence.prompts(), 1);
}

/// A platform prompt failure returns PromptFailed rather than letting the act proceed.
#[test]
fn a_platform_failure_refuses_as_prompt_failed() {
    let (vault, _dir) = open_vault(HostingPrivacyPosture::SelfHostLocal);
    scripted_gate(&vault, [Err(PresenceError::Platform("test", 7))]);
    assert!(matches!(
        vault.owner_presence(OwnerActImportance::Important, REASON),
        Err(Error::Record(RecordError::OwnerPresenceRequired {
            here: OwnerPresenceRefusal::PromptFailed
        }))
    ));
}

/// A handle with no platform gate or keystore lets an important act proceed under the interim rule.
#[test]
fn a_handle_with_no_gate_lets_an_important_act_stand() {
    let (vault, _dir) = open_vault(HostingPrivacyPosture::SelfHostLocal);
    let witness = vault
        .owner_presence(OwnerActImportance::Important, REASON)
        .expect("presence witness");
    assert_eq!(witness.basis(), OwnerPresenceBasis::DeviceCannotAsk);
}

/// A gate on a device with no prompt lets an important act proceed under the interim rule.
#[test]
fn a_device_with_no_prompt_lets_an_important_act_stand() {
    let (vault, _dir) = open_vault(HostingPrivacyPosture::SelfHostLocal);
    let presence = Arc::new(NoPromptPresence::new("test device has no prompt"));
    let window = PresenceWindow::new(ManualPresenceClock::new(1_000_000, 1_000_000));
    vault.install_presence_gate(Arc::new(PresenceGate::new(presence, window)));
    let witness = vault
        .owner_presence(OwnerActImportance::Important, REASON)
        .expect("presence witness");
    assert_eq!(witness.basis(), OwnerPresenceBasis::DeviceCannotAsk);
}

/// A closed PIN window requires the PIN even when the platform could confirm the act.
#[test]
fn a_device_with_a_pin_set_asks_for_the_pin_outside_its_window() {
    let device = PinDevice::with_pin_set();
    device.pin.end_window();
    let presence = scripted_gate(&device.vault, [Ok(())]);
    assert!(matches!(
        device
            .vault
            .owner_presence(OwnerActImportance::Important, REASON),
        Err(Error::Secret(SecretError::DevicePin(
            DevicePinRefusal::Required
        )))
    ));
    assert_eq!(presence.prompts(), 0);
}

/// A right device PIN opens the window that lets an important act proceed.
#[test]
fn a_right_pin_opens_the_window_an_important_act_stands_in() {
    let device = PinDevice::with_pin_set();
    device.pin.end_window();
    device
        .vault
        .confirm_device_pin(PIN)
        .expect("the right device PIN");
    let witness = device
        .vault
        .owner_presence(OwnerActImportance::Important, REASON)
        .expect("presence witness");
    assert_eq!(witness.basis(), OwnerPresenceBasis::WithinWindow);
}

/// A stored PIN with no installed PIN handle refuses the act instead of letting it proceed.
#[test]
fn a_device_with_a_pin_set_and_no_device_pin_on_the_handle_refuses() {
    let device = PinDevice::with_pin_set();
    device
        .vault
        .install_device_keystore(device.keystore.clone());
    assert!(matches!(
        device
            .vault
            .owner_presence(OwnerActImportance::Important, REASON),
        Err(Error::Secret(SecretError::DevicePin(
            DevicePinRefusal::Unavailable(..)
        )))
    ));
}

/// A declined prompt keeps its error kind and both stable reason codes in the facade.
#[test]
fn the_refusal_carries_its_reason_codes() {
    let (vault, _dir) = open_vault(HostingPrivacyPosture::SelfHostLocal);
    scripted_gate(&vault, [Err(PresenceError::Declined)]);
    let error = vault
        .owner_presence(OwnerActImportance::Important, REASON)
        .expect_err("declined prompt");
    assert_eq!(error.kind(), ErrorKind::OwnerPresenceRequired);
    let reply = MemoryError::from(error);
    assert_eq!(reply.code, "INVALID_STATE");
    assert_eq!(
        reply.reason_codes,
        ["owner_presence_required", "here:declined"]
    );
}
