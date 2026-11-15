//! The device PIN and the owner signing key it guards (row OCS-OWNER-PIN;
//! lead ruling OCS-NO-PROMPT-DEVICE = D, 15 Nov: a device with no unlock
//! prompt asks for a PIN that wraps its owner key, "so nothing running as
//! him can sign without it").
//!
//! Each test opens its own vault over a process-memory keystore, with the
//! device PIN on a clock the test moves. A keystore made with a counter
//! stands in for the hardware tier; one made without stands in for the file
//! tier, sealed at the kit's floor cost so a test's stretches stay short.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test device_pin`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use ed25519_dalek::{Signature, VerifyingKey};
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityAttestation, AuthorityKey, AuthorityTier,
    CheckpointRootSigner, DeviceAuthority, HostSlipIssuer, MachineRole, ROLE_ADMIN, ROLE_CLOUD,
    ROLE_OWNER,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{DevicePinRefusal, SecretError};
use oneiron::recovery::PassphraseCost;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::steward::recover_cloud_account_signed_by_host_root;
use oneiron::world_keys::{
    DEVICE_PIN_MIN_CHARS, DEVICE_PIN_SHORT_MIN_CHARS, DevicePin, DevicePinTier, OwnerKeyRest,
};
use oneiron::{Error, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_keystore::{
    DEVICE_PIN_WAIT_SECS, DEVICE_PIN_WRONG_TRIES, DeviceKeystore, KeystoreSlot,
    ManualPresenceClock, MemoryKeystore, PRESENCE_WINDOW_SECS, PresenceCapability, SealedBytesName,
    SlotKind,
};

/// A statement in the checkpoint attestation domain: what the owner key
/// signs for the checkpoint pass.
const STATEMENT: &[u8] = b"oneiron/authority/checkpoint-attestation/v2 device pin test";

const PIN: &[u8] = b"271828";
const OTHER_PIN: &[u8] = b"314159";
const PASSPHRASE: &[u8] = b"quiet harbour lantern";
const OTHER_PASSPHRASE: &[u8] = b"seven green bottles";

/// One vault under the Hosted posture, rooted under the test host, with
/// this install's machine profile enrolled, the embedded owner
/// authenticated, and a device PIN over the vault's keystore on a manual
/// clock. The vault drops first.
struct PinDevice {
    vault: Vault,
    issuer: HostSlipIssuer,
    proof: AuthenticatedOwner,
    keystore: Arc<MemoryKeystore>,
    pin: Arc<DevicePin>,
    clock: Arc<ManualPresenceClock>,
    _dir: tempfile::TempDir,
}

impl PinDevice {
    /// A device whose keystore hardware counts wrong PINs.
    fn hardware_counted() -> Self {
        Self::open(MemoryKeystore::with_counted_auth_bound(32, 1000))
    }

    /// A device whose PIN is a passphrase over a sealed file.
    fn passphrase() -> Self {
        Self::open(MemoryKeystore::new())
    }

    fn open(keystore: MemoryKeystore) -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        let vault = Vault::open(dir.path(), config).expect("hosted vault");
        let keystore = Arc::new(keystore);
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let (_owner, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
        let clock = ManualPresenceClock::new(1_000_000, 1_000_000);
        let pin = DevicePin::with_clock_and_cost(
            Arc::<MemoryKeystore>::clone(&keystore),
            Arc::<ManualPresenceClock>::clone(&clock),
            PassphraseCost::FLOOR,
        )
        .expect("the device PIN over the vault's keystore");
        vault
            .install_device_pin(Arc::clone(&pin))
            .expect("the device PIN goes on the handle");
        Self {
            vault,
            issuer,
            proof,
            keystore,
            pin,
            clock,
            _dir: dir,
        }
    }

    fn owner(&self) -> ActAuthority {
        ActAuthority::Owner(self.proof.clone(), ActSurface::ThisInstall)
    }

    /// The owner enrols this install's owner signing key; its public half.
    fn enrol(&self) -> [u8; 32] {
        self.vault
            .enrol_device_owner_signing_key(&self.owner(), &self.issuer)
            .expect("the owner enrols this install's owner signing key")
            .public_key
    }

    /// The owner signing key's keystore slot.
    fn owner_slot(&self) -> KeystoreSlot {
        let machine = self
            .vault
            .local_machine()
            .expect("local machine read")
            .expect("this install's machine")
            .id;
        KeystoreSlot {
            vault_id: self.vault.vault_key_vault_id(),
            install: *machine.as_bytes(),
            kind: SlotKind::OwnerSigning,
        }
    }

    /// The signer the checkpoint pass gets for `key` now, when it gets one.
    fn listed_signer(&self, key: [u8; 32]) -> Option<Arc<dyn CheckpointRootSigner>> {
        self.vault
            .checkpoint_root_signers()
            .into_iter()
            .find(|signer| signer.root() == AuthorityKey::Ed25519(key))
    }

    /// Whether the checkpoint pass gets a signer for `key` now and its
    /// signature over a checkpoint statement verifies under `key`.
    fn signs(&self, key: [u8; 32]) -> bool {
        let Some(signer) = self.listed_signer(key) else {
            return false;
        };
        let signature = signer
            .sign_checkpoint_statement(STATEMENT)
            .expect("a listed signer signs a checkpoint statement");
        verifies(key, &signature)
    }

    fn rest(&self) -> OwnerKeyRest {
        self.vault
            .device_owner_key_rest()
            .expect("the owner key's rest reads with no PIN")
    }

    /// Moves both clocks past the end of a window opened now.
    fn pass_the_window(&self) {
        self.clock.advance(PRESENCE_WINDOW_SECS * 1000 + 1);
    }
}

fn verifies(key: [u8; 32], signature: &[u8]) -> bool {
    let verifying = VerifyingKey::from_bytes(&key).expect("an Ed25519 public key");
    let signature = Signature::from_slice(signature).expect("a 64-byte signature");
    verifying.verify_strict(STATEMENT, &signature).is_ok()
}

/// The device PIN refusal `result` carries; anything else fails the test.
fn pin_refusal<T: std::fmt::Debug>(result: oneiron::Result<T>) -> DevicePinRefusal {
    match result {
        Err(Error::Secret(SecretError::DevicePin(refusal))) => refusal,
        other => panic!("expected a device PIN refusal, got {other:?}"),
    }
}

/// The roster row a managed host's new root holds: attested as its root,
/// `ROLE_CLOUD`, `CloudCustodial`.
fn hosted_root(issuer: &HostSlipIssuer) -> DeviceAuthority {
    DeviceAuthority {
        key: issuer.public_key(),
        transport_key_binding: issuer.binding_key(),
        attestation: AuthorityAttestation {
            kind: "HostRoot".into(),
            evidence: Vec::new(),
        },
        tier: AuthorityTier::CloudCustodial,
        roles: ROLE_OWNER | ROLE_ADMIN | ROLE_CLOUD,
    }
}

/// The host migrates its root under the owner's account: a re-root, which
/// retires every key of the roster, this install's owner key among them.
fn retire_the_roster(device: &PinDevice, key: [u8; 32]) {
    let next = HostSlipIssuer::from_secret(b"device pin test next host root")
        .expect("the managed host's next root");
    recover_cloud_account_signed_by_host_root(
        &device.vault,
        &device.proof,
        &device.issuer,
        hosted_root(&next),
    )
    .expect("the host re-roots under the owner's account");
    let fold = device.vault.authority_fold().expect("authority fold");
    assert!(
        fold.roster
            .get(&AuthorityKey::Ed25519(key))
            .is_some_and(|row| row.revoked),
        "guard: the re-root revoked this install's owner key"
    );
}

#[test]
fn a_right_pin_opens_the_window_and_the_owner_key_signs_and_a_wrong_one_does_neither() {
    let device = PinDevice::hardware_counted();
    assert_eq!(
        device.pin.capability(),
        PresenceCapability::DevicePin { set: false },
        "guard: the device takes a PIN and has none"
    );
    assert_eq!(device.pin.tier(), Some(DevicePinTier::HardwareCounted));
    assert_eq!(
        pin_refusal(device.vault.confirm_device_pin(PIN)),
        DevicePinRefusal::NotSet,
        "no PIN confirms before one is set"
    );

    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner sets this device's first PIN");
    assert_eq!(
        device.pin.capability(),
        PresenceCapability::DevicePin { set: true }
    );
    assert!(
        device.pin.window_is_open(),
        "setting the PIN opens a window"
    );
    assert_eq!(
        pin_refusal(
            device
                .vault
                .set_device_pin_as(&device.owner(), OTHER_PIN, false)
        ),
        DevicePinRefusal::AlreadySet,
        "a set PIN changes only with that PIN"
    );

    let key = device.enrol();
    assert_eq!(
        device.rest(),
        OwnerKeyRest::DevicePin {
            public_key: key,
            tier: DevicePinTier::HardwareCounted,
        },
        "a key enrolled on a device with a PIN rests under it"
    );
    assert!(device.signs(key), "inside the window the owner key signs");

    device.pin.end_window();
    assert!(
        device.listed_signer(key).is_none(),
        "outside the window the checkpoint pass gets no owner signer"
    );

    assert_eq!(
        pin_refusal(device.vault.confirm_device_pin(OTHER_PIN)),
        DevicePinRefusal::Wrong
    );
    assert!(!device.pin.window_is_open(), "a wrong PIN opens no window");
    assert!(
        device.listed_signer(key).is_none(),
        "a wrong PIN lets nothing sign"
    );

    device
        .vault
        .confirm_device_pin(PIN)
        .expect("the right PIN confirms");
    assert!(device.pin.window_is_open());
    assert!(
        device.signs(key),
        "the right PIN lets the owner key sign again"
    );
}

#[test]
fn after_the_window_ends_the_key_does_not_sign_and_no_seed_rests_in_the_slot() {
    let device = PinDevice::hardware_counted();
    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner sets the PIN");
    let key = device.enrol();
    let slot = device.owner_slot();
    assert!(
        device
            .keystore
            .get(&slot)
            .expect("the slot reads")
            .is_none(),
        "the owner signing slot of a PIN device is empty"
    );
    let sealed_home = device
        .keystore
        .sealed_bytes()
        .expect("the keystore's home for sealed bytes");
    assert!(
        sealed_home
            .get_sealed(&SealedBytesName::Slot(slot))
            .expect("the sealed seed reads")
            .is_some(),
        "the seed rests sealed, under the slot's name"
    );
    assert!(
        sealed_home
            .get_sealed(&SealedBytesName::DevicePinKey)
            .expect("the device PIN key's name reads")
            .is_none(),
        "on the hardware tier the device PIN key rests in the hardware, not in a file"
    );
    assert!(
        device
            .keystore
            .auth_bound_secret()
            .expect("the keystore's counted hardware")
            .holds_auth_bound()
            .expect("the hardware answers"),
        "the device PIN key rests in the hardware"
    );

    // A signer the pass took inside the window.
    let held = device
        .listed_signer(key)
        .expect("inside the window the pass gets the signer");
    device.pass_the_window();
    assert!(!device.pin.window_is_open(), "the window ends by its clock");
    assert_eq!(
        pin_refusal(held.sign_checkpoint_statement(STATEMENT)),
        DevicePinRefusal::Required,
        "a signer taken inside the window signs nothing after it"
    );
    assert!(device.listed_signer(key).is_none());
    assert_eq!(
        pin_refusal(
            device
                .vault
                .enrol_device_owner_signing_key(&device.owner(), &device.issuer)
        ),
        DevicePinRefusal::Required,
        "an enrollment on a PIN device needs the window"
    );
}

#[test]
fn five_wrong_pins_refuse_the_sixth_and_a_right_pin_after_the_wait_works() {
    let device = PinDevice::passphrase();
    assert_eq!(device.pin.tier(), Some(DevicePinTier::Passphrase));
    assert_eq!(
        pin_refusal(device.vault.set_device_pin_as(&device.owner(), PIN, false)),
        DevicePinRefusal::TooShort {
            min_chars: DEVICE_PIN_MIN_CHARS
        },
        "where nothing counts wrong tries but this process, the PIN is a passphrase"
    );
    device
        .vault
        .set_device_pin_as(&device.owner(), PASSPHRASE, false)
        .expect("the owner sets a passphrase for this device");
    assert!(
        device
            .keystore
            .sealed_bytes()
            .expect("the keystore's home for sealed bytes")
            .get_sealed(&SealedBytesName::DevicePinKey)
            .expect("the device PIN key's name reads")
            .is_some_and(|sealed| !sealed
                .windows(PASSPHRASE.len())
                .any(|part| part == PASSPHRASE)),
        "the device PIN key rests sealed, and the passphrase is not in it"
    );
    device.pin.end_window();

    for wrong in 1..DEVICE_PIN_WRONG_TRIES {
        assert_eq!(
            pin_refusal(device.vault.confirm_device_pin(OTHER_PASSPHRASE)),
            DevicePinRefusal::Wrong,
            "wrong passphrase {wrong}"
        );
    }
    assert_eq!(
        pin_refusal(device.vault.confirm_device_pin(OTHER_PASSPHRASE)),
        DevicePinRefusal::TooManyTries {
            wait_secs: DEVICE_PIN_WAIT_SECS
        },
        "the fifth wrong passphrase in a row starts the wait"
    );
    assert_eq!(
        pin_refusal(device.vault.confirm_device_pin(PASSPHRASE)),
        DevicePinRefusal::TooManyTries {
            wait_secs: DEVICE_PIN_WAIT_SECS
        },
        "inside the wait the right passphrase is refused too"
    );
    assert!(!device.pin.window_is_open());
    assert_eq!(device.pin.wait_secs(), Some(DEVICE_PIN_WAIT_SECS));

    device.clock.advance(DEVICE_PIN_WAIT_SECS * 1000);
    assert_eq!(device.pin.wait_secs(), None, "the wait is over");
    device
        .vault
        .confirm_device_pin(PASSPHRASE)
        .expect("after the wait the right passphrase confirms");
    assert!(device.pin.window_is_open());
}

#[test]
fn a_changed_pin_opens_with_the_new_one_only_and_the_key_is_unchanged() {
    let device = PinDevice::passphrase();
    device
        .vault
        .set_device_pin_as(&device.owner(), PASSPHRASE, false)
        .expect("the owner sets a passphrase");
    let key = device.enrol();

    assert_eq!(
        pin_refusal(
            device
                .vault
                .change_device_pin_as(&device.owner(), PASSPHRASE, PIN, false)
        ),
        DevicePinRefusal::TooShort {
            min_chars: DEVICE_PIN_MIN_CHARS
        },
        "a short PIN needs the owner's choice for this device"
    );
    assert_eq!(
        pin_refusal(device.vault.change_device_pin_as(
            &device.owner(),
            OTHER_PASSPHRASE,
            PIN,
            true
        )),
        DevicePinRefusal::Wrong,
        "the PIN changes only with the PIN it has"
    );
    assert_eq!(device.pin.min_chars(true), DEVICE_PIN_SHORT_MIN_CHARS);
    device
        .vault
        .change_device_pin_as(&device.owner(), PASSPHRASE, PIN, true)
        .expect("with the owner's choice, a short PIN takes the passphrase's place");

    device.pin.end_window();
    assert_eq!(
        pin_refusal(device.vault.confirm_device_pin(PASSPHRASE)),
        DevicePinRefusal::Wrong,
        "the old passphrase opens nothing"
    );
    device
        .vault
        .confirm_device_pin(PIN)
        .expect("the new PIN confirms");
    assert_eq!(
        device.rest(),
        OwnerKeyRest::DevicePin {
            public_key: key,
            tier: DevicePinTier::Passphrase,
        },
        "the same key rests under the new PIN"
    );
    assert!(
        device.signs(key),
        "the key sealed before the change signs after it"
    );
}

#[test]
fn forgetting_the_pin_leaves_no_key_and_a_fresh_enrolment_makes_a_new_one() {
    let device = PinDevice::hardware_counted();
    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner sets the PIN");
    let lost = device.enrol();
    let slot = device.owner_slot();

    device
        .vault
        .forget_device_pin_as(&device.owner())
        .expect("the owner forgets this device's PIN");
    assert_eq!(
        device.pin.capability(),
        PresenceCapability::DevicePin { set: false }
    );
    assert!(!device.pin.window_is_open());
    assert_eq!(device.rest(), OwnerKeyRest::NoKey);
    assert!(
        device
            .keystore
            .sealed_bytes()
            .expect("the keystore's home for sealed bytes")
            .get_sealed(&SealedBytesName::Slot(slot))
            .expect("the sealed seed's name reads")
            .is_none(),
        "the sealed seed is gone"
    );
    assert!(
        device
            .keystore
            .get(&slot)
            .expect("the slot reads")
            .is_none(),
        "no seed came back to the slot"
    );
    assert!(
        device.listed_signer(lost).is_none(),
        "the lost key signs nothing"
    );

    device
        .vault
        .set_device_pin_as(&device.owner(), OTHER_PIN, false)
        .expect("the owner sets a new PIN");
    let fresh = device.enrol();
    assert_ne!(fresh, lost, "a fresh key is enrolled, never the lost one");
    assert_eq!(
        device.rest(),
        OwnerKeyRest::DevicePin {
            public_key: fresh,
            tier: DevicePinTier::HardwareCounted,
        }
    );
    assert!(device.signs(fresh));
}

#[test]
fn a_key_enrolled_before_the_pin_signs_until_a_pin_is_set_and_then_only_inside_a_window() {
    let device = PinDevice::hardware_counted();
    let key = device.enrol();
    let slot = device.owner_slot();
    assert_eq!(device.rest(), OwnerKeyRest::Slot);
    assert!(
        device
            .keystore
            .get(&slot)
            .expect("the slot reads")
            .is_some(),
        "guard: with no PIN the seed rests in its slot"
    );
    assert!(
        device.signs(key),
        "with no PIN set the key signs with nobody there, as before"
    );

    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner adds a PIN to this device");
    assert_eq!(
        device.rest(),
        OwnerKeyRest::DevicePin {
            public_key: key,
            tier: DevicePinTier::HardwareCounted,
        },
        "the same key now rests under the PIN"
    );
    assert!(
        device
            .keystore
            .get(&slot)
            .expect("the slot reads")
            .is_none(),
        "its slot is emptied"
    );
    assert!(device.signs(key), "inside the window it signs");

    device.pin.end_window();
    assert!(
        device.listed_signer(key).is_none(),
        "after the PIN is added the key signs nothing outside a window"
    );
    device
        .vault
        .confirm_device_pin(PIN)
        .expect("the right PIN confirms");
    assert!(device.signs(key));
    assert_eq!(
        device.enrol(),
        key,
        "an enrollment asked again answers the same key"
    );
}

#[test]
fn the_checkpoint_pass_gets_the_owner_signer_only_inside_a_window_and_each_right_pin_counts_once() {
    let device = PinDevice::hardware_counted();
    assert_eq!(device.vault.device_pin_right_pins(), 0);
    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner sets the PIN");
    assert_eq!(
        device.vault.device_pin_right_pins(),
        1,
        "setting the PIN is its first right entry"
    );
    let key = device.enrol();
    device.pin.end_window();
    assert!(
        device.vault.checkpoint_root_signers().is_empty(),
        "with the window closed the pass holds no signer: it dials nothing"
    );

    assert_eq!(
        pin_refusal(device.vault.confirm_device_pin(OTHER_PIN)),
        DevicePinRefusal::Wrong
    );
    assert_eq!(
        device.vault.device_pin_right_pins(),
        1,
        "a wrong PIN is not counted as a right one"
    );
    device
        .vault
        .confirm_device_pin(PIN)
        .expect("the right PIN confirms");
    assert_eq!(device.vault.device_pin_right_pins(), 2);
    assert!(
        device.listed_signer(key).is_some(),
        "inside the window the pass gets the owner signer"
    );
}

#[test]
fn a_revoked_key_stops_at_its_next_use() {
    let bound = PinDevice::hardware_counted();
    bound
        .vault
        .set_device_pin_as(&bound.owner(), PIN, false)
        .expect("the owner sets the PIN");
    let key = bound.enrol();
    assert!(
        bound.signs(key),
        "guard: the live key signs inside the window"
    );
    retire_the_roster(&bound, key);
    assert!(
        bound.pin.window_is_open(),
        "guard: the window is still open"
    );
    assert!(
        bound.listed_signer(key).is_none(),
        "a revoked key under the PIN is not asked again, window or not"
    );

    let unbound = PinDevice::hardware_counted();
    let key = unbound.enrol();
    assert!(unbound.signs(key), "guard: the live key in its slot signs");
    retire_the_roster(&unbound, key);
    assert!(
        unbound.listed_signer(key).is_none(),
        "a revoked key in its slot is not asked again either"
    );
}

#[test]
fn a_host_that_takes_no_pin_never_makes_the_key_beside_a_set_pin() {
    let device = PinDevice::hardware_counted();
    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner sets the PIN");

    let other_keystore = Arc::new(MemoryKeystore::new());
    let other_pin = DevicePin::with_clock_and_cost(
        other_keystore,
        Arc::<ManualPresenceClock>::clone(&device.clock),
        PassphraseCost::FLOOR,
    )
    .expect("a device PIN over another keystore");
    assert!(
        device.vault.install_device_pin(other_pin).is_err(),
        "a device PIN over another keystore is refused"
    );

    // The same keystore installed again, as a host that takes no PIN does.
    device
        .vault
        .install_device_keystore(Arc::<MemoryKeystore>::clone(&device.keystore));
    assert!(
        device.vault.device_pin().is_none(),
        "guard: the handle has no device PIN now"
    );
    assert!(
        matches!(
            pin_refusal(
                device
                    .vault
                    .enrol_device_owner_signing_key(&device.owner(), &device.issuer)
            ),
            DevicePinRefusal::Unavailable(_)
        ),
        "with a PIN set on the device, a host that takes none enrols no key"
    );
    assert!(
        device.vault.device_owner_signing_key().is_err(),
        "and is handed no key"
    );
    assert!(
        device
            .keystore
            .get(&device.owner_slot())
            .expect("the slot reads")
            .is_none(),
        "no seed was made in the clear"
    );
}
