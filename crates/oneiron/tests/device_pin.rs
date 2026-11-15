//! The device PIN and the owner signing key it guards (row OCS-OWNER-PIN;
//! lead ruling OCS-NO-PROMPT-DEVICE = D, 15 Nov: a device with no unlock
//! prompt asks for a PIN that wraps its owner key, "so nothing running as
//! him can sign without it").
//!
//! Each test opens its own vault over a process-memory keystore, with the
//! device PIN on a clock the test moves. A keystore made with a counter
//! stands in for the hardware tier; one made without stands in for the file
//! tier, sealed at the kit's floor cost so a test's stretches stay short.
//! The keystore is wrapped so that a test can stop one call in the middle
//! of a step, refuse it once, or fail it once after its effect: that is how
//! the tests of a step that cannot finish are made to run the same way each
//! time. A test of two steps at once stops the first inside its step, and
//! then waits until the device PIN counted that the second one waited for
//! it (`test_doors::device_pin`), or hears that the second one went on
//! instead: it never gives the second step a length of time to run in.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test device_pin`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use oneiron::authority::{
    ActAuthority, ActSurface, AuthorityAttestation, AuthorityKey, AuthorityTier,
    CheckpointRootSigner, DeviceAuthority, HostSlipIssuer, MachineRole, ROLE_ADMIN, ROLE_CLOUD,
    ROLE_OWNER,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{DevicePinRefusal, SecretError};
use oneiron::recovery::PassphraseCost;
use oneiron::test_doors::device_pin::steps_that_waited;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::steward::recover_cloud_account_signed_by_host_root;
use oneiron::world_keys::{
    DEVICE_PIN_MIN_CHARS, DEVICE_PIN_SHORT_MIN_CHARS, DevicePin, DevicePinTier, OwnerKeyRest,
};
use oneiron::{Error, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_keystore::{
    AuthBoundError, AuthBoundSecretStore, DEVICE_PIN_WAIT_SECS, DEVICE_PIN_WRONG_TRIES,
    DeviceKeystore, KeystoreAssurance, KeystoreError, KeystoreLocality, KeystoreSlot,
    ManualPresenceClock, MemoryKeystore, PRESENCE_WINDOW_SECS, PresenceCapability, SealedBytesName,
    SealedBytesStore, SlotKind,
};
use zeroize::Zeroizing;

/// A statement in the checkpoint attestation domain: what the owner key
/// signs for the checkpoint pass.
const STATEMENT: &[u8] = b"oneiron/authority/checkpoint-attestation/v2 device pin test";

const PIN: &[u8] = b"271828";
const OTHER_PIN: &[u8] = b"314159";
const PASSPHRASE: &[u8] = b"quiet harbour lantern";
const OTHER_PASSPHRASE: &[u8] = b"seven green bottles";

/// How long a test waits for a step to reach the call it stops at, a
/// stopped call for the test's word, and a second step to wait or go on.
const PAUSE_WAIT: Duration = Duration::from_secs(30);

/// A keystore call a test stops at, refuses once, or fails once after its
/// effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeystoreCall {
    /// The owner signing slot's delete.
    DeleteOwnerSlot,
    /// A read of the owner signing slot.
    GetOwnerSlot,
    /// A read of a slot's sealed secret.
    GetSealedSlot,
    /// A write of a slot's sealed secret.
    PutSealedSlot,
    /// The delete of the secret the hardware holds under an auth value.
    DeleteAuthBound,
}

/// A call stopped before it reaches the keystore: it tells the test through
/// the sender and goes on at the test's word on the receiver.
type Pause = (KeystoreCall, mpsc::Sender<()>, mpsc::Receiver<()>);

/// The process-memory keystore, with one call that a test stops in the
/// middle of a step, calls that it refuses once, and one that it fails once
/// after the call's effect.
struct SteppedKeystore {
    inner: MemoryKeystore,
    pause: Mutex<Option<Pause>>,
    /// The calls refused once each, before they reach the keystore.
    refuse: Mutex<Vec<KeystoreCall>>,
    /// The call that reaches the keystore and then answers a failure, with
    /// the call that is refused next.
    fail_after: Mutex<Option<(KeystoreCall, Option<KeystoreCall>)>>,
    /// How many values the keystore was given to keep.
    puts: AtomicU64,
}

impl SteppedKeystore {
    fn new(inner: MemoryKeystore) -> Self {
        Self {
            inner,
            pause: Mutex::new(None),
            refuse: Mutex::new(Vec::new()),
            fail_after: Mutex::new(None),
            puts: AtomicU64::new(0),
        }
    }

    /// Stops the next `call` before it reaches the keystore. The test hears
    /// of it on the receiver and lets the call go on through the sender.
    fn pause_at(&self, call: KeystoreCall) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (reached, test_hears) = mpsc::channel();
        let (test_resumes, resumed) = mpsc::channel();
        *self.pause.lock().unwrap_or_else(PoisonError::into_inner) = Some((call, reached, resumed));
        (test_hears, test_resumes)
    }

    /// Stops no call any more: a stop that was set and never reached.
    fn pause_nothing(&self) {
        *self.pause.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Refuses the next `call`, once, before it reaches the keystore.
    fn refuse_once(&self, call: KeystoreCall) {
        self.refuse
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call);
    }

    /// Lets the next `call` reach the keystore and then answers a failure
    /// for it, once: what a file keystore does when it removed or replaced a
    /// file and its directory does not sync. `then_refuse` is refused next,
    /// once.
    fn fail_after_once(&self, call: KeystoreCall, then_refuse: Option<KeystoreCall>) {
        *self
            .fail_after
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some((call, then_refuse));
    }

    /// How many values the keystore was given to keep: slots made or
    /// replaced, sealed bytes, and secrets for its hardware.
    fn puts(&self) -> u64 {
        self.puts.load(Ordering::Relaxed)
    }

    /// The test's part of `call`: the stop, then the refusal.
    fn at(&self, call: KeystoreCall) -> Result<(), KeystoreError> {
        let stopped = {
            let mut pause = self.pause.lock().unwrap_or_else(PoisonError::into_inner);
            if pause.as_ref().is_some_and(|(at, _, _)| *at == call) {
                pause.take()
            } else {
                None
            }
        };
        if let Some((_, reached, resumed)) = stopped {
            reached.send(()).expect("the test waits for the stop");
            resumed
                .recv_timeout(PAUSE_WAIT)
                .expect("the test lets the stopped call go on");
        }
        let mut refuse = self.refuse.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(armed) = refuse.iter().position(|refused| *refused == call) {
            refuse.remove(armed);
            return Err(KeystoreError::Denied);
        }
        Ok(())
    }

    /// The test's part of `call` once it reached the keystore: the failure
    /// answered after the call's effect.
    fn after(&self, call: KeystoreCall) -> Result<(), KeystoreError> {
        let failed = self
            .fail_after
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take_if(|(armed, _)| *armed == call);
        let Some((_, then_refuse)) = failed else {
            return Ok(());
        };
        if let Some(next) = then_refuse {
            self.refuse_once(next);
        }
        Err(KeystoreError::Platform("io", 5))
    }

    fn sealed(&self) -> &dyn SealedBytesStore {
        self.inner
            .sealed_bytes()
            .expect("the memory keystore keeps sealed bytes")
    }

    fn hardware(&self) -> &dyn AuthBoundSecretStore {
        self.inner
            .auth_bound_secret()
            .expect("a memory keystore made with a counter")
    }
}

impl DeviceKeystore for SteppedKeystore {
    fn get(&self, slot: &KeystoreSlot) -> Result<Option<Zeroizing<[u8; 32]>>, KeystoreError> {
        if slot.kind == SlotKind::OwnerSigning {
            self.at(KeystoreCall::GetOwnerSlot)?;
        }
        DeviceKeystore::get(&self.inner, slot)
    }

    fn create(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<(), KeystoreError> {
        self.puts.fetch_add(1, Ordering::Relaxed);
        DeviceKeystore::create(&self.inner, slot, secret)
    }

    fn delete(&self, slot: &KeystoreSlot) -> Result<(), KeystoreError> {
        if slot.kind != SlotKind::OwnerSigning {
            return DeviceKeystore::delete(&self.inner, slot);
        }
        self.at(KeystoreCall::DeleteOwnerSlot)?;
        DeviceKeystore::delete(&self.inner, slot)?;
        self.after(KeystoreCall::DeleteOwnerSlot)
    }

    fn replace(&self, slot: &KeystoreSlot, secret: &[u8; 32]) -> Result<bool, KeystoreError> {
        self.puts.fetch_add(1, Ordering::Relaxed);
        DeviceKeystore::replace(&self.inner, slot, secret)
    }

    fn locality(&self) -> KeystoreLocality {
        self.inner.locality()
    }

    fn assurance(&self) -> KeystoreAssurance {
        self.inner.assurance()
    }

    fn sealed_bytes(&self) -> Option<&dyn SealedBytesStore> {
        Some(self)
    }

    fn auth_bound_secret(&self) -> Option<&dyn AuthBoundSecretStore> {
        self.inner
            .auth_bound_secret()
            .map(|_| self as &dyn AuthBoundSecretStore)
    }
}

impl SealedBytesStore for SteppedKeystore {
    fn get_sealed(&self, name: &SealedBytesName) -> Result<Option<Vec<u8>>, KeystoreError> {
        if matches!(name, SealedBytesName::Slot(_)) {
            self.at(KeystoreCall::GetSealedSlot)?;
        }
        self.sealed().get_sealed(name)
    }

    fn put_sealed(&self, name: &SealedBytesName, sealed: &[u8]) -> Result<(), KeystoreError> {
        let slot_secret = matches!(name, SealedBytesName::Slot(_));
        if slot_secret {
            self.at(KeystoreCall::PutSealedSlot)?;
        }
        self.puts.fetch_add(1, Ordering::Relaxed);
        self.sealed().put_sealed(name, sealed)?;
        if slot_secret {
            self.after(KeystoreCall::PutSealedSlot)?;
        }
        Ok(())
    }

    fn delete_sealed(&self, name: &SealedBytesName) -> Result<(), KeystoreError> {
        self.sealed().delete_sealed(name)
    }
}

impl AuthBoundSecretStore for SteppedKeystore {
    fn holds_auth_bound(&self) -> Result<bool, KeystoreError> {
        self.hardware().holds_auth_bound()
    }

    fn put_auth_bound(&self, auth: &[u8], secret: &[u8; 32]) -> Result<(), KeystoreError> {
        self.puts.fetch_add(1, Ordering::Relaxed);
        self.hardware().put_auth_bound(auth, secret)
    }

    fn open_auth_bound(&self, auth: &[u8]) -> Result<Option<Zeroizing<[u8; 32]>>, AuthBoundError> {
        self.hardware().open_auth_bound(auth)
    }

    fn delete_auth_bound(&self) -> Result<(), KeystoreError> {
        self.at(KeystoreCall::DeleteAuthBound)?;
        self.hardware().delete_auth_bound()
    }
}

/// One vault under the Hosted posture, rooted under the test host, with
/// this install's machine profile enrolled, the embedded owner
/// authenticated, and a device PIN over the vault's keystore on a manual
/// clock. The vault drops first.
struct PinDevice {
    vault: Vault,
    issuer: HostSlipIssuer,
    proof: AuthenticatedOwner,
    keystore: Arc<SteppedKeystore>,
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
        let keystore = Arc::new(SteppedKeystore::new(keystore));
        let clock = ManualPresenceClock::new(1_000_000, 1_000_000);
        let pin = DevicePin::with_clock_and_cost(
            Arc::<SteppedKeystore>::clone(&keystore),
            Arc::<ManualPresenceClock>::clone(&clock),
            PassphraseCost::FLOOR,
        )
        .expect("the device PIN over the device's keystore");
        Self::open_over(keystore, pin, clock)
    }

    /// Another vault of the same device: a vault and an owner of its own,
    /// over this device's keystore and its one device PIN.
    fn second_vault(&self) -> Self {
        Self::open_over(
            Arc::clone(&self.keystore),
            Arc::clone(&self.pin),
            Arc::clone(&self.clock),
        )
    }

    fn open_over(
        keystore: Arc<SteppedKeystore>,
        pin: Arc<DevicePin>,
        clock: Arc<ManualPresenceClock>,
    ) -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        let vault = Vault::open(dir.path(), config).expect("hosted vault");
        vault.install_device_keystore(Arc::<SteppedKeystore>::clone(&keystore));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let (_owner, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
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
            .sign_checkpoint_statement(&self.vault, STATEMENT)
            .expect("a listed signer signs a checkpoint statement");
        verifies(key, &signature)
    }

    /// What rests under `name` in the keystore's home for sealed bytes.
    fn sealed(&self, name: &SealedBytesName) -> Option<Vec<u8>> {
        self.keystore
            .sealed()
            .get_sealed(name)
            .expect("the home for sealed bytes reads")
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

/// Whether a second step waited for the first, which the test stopped
/// inside its step: true once `pin` counted a step that waited, false when
/// the second step went on instead and `went_on` heard of it. A second step
/// that does neither fails the test.
fn second_step_waited(pin: &DevicePin, waited_before: u64, went_on: &mpsc::Receiver<()>) -> bool {
    let deadline = Instant::now() + PAUSE_WAIT;
    loop {
        if steps_that_waited(pin) > waited_before {
            return true;
        }
        if went_on.recv_timeout(Duration::from_millis(10)).is_ok() {
            return false;
        }
        assert!(
            Instant::now() < deadline,
            "the second step neither waited for the first nor went on"
        );
    }
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
        pin_refusal(held.sign_checkpoint_statement(&device.vault, STATEMENT)),
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
    assert!(
        device
            .sealed(&SealedBytesName::DevicePinForgotten)
            .is_some(),
        "the device is marked as one that forgot its PIN"
    );
    assert_eq!(
        pin_refusal(
            device
                .vault
                .enrol_device_owner_signing_key(&device.owner(), &device.issuer)
        ),
        DevicePinRefusal::NotSet,
        "a device that forgot its PIN makes its next key under a new PIN, never in a slot"
    );
    assert!(
        device
            .keystore
            .get(&slot)
            .expect("the slot reads")
            .is_none(),
        "no seed was made in the clear"
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
    // A signer the pass took while the key was live.
    let taken = bound
        .listed_signer(key)
        .expect("guard: inside the window the pass gets the signer");
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
        taken
            .sign_checkpoint_statement(&bound.vault, STATEMENT)
            .is_err(),
        "a signer taken before the key was revoked signs nothing after, window or not"
    );
    assert!(
        bound.listed_signer(key).is_none(),
        "and a revoked key under the PIN is not asked again"
    );

    let unbound = PinDevice::hardware_counted();
    let key = unbound.enrol();
    let taken = unbound
        .listed_signer(key)
        .expect("guard: with no PIN the pass gets the signer");
    assert!(unbound.signs(key), "guard: the live key in its slot signs");
    retire_the_roster(&unbound, key);
    assert!(
        taken
            .sign_checkpoint_statement(&unbound.vault, STATEMENT)
            .is_err(),
        "a signer of a key in its slot, taken before the key was revoked, signs nothing after"
    );
    assert!(
        unbound.listed_signer(key).is_none(),
        "and a revoked key in its slot is not asked again either"
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
        .install_device_keystore(Arc::<SteppedKeystore>::clone(&device.keystore));
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

#[test]
fn a_signer_taken_before_the_pin_was_set_signs_nothing_after_it() {
    let device = PinDevice::hardware_counted();
    let key = device.enrol();
    // The two ways a caller comes by the key while no PIN is set.
    let listed = device
        .listed_signer(key)
        .expect("guard: with no PIN the pass gets the signer");
    let handed_out = device
        .vault
        .device_owner_signing_key()
        .expect("guard: with no PIN the key is handed out");
    for signer in [&*listed, &handed_out as &dyn CheckpointRootSigner] {
        let signature = signer
            .sign_checkpoint_statement(&device.vault, STATEMENT)
            .expect("guard: with no PIN the key signs from its slot");
        assert!(verifies(key, &signature));
    }

    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner adds a PIN to this device");
    for signer in [&*listed, &handed_out as &dyn CheckpointRootSigner] {
        assert_eq!(
            pin_refusal(signer.sign_checkpoint_statement(&device.vault, STATEMENT)),
            DevicePinRefusal::Required,
            "a signer taken before the PIN was set is dead once it is set, inside the window too"
        );
    }
    device.pin.end_window();
    for signer in [&*listed, &handed_out as &dyn CheckpointRootSigner] {
        assert_eq!(
            pin_refusal(signer.sign_checkpoint_statement(&device.vault, STATEMENT)),
            DevicePinRefusal::Required,
            "and it signs nothing with the window closed"
        );
    }
    device
        .vault
        .confirm_device_pin(PIN)
        .expect("the right PIN confirms");
    assert!(
        device.signs(key),
        "the signer the pass takes inside a window opens the seed from under the PIN"
    );
}

#[test]
fn a_signature_whose_sealed_read_outlasts_the_window_signs_nothing() {
    let device = PinDevice::hardware_counted();
    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner sets the PIN");
    let key = device.enrol();
    let signer = device
        .listed_signer(key)
        .expect("inside the window the pass gets the signer");

    // The signature stops where it reads the sealed seed from its home,
    // before it takes the device PIN key's lock.
    let (reached, resume) = device.keystore.pause_at(KeystoreCall::GetSealedSlot);
    let vault = &device.vault;
    let signed = thread::scope(|scope| {
        let signing = scope.spawn(move || signer.sign_checkpoint_statement(vault, STATEMENT));
        reached
            .recv_timeout(PAUSE_WAIT)
            .expect("the signature reaches the sealed seed's home");
        device.pin.end_window();
        resume.send(()).expect("the signature goes on");
        signing.join().expect("the signing thread ends")
    });
    assert_eq!(
        pin_refusal(signed),
        DevicePinRefusal::Required,
        "a window that ended while a signature was on its way leaves it nothing to sign with"
    );
}

#[test]
fn a_first_pin_refused_with_the_seed_still_in_its_slot_leaves_a_device_with_no_pin() {
    let device = PinDevice::hardware_counted();
    let key = device.enrol();
    let slot = device.owner_slot();

    // The keystore refuses the set's last step, emptying the slot, before
    // it removed anything.
    device.keystore.refuse_once(KeystoreCall::DeleteOwnerSlot);
    assert!(
        device
            .vault
            .set_device_pin_as(&device.owner(), PIN, false)
            .is_err(),
        "the set reports the keystore's refusal"
    );
    assert_eq!(
        device.pin.capability(),
        PresenceCapability::DevicePin { set: false },
        "a set that did not finish leaves no PIN set"
    );
    assert!(!device.pin.window_is_open());
    assert!(
        device
            .keystore
            .get(&slot)
            .expect("the slot reads")
            .is_some(),
        "the seed never left its slot"
    );
    assert!(
        device.sealed(&SealedBytesName::Slot(slot)).is_none(),
        "and no sealed copy of it is left"
    );
    assert_eq!(device.rest(), OwnerKeyRest::Slot);
    assert!(
        device.signs(key),
        "the key signs from its slot, as on any device with no PIN"
    );

    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the set asked again finishes");
    assert_eq!(
        device.rest(),
        OwnerKeyRest::DevicePin {
            public_key: key,
            tier: DevicePinTier::HardwareCounted,
        }
    );
    assert!(
        device
            .keystore
            .get(&slot)
            .expect("the slot reads")
            .is_none(),
        "and the slot is emptied in the same step"
    );
}

#[test]
fn another_vault_of_the_device_signs_nothing_from_its_slot_once_a_pin_is_set() {
    let first = PinDevice::hardware_counted();
    let second = first.second_vault();
    let _first_key = first.enrol();
    let second_key = second.enrol();
    let taken = second
        .listed_signer(second_key)
        .expect("guard: with no PIN the second vault's key signs from its slot");

    first
        .vault
        .set_device_pin_as(&first.owner(), PIN, false)
        .expect("the owner adds a PIN to this device through the first vault");
    assert_eq!(
        pin_refusal(taken.sign_checkpoint_statement(&second.vault, STATEMENT)),
        DevicePinRefusal::Required,
        "from that step on the second vault's seed signs nothing from its slot"
    );
    assert_eq!(
        second.rest(),
        OwnerKeyRest::DevicePinUnopened {
            tier: DevicePinTier::HardwareCounted,
            seed_in_slot: true,
        },
        "its seed is told as still in its slot"
    );

    // The second vault's next checkpoint pass, inside the window the first
    // vault's PIN opened.
    second.vault.hold_device_owner_signer_in_pin_window();
    assert!(
        second
            .keystore
            .get(&second.owner_slot())
            .expect("the slot reads")
            .is_none(),
        "the pass puts the seed under the PIN and empties its slot"
    );
    assert_eq!(
        second.rest(),
        OwnerKeyRest::DevicePin {
            public_key: second_key,
            tier: DevicePinTier::HardwareCounted,
        }
    );
    assert!(
        second.signs(second_key),
        "inside the window the second vault's key signs from under the PIN"
    );
    first.pin.end_window();
    assert!(
        second.listed_signer(second_key).is_none(),
        "and outside it the second vault's key signs nothing"
    );
}

#[test]
fn a_host_that_takes_no_pin_holds_no_key_from_a_slot_beside_a_set_pin() {
    let first = PinDevice::hardware_counted();
    let second = first.second_vault();
    let second_key = second.enrol();
    first
        .vault
        .set_device_pin_as(&first.owner(), PIN, false)
        .expect("the owner adds a PIN to this device through the first vault");
    first.pin.end_window();

    // The second vault under a host that installs the keystore and no
    // device PIN.
    second
        .vault
        .install_device_keystore(Arc::<SteppedKeystore>::clone(&second.keystore));
    assert!(
        second.vault.device_pin().is_none(),
        "guard: the handle has no device PIN now"
    );
    assert!(
        second
            .keystore
            .get(&second.owner_slot())
            .expect("the slot reads")
            .is_some(),
        "guard: the second vault's seed still rests in its slot"
    );
    assert!(
        !second.vault.hold_device_owner_signer_logged(),
        "the slot of a device with a PIN set is not read as a key"
    );
    assert!(
        second.listed_signer(second_key).is_none(),
        "and nothing signs from it"
    );
    assert_eq!(
        second.rest(),
        OwnerKeyRest::DevicePinUnopened {
            tier: DevicePinTier::HardwareCounted,
            seed_in_slot: true,
        }
    );
}

#[test]
fn two_enrolments_at_once_make_one_key_that_rests_under_the_pin() {
    let device = PinDevice::hardware_counted();
    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner sets the PIN");

    // The first enrollment stops where it puts its sealed seed to rest,
    // inside its step.
    let waited_before = steps_that_waited(&device.pin);
    let (first_reached, first_resume) = device.keystore.pause_at(KeystoreCall::PutSealedSlot);
    let (vault, issuer) = (&device.vault, &device.issuer);
    let enrol = move |proof: AuthenticatedOwner| {
        vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(proof, ActSurface::ThisInstall),
                issuer,
            )
            .map(|receipt| receipt.public_key)
    };
    let (first_proof, second_proof) = (device.proof.clone(), device.proof.clone());
    let (first, second, second_waited) = thread::scope(|scope| {
        let first = scope.spawn(move || enrol(first_proof));
        first_reached
            .recv_timeout(PAUSE_WAIT)
            .expect("the first enrollment reaches its seal");
        // A second enrollment that did not wait for the first finds no key
        // under the PIN and reaches a seal of its own: it is stopped there.
        let (second_reached, second_resume) = device.keystore.pause_at(KeystoreCall::PutSealedSlot);
        let second = scope.spawn(move || enrol(second_proof));
        let second_waited = second_step_waited(&device.pin, waited_before, &second_reached);
        device.keystore.pause_nothing();
        let _went_on = second_resume.send(());
        first_resume.send(()).expect("the first enrollment goes on");
        (
            first.join().expect("the first enrollment's thread ends"),
            second.join().expect("the second enrollment's thread ends"),
            second_waited,
        )
    });
    assert!(
        second_waited,
        "the second enrollment waits for the first; it reached a seal of its own instead"
    );
    let first = first.expect("the first enrollment enrols a key");
    let second = second.expect("the second enrollment answers");
    assert_eq!(
        first, second,
        "two enrollments at once enrol one key, and both answer it"
    );
    assert_eq!(
        device.rest(),
        OwnerKeyRest::DevicePin {
            public_key: first,
            tier: DevicePinTier::HardwareCounted,
        }
    );
    assert!(
        device.signs(first),
        "the one enrolled key's seed rests under the PIN"
    );
}

#[test]
fn a_pin_typed_while_the_pin_is_forgotten_opens_no_window() {
    let device = PinDevice::hardware_counted();
    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner sets the PIN");
    let _key = device.enrol();
    device.pin.end_window();

    // The forget stops after it ended the window and before the device PIN
    // key leaves the hardware, inside its step.
    let waited_before = steps_that_waited(&device.pin);
    let (reached, resume) = device.keystore.pause_at(KeystoreCall::DeleteAuthBound);
    let (vault, pin) = (&device.vault, &device.pin);
    let proof = device.proof.clone();
    let (typing_ended, typed_instead) = mpsc::channel();
    let (forgotten, typed, typing_waited) = thread::scope(|scope| {
        let forgetting = scope.spawn(move || {
            vault.forget_device_pin_as(&ActAuthority::Owner(proof, ActSurface::ThisInstall))
        });
        reached
            .recv_timeout(PAUSE_WAIT)
            .expect("the forget reaches the hardware");
        // A typed PIN that did not wait for the forget is answered while
        // the device PIN key still rests in the hardware.
        let typing = scope.spawn(move || {
            let answer = pin.confirm(PIN);
            let _told = typing_ended.send(());
            answer
        });
        let typing_waited = second_step_waited(pin, waited_before, &typed_instead);
        resume.send(()).expect("the forget goes on");
        (
            forgetting.join().expect("the forget's thread ends"),
            typing.join().expect("the typed PIN's thread ends"),
            typing_waited,
        )
    });
    assert!(
        typing_waited,
        "a PIN typed during the forget waits for it; it was answered while the forget ran"
    );
    forgotten.expect("the owner forgets this device's PIN");
    assert_eq!(
        pin_refusal(typed),
        DevicePinRefusal::NotSet,
        "a PIN typed during the forget waits for it, and then finds no PIN set"
    );
    assert!(
        !device.pin.window_is_open(),
        "no window is open once the PIN is forgotten"
    );
    assert_eq!(
        device.pin.capability(),
        PresenceCapability::DevicePin { set: false }
    );
}

#[test]
fn sealed_bytes_this_device_cannot_open_are_not_told_as_its_key() {
    let device = PinDevice::hardware_counted();
    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner sets the PIN");
    let lost = device.enrol();
    let name = SealedBytesName::Slot(device.owner_slot());
    let lost_envelope = device.sealed(&name).expect("the sealed seed rests");

    device
        .vault
        .forget_device_pin_as(&device.owner())
        .expect("the owner forgets this device's PIN");
    device
        .vault
        .set_device_pin_as(&device.owner(), OTHER_PIN, false)
        .expect("the owner sets a new PIN");
    // A writer of the keystore's files puts back the envelope that names the
    // lost key. The roster still lists that key live.
    device
        .keystore
        .sealed()
        .put_sealed(&name, &lost_envelope)
        .expect("the envelope goes back under the slot's name");

    assert!(
        device.pin.window_is_open(),
        "guard: the new PIN's window is open"
    );
    assert!(
        !device.vault.hold_device_owner_signer_logged(),
        "bytes that do not open under this device's PIN key are no key of it"
    );
    assert_eq!(
        device.rest(),
        OwnerKeyRest::DevicePinUnopened {
            tier: DevicePinTier::HardwareCounted,
            seed_in_slot: false,
        },
        "and no public half is told for them"
    );
    assert!(
        device.listed_signer(lost).is_none(),
        "the pass gets no signer for the key they name"
    );
}

#[test]
fn a_passphrase_cost_no_reader_takes_is_refused_before_a_pin_is_sealed_at_it() {
    let keystore = Arc::new(MemoryKeystore::new());
    let clock = ManualPresenceClock::new(1_000_000, 1_000_000);
    // One pass more than a reader of the envelope spends.
    let over_the_ceiling = PassphraseCost {
        memory_mib: PassphraseCost::FLOOR.memory_mib,
        passes: PassphraseCost::CEILING.passes + 1,
    };
    assert!(
        DevicePin::with_clock_and_cost(keystore, clock, over_the_ceiling).is_err(),
        "a device PIN is not made at a cost its own reader would refuse"
    );
}

#[test]
fn a_first_pin_inside_the_wait_is_refused_and_nothing_is_stored() {
    let device = PinDevice::passphrase();
    device
        .vault
        .set_device_pin_as(&device.owner(), PASSPHRASE, false)
        .expect("the owner sets a passphrase for this device");
    device.pin.end_window();
    for _ in 0..DEVICE_PIN_WRONG_TRIES {
        let _refused = device.vault.confirm_device_pin(OTHER_PASSPHRASE);
    }
    assert_eq!(
        device.pin.wait_secs(),
        Some(DEVICE_PIN_WAIT_SECS),
        "guard: the wait runs"
    );
    device
        .vault
        .forget_device_pin_as(&device.owner())
        .expect("a forget takes no PIN, so the wait does not stop it");

    let puts_before = device.keystore.puts();
    assert_eq!(
        pin_refusal(
            device
                .vault
                .set_device_pin_as(&device.owner(), OTHER_PASSPHRASE, false)
        ),
        DevicePinRefusal::TooManyTries {
            wait_secs: DEVICE_PIN_WAIT_SECS
        },
        "inside the wait a new PIN could not be confirmed, so none is set"
    );
    assert_eq!(
        device.keystore.puts(),
        puts_before,
        "the refusal comes before anything is given to the keystore to keep"
    );
    assert_eq!(
        device.pin.capability(),
        PresenceCapability::DevicePin { set: false }
    );
    assert!(
        device.sealed(&SealedBytesName::DevicePinKey).is_none(),
        "no device PIN key was put to rest"
    );

    device.clock.advance(DEVICE_PIN_WAIT_SECS * 1000);
    device
        .vault
        .set_device_pin_as(&device.owner(), OTHER_PASSPHRASE, false)
        .expect("after the wait the owner sets a new PIN");
    assert!(device.pin.window_is_open());
}

#[test]
fn a_signer_taken_before_the_pin_signs_nothing_once_the_pin_is_forgotten() {
    let device = PinDevice::hardware_counted();
    let key = device.enrol();
    let listed = device
        .listed_signer(key)
        .expect("guard: with no PIN the pass gets the signer");
    let handed_out = device
        .vault
        .device_owner_signing_key()
        .expect("guard: with no PIN the key is handed out");

    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner adds a PIN to this device");
    // Neither signer is asked while the PIN is set: what stops them after
    // the forget is the forget's own mark.
    device
        .vault
        .forget_device_pin_as(&device.owner())
        .expect("the owner forgets this device's PIN");
    assert_eq!(
        device.pin.capability(),
        PresenceCapability::DevicePin { set: false },
        "guard: no PIN is set now"
    );
    for signer in [&*listed, &handed_out as &dyn CheckpointRootSigner] {
        assert!(
            signer
                .sign_checkpoint_statement(&device.vault, STATEMENT)
                .is_err(),
            "a key lost with a forgotten PIN does not sign again from a signer taken before it"
        );
    }
    assert!(
        device.listed_signer(key).is_none(),
        "and the pass gets no signer for it"
    );
    assert_eq!(device.rest(), OwnerKeyRest::NoKey);
    assert_eq!(
        pin_refusal(device.vault.device_owner_signing_key()),
        DevicePinRefusal::NotSet,
        "no key is handed out from a slot of a device that forgot its PIN"
    );
    assert!(
        device
            .keystore
            .get(&device.owner_slot())
            .expect("the slot reads")
            .is_none(),
        "and none is made there"
    );
}

#[test]
fn another_vault_whose_seed_waited_in_its_slot_loses_its_key_when_the_pin_is_forgotten() {
    let first = PinDevice::hardware_counted();
    let second = first.second_vault();
    let second_key = second.enrol();
    let second_slot = second.owner_slot();
    let taken = second
        .listed_signer(second_key)
        .expect("guard: with no PIN the second vault's key signs from its slot");

    first
        .vault
        .set_device_pin_as(&first.owner(), PIN, false)
        .expect("the owner adds a PIN to this device through the first vault");
    // The second vault takes no step inside the window: its seed waits in
    // its slot when the PIN is forgotten.
    first
        .vault
        .forget_device_pin_as(&first.owner())
        .expect("the owner forgets this device's PIN through the first vault");
    assert!(
        second
            .keystore
            .get(&second_slot)
            .expect("the slot reads")
            .is_some(),
        "guard: the forget through the first vault does not reach the second vault's slot"
    );
    assert!(
        taken
            .sign_checkpoint_statement(&second.vault, STATEMENT)
            .is_err(),
        "a seed that waited in its slot is no key once the PIN is forgotten"
    );
    assert!(
        !second.vault.hold_device_owner_signer_logged(),
        "the second vault's handle holds no key from that slot"
    );
    assert!(second.listed_signer(second_key).is_none());
    assert_eq!(second.rest(), OwnerKeyRest::NoKey);
    assert_eq!(
        pin_refusal(
            second
                .vault
                .enrol_device_owner_signing_key(&second.owner(), &second.issuer)
        ),
        DevicePinRefusal::NotSet,
        "the second vault's next key is made under a new PIN"
    );

    second
        .vault
        .set_device_pin_as(&second.owner(), OTHER_PIN, false)
        .expect("the owner sets a new PIN through the second vault");
    assert!(
        second
            .keystore
            .get(&second_slot)
            .expect("the slot reads")
            .is_none(),
        "the new PIN's set removes the lost seed from its slot"
    );
    assert!(
        second.sealed(&SealedBytesName::Slot(second_slot)).is_none(),
        "and does not seal it under the new PIN"
    );
    assert!(
        second.listed_signer(second_key).is_none(),
        "the lost key signs nothing under the new PIN"
    );
    let fresh = second.enrol();
    assert_ne!(
        fresh, second_key,
        "a fresh key is enrolled, never the lost one"
    );
    assert!(second.signs(fresh));
}

#[test]
fn a_seed_that_waited_through_a_forgotten_pin_is_removed_in_the_next_pin_s_window() {
    let first = PinDevice::hardware_counted();
    let second = first.second_vault();
    let second_key = second.enrol();
    let second_slot = second.owner_slot();

    first
        .vault
        .set_device_pin_as(&first.owner(), PIN, false)
        .expect("the owner adds a PIN to this device through the first vault");
    first
        .vault
        .forget_device_pin_as(&first.owner())
        .expect("the owner forgets this device's PIN");
    first
        .vault
        .set_device_pin_as(&first.owner(), OTHER_PIN, false)
        .expect("a new PIN is set through the first vault");
    assert!(
        first.pin.window_is_open(),
        "guard: the new PIN's window is open"
    );
    assert!(
        second
            .keystore
            .get(&second_slot)
            .expect("the slot reads")
            .is_some(),
        "guard: the second vault's seed still rests in its slot"
    );

    // The second vault's next checkpoint pass, inside the new PIN's window.
    second.vault.hold_device_owner_signer_in_pin_window();
    assert!(
        second
            .keystore
            .get(&second_slot)
            .expect("the slot reads")
            .is_none(),
        "the pass removes the seed that was lost with the forgotten PIN"
    );
    assert!(
        second.sealed(&SealedBytesName::Slot(second_slot)).is_none(),
        "and does not put it under the new PIN"
    );
    assert_eq!(second.rest(), OwnerKeyRest::NoKey);
    assert!(
        second.listed_signer(second_key).is_none(),
        "the lost key signs nothing inside the new PIN's window"
    );
}

#[test]
fn a_forget_on_a_device_that_never_had_a_pin_is_refused_and_its_key_stays() {
    let device = PinDevice::hardware_counted();
    let key = device.enrol();
    assert_eq!(
        pin_refusal(device.vault.forget_device_pin_as(&device.owner())),
        DevicePinRefusal::NotSet,
        "there is no PIN to forget"
    );
    assert!(
        device
            .sealed(&SealedBytesName::DevicePinForgotten)
            .is_none(),
        "and the device is not marked as one that forgot its PIN"
    );
    assert_eq!(device.rest(), OwnerKeyRest::Slot);
    assert!(device.signs(key), "the key in its slot signs as before");
}

#[test]
fn a_first_pin_whose_slot_delete_fails_after_it_removed_the_seed_keeps_the_key_under_the_pin() {
    let device = PinDevice::hardware_counted();
    let key = device.enrol();
    let slot = device.owner_slot();

    // The keystore removes the seed from its slot and then answers a
    // failure.
    device
        .keystore
        .fail_after_once(KeystoreCall::DeleteOwnerSlot, None);
    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the seed left its slot, so the first PIN is set whole");
    assert_eq!(
        device.pin.capability(),
        PresenceCapability::DevicePin { set: true }
    );
    assert!(
        device
            .keystore
            .get(&slot)
            .expect("the slot reads")
            .is_none(),
        "guard: the slot is empty"
    );
    assert!(
        device.sealed(&SealedBytesName::Slot(slot)).is_some(),
        "the sealed seed, now the only copy, is kept"
    );
    assert_eq!(
        device.rest(),
        OwnerKeyRest::DevicePin {
            public_key: key,
            tier: DevicePinTier::HardwareCounted,
        }
    );
    assert!(device.signs(key), "the key signs from under the PIN");
    device.pin.end_window();
    device
        .vault
        .confirm_device_pin(PIN)
        .expect("the PIN that was set confirms");
    assert!(device.signs(key));
}

#[test]
fn a_first_pin_that_fails_where_the_slot_does_not_answer_removes_nothing() {
    let device = PinDevice::hardware_counted();
    let key = device.enrol();
    let slot = device.owner_slot();

    // The slot's delete fails after its effect, and the read that would
    // tell where the seed is fails too.
    device.keystore.fail_after_once(
        KeystoreCall::DeleteOwnerSlot,
        Some(KeystoreCall::GetOwnerSlot),
    );
    assert!(
        device
            .vault
            .set_device_pin_as(&device.owner(), PIN, false)
            .is_err(),
        "the set reports the keystore's failure"
    );
    assert_eq!(
        device.pin.capability(),
        PresenceCapability::DevicePin { set: true },
        "nothing is undone where the seed is not seen in its slot: the PIN stays set"
    );
    assert!(
        device.sealed(&SealedBytesName::Slot(slot)).is_some(),
        "and the sealed seed is kept"
    );
    assert!(
        device.pin.window_is_open(),
        "guard: the set's own window is open"
    );
    assert!(
        device.vault.hold_device_owner_signer_logged(),
        "the next step inside a window opens the key from under the PIN"
    );
    assert!(device.signs(key), "no key was lost");
}

#[test]
fn a_first_pin_whose_undo_cannot_finish_keeps_the_seed_under_the_pin() {
    let device = PinDevice::hardware_counted();
    let key = device.enrol();
    let slot = device.owner_slot();

    // The slot's delete is refused with the seed still there, and so is the
    // removal of the device PIN key that would undo the set.
    device.keystore.refuse_once(KeystoreCall::DeleteOwnerSlot);
    device.keystore.refuse_once(KeystoreCall::DeleteAuthBound);
    assert!(
        device
            .vault
            .set_device_pin_as(&device.owner(), PIN, false)
            .is_err(),
        "the set reports the keystore's refusal"
    );
    assert_eq!(
        device.pin.capability(),
        PresenceCapability::DevicePin { set: true },
        "the device PIN key could not be removed: the PIN stays set"
    );
    assert!(
        device.sealed(&SealedBytesName::Slot(slot)).is_some(),
        "so the sealed seed stays too"
    );
    assert!(
        device
            .keystore
            .get(&slot)
            .expect("the slot reads")
            .is_some(),
        "guard: the seed is still in its slot"
    );
    assert!(!device.pin.window_is_open());
    assert_eq!(
        device.rest(),
        OwnerKeyRest::DevicePinUnopened {
            tier: DevicePinTier::HardwareCounted,
            seed_in_slot: true,
        }
    );
    assert!(
        device.listed_signer(key).is_none(),
        "the seed in the slot signs nothing beside a set PIN"
    );

    device
        .vault
        .confirm_device_pin(PIN)
        .expect("the PIN that stayed set confirms");
    assert!(
        device
            .keystore
            .get(&slot)
            .expect("the slot reads")
            .is_none(),
        "the next right PIN finishes the step: the slot is emptied"
    );
    assert_eq!(
        device.rest(),
        OwnerKeyRest::DevicePin {
            public_key: key,
            tier: DevicePinTier::HardwareCounted,
        }
    );
    assert!(device.signs(key));
}

#[test]
fn a_signer_whose_seed_left_its_slot_signs_nothing_once_the_mark_of_the_forgotten_pin_is_removed() {
    let device = PinDevice::hardware_counted();
    let key = device.enrol();
    let slot = device.owner_slot();
    // The two ways a caller comes by the key while no PIN is set.
    let listed = device
        .listed_signer(key)
        .expect("guard: with no PIN the pass gets the signer");
    let handed_out = device
        .vault
        .device_owner_signing_key()
        .expect("guard: with no PIN the key is handed out");

    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner adds a PIN to this device");
    device
        .vault
        .forget_device_pin_as(&device.owner())
        .expect("the owner forgets this device's PIN");
    // A writer of the keystore's files removes the mark the forget left.
    let mark = SealedBytesName::DevicePinForgotten;
    assert!(
        device.sealed(&mark).is_some(),
        "guard: the forget left its mark"
    );
    device
        .keystore
        .sealed()
        .delete_sealed(&mark)
        .expect("the mark is removed");
    assert!(device.sealed(&mark).is_none(), "guard: the mark is gone");
    assert_eq!(
        device.pin.capability(),
        PresenceCapability::DevicePin { set: false },
        "guard: no PIN is set, so the keystore says nothing of a PIN now"
    );
    assert!(
        device
            .keystore
            .get(&slot)
            .expect("the slot reads")
            .is_none(),
        "guard: the seed left its slot when the PIN was set"
    );
    for signer in [&*listed, &handed_out as &dyn CheckpointRootSigner] {
        assert!(
            !signer.signs_now(&device.vault),
            "a signer whose seed left its slot is not listed for the pass, mark or no mark"
        );
        assert!(
            signer
                .sign_checkpoint_statement(&device.vault, STATEMENT)
                .is_err(),
            "and it signs nothing: the roster still lists the lost key, and nothing else stops it"
        );
    }

    // Another seed in the slot is another key.
    device
        .keystore
        .create(&slot, &[0x5a; 32])
        .expect("another seed goes into the slot");
    for signer in [&*listed, &handed_out as &dyn CheckpointRootSigner] {
        assert!(
            signer
                .sign_checkpoint_statement(&device.vault, STATEMENT)
                .is_err(),
            "a signer of the lost key signs nothing for a seed that is not its own"
        );
    }
}

#[test]
fn a_replacement_whose_sealed_write_answers_a_failure_is_not_told_as_the_replaced_key() {
    let device = PinDevice::hardware_counted();
    device
        .vault
        .set_device_pin_as(&device.owner(), PIN, false)
        .expect("the owner sets the PIN");
    let replaced = device.enrol();
    assert_eq!(
        device.rest(),
        OwnerKeyRest::DevicePin {
            public_key: replaced,
            tier: DevicePinTier::HardwareCounted,
        },
        "guard: this handle names the key it enrolled under the PIN"
    );

    // The sealed seed no longer opens, as after a write that was cut short:
    // the next enrollment puts a fresh key in its place.
    let name = SealedBytesName::Slot(device.owner_slot());
    let mut cut_short = device.sealed(&name).expect("the sealed seed rests");
    let kept = cut_short.len() / 2;
    cut_short.truncate(kept);
    device
        .keystore
        .sealed()
        .put_sealed(&name, &cut_short)
        .expect("the damaged bytes go under the slot's name");
    // The replacement's sealed write lands, and the keystore answers a
    // failure for it.
    device
        .keystore
        .fail_after_once(KeystoreCall::PutSealedSlot, None);
    assert!(
        device.pin.window_is_open(),
        "guard: the window is still open"
    );
    assert!(
        device
            .vault
            .enrol_device_owner_signing_key(&device.owner(), &device.issuer)
            .is_err(),
        "the enrollment reports the keystore's failure"
    );
    let landed = device.sealed(&name).expect("the replacement's bytes rest");
    assert_ne!(
        landed, cut_short,
        "guard: the write that answered a failure did replace what rested"
    );
    assert_eq!(
        device.rest(),
        OwnerKeyRest::DevicePinUnopened {
            tier: DevicePinTier::HardwareCounted,
            seed_in_slot: false,
        },
        "the handle no longer names the key whose sealed seed that write replaced"
    );

    // The next step inside the window opens what rests now, and names that.
    assert!(
        !device.vault.hold_device_owner_signer_logged(),
        "the key that landed is not on the roster, so it is not held"
    );
    assert!(
        matches!(
            device.rest(),
            OwnerKeyRest::DevicePin { public_key, tier: DevicePinTier::HardwareCounted }
                if public_key != replaced
        ),
        "the handle then names the key that rests, never the replaced one"
    );
}
