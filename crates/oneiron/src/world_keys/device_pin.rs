//! The device PIN (row OCS-OWNER-PIN): how a device with no unlock prompt of
//! its own confirms its owner, and what keeps this install's owner signing
//! key from signing with nobody there.
//!
//! One PIN per device guards one random 32-byte key, the device PIN key, and
//! that key seals each vault's owner signing seed (the `owner_key` module
//! below this one). So a new PIN re-seals one object, and one PIN serves
//! every vault this install holds.
//!
//! Where the device PIN key rests:
//! - A keystore whose secure hardware counts wrong tries
//!   ([`DeviceKeystore::auth_bound_secret`], the TPM tier): in the hardware,
//!   under an auth value derived from the PIN. The PIN is not stretched
//!   there: a guess needs the hardware, and the hardware counts.
//! - Any other keystore with a home for sealed bytes
//!   ([`DeviceKeystore::sealed_bytes`], the file tier): in a passphrase
//!   envelope at the recovery kit's Argon2id cost. Nothing limits guesses on
//!   a copy of that file, which is why a PIN there is a passphrase.
//! - A keystore with neither takes no device PIN.
//!
//! The key is in this process's memory only inside the window a right PIN
//! opens ([`oneiron_keystore::PRESENCE_WINDOW_SECS`]). The keystore crate's
//! [`PresenceGate`] keeps that window and counts wrong PINs; this module is
//! its backend. When the window ends the gate tells the backend, which wipes
//! the key. The key is not handed out: each use runs under the lock that
//! wipe takes, so a use begun inside the window ends before the window does,
//! and none begins after it. A key that a typed PIN opened is no key a use
//! reads until the gate took that PIN's window: a PIN checked while the
//! window was ended gives a use nothing, however the two fall in time.
//!
//! One step at a time reads or changes what rests under the PIN: a typed
//! PIN's check, a set, a change, a forget, and each step that puts an owner
//! signing key under the device PIN key. The lock is this process's. A host
//! makes one [`DevicePin`] per keystore and installs it on every vault handle
//! over that keystore.
//!
//! A forgotten PIN is a lost key, and it stays lost. The forget leaves a
//! mark in the keystore's home for sealed bytes before it removes the device
//! PIN key ([`SealedBytesName::DevicePinForgotten`]). From then on a seed in
//! a keystore slot of this device is no owner signing key, with a PIN set or
//! with none: not one that waited in its slot while the PIN was set, and not
//! one a signer read before it. The device makes its next key under a new
//! PIN.
//!
//! What the PIN guards is the owner signing key and each act that needs its
//! signature. It is not a second login: an act this install carries with its
//! own machine key needs no PIN.

mod owner_key;
mod presence_backend;
mod secret_seal;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::Duration;

use oneiron_crypto::Passphrase;
use oneiron_keystore::{
    DeviceKeystore, KeystoreError, KeystoreSlot, PresenceCapability, PresenceClock, PresenceError,
    PresenceGate, PresenceWindow, SCREEN_LOCK_POLL_MS, SealedBytesName, SealedBytesStore,
    SystemPresenceClock,
};
use zeroize::Zeroizing;

pub use self::owner_key::OwnerKeyRest;
pub(super) use self::owner_key::PinBoundOwnerKey;
use super::{keystore_error, refused};
use crate::error::{DevicePinRefusal, Error, Result, SecretError};
use crate::recovery::PassphraseCost;

/// The fewest characters of a device PIN where nothing counts wrong tries
/// but this process: there the PIN is a passphrase.
pub const DEVICE_PIN_MIN_CHARS: u32 = 12;

/// The fewest characters of a device PIN where the keystore's hardware
/// counts wrong tries, and anywhere the owner chose a short PIN for this
/// device.
pub const DEVICE_PIN_SHORT_MIN_CHARS: u32 = 6;

/// What the mark of a forgotten PIN holds. It is no secret: that it rests is
/// the fact.
const FORGOTTEN_MARK: &[u8] = b"oneiron/device-pin-forgotten/v1";

const NO_PIN_HOME: &str = "its keystore has no home for a device PIN key";
const NO_PIN_SET: &str = "no device PIN is set on it";
const PIN_HOME_UNREADABLE: &str = "its keystore did not answer for the device PIN key";
const NO_WINDOW_WATCH: &str = "the watch that ends the device PIN's window could not start";
const SCREEN_LOCKED: &str = "its screen is locked";
const NOT_CONFIRMED: &str = "the confirm was not given";
const NO_DEVICE_PIN_HERE: &str = "this host installed no device PIN on this vault";
const COST_OUT_OF_RANGE: &str = "the device PIN's passphrase cost is outside the recovery kit's \
                                 floor and ceiling";
const PIN_KEY_NOT_READ_BACK: &str = "the device PIN key did not read back from its home; this \
                                     device has no PIN";

/// What counts wrong device PINs on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePinTier {
    /// The keystore's secure hardware holds the device PIN key and counts
    /// wrong PINs itself, across restarts.
    HardwareCounted,
    /// The device PIN key rests in a passphrase envelope. This process
    /// counts wrong PINs at its own door; nothing limits guesses on a copy
    /// of the file.
    Passphrase,
}

/// One process's device PIN: the gate that takes the PIN, and the device PIN
/// key while a right PIN's window is open. Every vault handle of the process
/// that shares its keystore shares it ([`crate::Vault::install_device_pin`]),
/// so one right PIN serves them all.
pub struct DevicePin {
    gate: PresenceGate,
    backend: Arc<DevicePinBackend>,
    /// Held across each whole step that reads or changes what rests under
    /// the PIN ([`Self::step`]), so no two of them cross.
    step: Mutex<()>,
    /// How many steps found another one running and waited for it.
    step_waits: AtomicU64,
    /// How many right PINs this process took.
    right_pins: AtomicU64,
    /// How many times this process set or forgot the device PIN key. What a
    /// vault handle opened under one key counts for nothing under the next.
    key_generation: AtomicU64,
}

/// Proof that its holder is inside a device PIN's step ([`DevicePin::step`]).
pub(crate) struct DevicePinStep<'a> {
    _held: MutexGuard<'a, ()>,
}

impl std::fmt::Debug for DevicePin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DevicePin")
            .field("capability", &self.capability())
            .finish_non_exhaustive()
    }
}

/// The gate's backend: it checks a typed PIN by opening the device PIN key
/// with it, and holds that key until the gate says the window ended.
struct DevicePinBackend {
    keystore: Arc<dyn DeviceKeystore>,
    /// The Argon2id cost a new passphrase envelope is sealed at.
    cost: PassphraseCost,
    /// The device PIN key in this process's memory.
    held: Mutex<HeldPinKey>,
}

/// The device PIN key in this process's memory. The window's end wipes both
/// places.
#[derive(Default)]
struct HeldPinKey {
    /// The key a typed PIN just opened, while the gate has not taken that
    /// PIN's window. No use reads it.
    checked: Option<Zeroizing<[u8; 32]>>,
    /// The key inside a window the gate took: the one a use reads.
    open: Option<Zeroizing<[u8; 32]>>,
}

impl DevicePin {
    /// The device PIN over `keystore`, on the system's clocks, sealing at
    /// the recovery kit's default cost.
    ///
    /// # Errors
    /// As [`Self::with_clock_and_cost`].
    pub fn new(keystore: Arc<dyn DeviceKeystore>) -> Result<Arc<Self>> {
        Self::with_clock_and_cost(
            keystore,
            Arc::new(SystemPresenceClock::new()),
            PassphraseCost::DEFAULT,
        )
    }

    /// The device PIN over `keystore`, whose window and wait read `clock`,
    /// and whose passphrase envelope is sealed at `cost`, stepping down to
    /// the kit's floor when the device cannot give the memory. Its gate's
    /// watch is started: it ends a window whose time is over when no act
    /// comes, so the key is never held past its window.
    ///
    /// # Errors
    /// A `cost` outside the recovery kit's floor and ceiling, which a reader
    /// of the envelope would refuse; the watch could not start.
    pub fn with_clock_and_cost(
        keystore: Arc<dyn DeviceKeystore>,
        clock: Arc<dyn PresenceClock>,
        cost: PassphraseCost,
    ) -> Result<Arc<Self>> {
        let cost = PassphraseCost::new(cost.memory_mib, cost.passes)
            .map_err(|_| refused(COST_OUT_OF_RANGE))?;
        let backend = Arc::new(DevicePinBackend {
            keystore,
            cost,
            held: Mutex::new(HeldPinKey::default()),
        });
        let gate = PresenceGate::new(
            Arc::<DevicePinBackend>::clone(&backend),
            PresenceWindow::new(clock),
        );
        gate.watch_screen_lock(Duration::from_millis(SCREEN_LOCK_POLL_MS))
            .map_err(|_| pin_refused(DevicePinRefusal::Unavailable(NO_WINDOW_WATCH)))?;
        Ok(Arc::new(Self {
            gate,
            backend,
            step: Mutex::new(()),
            step_waits: AtomicU64::new(0),
            right_pins: AtomicU64::new(0),
            key_generation: AtomicU64::new(0),
        }))
    }

    /// Whether this device takes a PIN, and whether one is set.
    #[must_use]
    pub fn capability(&self) -> PresenceCapability {
        self.gate.capability()
    }

    /// What counts wrong PINs here; `None` on a device that takes no PIN.
    #[must_use]
    pub fn tier(&self) -> Option<DevicePinTier> {
        device_pin_tier(self.backend.keystore.as_ref())
    }

    /// The fewest characters a new PIN has on this device:
    /// [`DEVICE_PIN_SHORT_MIN_CHARS`] where the hardware counts wrong tries
    /// or the owner chose a short PIN for this device (`short_pin_allowed`),
    /// else [`DEVICE_PIN_MIN_CHARS`].
    #[must_use]
    pub fn min_chars(&self, short_pin_allowed: bool) -> u32 {
        if short_pin_allowed || self.tier() == Some(DevicePinTier::HardwareCounted) {
            DEVICE_PIN_SHORT_MIN_CHARS
        } else {
            DEVICE_PIN_MIN_CHARS
        }
    }

    /// Whether a right PIN's window is open now.
    #[must_use]
    pub fn window_is_open(&self) -> bool {
        self.gate.window_is_open()
    }

    /// Ends the window at once. The device PIN key is wiped with it.
    pub fn end_window(&self) {
        self.gate.end_window();
    }

    /// How long this device still takes no PIN after too many wrong ones, in
    /// whole seconds; `None` when it takes one now. The hardware's own
    /// lockout, where there is one, is told only by a refused PIN.
    #[must_use]
    pub fn wait_secs(&self) -> Option<u64> {
        self.gate.typed_secret_wait_secs()
    }

    /// How many right PINs this process took. A host that does work once at
    /// each right PIN compares it with the count it last saw.
    #[must_use]
    pub fn right_pins(&self) -> u64 {
        self.right_pins.load(Ordering::Relaxed)
    }

    /// Takes the PIN the owner typed. The right one opens the window and
    /// puts the device PIN key in memory for it; anything else opens
    /// nothing. It neither keeps nor logs `pin`. It is a step of its own: it
    /// waits for a set, a change or a forget that runs, so a PIN is never
    /// checked against a key that is on its way out. The check may take a
    /// second: never call it while holding a lock other work waits on.
    ///
    /// The count of wrong PINs is this object's, in memory
    /// ([`PresenceGate::confirm_with_secret`]): it stops a person at the
    /// device and an agent that calls a door. A host that makes a new
    /// `DevicePin`, and a restart, start it over; the hardware's own count,
    /// where there is one, is the chip's and stays.
    ///
    /// # Errors
    /// [`SecretError::DevicePin`]: `Wrong`; `TooManyTries` for the wrong PIN
    /// that starts the wait, for every PIN inside it, and while the hardware
    /// itself refuses; `NotSet`; `Unavailable` on a device that takes no PIN.
    pub fn confirm(&self, pin: &[u8]) -> Result<()> {
        self.confirm_in_step(&self.step(), pin)
    }

    /// [`Self::confirm`], for a caller inside a step.
    fn confirm_in_step(&self, _step: &DevicePinStep<'_>, pin: &[u8]) -> Result<()> {
        match self.capability() {
            PresenceCapability::DevicePin { set: true } => {}
            PresenceCapability::DevicePin { set: false } => {
                return Err(pin_refused(DevicePinRefusal::NotSet));
            }
            PresenceCapability::NoPrompt(reason) => {
                return Err(pin_refused(DevicePinRefusal::Unavailable(reason)));
            }
            PresenceCapability::DevicePrompt => {
                return Err(pin_refused(DevicePinRefusal::Unavailable(NO_PIN_HOME)));
            }
        }
        if let Err(refusal) = self.gate.confirm_with_secret(pin) {
            // The gate took no window: what the PIN opened is not kept.
            self.backend.drop_checked_key();
            return Err(presence_refused(refusal));
        }
        // The gate took the window. Only now is the key one a use reads; a
        // window that ended since has wiped it.
        self.backend.admit_checked_key();
        self.right_pins.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Whether this device PIN guards `keystore`: the one a vault handle
    /// keeps its slots in.
    fn guards(&self, keystore: &Arc<dyn DeviceKeystore>) -> bool {
        std::ptr::addr_eq(Arc::as_ptr(&self.backend.keystore), Arc::as_ptr(keystore))
    }

    /// Runs `use_key` with the device PIN key, while a right PIN's window is
    /// open. The key is not copied out: `use_key` runs under the lock the
    /// window's end takes to wipe it, so an end lands wholly before a use or
    /// wholly after it, and what a use opened is dropped inside it.
    /// `use_key` is short, reads no home and never calls the gate.
    ///
    /// # Errors
    /// [`DevicePinRefusal::Required`] outside a window; `NotSet` and
    /// `Unavailable` as [`Self::confirm`].
    fn with_pin_key<T>(&self, use_key: impl FnOnce(&[u8; 32]) -> T) -> Result<T> {
        // The window is read first and outside the key's lock: a window
        // found over tells the backend under its own lock. A window that
        // ends between the two has wiped the key, and a PIN checked since
        // gives none until the gate took its window.
        if self.gate.window_is_open() {
            let held = self.backend.held_key();
            if let Some(key) = held.open.as_deref() {
                return Ok(use_key(key));
            }
        }
        Err(pin_refused(match self.capability() {
            PresenceCapability::DevicePin { set: true } => DevicePinRefusal::Required,
            PresenceCapability::DevicePin { set: false } => DevicePinRefusal::NotSet,
            PresenceCapability::NoPrompt(reason) => DevicePinRefusal::Unavailable(reason),
            PresenceCapability::DevicePrompt => DevicePinRefusal::Unavailable(NO_PIN_HOME),
        }))
    }

    /// Refuses outside a right PIN's window, as [`Self::with_pin_key`].
    fn require_window(&self) -> Result<()> {
        self.with_pin_key(|_| ())
    }

    /// Whether this device can take `pin` as its first PIN now. Nothing is
    /// stored.
    ///
    /// # Errors
    /// [`DevicePinRefusal::AlreadySet`]; `TooShort`; `TooManyTries` while
    /// this device takes no PIN after too many wrong ones, because a PIN set
    /// then could not be confirmed; `Unavailable` on a device that takes no
    /// PIN. A PIN longer than 1024 bytes is refused as no passphrase an
    /// envelope takes.
    fn check_first_pin(
        &self,
        _step: &DevicePinStep<'_>,
        pin: &[u8],
        short_pin_allowed: bool,
    ) -> Result<()> {
        match self.capability() {
            PresenceCapability::DevicePin { set: false } => {}
            PresenceCapability::DevicePin { set: true } => {
                return Err(pin_refused(DevicePinRefusal::AlreadySet));
            }
            PresenceCapability::NoPrompt(reason) => {
                return Err(pin_refused(DevicePinRefusal::Unavailable(reason)));
            }
            PresenceCapability::DevicePrompt => {
                return Err(pin_refused(DevicePinRefusal::Unavailable(NO_PIN_HOME)));
            }
        }
        check_new_pin(pin, self.min_chars(short_pin_allowed))?;
        match self.wait_secs() {
            Some(wait_secs) => Err(pin_refused(DevicePinRefusal::TooManyTries { wait_secs })),
            None => Ok(()),
        }
    }

    /// Puts `key` to rest under `pin` as this device's PIN key, and opens a
    /// window with it. `Ok` only when the key the window then holds is `key`,
    /// read back from its home with `pin`. The caller undoes a refusal with
    /// [`Self::remove_pin_key`].
    ///
    /// # Errors
    /// The keystore's refusal; as [`Self::confirm`] for a PIN its home does
    /// not open with (the hardware's own lockout, a locked screen); a
    /// refusal for a home that gives back another key.
    fn store_first_key(&self, step: &DevicePinStep<'_>, pin: &[u8], key: &[u8; 32]) -> Result<()> {
        self.backend.store_pin_key(pin, key)?;
        self.confirm_in_step(step, pin)?;
        if !self.with_pin_key(|held| held == key)? {
            return Err(refused(PIN_KEY_NOT_READ_BACK));
        }
        self.key_generation.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Changes the PIN: `old` is checked as any typed PIN is, and the same
    /// device PIN key then rests under `new`. Nothing sealed under that key
    /// changes.
    ///
    /// # Errors
    /// As [`Self::confirm`] for `old`; [`DevicePinRefusal::TooShort`] for
    /// `new`, before `old` is checked; the keystore's refusal. A `new` longer
    /// than 1024 bytes is refused as no passphrase an envelope takes.
    fn change(
        &self,
        step: &DevicePinStep<'_>,
        old: &[u8],
        new: &[u8],
        short_pin_allowed: bool,
    ) -> Result<()> {
        check_new_pin(new, self.min_chars(short_pin_allowed))?;
        self.confirm_in_step(step, old)?;
        // The one copy of the key made outside the backend. Sealing it under
        // the new PIN may take a second, and the window's end never waits
        // that long. It lives inside this step, which `old` just opened.
        let key = self.with_pin_key(|held| {
            let mut copy = Zeroizing::new([0u8; 32]);
            copy.copy_from_slice(held);
            copy
        })?;
        self.backend.store_pin_key(new, &key)
    }

    /// Forgets the PIN: marks this device as one whose PIN was forgotten,
    /// ends the window and removes the device PIN key from its home.
    /// Everything sealed under that key is lost with it, and so is every
    /// seed that still waited in a keystore slot of this device
    /// ([`slot_seed_bar`]). It takes no PIN, because it only loses.
    ///
    /// The mark is written first: a forget that stops after it has lost the
    /// slot seeds and not yet the device PIN key, and the forget asked again
    /// finishes it. So it also runs on a device that holds the mark and no
    /// PIN.
    ///
    /// # Errors
    /// [`DevicePinRefusal::NotSet`] on a device that has no PIN and never
    /// forgot one: there is nothing to lose, and its slot keys stay keys.
    /// The keystore's refusal.
    fn forget(&self, step: &DevicePinStep<'_>) -> Result<()> {
        let keystore = self.backend.keystore.as_ref();
        if slot_seed_bar(keystore).map_err(keystore_error)?.is_none() {
            return Err(pin_refused(DevicePinRefusal::NotSet));
        }
        self.sealed_home()?
            .put_sealed(&SealedBytesName::DevicePinForgotten, FORGOTTEN_MARK)
            .map_err(keystore_error)?;
        self.remove_pin_key(step)
    }

    /// Ends the window and removes the device PIN key from its home, with no
    /// mark: [`Self::forget`]'s last part, and the undo of a first PIN that
    /// did not finish.
    ///
    /// # Errors
    /// The keystore's refusal.
    fn remove_pin_key(&self, _step: &DevicePinStep<'_>) -> Result<()> {
        self.gate.end_window();
        self.key_generation.fetch_add(1, Ordering::Relaxed);
        let keystore = self.backend.keystore.as_ref();
        if let Some(hardware) = keystore.auth_bound_secret() {
            hardware.delete_auth_bound().map_err(keystore_error)?;
        }
        if let Some(home) = keystore.sealed_bytes() {
            home.delete_sealed(&SealedBytesName::DevicePinKey)
                .map_err(keystore_error)?;
        }
        Ok(())
    }

    /// The count of device PIN keys this process set or forgot.
    fn key_generation(&self) -> u64 {
        self.key_generation.load(Ordering::Relaxed)
    }

    /// The home of the secrets sealed under the device PIN key.
    fn sealed_home(&self) -> Result<&dyn SealedBytesStore> {
        self.backend
            .keystore
            .sealed_bytes()
            .ok_or_else(|| pin_refused(DevicePinRefusal::Unavailable(NO_PIN_HOME)))
    }

    /// The sealed secret of `slot` as it rests; `None` when none does.
    fn sealed_slot(&self, slot: &KeystoreSlot) -> Result<Option<Vec<u8>>> {
        self.sealed_home()?
            .get_sealed(&SealedBytesName::Slot(*slot))
            .map_err(keystore_error)
    }

    fn put_sealed_slot(&self, slot: &KeystoreSlot, sealed: &[u8]) -> Result<()> {
        self.sealed_home()?
            .put_sealed(&SealedBytesName::Slot(*slot), sealed)
            .map_err(keystore_error)
    }

    fn delete_sealed_slot(&self, slot: &KeystoreSlot) -> Result<()> {
        self.sealed_home()?
            .delete_sealed(&SealedBytesName::Slot(*slot))
            .map_err(keystore_error)
    }

    /// Enters a step: one at a time reads or changes what rests under the
    /// PIN. A typed PIN's check, a set, a change and a forget are each one
    /// whole step, and so is each step that puts an owner signing key under
    /// the device PIN key, makes one there, or makes one in a slot while no
    /// PIN is set. A signature is no step: it takes only the key's own lock.
    pub(crate) fn step(&self) -> DevicePinStep<'_> {
        let held = match self.step.try_lock() {
            Ok(held) => held,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                self.step_waits.fetch_add(1, Ordering::Relaxed);
                self.step.lock().unwrap_or_else(PoisonError::into_inner)
            }
        };
        DevicePinStep { _held: held }
    }

    /// Test door (`test_doors::device_pin`): how many steps found another
    /// one running and waited for it.
    #[cfg(oneiron_test_support)]
    pub(crate) fn steps_that_waited(&self) -> u64 {
        self.step_waits.load(Ordering::Relaxed)
    }
}

/// Whether a device PIN key rests in `keystore`: in its hardware where that
/// counts wrong tries, else in its home for sealed bytes.
pub(super) fn device_pin_is_set(
    keystore: &dyn DeviceKeystore,
) -> std::result::Result<bool, KeystoreError> {
    if let Some(hardware) = keystore.auth_bound_secret() {
        return hardware.holds_auth_bound();
    }
    match keystore.sealed_bytes() {
        Some(home) => Ok(home.get_sealed(&SealedBytesName::DevicePinKey)?.is_some()),
        None => Ok(false),
    }
}

/// Whether a PIN of this device was forgotten: the mark
/// [`DevicePin::forget`] leaves in `keystore`'s home for sealed bytes.
pub(super) fn device_pin_was_forgotten(
    keystore: &dyn DeviceKeystore,
) -> std::result::Result<bool, KeystoreError> {
    match keystore.sealed_bytes() {
        Some(home) => Ok(home
            .get_sealed(&SealedBytesName::DevicePinForgotten)?
            .is_some()),
        None => Ok(false),
    }
}

/// Why a seed in a keystore slot is no owner signing key on a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SlotSeedBar {
    /// A PIN is set: the key rests under it, and signs from there.
    PinSet,
    /// No PIN is set, and one was forgotten: every key this device held was
    /// lost with it. The next key is made under a new PIN.
    PinForgotten,
}

/// Why a seed in a slot of `keystore` is no owner signing key now; `None`
/// on a device that has no PIN and never forgot one, where it is the key.
/// Every door that reads a slot seed as a key, or makes one there, asks it,
/// and so does a signer read from a slot, at each signature.
pub(super) fn slot_seed_bar(
    keystore: &dyn DeviceKeystore,
) -> std::result::Result<Option<SlotSeedBar>, KeystoreError> {
    if device_pin_is_set(keystore)? {
        return Ok(Some(SlotSeedBar::PinSet));
    }
    if device_pin_was_forgotten(keystore)? {
        return Ok(Some(SlotSeedBar::PinForgotten));
    }
    Ok(None)
}

/// What counts wrong device PINs on `keystore`; `None` for one that takes no
/// PIN.
fn device_pin_tier(keystore: &dyn DeviceKeystore) -> Option<DevicePinTier> {
    keystore.sealed_bytes()?;
    Some(if keystore.auth_bound_secret().is_some() {
        DevicePinTier::HardwareCounted
    } else {
        DevicePinTier::Passphrase
    })
}

pub(super) fn pin_refused(refusal: DevicePinRefusal) -> Error {
    Error::Secret(SecretError::DevicePin(refusal))
}

/// The refusal of a host that installed no device PIN on a vault handle, on
/// a device where a PIN is set.
pub(super) fn no_device_pin_here() -> Error {
    pin_refused(DevicePinRefusal::Unavailable(NO_DEVICE_PIN_HERE))
}

/// The gate's refusal of a typed PIN, as this crate's error.
pub(super) fn presence_refused(refusal: PresenceError) -> Error {
    pin_refused(match refusal {
        PresenceError::PinRequired => DevicePinRefusal::Required,
        PresenceError::WrongPin => DevicePinRefusal::Wrong,
        PresenceError::TooManyTries { wait_secs } => DevicePinRefusal::TooManyTries { wait_secs },
        PresenceError::NoPrompt(reason) | PresenceError::Platform(reason, _) => {
            DevicePinRefusal::Unavailable(reason)
        }
        PresenceError::ScreenLocked => DevicePinRefusal::Unavailable(SCREEN_LOCKED),
        PresenceError::Declined | PresenceError::NoAnswer => {
            DevicePinRefusal::Unavailable(NOT_CONFIRMED)
        }
    })
}

/// Refuses a new PIN shorter than `min_chars`, counted in characters where
/// the PIN is text and in bytes where it is not, and one longer than a
/// passphrase envelope takes.
fn check_new_pin(pin: &[u8], min_chars: u32) -> Result<()> {
    let chars = std::str::from_utf8(pin).map_or(pin.len(), |text| text.chars().count());
    if chars < usize::try_from(min_chars).unwrap_or(usize::MAX) {
        return Err(pin_refused(DevicePinRefusal::TooShort { min_chars }));
    }
    if pin.len() > Passphrase::MAX_LEN {
        return Err(refused("the device PIN is longer than 1024 bytes"));
    }
    Ok(())
}
