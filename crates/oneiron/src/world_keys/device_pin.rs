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
//! and none begins after it.
//!
//! One step at a time reads or changes what rests under the PIN: a typed
//! PIN's check, a set, a change, a forget, and each step that puts an owner
//! signing key under the device PIN key. The lock is this process's. A host
//! makes one [`DevicePin`] per keystore and installs it on every vault handle
//! over that keystore.
//!
//! What the PIN guards is the owner signing key and each act that needs its
//! signature. It is not a second login: an act this install carries with its
//! own machine key needs no PIN.

mod owner_key;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use getrandom::SysRng;
use oneiron_crypto::{
    Argon2Cost, Envelope, Kek, OpenKey, OpenPolicy, Passphrase, Purpose, SealKey, SealParams,
    SuiteId, WrapType, seal, seal_with_aad,
};
use oneiron_keystore::{
    AuthBoundError, DeviceKeystore, KeystoreError, KeystoreSlot, PresenceCapability, PresenceClock,
    PresenceError, PresenceGate, PresenceWindow, SCREEN_LOCK_POLL_MS, SealedBytesName,
    SealedBytesStore, SystemPresenceClock, UserPresence,
};
use zeroize::Zeroizing;

pub use self::owner_key::OwnerKeyRest;
use super::{derive_guarded, keystore_error, refused};
use crate::error::{DevicePinRefusal, Error, Result, SecretError};
use crate::recovery::PassphraseCost;

/// The fewest characters of a device PIN where nothing counts wrong tries
/// but this process: there the PIN is a passphrase.
pub const DEVICE_PIN_MIN_CHARS: u32 = 12;

/// The fewest characters of a device PIN where the keystore's hardware
/// counts wrong tries, and anywhere the owner chose a short PIN for this
/// device.
pub const DEVICE_PIN_SHORT_MIN_CHARS: u32 = 6;

const AEAD: SuiteId = SuiteId::XCHACHA20POLY1305_V1;
const DEVICE_PIN_EPOCH: u64 = 1;

/// The context the hardware's auth value is derived under from the PIN.
const AUTH_VALUE_CONTEXT: &str = "oneiron/device-pin-auth-value/v1";

// The ids the device PIN key's envelope is bound to. The key belongs to the
// device and to no vault, so they are constants.
const PIN_KEY_SCOPE: &[u8] = b"oneiron/this-device";
const PIN_KEY_RECIPIENT: &[u8] = b"oneiron/device-pin";
const PIN_KEY_ID: &[u8] = b"oneiron/device-pin-key/v1";

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
    /// How many right PINs this process took.
    right_pins: AtomicU64,
    /// How many times this process set or forgot the device PIN key. What a
    /// vault handle opened under one key counts for nothing under the next.
    key_generation: AtomicU64,
}

/// Proof that its holder is inside a device PIN's step ([`DevicePin::step`]).
pub(in crate::world_keys) struct DevicePinStep<'a> {
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
    /// The device PIN key, only inside a window.
    open_key: Mutex<Option<Zeroizing<[u8; 32]>>>,
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
            open_key: Mutex::new(None),
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
        self.gate
            .confirm_with_secret(pin)
            .map_err(presence_refused)?;
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
        // found over tells the backend under its own lock.
        if self.gate.window_is_open() {
            let held = self.backend.open_key();
            if let Some(key) = held.as_deref() {
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
    /// [`Self::forget`].
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

    /// Forgets the PIN: ends the window and removes the device PIN key from
    /// its home. Everything sealed under that key is lost with it. It takes
    /// no PIN, because it only loses.
    ///
    /// # Errors
    /// The keystore's refusal.
    fn forget(&self, _step: &DevicePinStep<'_>) -> Result<()> {
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
    pub(in crate::world_keys) fn step(&self) -> DevicePinStep<'_> {
        DevicePinStep {
            _held: self.step.lock().unwrap_or_else(PoisonError::into_inner),
        }
    }
}

impl DevicePinBackend {
    fn open_key(&self) -> MutexGuard<'_, Option<Zeroizing<[u8; 32]>>> {
        self.open_key.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The device PIN key, opened from its home with `pin`.
    fn open_pin_key(&self, pin: &[u8]) -> std::result::Result<Zeroizing<[u8; 32]>, PresenceError> {
        if let Some(hardware) = self.keystore.auth_bound_secret() {
            let auth = auth_value(pin);
            return match hardware.open_auth_bound(&auth[..]) {
                Ok(Some(key)) => Ok(key),
                Ok(None) => Err(PresenceError::NoPrompt(NO_PIN_SET)),
                Err(AuthBoundError::WrongAuth) => Err(PresenceError::WrongPin),
                Err(AuthBoundError::LockedOut { wait_secs }) => {
                    Err(PresenceError::TooManyTries { wait_secs })
                }
                Err(AuthBoundError::Keystore(_)) => {
                    Err(PresenceError::Platform(PIN_HOME_UNREADABLE, 0))
                }
            };
        }
        let home = self
            .keystore
            .sealed_bytes()
            .ok_or(PresenceError::NoPrompt(NO_PIN_HOME))?;
        let sealed = home
            .get_sealed(&SealedBytesName::DevicePinKey)
            .map_err(|_| PresenceError::Platform(PIN_HOME_UNREADABLE, 0))?
            .ok_or(PresenceError::NoPrompt(NO_PIN_SET))?;
        // An envelope that does not open is a wrong PIN: the two are not
        // told apart.
        open_pin_key_envelope(&sealed, pin).ok_or(PresenceError::WrongPin)
    }

    /// Puts `key` to rest under `pin`, in place of any key there, in one
    /// step of its home.
    fn store_pin_key(&self, pin: &[u8], key: &[u8; 32]) -> Result<()> {
        if let Some(hardware) = self.keystore.auth_bound_secret() {
            let auth = auth_value(pin);
            return hardware
                .put_auth_bound(&auth[..], key)
                .map_err(keystore_error);
        }
        let home = self
            .keystore
            .sealed_bytes()
            .ok_or_else(|| pin_refused(DevicePinRefusal::Unavailable(NO_PIN_HOME)))?;
        let sealed = seal_pin_key_envelope(key, pin, self.cost)?;
        home.put_sealed(&SealedBytesName::DevicePinKey, &sealed)
            .map_err(keystore_error)
    }
}

impl UserPresence for DevicePinBackend {
    fn capability(&self) -> PresenceCapability {
        if self.keystore.sealed_bytes().is_none() {
            return PresenceCapability::NoPrompt(NO_PIN_HOME);
        }
        match device_pin_is_set(self.keystore.as_ref()) {
            Ok(set) => PresenceCapability::DevicePin { set },
            Err(_) => PresenceCapability::NoPrompt(PIN_HOME_UNREADABLE),
        }
    }

    /// A device PIN has no prompt to show: the host collects the PIN.
    fn confirm(&self, _reason: &str) -> std::result::Result<(), PresenceError> {
        match self.capability() {
            PresenceCapability::DevicePin { set: true } => Err(PresenceError::PinRequired),
            PresenceCapability::DevicePin { set: false } => {
                Err(PresenceError::NoPrompt(NO_PIN_SET))
            }
            PresenceCapability::DevicePrompt => Err(PresenceError::NoPrompt(NO_PIN_HOME)),
            PresenceCapability::NoPrompt(reason) => Err(PresenceError::NoPrompt(reason)),
        }
    }

    fn confirm_with_secret(&self, secret: &[u8]) -> std::result::Result<(), PresenceError> {
        // The key is opened outside its lock: the stretch may take a second.
        let key = self.open_pin_key(secret)?;
        *self.open_key() = Some(key);
        Ok(())
    }

    /// Wipes the device PIN key. It takes one short lock and never calls
    /// the gate.
    fn window_ended(&self) {
        *self.open_key() = None;
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
fn presence_refused(refusal: PresenceError) -> Error {
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

/// The auth value the keystore's hardware compares: 32 bytes derived from
/// the PIN under a context of their own, so the hardware never holds the PIN
/// itself.
fn auth_value(pin: &[u8]) -> Zeroizing<[u8; 32]> {
    derive_guarded(AUTH_VALUE_CONTEXT, &[pin])
}

/// The device PIN key sealed under `pin` as a passphrase, at `cost`, stepping
/// down toward the kit's floor while the device cannot give the memory. The
/// envelope's header records the cost in force.
fn seal_pin_key_envelope(key: &[u8; 32], pin: &[u8], mut cost: PassphraseCost) -> Result<Vec<u8>> {
    let passphrase = Passphrase::new(pin)
        .map_err(|_| refused("the device PIN is not a passphrase an envelope takes"))?;
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::DevicePinKey,
        epoch: DEVICE_PIN_EPOCH,
        key_id: PIN_KEY_ID,
        recipient: PIN_KEY_RECIPIENT,
        vault_id: PIN_KEY_SCOPE,
    };
    loop {
        let seal_key = SealKey::Passphrase {
            passphrase: &passphrase,
            cost: cost.argon2(),
        };
        match seal(&params, seal_key, &key[..], &mut SysRng) {
            Ok(envelope) => return Ok(envelope.to_bytes()),
            Err(oneiron_crypto::Error::OutOfMemory)
                if cost.memory_mib > PassphraseCost::FLOOR.memory_mib =>
            {
                cost.memory_mib = (cost.memory_mib / 2).max(PassphraseCost::FLOOR.memory_mib);
            }
            Err(_) => return Err(refused("sealing the device PIN key failed")),
        }
    }
}

/// The device PIN key from its passphrase envelope; `None` for a wrong PIN
/// and for an envelope that does not open. A reader spends at most the
/// kit's ceiling on one try.
fn open_pin_key_envelope(sealed: &[u8], pin: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let passphrase = Passphrase::new(pin).ok()?;
    let envelope = Envelope::parse(sealed).ok()?;
    let policy = OpenPolicy {
        purpose: Purpose::DevicePinKey,
        vault_id: PIN_KEY_SCOPE,
        recipient: PIN_KEY_RECIPIENT,
        key_id: PIN_KEY_ID,
        wraps: &[WrapType::Passphrase],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: DEVICE_PIN_EPOCH,
        argon2_max: PassphraseCost::CEILING.argon2(),
    };
    let opened = envelope
        .open(OpenKey::Passphrase(&passphrase), &policy)
        .ok()?;
    secret_bytes(&opened)
}

/// One slot's secret sealed under the device PIN key, for exactly `slot`
/// and the public half `public_key`, which the stored envelope shows with no
/// key.
fn seal_slot_secret(
    pin_key: &[u8; 32],
    slot: &KeystoreSlot,
    public_key: &[u8; 32],
    secret: &[u8; 32],
) -> Result<Vec<u8>> {
    let kek = Kek::from_bytes_ref(pin_key);
    let params = SealParams {
        suite: AEAD,
        purpose: Purpose::DevicePinSlotSecret,
        epoch: DEVICE_PIN_EPOCH,
        key_id: public_key,
        recipient: &slot.install,
        vault_id: &slot.vault_id,
    };
    let envelope = seal_with_aad(
        &params,
        SealKey::SymmetricKek(&kek),
        &secret[..],
        slot.name().as_bytes(),
        &mut SysRng,
    )
    .map_err(|_| refused("sealing a slot's secret under the device PIN key failed"))?;
    Ok(envelope.to_bytes())
}

/// The secret of `slot` from `sealed`, opened with the device PIN key;
/// `None` for anything not sealed under that key for exactly `slot` and
/// `public_key`.
fn open_slot_secret(
    pin_key: &[u8; 32],
    slot: &KeystoreSlot,
    public_key: &[u8; 32],
    sealed: &[u8],
) -> Option<Zeroizing<[u8; 32]>> {
    let envelope = Envelope::parse(sealed).ok()?;
    let kek = Kek::from_bytes_ref(pin_key);
    let policy = OpenPolicy {
        purpose: Purpose::DevicePinSlotSecret,
        vault_id: &slot.vault_id,
        recipient: &slot.install,
        key_id: public_key,
        wraps: &[WrapType::SymmetricKek],
        aead_suites: &[AEAD],
        kem_suites: &[],
        min_epoch: DEVICE_PIN_EPOCH,
        argon2_max: Argon2Cost::RFC9106_SECOND,
    };
    let opened = envelope
        .open_with_aad(OpenKey::SymmetricKek(&kek), &policy, slot.name().as_bytes())
        .ok()?;
    secret_bytes(&opened)
}

/// The public half a sealed slot secret names, read with no key; `None` for
/// bytes that are no such envelope. It proves nothing until the secret
/// opens.
fn sealed_slot_public_key(sealed: &[u8]) -> Option<[u8; 32]> {
    let envelope = Envelope::parse(sealed).ok()?;
    let header = envelope.header();
    if header.purpose != Purpose::DevicePinSlotSecret {
        return None;
    }
    <[u8; 32]>::try_from(header.key_id.as_slice()).ok()
}

/// `opened` as a 32-byte secret in guarded memory; `None` for any other
/// length.
fn secret_bytes(opened: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let mut secret = Zeroizing::new([0u8; 32]);
    if opened.len() != secret.len() {
        return None;
    }
    secret.copy_from_slice(opened);
    Some(secret)
}
