//! Confirming that this device's user is present now (row OWNER-CONFIRM-SHEET;
//! owner ruling 15 Nov, OWNER-KEY-PRESENCE = B).
//!
//! The engine asks before it signs an owner's act with the owner key. The
//! question goes through whatever unlocks the device: biometry, else the
//! device's own PIN or password. No secret of the engine's is involved and no
//! key slot changes: the check is a gate before a signature, never a lock on
//! a key, because the same key also signs unattended.
//!
//! - [`UserPresence`] is one device's prompt. [`platform_user_presence`]
//!   picks this platform's. A device with none answers
//!   [`PresenceError::NoPrompt`], and the caller hands the confirm to another
//!   of the owner's devices.
//! - [`PresenceWindow`]: one confirm lasts [`PRESENCE_WINDOW_SECS`] and ends
//!   at once on a screen lock ([`PresenceWindow::end`]). A lock also refuses
//!   the answer of a prompt that was up when it came
//!   ([`PresenceError::ScreenLocked`]): no confirm outlasts a lock. A device
//!   that sends no lock signal is asked instead
//!   ([`UserPresence::screen_is_locked`]): at each act, and on a timer
//!   ([`PresenceGate::watch_screen_lock`]).
//! - [`PresenceGate`] joins the two for one process: inside an open window it
//!   confirms with no prompt, else it prompts, and a confirm opens the
//!   window.
//! - A device with no prompt of its own may ask for a device PIN instead
//!   (row OCS-OWNER-PIN; [`PresenceCapability::DevicePin`]): a secret set
//!   for this purpose, which the device's backend checks. Its confirm
//!   answers [`PresenceError::PinRequired`], the host collects the PIN, and
//!   [`PresenceGate::confirm_with_secret`] opens the same window with it.
//!   [`DEVICE_PIN_WRONG_TRIES`] wrong PINs in a row start a wait of
//!   [`DEVICE_PIN_WAIT_SECS`]. A backend that holds something for the
//!   window is told when it ends ([`UserPresence::window_ended`]).
//!
//! Nothing here is persisted: a new process asks again, and counts wrong
//! PINs from none. The gate neither keeps nor logs a PIN.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub use gate::{PresenceConfirmation, PresenceGate};
pub use platform_codes::WindowsScreenSession;

mod gate;
mod platform_codes;

/// How long one confirm lasts, in seconds: the owner's 15 minutes.
pub const PRESENCE_WINDOW_SECS: u64 = 15 * 60;

/// How long a device's prompt stays up with no answer, in seconds. After it
/// the prompt is taken down and the confirm answers
/// [`PresenceError::NoAnswer`].
pub const PRESENCE_PROMPT_SECS: u64 = 60;

/// How often [`PresenceGate::platform`] reads the screen lock of a device
/// that sends no lock signal, in milliseconds.
pub const SCREEN_LOCK_POLL_MS: u64 = 1000;

/// How many wrong device PINs in a row a device takes. The last of them
/// starts the wait of [`DEVICE_PIN_WAIT_SECS`] (Engine ruling 15 Nov,
/// OCS-PIN-WRONG-TRIES = A).
pub const DEVICE_PIN_WRONG_TRIES: u32 = 5;

/// How long a device takes no device PIN after [`DEVICE_PIN_WRONG_TRIES`]
/// wrong ones in a row, in seconds.
pub const DEVICE_PIN_WAIT_SECS: u64 = 15 * 60;

/// Whether a device can ask its user to confirm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceCapability {
    /// The device shows its own unlock prompt.
    DevicePrompt,
    /// The device has no prompt of its own and asks for its device PIN,
    /// which the host collects. `set` says whether a PIN is set: until one
    /// is, the device cannot confirm.
    DevicePin {
        /// Whether this device has a PIN.
        set: bool,
    },
    /// The device has no prompt, with the reason.
    NoPrompt(&'static str),
}

/// Why a confirm did not happen. A refusal here is never a keystore fault:
/// the slots are untouched. No secret appears in these errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PresenceError {
    /// This device cannot ask at all. The confirm belongs on another of the
    /// owner's devices.
    #[error("this device cannot ask its user to confirm: {0}")]
    NoPrompt(&'static str),
    /// The user was asked and did not confirm: cancelled, or failed.
    #[error("the user did not confirm")]
    Declined,
    /// The prompt was shown and nobody answered it in time.
    #[error("nobody answered the confirm prompt")]
    NoAnswer,
    /// The screen is locked, or it locked (or the user signed out) after
    /// the prompt showed and before its answer was taken. No act is
    /// confirmed on a locked device; an answer from before a lock does not
    /// count and opens no window: the act asks again.
    #[error("the screen is locked, or it locked while the confirm prompt was up")]
    ScreenLocked,
    /// This device asks for its device PIN and no confirm holds: the host
    /// collects the PIN, hands it to [`PresenceGate::confirm_with_secret`]
    /// and runs the act again.
    #[error("this device asks for its device PIN")]
    PinRequired,
    /// The typed secret is not this device's PIN.
    #[error("that is not this device's PIN")]
    WrongPin,
    /// Too many wrong PINs in a row: this device takes none for `wait_secs`
    /// more seconds. The confirm belongs on another of the owner's devices
    /// until then.
    #[error("too many wrong PINs: this device takes none for {wait_secs} s")]
    TooManyTries {
        /// How long the device still takes no PIN, in whole seconds.
        wait_secs: u64,
    },
    /// Any other platform failure, by name and code only.
    #[error("presence check failure: {0} ({1})")]
    Platform(&'static str, i64),
}

const NO_TYPED_SECRET: &str = "this device confirms without a typed secret";
const NO_DEVICE_PIN_SET: &str = "no device PIN is set on this device";

/// One device's way to ask its user to confirm, with whatever unlocks the
/// device.
pub trait UserPresence: Send + Sync + 'static {
    /// Whether this device can ask.
    fn capability(&self) -> PresenceCapability;
    /// Shows the device's own unlock prompt with `reason` and blocks until it
    /// is answered. `Ok` only when the user confirmed.
    ///
    /// A device that asks for its PIN ([`PresenceCapability::DevicePin`])
    /// has no prompt to show: it answers [`PresenceError::PinRequired`], or
    /// [`PresenceError::NoPrompt`] while no PIN is set, and never `Ok`.
    fn confirm(&self, reason: &str) -> Result<(), PresenceError>;
    /// Checks a secret the user typed: this device's PIN. `Ok` only when it
    /// is; a wrong one is [`PresenceError::WrongPin`]. A backend whose own
    /// hardware counts wrong tries answers [`PresenceError::TooManyTries`]
    /// while that hardware refuses. The backend keeps `secret` nowhere and
    /// logs nothing of it.
    ///
    /// [`PresenceGate::confirm_with_secret`] calls it only on a device whose
    /// capability says a PIN is set. The default is a device that takes no
    /// typed secret.
    fn confirm_with_secret(&self, secret: &[u8]) -> Result<(), PresenceError> {
        let _ = secret;
        Err(PresenceError::NoPrompt(NO_TYPED_SECRET))
    }
    /// Told that what a confirm of this backend allowed is over: the window
    /// it opened ended, or its typed secret was right and a screen lock let
    /// no window open. A backend that holds something for the window (a key
    /// the device PIN opened) wipes it here. It may be told more than once
    /// for one window, and is never told while a window is open.
    ///
    /// When a window ends it is called under that window's lock, so an end
    /// and the next confirm reach the backend in their order: return at
    /// once, and never call the gate or the window. The default does
    /// nothing.
    fn window_ended(&self) {}
    /// Whether the device's screen is locked now, or its user's session is
    /// off the screen. [`PresenceGate`] reads it before it answers an act
    /// inside a window and when a prompt's answer comes, and
    /// [`PresenceGate::watch_screen_lock`] reads it on a timer; a locked
    /// reading ends the window.
    ///
    /// The default, `false`, is for a device with no prompt, and for one
    /// whose lock arrives as a signal the host hands to
    /// [`PresenceGate::end_window`]. A device with a prompt and no such
    /// signal must answer it.
    fn screen_is_locked(&self) -> bool {
        false
    }
}

/// A device with no prompt: the Linux file and TPM keystores, and a platform
/// whose prompt is not built.
#[derive(Clone, Copy, Debug)]
pub struct NoPromptPresence(&'static str);

impl NoPromptPresence {
    /// A device that cannot ask, for `reason`.
    #[must_use]
    pub const fn new(reason: &'static str) -> Self {
        Self(reason)
    }
}

impl UserPresence for NoPromptPresence {
    fn capability(&self) -> PresenceCapability {
        PresenceCapability::NoPrompt(self.0)
    }

    fn confirm(&self, _reason: &str) -> Result<(), PresenceError> {
        Err(PresenceError::NoPrompt(self.0))
    }
}

// macOS is the one Apple platform with a prompt here: the others have no
// screen-lock reading built, and a window must never outlast a lock.
#[cfg(all(target_vendor = "apple", not(target_os = "macos")))]
const NO_PLATFORM_PROMPT: &str = "this platform's unlock prompt is not built yet";
#[cfg(not(any(target_vendor = "apple", windows)))]
const NO_PLATFORM_PROMPT: &str = "this platform has no unlock prompt the engine can show";

/// This platform's prompt. A platform with none, and one whose prompt is not
/// built yet, answers as a device that cannot ask: never a silent yes.
#[cfg(not(any(target_os = "macos", windows)))]
#[must_use]
pub fn platform_user_presence() -> Arc<dyn UserPresence> {
    Arc::new(NoPromptPresence::new(NO_PLATFORM_PROMPT))
}

/// This platform's prompt: Windows Hello, which also answers whether the
/// session is locked.
#[cfg(windows)]
#[must_use]
pub fn platform_user_presence() -> Arc<dyn UserPresence> {
    Arc::new(crate::windows_presence::WindowsUserPresence::new())
}

/// This platform's prompt: the macOS unlock sheet, which also answers
/// whether the screen is locked.
#[cfg(target_os = "macos")]
#[must_use]
pub fn platform_user_presence() -> Arc<dyn UserPresence> {
    Arc::new(crate::macos_presence::MacosUserPresence::new())
}

/// One reading of this device's two clocks, both in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresenceInstant {
    /// The wall clock, since the Unix epoch. It counts the time the device
    /// slept, and the user or the network may set it.
    pub wall_ms: u64,
    /// The monotonic clock, since an origin the clock fixed when it was
    /// made. It never goes back, and on most platforms it stands still
    /// while the device sleeps.
    pub monotonic_ms: u64,
}

/// The clocks a [`PresenceWindow`] reads.
pub trait PresenceClock: Send + Sync + 'static {
    /// Both clocks now. The window reads it while it holds its own lock, so
    /// an implementation never calls back into the window.
    fn now(&self) -> PresenceInstant;
}

/// The system's clocks.
#[derive(Clone, Copy, Debug)]
pub struct SystemPresenceClock {
    origin: Instant,
}

impl SystemPresenceClock {
    /// The system's clocks, the monotonic one counted from now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemPresenceClock {
    fn default() -> Self {
        Self::new()
    }
}

impl PresenceClock for SystemPresenceClock {
    fn now(&self) -> PresenceInstant {
        PresenceInstant {
            // A wall clock before the epoch reads zero, which no window outlasts.
            wall_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, millis),
            monotonic_ms: millis(self.origin.elapsed()),
        }
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The window one confirm opens: [`PRESENCE_WINDOW_SECS`] long on both
/// clocks. The wall clock ends it across a sleep, which the monotonic clock
/// does not count; the monotonic clock ends it when the wall clock is held
/// back. A wall clock set behind the confirm ends it too. In memory only.
pub struct PresenceWindow {
    clock: Arc<dyn PresenceClock>,
    /// The backend of the gate that keeps this window. It is told, under the
    /// window's lock, each time an open window ends
    /// ([`UserPresence::window_ended`]).
    backend: Option<Arc<dyn UserPresence>>,
    state: Mutex<WindowState>,
}

/// What a [`PresenceWindow`] keeps, under one lock. Every clock reading the
/// window stores or compares is taken under that lock, so the readings are
/// in the order of the steps that took them.
#[derive(Default)]
struct WindowState {
    /// When the user last confirmed, while that confirm still holds.
    confirmed: Option<PresenceInstant>,
    /// How many times [`PresenceWindow::end`] ran. It wraps: only a change
    /// is read.
    ends: u64,
}

/// A confirm that has begun: the reading [`PresenceWindow::begin_confirm`]
/// takes before the prompt shows. [`PresenceWindow::open`] opens the window
/// for it only when no end came since.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingPresenceConfirm {
    ends: u64,
}

impl PresenceWindow {
    /// A closed window that reads `clock`.
    #[must_use]
    pub fn new(clock: Arc<dyn PresenceClock>) -> Self {
        Self {
            clock,
            backend: None,
            state: Mutex::new(WindowState::default()),
        }
    }

    /// A closed window on the system's clocks.
    #[must_use]
    pub fn system() -> Self {
        Self::new(Arc::new(SystemPresenceClock::new()))
    }

    /// Whether a confirm still holds. A window found ended stays ended: a
    /// clock that moves back later never opens it again.
    #[must_use]
    pub fn is_open(&self) -> bool {
        let mut state = self.state();
        self.still_open(&mut state)
    }

    /// Whether a confirm still holds now, for a caller that holds the
    /// window's lock. A window found over is closed.
    fn still_open(&self, state: &mut WindowState) -> bool {
        // Read under the lock. A reading taken before it could be older than
        // a confirm stored meanwhile, and would end that confirm as a clock
        // set back.
        let now = self.clock.now();
        let open = state.confirmed.is_some_and(|at| within_window(at, now));
        if !open {
            self.close(state);
        }
        open
    }

    /// Closes the window, for a caller that holds its lock, and tells the
    /// gate's backend when a confirm held until now.
    fn close(&self, state: &mut WindowState) {
        if state.confirmed.take().is_some()
            && let Some(backend) = &self.backend
        {
            backend.window_ended();
        }
    }

    /// Closes a window whose time is over. The watch calls it when no act
    /// comes to read the window, so the backend is told all the same.
    fn close_when_over(&self) {
        let mut state = self.state();
        let _open = self.still_open(&mut state);
    }

    /// Begins a confirm. Call it before the prompt shows, and hand the
    /// reading to [`Self::open`] with the prompt's answer.
    #[must_use]
    pub fn begin_confirm(&self) -> PendingPresenceConfirm {
        PendingPresenceConfirm {
            ends: self.state().ends,
        }
    }

    /// Opens the window: the user confirmed the prompt `pending` began.
    /// `false`, with the window left closed, when [`Self::end`] ran since
    /// `pending` was read: an answer from before a screen lock opens
    /// nothing. The check and the opening are one step under the window's
    /// lock, so an end lands wholly before it or wholly after it.
    #[must_use]
    pub fn open(&self, pending: PendingPresenceConfirm) -> bool {
        let mut state = self.state();
        if state.ends != pending.ends {
            return false;
        }
        state.confirmed = Some(self.clock.now());
        true
    }

    /// Ends the window at once: the screen locked, or the user signed out.
    /// A confirm that had begun and is not open yet never opens.
    pub fn end(&self) {
        let mut state = self.state();
        self.close(&mut state);
        state.ends = state.ends.wrapping_add(1);
    }

    fn state(&self) -> MutexGuard<'_, WindowState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Whether `now` is less than [`PRESENCE_WINDOW_SECS`] after `at` on both
/// clocks. A clock behind `at` was set back, which ends the window.
fn within_window(at: PresenceInstant, now: PresenceInstant) -> bool {
    let window_ms = PRESENCE_WINDOW_SECS * 1000;
    let (Some(wall), Some(monotonic)) = (
        now.wall_ms.checked_sub(at.wall_ms),
        now.monotonic_ms.checked_sub(at.monotonic_ms),
    ) else {
        return false;
    };
    wall < window_ms && monotonic < window_ms
}

#[cfg(any(test, feature = "test-keystore", oneiron_test_support))]
pub use doubles::{ManualPresenceClock, ScriptedPresence};

/// Test doubles, built with the process-memory keystore and never for a host.
#[cfg(any(test, feature = "test-keystore", oneiron_test_support))]
mod doubles {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};

    use super::{
        NO_DEVICE_PIN_SET, NO_TYPED_SECRET, PresenceCapability, PresenceClock, PresenceError,
        PresenceInstant, UserPresence,
    };

    /// A device whose prompt answers from a script, or one that asks for a
    /// scripted device PIN, and whose screen a test locks and unlocks.
    pub struct ScriptedPresence {
        asks: Asks,
        answers: Mutex<VecDeque<Result<(), PresenceError>>>,
        reasons: Mutex<Vec<String>>,
        screen_locked: AtomicBool,
        screen_lock_reads: AtomicUsize,
        secrets_checked: AtomicUsize,
        window_ends: AtomicUsize,
    }

    /// How a scripted device asks its user.
    enum Asks {
        /// Through its own prompt.
        Prompt,
        /// For its device PIN: the one that is set, or none yet.
        DevicePin(Option<Vec<u8>>),
    }

    impl ScriptedPresence {
        /// A device that prompts and gives `answers` in order. A prompt past
        /// the script is declined.
        #[must_use]
        pub fn new(answers: impl IntoIterator<Item = Result<(), PresenceError>>) -> Self {
            Self::asking(Asks::Prompt, answers.into_iter().collect())
        }

        /// A device with no prompt that asks for its device PIN: `pin` when
        /// one is set, `None` before the owner has set one.
        #[must_use]
        pub fn with_device_pin(pin: Option<&[u8]>) -> Self {
            Self::asking(Asks::DevicePin(pin.map(<[u8]>::to_vec)), VecDeque::new())
        }

        fn asking(asks: Asks, answers: VecDeque<Result<(), PresenceError>>) -> Self {
            Self {
                asks,
                answers: Mutex::new(answers),
                reasons: Mutex::new(Vec::new()),
                screen_locked: AtomicBool::new(false),
                screen_lock_reads: AtomicUsize::new(0),
                secrets_checked: AtomicUsize::new(0),
                window_ends: AtomicUsize::new(0),
            }
        }

        /// How many typed secrets the device was handed to check.
        #[must_use]
        pub fn secrets_checked(&self) -> usize {
            self.secrets_checked.load(Ordering::SeqCst)
        }

        /// How many times the device was told its window ended.
        #[must_use]
        pub fn window_ends(&self) -> usize {
            self.window_ends.load(Ordering::SeqCst)
        }

        /// Locks or unlocks the device's screen. It starts unlocked.
        pub fn set_screen_locked(&self, locked: bool) {
            self.screen_locked.store(locked, Ordering::SeqCst);
        }

        /// How many times the screen lock was read. A read is counted
        /// before it takes its reading.
        #[must_use]
        pub fn screen_lock_reads(&self) -> usize {
            self.screen_lock_reads.load(Ordering::SeqCst)
        }

        /// How many prompts were shown.
        #[must_use]
        pub fn prompts(&self) -> usize {
            self.reasons
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len()
        }

        /// The reason each prompt showed, in order.
        #[must_use]
        pub fn reasons(&self) -> Vec<String> {
            self.reasons
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl UserPresence for ScriptedPresence {
        fn capability(&self) -> PresenceCapability {
            match &self.asks {
                Asks::Prompt => PresenceCapability::DevicePrompt,
                Asks::DevicePin(pin) => PresenceCapability::DevicePin { set: pin.is_some() },
            }
        }

        fn confirm(&self, reason: &str) -> Result<(), PresenceError> {
            match &self.asks {
                Asks::Prompt => {}
                Asks::DevicePin(Some(_)) => return Err(PresenceError::PinRequired),
                Asks::DevicePin(None) => return Err(PresenceError::NoPrompt(NO_DEVICE_PIN_SET)),
            }
            self.reasons
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(reason.to_owned());
            self.answers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
                .unwrap_or(Err(PresenceError::Declined))
        }

        fn confirm_with_secret(&self, secret: &[u8]) -> Result<(), PresenceError> {
            self.secrets_checked.fetch_add(1, Ordering::SeqCst);
            match &self.asks {
                Asks::Prompt => Err(PresenceError::NoPrompt(NO_TYPED_SECRET)),
                Asks::DevicePin(None) => Err(PresenceError::NoPrompt(NO_DEVICE_PIN_SET)),
                Asks::DevicePin(Some(pin)) if pin.as_slice() == secret => Ok(()),
                Asks::DevicePin(Some(_)) => Err(PresenceError::WrongPin),
            }
        }

        fn window_ended(&self) {
            self.window_ends.fetch_add(1, Ordering::SeqCst);
        }

        fn screen_is_locked(&self) -> bool {
            self.screen_lock_reads.fetch_add(1, Ordering::SeqCst);
            self.screen_locked.load(Ordering::SeqCst)
        }
    }

    /// Clocks a test sets by hand. Nothing else moves them.
    pub struct ManualPresenceClock {
        now: Mutex<PresenceInstant>,
    }

    impl ManualPresenceClock {
        /// Both clocks at the given readings.
        #[must_use]
        pub fn new(wall_ms: u64, monotonic_ms: u64) -> Arc<Self> {
            Arc::new(Self {
                now: Mutex::new(PresenceInstant {
                    wall_ms,
                    monotonic_ms,
                }),
            })
        }

        /// Sets each clock on its own: a sleep moves only the wall clock.
        pub fn set(&self, wall_ms: u64, monotonic_ms: u64) {
            *self.now.lock().unwrap_or_else(PoisonError::into_inner) = PresenceInstant {
                wall_ms,
                monotonic_ms,
            };
        }

        /// Moves both clocks forward by `ms`: time passing while awake.
        pub fn advance(&self, ms: u64) {
            let mut now = self.now.lock().unwrap_or_else(PoisonError::into_inner);
            now.wall_ms = now.wall_ms.saturating_add(ms);
            now.monotonic_ms = now.monotonic_ms.saturating_add(ms);
        }
    }

    impl PresenceClock for ManualPresenceClock {
        fn now(&self) -> PresenceInstant {
            *self.now.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }
}
