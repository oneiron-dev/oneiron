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
//!
//! Nothing here is persisted: a new process asks again.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{io, thread};

/// How long one confirm lasts, in seconds: the owner's 15 minutes.
pub const PRESENCE_WINDOW_SECS: u64 = 15 * 60;

/// How long a device's prompt stays up with no answer, in seconds. After it
/// the prompt is taken down and the confirm answers
/// [`PresenceError::NoAnswer`].
pub const PRESENCE_PROMPT_SECS: u64 = 60;

/// How often [`PresenceGate::platform`] reads the screen lock of a device
/// that sends no lock signal, in milliseconds.
pub const SCREEN_LOCK_POLL_MS: u64 = 1000;

/// Whether a device can ask its user to confirm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceCapability {
    /// The device shows its own unlock prompt.
    DevicePrompt,
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
    /// Any other platform failure, by name and code only.
    #[error("presence check failure: {0} ({1})")]
    Platform(&'static str, i64),
}

// Apple's `LAError` codes (LocalAuthentication/LAError.h).
const LA_ERROR_AUTHENTICATION_FAILED: i64 = -1;
const LA_ERROR_USER_CANCEL: i64 = -2;
const LA_ERROR_USER_FALLBACK: i64 = -3;
const LA_ERROR_SYSTEM_CANCEL: i64 = -4;
const LA_ERROR_PASSCODE_NOT_SET: i64 = -5;
const LA_ERROR_APP_CANCEL: i64 = -9;
const LA_ERROR_NOT_INTERACTIVE: i64 = -1004;

const NO_DEVICE_PASSCODE: &str = "no passcode or password is set on this device";
const PROMPT_NOT_ALLOWED: &str = "this process may not show the device's unlock prompt";

// Windows' `UserConsentVerificationResult` values
// (Windows.Security.Credentials.UI). `UserConsentVerifierAvailability` has
// the first five under the same numbers, with `Available` for 0.
const USER_CONSENT_VERIFIED: i32 = 0;
const USER_CONSENT_DEVICE_NOT_PRESENT: i32 = 1;
const USER_CONSENT_NOT_CONFIGURED_FOR_USER: i32 = 2;
const USER_CONSENT_DISABLED_BY_POLICY: i32 = 3;
const USER_CONSENT_DEVICE_BUSY: i32 = 4;
const USER_CONSENT_RETRIES_EXHAUSTED: i32 = 5;
const USER_CONSENT_CANCELED: i32 = 6;
const USER_CONSENT_AVAILABLE: i32 = 0;

const NO_HELLO_DEVICE: &str = "this device has no Windows Hello sign-in";
const HELLO_NOT_SET_UP: &str = "Windows Hello is not set up for this user";
const HELLO_OFF_BY_POLICY: &str = "Windows Hello is turned off by policy on this device";
const HELLO_AVAILABILITY_UNKNOWN: &str =
    "Windows Hello gave an availability this build does not know";

impl PresenceError {
    /// The refusal one of Apple's LocalAuthentication error codes (`LAError`)
    /// stands for. It is here, and not with the macOS prompt, so that every
    /// platform's tests run it.
    ///
    /// - The user failed, cancelled or asked for a fallback the policy does
    ///   not have: [`Self::Declined`].
    /// - The system took the prompt down (another app came to the front, the
    ///   device slept), or this crate did after [`PRESENCE_PROMPT_SECS`]:
    ///   [`Self::NoAnswer`].
    /// - No passcode is set, or the process may show no prompt:
    ///   [`Self::NoPrompt`].
    /// - Every other code, the biometry ones too (the device-owner policy
    ///   falls back to the password by itself): [`Self::Platform`].
    #[must_use]
    pub const fn from_local_authentication_code(code: i64) -> Self {
        match code {
            LA_ERROR_AUTHENTICATION_FAILED | LA_ERROR_USER_CANCEL | LA_ERROR_USER_FALLBACK => {
                Self::Declined
            }
            LA_ERROR_SYSTEM_CANCEL | LA_ERROR_APP_CANCEL => Self::NoAnswer,
            LA_ERROR_PASSCODE_NOT_SET => Self::NoPrompt(NO_DEVICE_PASSCODE),
            LA_ERROR_NOT_INTERACTIVE => Self::NoPrompt(PROMPT_NOT_ALLOWED),
            other => Self::Platform("local authentication", other),
        }
    }

    /// What one of Windows' `UserConsentVerificationResult` values stands
    /// for: `Ok` only when Windows Hello verified the user. It is here, and
    /// not with the Windows prompt, so that every platform's tests run it.
    ///
    /// # Errors
    /// - The user cancelled, or failed too many times: [`Self::Declined`].
    ///   Windows gives one value for the user's cancel and its own.
    /// - The device has no Windows Hello, Hello is not set up for this
    ///   user, or policy turned it off: [`Self::NoPrompt`].
    /// - The device was busy, and every other value: [`Self::Platform`].
    pub const fn user_consent_verification(result: i32) -> Result<(), Self> {
        match result {
            USER_CONSENT_VERIFIED => Ok(()),
            USER_CONSENT_RETRIES_EXHAUSTED | USER_CONSENT_CANCELED => Err(Self::Declined),
            USER_CONSENT_DEVICE_NOT_PRESENT => Err(Self::NoPrompt(NO_HELLO_DEVICE)),
            USER_CONSENT_NOT_CONFIGURED_FOR_USER => Err(Self::NoPrompt(HELLO_NOT_SET_UP)),
            USER_CONSENT_DISABLED_BY_POLICY => Err(Self::NoPrompt(HELLO_OFF_BY_POLICY)),
            other => Err(Self::Platform(
                "user consent verification result",
                other as i64,
            )),
        }
    }
}

impl PresenceCapability {
    /// Whether a device can ask, from one of Windows'
    /// `UserConsentVerifierAvailability` values. A busy device can ask: the
    /// confirm that meets it busy answers that fault itself. A value this
    /// build does not know is a device that cannot ask.
    #[must_use]
    pub const fn from_user_consent_availability(availability: i32) -> Self {
        match availability {
            USER_CONSENT_AVAILABLE | USER_CONSENT_DEVICE_BUSY => Self::DevicePrompt,
            USER_CONSENT_DEVICE_NOT_PRESENT => Self::NoPrompt(NO_HELLO_DEVICE),
            USER_CONSENT_NOT_CONFIGURED_FOR_USER => Self::NoPrompt(HELLO_NOT_SET_UP),
            USER_CONSENT_DISABLED_BY_POLICY => Self::NoPrompt(HELLO_OFF_BY_POLICY),
            _ => Self::NoPrompt(HELLO_AVAILABILITY_UNKNOWN),
        }
    }
}

// Windows' record of a session (wtsapi32.h, `WTSINFOEX_LEVEL1`).
const WTS_SERVICES_SESSION_ID: u32 = 0;
const WTS_ACTIVE: i32 = 0;
const WTS_SESSIONSTATE_LOCK: i32 = 0;
const WTS_SESSIONSTATE_UNLOCK: i32 = 1;

/// What Windows' record of a session says about asking its user. It is
/// here, and not with the Windows prompt, so that every platform's tests
/// run its table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowsScreenSession {
    /// Session 0: services, which have no screen.
    Services,
    /// Not the active session of a screen: its user switched out, or
    /// disconnected.
    OffScreen,
    /// On a screen, and locked.
    Locked,
    /// On a screen, and unlocked.
    Unlocked,
    /// The record could not be read, or its lock state is not one of the
    /// two this build knows. It is never read as unlocked.
    Unreadable,
}

impl WindowsScreenSession {
    /// Reads `WTSINFOEX_LEVEL1`'s `SessionId`, `SessionState` and
    /// `SessionFlags`. Only an active session that says it is unlocked
    /// reads as unlocked. (Windows 7 gave the two lock values the other
    /// way round; it has no prompt here, so no window opens on it.)
    #[must_use]
    pub const fn from_session_info(
        session_id: u32,
        connect_state: i32,
        session_flags: i32,
    ) -> Self {
        if session_id == WTS_SERVICES_SESSION_ID {
            return Self::Services;
        }
        if connect_state != WTS_ACTIVE {
            return Self::OffScreen;
        }
        match session_flags {
            WTS_SESSIONSTATE_LOCK => Self::Locked,
            WTS_SESSIONSTATE_UNLOCK => Self::Unlocked,
            _ => Self::Unreadable,
        }
    }
}

/// One device's way to ask its user to confirm, with whatever unlocks the
/// device.
pub trait UserPresence: Send + Sync + 'static {
    /// Whether this device can ask.
    fn capability(&self) -> PresenceCapability;
    /// Shows the device's own unlock prompt with `reason` and blocks until it
    /// is answered. `Ok` only when the user confirmed.
    fn confirm(&self, reason: &str) -> Result<(), PresenceError>;
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
        // Read under the lock. A reading taken before it could be older than
        // a confirm stored meanwhile, and would end that confirm as a clock
        // set back.
        let now = self.clock.now();
        let open = state.confirmed.is_some_and(|at| within_window(at, now));
        if !open {
            state.confirmed = None;
        }
        open
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
        state.confirmed = None;
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

/// How a confirm was reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresenceConfirmation {
    /// The user answered this device's prompt now.
    Prompted,
    /// An earlier confirm still holds: no prompt was shown.
    WithinWindow,
}

/// One process's presence check: this device's prompt and the window one
/// confirm opens. Every vault the process holds shares it, so one confirm
/// serves them all.
pub struct PresenceGate {
    presence: Arc<dyn UserPresence>,
    /// Shared with the screen-lock watch, which holds it weakly.
    window: Arc<PresenceWindow>,
    /// Held while a prompt shows, so acts that arrive together share one.
    prompting: Mutex<()>,
}

#[cfg(any(target_os = "macos", windows))]
const NO_SCREEN_LOCK_WATCH: &str = "the screen-lock watch could not start";

impl PresenceGate {
    /// A gate that asks through `presence` and keeps `window`.
    #[must_use]
    pub fn new(presence: Arc<dyn UserPresence>, window: PresenceWindow) -> Self {
        Self {
            presence,
            window: Arc::new(window),
            prompting: Mutex::new(()),
        }
    }

    /// This platform's prompt on the system's clocks. On a platform that
    /// sends no screen-lock signal the gate also starts its own watch
    /// ([`Self::watch_screen_lock`], every [`SCREEN_LOCK_POLL_MS`]).
    #[must_use]
    pub fn platform() -> Self {
        Self::new(platform_user_presence(), PresenceWindow::system()).watching_platform_lock()
    }

    /// macOS delivers its lock notification only to a main thread that runs
    /// a run loop, and Windows only to a window whose thread runs a message
    /// loop. A headless host has neither: the gate reads the lock on a
    /// timer. With no watch a window could outlast a lock, so a gate whose
    /// watch cannot start answers as a device that cannot ask.
    #[cfg(any(target_os = "macos", windows))]
    fn watching_platform_lock(self) -> Self {
        match self.watch_screen_lock(Duration::from_millis(SCREEN_LOCK_POLL_MS)) {
            Ok(()) => self,
            Err(_) => Self::new(
                Arc::new(NoPromptPresence::new(NO_SCREEN_LOCK_WATCH)),
                PresenceWindow::system(),
            ),
        }
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    fn watching_platform_lock(self) -> Self {
        self
    }

    /// Starts a thread that reads the device's screen lock
    /// ([`UserPresence::screen_is_locked`]) every `every` and ends the
    /// window on a locked reading, so that a lock ends the window when no
    /// act comes to read it. A lock shorter than `every` that no act meets
    /// is not seen. The thread stops once the gate is dropped. Call it once.
    ///
    /// # Errors
    /// The thread could not start.
    pub fn watch_screen_lock(&self, every: Duration) -> io::Result<()> {
        let window = Arc::downgrade(&self.window);
        let presence = Arc::clone(&self.presence);
        thread::Builder::new()
            .name("oneiron-screen-lock-watch".to_owned())
            .spawn(move || {
                loop {
                    thread::sleep(every);
                    let Some(live) = window.upgrade() else {
                        return;
                    };
                    if presence.screen_is_locked() {
                        live.end();
                    }
                }
            })
            .map(|_watch| ())
    }

    /// Whether this device can ask.
    #[must_use]
    pub fn capability(&self) -> PresenceCapability {
        self.presence.capability()
    }

    /// Whether an earlier confirm still holds. A screen that reads locked
    /// ends it.
    #[must_use]
    pub fn window_is_open(&self) -> bool {
        !self.screen_lock_ends_window() && self.window.is_open()
    }

    /// Confirms the user is present: with no prompt inside an open window,
    /// else through the device's prompt, which blocks until it is answered.
    /// A confirm opens the window; a refusal opens nothing. Never call it
    /// while holding a lock other work waits on.
    ///
    /// The answer is true when it is read. A screen lock after that is not
    /// seen here, so the caller signs at once.
    ///
    /// # Errors
    /// The prompt's own refusal, or [`PresenceError::ScreenLocked`] when the
    /// screen reads locked, or when [`Self::end_window`] ran while the
    /// prompt was up.
    pub fn confirm(&self, reason: &str) -> Result<PresenceConfirmation, PresenceError> {
        if self.earlier_confirm_holds()? {
            return Ok(PresenceConfirmation::WithinWindow);
        }
        let _prompting = self
            .prompting
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // Another act's prompt may have been answered while this one waited,
        // and the screen may have locked.
        if self.earlier_confirm_holds()? {
            return Ok(PresenceConfirmation::WithinWindow);
        }
        let pending = self.window.begin_confirm();
        self.presence.confirm(reason)?;
        // A lock that came while the prompt was up outlasts its answer:
        // whether it is still in force, or it ended the window meanwhile.
        if self.screen_lock_ends_window() || !self.window.open(pending) {
            return Err(PresenceError::ScreenLocked);
        }
        Ok(PresenceConfirmation::Prompted)
    }

    /// Whether an earlier confirm serves an act that comes now. No act is
    /// confirmed on a locked device: a screen that reads locked ends the
    /// window and answers [`PresenceError::ScreenLocked`].
    fn earlier_confirm_holds(&self) -> Result<bool, PresenceError> {
        if self.screen_lock_ends_window() {
            return Err(PresenceError::ScreenLocked);
        }
        Ok(self.window.is_open())
    }

    /// Reads the device's screen lock, and ends the window on a locked
    /// reading.
    fn screen_lock_ends_window(&self) -> bool {
        let locked = self.presence.screen_is_locked();
        if locked {
            self.window.end();
        }
        locked
    }

    /// Ends the window at once: the screen locked, or the user signed out.
    /// A prompt that is up is refused when its answer comes.
    pub fn end_window(&self) {
        self.window.end();
    }
}

#[cfg(any(test, feature = "test-keystore", oneiron_test_support))]
pub use doubles::{ManualPresenceClock, ScriptedPresence};

/// Test doubles, built with the process-memory keystore and never for a host.
#[cfg(any(test, feature = "test-keystore", oneiron_test_support))]
mod doubles {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};

    use super::{PresenceCapability, PresenceClock, PresenceError, PresenceInstant, UserPresence};

    /// A device whose prompt answers from a script, and whose screen a test
    /// locks and unlocks.
    pub struct ScriptedPresence {
        answers: Mutex<VecDeque<Result<(), PresenceError>>>,
        reasons: Mutex<Vec<String>>,
        screen_locked: AtomicBool,
        screen_lock_reads: AtomicUsize,
    }

    impl ScriptedPresence {
        /// A device that prompts and gives `answers` in order. A prompt past
        /// the script is declined.
        #[must_use]
        pub fn new(answers: impl IntoIterator<Item = Result<(), PresenceError>>) -> Self {
            Self {
                answers: Mutex::new(answers.into_iter().collect()),
                reasons: Mutex::new(Vec::new()),
                screen_locked: AtomicBool::new(false),
                screen_lock_reads: AtomicUsize::new(0),
            }
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
            PresenceCapability::DevicePrompt
        }

        fn confirm(&self, reason: &str) -> Result<(), PresenceError> {
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
