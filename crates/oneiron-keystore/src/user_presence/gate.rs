//! One process's presence check: [`PresenceGate`] joins a device's prompt
//! with the window one confirm opens, counts wrong typed secrets, and
//! watches the screen lock.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;
use std::{io, thread};

use super::{
    DEVICE_PIN_WAIT_SECS, DEVICE_PIN_WRONG_TRIES, NO_DEVICE_PIN_SET, NO_TYPED_SECRET,
    NoPromptPresence, PresenceCapability, PresenceError, PresenceInstant, PresenceWindow,
    SCREEN_LOCK_POLL_MS, UserPresence, platform_user_presence,
};

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
    /// Held while a prompt shows or a typed secret is checked, so acts that
    /// arrive together share one confirm.
    prompting: Mutex<()>,
    /// The wrong typed secrets counted, and the wait they started.
    tries: Mutex<TypedSecretTries>,
}

/// The wrong typed secrets a gate has counted. In memory only: a new process
/// starts at none.
#[derive(Default)]
struct TypedSecretTries {
    /// Wrong secrets in a row, since the last right one or the last wait.
    wrong: u32,
    /// The reading at the wrong secret that started the wait, while it runs.
    waiting_since: Option<PresenceInstant>,
}

/// How much of [`DEVICE_PIN_WAIT_SECS`] is left at `now`, in milliseconds,
/// for a wait that began at `since`. Either clock counts it down: the
/// monotonic clock, which nothing sets, and the wall clock, which counts a
/// sleep. A wall clock set back counts nothing, so it neither shortens the
/// wait nor lengthens it. One set forward can end the wait early; whoever
/// may set the clock may also restart the process, which forgets the count.
fn wait_left_ms(since: PresenceInstant, now: PresenceInstant) -> u64 {
    let counted = now
        .monotonic_ms
        .saturating_sub(since.monotonic_ms)
        .max(now.wall_ms.saturating_sub(since.wall_ms));
    (DEVICE_PIN_WAIT_SECS * 1000).saturating_sub(counted)
}

const NO_SCREEN_LOCK_WATCH: &str = "the screen-lock watch could not start";

impl PresenceGate {
    /// A gate that asks through `presence` and keeps `window`. The window
    /// tells `presence` each time it ends ([`UserPresence::window_ended`]).
    #[must_use]
    pub fn new(presence: Arc<dyn UserPresence>, mut window: PresenceWindow) -> Self {
        window.backend = Some(Arc::clone(&presence));
        Self {
            presence,
            window: Arc::new(window),
            prompting: Mutex::new(()),
            tries: Mutex::new(TypedSecretTries::default()),
        }
    }

    /// This platform's prompt on the system's clocks, with the gate's own
    /// watch ([`Self::watched`]): the platform sends no screen-lock signal
    /// that a headless host can take.
    #[cfg(any(target_os = "macos", windows))]
    #[must_use]
    pub fn platform() -> Self {
        Self::watched(platform_user_presence())
    }

    /// This platform's prompt on the system's clocks. The platform has
    /// none, so the gate answers as a device that cannot ask.
    #[cfg(not(any(target_os = "macos", windows)))]
    #[must_use]
    pub fn platform() -> Self {
        Self::new(platform_user_presence(), PresenceWindow::system())
    }

    /// A gate over `presence` on the system's clocks, with its watch started
    /// ([`Self::watch_screen_lock`], every [`SCREEN_LOCK_POLL_MS`]).
    ///
    /// macOS delivers its lock notification only to a main thread that runs
    /// a run loop, and Windows only to a window whose thread runs a message
    /// loop. A headless host has neither: the gate reads the lock on a
    /// timer. A backend that holds something for the window needs the watch
    /// on every platform: it ends a window whose time is over when no act
    /// comes. With no watch a window could outlast a lock, and a backend
    /// could hold on past its window, so a gate whose watch cannot start
    /// answers as a device that cannot ask.
    #[must_use]
    pub fn watched(presence: Arc<dyn UserPresence>) -> Self {
        let gate = Self::new(presence, PresenceWindow::system());
        match gate.watch_screen_lock(Duration::from_millis(SCREEN_LOCK_POLL_MS)) {
            Ok(()) => gate,
            Err(_) => Self::new(
                Arc::new(NoPromptPresence::new(NO_SCREEN_LOCK_WATCH)),
                PresenceWindow::system(),
            ),
        }
    }

    /// Starts a thread that reads the device's screen lock
    /// ([`UserPresence::screen_is_locked`]) every `every` and ends the
    /// window on a locked reading, so that a lock ends the window when no
    /// act comes to read it. A lock shorter than `every` that no act meets
    /// is not seen. On an unlocked reading it closes a window whose time is
    /// over, so the backend is told ([`UserPresence::window_ended`]) within
    /// `every` of the window's end. The thread stops once the gate is
    /// dropped. Call it once.
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
                    } else {
                        live.close_when_over();
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
    /// prompt was up. A device that asks for its PIN answers
    /// [`PresenceError::PinRequired`] outside a window: collect the PIN,
    /// call [`Self::confirm_with_secret`], and ask again.
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

    /// Confirms with a secret the user typed, on a device that asks for its
    /// PIN ([`PresenceCapability::DevicePin`]). The right one opens the
    /// window, as a confirmed prompt does. Anything else opens nothing.
    ///
    /// Each typed secret starts over: a window an earlier confirm opened
    /// ends when the next secret is taken, so a wrong one never rides on
    /// it. [`DEVICE_PIN_WRONG_TRIES`] wrong secrets in a row start a wait of
    /// [`DEVICE_PIN_WAIT_SECS`], in which the device takes none: the backend
    /// does not see a secret that comes then. A right secret, and the end of
    /// the wait, start the count over.
    ///
    /// The count stops a person at the device and an agent that calls the
    /// door. It is in memory only, so a restart forgets it, and it does not
    /// stop code that reads what the backend keeps at rest.
    ///
    /// The gate neither keeps nor logs `secret`. Never call it while holding
    /// a lock other work waits on: the backend's check may take a second.
    ///
    /// # Errors
    /// - [`PresenceError::NoPrompt`]: the device takes no typed secret, or
    ///   no PIN is set on it.
    /// - [`PresenceError::WrongPin`]; [`PresenceError::TooManyTries`] for
    ///   the wrong secret that starts the wait and for every secret inside
    ///   it. A backend may answer the second itself (a chip that refuses):
    ///   that one is passed on and not counted.
    /// - [`PresenceError::ScreenLocked`] when the screen reads locked, or
    ///   when [`Self::end_window`] ran while the secret was checked.
    pub fn confirm_with_secret(&self, secret: &[u8]) -> Result<(), PresenceError> {
        let _checking = self
            .prompting
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.screen_lock_ends_window() {
            return Err(PresenceError::ScreenLocked);
        }
        match self.presence.capability() {
            PresenceCapability::DevicePin { set: true } => {}
            PresenceCapability::DevicePin { set: false } => {
                return Err(PresenceError::NoPrompt(NO_DEVICE_PIN_SET));
            }
            PresenceCapability::DevicePrompt => {
                return Err(PresenceError::NoPrompt(NO_TYPED_SECRET));
            }
            PresenceCapability::NoPrompt(reason) => return Err(PresenceError::NoPrompt(reason)),
        }
        if let Some(wait_secs) = self.typed_secret_wait_secs() {
            return Err(PresenceError::TooManyTries { wait_secs });
        }
        // An earlier window still open here could run out while this secret
        // is checked. The backend would then be told of that end after it
        // took the secret, with nothing to refuse the new window. So the
        // earlier window ends first.
        self.window.end();
        let pending = self.window.begin_confirm();
        match self.presence.confirm_with_secret(secret) {
            Ok(()) => {
                *self.tries() = TypedSecretTries::default();
                // A lock that came while the secret was checked outlasts
                // it, as it outlasts a prompt's answer.
                if self.screen_lock_ends_window() || !self.window.open(pending) {
                    // No window opened, so no end of one will tell the
                    // backend to let go of what the secret gave it.
                    self.presence.window_ended();
                    return Err(PresenceError::ScreenLocked);
                }
                Ok(())
            }
            Err(PresenceError::WrongPin) => Err(self.count_wrong_secret()),
            Err(refusal) => Err(refusal),
        }
    }

    /// How long this device still takes no typed secret, in whole seconds
    /// rounded up, after [`DEVICE_PIN_WRONG_TRIES`] wrong ones in a row.
    /// `None` when it takes one now. A wait found over starts the count
    /// over.
    #[must_use]
    pub fn typed_secret_wait_secs(&self) -> Option<u64> {
        let mut tries = self.tries();
        let since = tries.waiting_since?;
        // Read under the count's lock, so the reading is never older than
        // the wait it is compared with.
        let left_ms = wait_left_ms(since, self.window.clock.now());
        if left_ms == 0 {
            *tries = TypedSecretTries::default();
            return None;
        }
        Some(left_ms.div_ceil(1000))
    }

    /// Counts one wrong typed secret and answers what its user is told: the
    /// last of [`DEVICE_PIN_WRONG_TRIES`] in a row starts the wait.
    fn count_wrong_secret(&self) -> PresenceError {
        let mut tries = self.tries();
        tries.wrong = tries.wrong.saturating_add(1);
        if tries.wrong < DEVICE_PIN_WRONG_TRIES {
            return PresenceError::WrongPin;
        }
        tries.waiting_since = Some(self.window.clock.now());
        PresenceError::TooManyTries {
            wait_secs: DEVICE_PIN_WAIT_SECS,
        }
    }

    fn tries(&self) -> MutexGuard<'_, TypedSecretTries> {
        self.tries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Drop for PresenceGate {
    /// A gate that goes away ends its window, so its backend holds nothing
    /// for a window that no gate keeps.
    fn drop(&mut self) {
        self.window.end();
    }
}
