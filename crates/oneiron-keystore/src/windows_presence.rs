//! Windows: the device's own unlock prompt (Windows Hello), and the session's
//! word on the screen lock (row OWNER-CONFIRM-SHEET).
//!
//! - The prompt is Windows Hello's consent dialog: face, fingerprint or the
//!   Hello PIN. Windows draws it and answers; the engine sees no secret and
//!   no key slot is read or changed. A desktop process asks through the
//!   verifier's window interop, which Windows has from build 22000
//!   (Windows 11); an older Windows has no prompt here and says so.
//! - A device where Hello is not set up, or is turned off by policy, has no
//!   prompt here: the account-password dialog is not built.
//! - The screen lock is read from the session's own record (the Remote
//!   Desktop Services API, which answers for every session, remote or
//!   not; Windows documents the reading). Windows sends its lock
//!   notification only to a window whose thread runs a message loop, which a
//!   headless host has not, so the presence gate asks: at each act, and on a
//!   timer.
//! - A process in the services session, or in a session that is not
//!   connected to a screen, cannot show the prompt and says so.

use std::ptr;
use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::Duration;

// The leading `::` names the `windows` crate: this crate's own `windows`
// module is the DPAPI keystore.
use ::windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
use ::windows::Win32::Foundation::HWND;
use ::windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use ::windows::core::{Error as WinrtError, HSTRING, RuntimeType, factory};
use windows_future::IAsyncOperation;
use windows_sys::Win32::System::Console::GetConsoleWindow;
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSFreeMemory, WTSINFOEXW,
    WTSQuerySessionInformationW, WTSSessionInfoEx,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GA_ROOTOWNER, GetAncestor, GetForegroundWindow, IsWindowVisible,
};

use crate::user_presence::{
    PRESENCE_PROMPT_SECS, PresenceCapability, PresenceError, UserPresence, WindowsScreenSession,
};

/// How long the availability question may take, in seconds. It shows
/// nothing; a device that does not answer it is one that cannot ask.
const AVAILABILITY_SECS: u64 = 5;

const SERVICES_SESSION: &str = "this process runs in the services session, which has no screen";
const SESSION_OFF_SCREEN: &str = "this user's session is not connected to a screen";
const SESSION_UNREADABLE: &str = "the session's lock state cannot be read";
const NO_DESKTOP_CONSENT_PROMPT: &str =
    "this Windows has no unlock prompt a desktop process can show";
const NO_AVAILABILITY_ANSWER: &str = "Windows Hello did not say whether it is available";

/// What this process's session says of itself. A record that cannot be read
/// is never read as unlocked.
fn screen_session() -> WindowsScreenSession {
    let mut record: *mut u16 = ptr::null_mut();
    let mut record_bytes: u32 = 0;
    // SAFETY: the two out-parameters point at live locals. On success the
    // call stores a buffer it allocated, which this function frees once
    // below, and the number of bytes in it.
    let read = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            WTS_CURRENT_SESSION,
            WTSSessionInfoEx,
            &mut record,
            &mut record_bytes,
        )
    };
    if read == 0 || record.is_null() {
        return WindowsScreenSession::Unreadable;
    }
    let whole = usize::try_from(record_bytes).is_ok_and(|bytes| bytes >= size_of::<WTSINFOEXW>());
    let session = if whole {
        // SAFETY: the buffer is live and holds at least one `WTSINFOEXW`,
        // which is plain data; it is copied out with no alignment assumed.
        let info = unsafe { ptr::read_unaligned(record.cast::<WTSINFOEXW>()) };
        if info.Level == 1 {
            // SAFETY: level 1 says the union holds its level-1 member,
            // which is plain data.
            let level1 = unsafe { info.Data.WTSInfoExLevel1 };
            WindowsScreenSession::from_session_info(
                level1.SessionId,
                level1.SessionState,
                level1.SessionFlags,
            )
        } else {
            WindowsScreenSession::Unreadable
        }
    } else {
        WindowsScreenSession::Unreadable
    };
    // SAFETY: `record` is the buffer the query allocated; it is freed once
    // and not read again.
    unsafe { WTSFreeMemory(record.cast()) };
    session
}

/// The Windows Hello prompt, and this session's screen lock.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsUserPresence;

impl WindowsUserPresence {
    /// This device's unlock prompt.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl UserPresence for WindowsUserPresence {
    fn capability(&self) -> PresenceCapability {
        match screen_session() {
            WindowsScreenSession::Services => PresenceCapability::NoPrompt(SERVICES_SESSION),
            WindowsScreenSession::OffScreen => PresenceCapability::NoPrompt(SESSION_OFF_SCREEN),
            WindowsScreenSession::Unreadable => PresenceCapability::NoPrompt(SESSION_UNREADABLE),
            WindowsScreenSession::Locked | WindowsScreenSession::Unlocked => hello_capability(),
        }
    }

    fn confirm(&self, reason: &str) -> Result<(), PresenceError> {
        match screen_session() {
            WindowsScreenSession::Services => {
                return Err(PresenceError::NoPrompt(SERVICES_SESSION));
            }
            WindowsScreenSession::OffScreen => {
                return Err(PresenceError::NoPrompt(SESSION_OFF_SCREEN));
            }
            WindowsScreenSession::Unreadable => {
                return Err(PresenceError::NoPrompt(SESSION_UNREADABLE));
            }
            WindowsScreenSession::Locked => return Err(PresenceError::ScreenLocked),
            WindowsScreenSession::Unlocked => {}
        }
        // The prompt must say what is confirmed, as on every platform.
        if reason.trim().is_empty() {
            return Err(PresenceError::Platform("empty confirm reason", 0));
        }
        show_consent_prompt(reason)
    }

    fn screen_is_locked(&self) -> bool {
        // A services session has no screen to lock; its confirm answers
        // `NoPrompt`, so it never opens a window.
        matches!(
            screen_session(),
            WindowsScreenSession::Locked
                | WindowsScreenSession::OffScreen
                | WindowsScreenSession::Unreadable
        )
    }
}

/// The verifier's entry for a desktop process: the consent dialog with an
/// owner window. A Windows before build 22000 has none.
fn consent_interop() -> Result<IUserConsentVerifierInterop, WinrtError> {
    factory::<UserConsentVerifier, IUserConsentVerifierInterop>()
}

/// Whether Windows Hello can ask this user on this device.
fn hello_capability() -> PresenceCapability {
    if consent_interop().is_err() {
        return PresenceCapability::NoPrompt(NO_DESKTOP_CONSENT_PROMPT);
    }
    let availability = UserConsentVerifier::CheckAvailabilityAsync()
        .map_err(|error| AsyncFault::Platform(hresult(&error)))
        .and_then(|asked| answer_within(&asked, Duration::from_secs(AVAILABILITY_SECS)));
    match availability {
        Ok(availability) => PresenceCapability::from_user_consent_availability(availability.0),
        Err(_) => PresenceCapability::NoPrompt(NO_AVAILABILITY_ANSWER),
    }
}

/// Why an asynchronous Windows call gave no value.
enum AsyncFault {
    /// It did not finish in the time allowed, and was cancelled.
    NoAnswer,
    /// It failed, with its `HRESULT`.
    Platform(i64),
}

fn hresult(error: &WinrtError) -> i64 {
    i64::from(error.code().0)
}

/// Waits for `asked` at most `limit`, then cancels it. The wait is on a
/// channel the completion fills from a thread of the system's, so the calling
/// thread needs no message loop.
fn answer_within<T>(asked: &IAsyncOperation<T>, limit: Duration) -> Result<T, AsyncFault>
where
    T: RuntimeType + Send + 'static,
{
    let (answer, answers) = sync_channel::<Result<T, i64>>(1);
    asked
        .when(move |outcome| {
            // Nobody listens once the wait below has ended: the answer of a
            // call that was cancelled is dropped.
            let _ = answer.send(outcome.map_err(|error| hresult(&error)));
        })
        .map_err(|error| AsyncFault::Platform(hresult(&error)))?;
    match answers.recv_timeout(limit) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(code)) => Err(AsyncFault::Platform(code)),
        Err(RecvTimeoutError::Timeout) => {
            // Cancelling takes the call's dialog down; its late completion
            // finds no listener.
            let _ = asked.Cancel();
            Err(AsyncFault::NoAnswer)
        }
        Err(RecvTimeoutError::Disconnected) => Err(AsyncFault::Platform(0)),
    }
}

/// The window the consent dialog shows over: the terminal this process
/// talks through when it has a visible one, else the window the user has in
/// front. `None` when the session shows no window at all.
fn owner_window() -> Option<HWND> {
    // SAFETY: none of these calls takes a pointer argument. Each answers
    // null or a window handle, and a handle that has gone stale is refused
    // by the next call, never dereferenced here.
    unsafe {
        let console = GetConsoleWindow();
        if !console.is_null() {
            // Under a terminal the console's own window is hidden, and the
            // terminal's window is its root owner.
            let terminal = GetAncestor(console, GA_ROOTOWNER);
            if !terminal.is_null() && IsWindowVisible(terminal) != 0 {
                return Some(HWND(terminal));
            }
        }
        let front = GetForegroundWindow();
        (!front.is_null()).then_some(HWND(front))
    }
}

/// Shows the consent dialog and waits for its answer, at most
/// [`PRESENCE_PROMPT_SECS`].
fn show_consent_prompt(reason: &str) -> Result<(), PresenceError> {
    let Ok(interop) = consent_interop() else {
        return Err(PresenceError::NoPrompt(NO_DESKTOP_CONSENT_PROMPT));
    };
    let Some(owner) = owner_window() else {
        return Err(PresenceError::Platform(
            "no window to show the unlock prompt over",
            0,
        ));
    };
    let message = HSTRING::from(reason);
    // SAFETY: `interop` is the live factory interface, `owner` is a window
    // handle Windows checks itself, and `message` outlives the call. The
    // type asked for is the one the interface documents for this method.
    let asked: IAsyncOperation<UserConsentVerificationResult> =
        unsafe { interop.RequestVerificationForWindowAsync(owner, &message) }.map_err(|error| {
            PresenceError::Platform("user consent verification request", hresult(&error))
        })?;
    match answer_within(&asked, Duration::from_secs(PRESENCE_PROMPT_SECS)) {
        Ok(result) => PresenceError::user_consent_verification(result.0),
        Err(AsyncFault::NoAnswer) => Err(PresenceError::NoAnswer),
        Err(AsyncFault::Platform(code)) => Err(PresenceError::Platform(
            "user consent verification call",
            code,
        )),
    }
}
