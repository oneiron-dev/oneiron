//! macOS: the device's own unlock sheet, and the window server's word on the
//! screen lock (row OWNER-CONFIRM-SHEET).
//!
//! - The sheet is LocalAuthentication's device-owner policy: Touch ID or a
//!   paired watch where the Mac has one, else the account password. No
//!   keychain item is read or changed.
//! - The screen lock is read from the window server's dictionary for this
//!   process's session. macOS posts its lock notification only to a main
//!   thread that runs a run loop, which a headless host has not, so the
//!   presence gate asks: at each act, and on a timer.
//! - A process with no session on the device's screen (a system daemon, a
//!   shell of a user with no session on the screen, a user switched out)
//!   cannot show the sheet and says so.
//!
//! Other Apple platforms have no screen-lock reading here, so they get no
//! prompt: a window must never outlast a lock.

use std::sync::mpsc::{RecvTimeoutError, sync_channel};
use std::time::Duration;

use block2::RcBlock;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use objc2::rc::autoreleasepool;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};

use crate::user_presence::{PRESENCE_PROMPT_SECS, PresenceCapability, PresenceError, UserPresence};

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    // CoreGraphics/CGSession.h. It answers null when the caller has no
    // window-server session; the caller owns a dictionary it answers.
    fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
}

/// CGSession.h's `kCGSessionOnConsoleKey`: whether the session is the one on
/// the device's screen. A user switched out reads false.
const SESSION_ON_CONSOLE_KEY: &str = "kCGSSessionOnConsoleKey";
/// The window server sets this key while the session's screen is locked.
/// Apple documents no name for it: it is read as observed, and the probe
/// (`examples/user_presence_probe.rs`) prints the reading on a real device.
const SESSION_SCREEN_IS_LOCKED_KEY: &str = "CGSSessionScreenIsLocked";

const NO_SCREEN_SESSION: &str = "this process has no session on the device's screen";
const SESSION_OFF_SCREEN: &str = "this user's session is not the one on the device's screen";
const NO_LOCAL_AUTHENTICATION: &str = "the device's unlock prompt is not available";

/// What the window server says of the session this process runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScreenSession {
    /// No window-server session: a system daemon, or a shell of a user with
    /// no session on the screen.
    Absent,
    /// A session that is not on the device's screen: its user switched out.
    OffScreen,
    /// On the screen, and locked.
    Locked,
    /// On the screen, and unlocked.
    Unlocked,
}

fn screen_session() -> ScreenSession {
    // SAFETY: the function takes no argument, and answers null or a
    // dictionary this caller owns.
    let session = unsafe { CGSessionCopyCurrentDictionary() };
    if session.is_null() {
        return ScreenSession::Absent;
    }
    // SAFETY: `session` is a non-null dictionary this call owns (the Copy
    // rule), so the wrapper releases it exactly once. Its keys are
    // CFStrings, and each value is read only through a type-checked cast.
    let session: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(session) };
    if session_flag(&session, SESSION_ON_CONSOLE_KEY) == Some(false) {
        return ScreenSession::OffScreen;
    }
    if session_flag(&session, SESSION_SCREEN_IS_LOCKED_KEY) == Some(true) {
        return ScreenSession::Locked;
    }
    ScreenSession::Unlocked
}

/// One flag of the session dictionary; `None` when the key is absent. A
/// value that is neither a boolean nor a number reads as set.
fn session_flag(session: &CFDictionary<CFString, CFType>, key: &'static str) -> Option<bool> {
    let key = CFString::from_static_string(key);
    let value = session.find(&key)?;
    if let Some(flag) = value.downcast::<CFBoolean>() {
        return Some(flag.into());
    }
    if let Some(number) = value.downcast::<CFNumber>() {
        return Some(number.to_i64() != Some(0));
    }
    Some(true)
}

/// The macOS unlock sheet, and this session's screen lock.
#[derive(Clone, Copy, Debug, Default)]
pub struct MacosUserPresence;

impl MacosUserPresence {
    /// This device's unlock sheet.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl UserPresence for MacosUserPresence {
    fn capability(&self) -> PresenceCapability {
        match screen_session() {
            ScreenSession::Absent => PresenceCapability::NoPrompt(NO_SCREEN_SESSION),
            ScreenSession::OffScreen => PresenceCapability::NoPrompt(SESSION_OFF_SCREEN),
            ScreenSession::Locked | ScreenSession::Unlocked => {
                match autoreleasepool(|_| policy_refusal(&new_context())) {
                    None => PresenceCapability::DevicePrompt,
                    Some(PresenceError::NoPrompt(reason)) => PresenceCapability::NoPrompt(reason),
                    Some(_) => PresenceCapability::NoPrompt(NO_LOCAL_AUTHENTICATION),
                }
            }
        }
    }

    fn confirm(&self, reason: &str) -> Result<(), PresenceError> {
        match screen_session() {
            ScreenSession::Absent => return Err(PresenceError::NoPrompt(NO_SCREEN_SESSION)),
            ScreenSession::OffScreen => return Err(PresenceError::NoPrompt(SESSION_OFF_SCREEN)),
            ScreenSession::Locked => return Err(PresenceError::ScreenLocked),
            ScreenSession::Unlocked => {}
        }
        // The framework raises an exception on an empty reason, which no
        // Rust frame may see.
        if reason.trim().is_empty() {
            return Err(PresenceError::Platform("empty confirm reason", 0));
        }
        autoreleasepool(|_| show_sheet(reason))
    }

    fn screen_is_locked(&self) -> bool {
        // A process with no session has no screen to lock; its confirm
        // answers `NoPrompt`, so it never opens a window.
        matches!(
            screen_session(),
            ScreenSession::Locked | ScreenSession::OffScreen
        )
    }
}

fn new_context() -> objc2::rc::Retained<LAContext> {
    // SAFETY: LAContext is an NSObject subclass any thread may make. The
    // caller keeps it on its own frame.
    unsafe { LAContext::new() }
}

/// Why `context` cannot evaluate the device-owner policy, if it cannot.
fn policy_refusal(context: &LAContext) -> Option<PresenceError> {
    // SAFETY: `context` is a live LAContext, the policy is one of the
    // framework's own, and the binding owns the error out-parameter.
    unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) }
        .err()
        .map(|error| PresenceError::from_local_authentication_code(error_code(&error)))
}

fn error_code(error: &NSError) -> i64 {
    i64::try_from(error.code()).unwrap_or(i64::MIN)
}

/// Shows the sheet and waits for its answer, at most
/// [`PRESENCE_PROMPT_SECS`].
fn show_sheet(reason: &str) -> Result<(), PresenceError> {
    let context = new_context();
    if let Some(refusal) = policy_refusal(&context) {
        return Err(refusal);
    }
    let (answer, answers) = sync_channel::<Result<(), i64>>(1);
    let reason = NSString::from_str(reason);
    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        let outcome = if success.as_bool() {
            Ok(())
        } else {
            // SAFETY: the framework passes null or an NSError that is valid
            // for the length of this call, and only its code is read here.
            Err(unsafe { error.as_ref() }.map_or(0, error_code))
        };
        // Nobody listens once the wait below has ended: the answer of a
        // sheet that was taken down is dropped.
        let _ = answer.send(outcome);
    });
    // SAFETY: the reply is sendable: its one capture is a `SyncSender` of
    // plain values, and no Objective-C pointer leaves the reply's thread.
    // The reason is not empty. The context and the block stay alive on this
    // frame through the wait.
    unsafe {
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &reason,
            &reply,
        );
    }
    match answers.recv_timeout(Duration::from_secs(PRESENCE_PROMPT_SECS)) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(code)) => Err(PresenceError::from_local_authentication_code(code)),
        Err(RecvTimeoutError::Timeout) => {
            // SAFETY: `context` is live; invalidating it takes its sheet
            // down, and its late reply finds no listener.
            unsafe { context.invalidate() };
            Err(PresenceError::NoAnswer)
        }
        Err(RecvTimeoutError::Disconnected) => {
            Err(PresenceError::Platform("local authentication reply", 0))
        }
    }
}
