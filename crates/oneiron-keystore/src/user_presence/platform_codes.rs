//! What each platform's result codes stand for: Apple's `LAError` codes,
//! Windows' user consent values and Windows' record of a session. The
//! tables are here, and not with each platform's prompt, so that every
//! platform's tests run them.

use super::{PresenceCapability, PresenceError};

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
    ///
    /// [`PRESENCE_PROMPT_SECS`]: super::PRESENCE_PROMPT_SECS
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
