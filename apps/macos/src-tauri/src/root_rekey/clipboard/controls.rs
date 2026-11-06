use objc2_foundation::{NSString, NSUserDefaults};
use oneiron::EntityId;
use oneiron::clipboard::{
    ClipboardEntry, ClipboardErase, ClipboardEraseReport, ClipboardRetention,
};
use serde::{Deserialize, Serialize};
use tauri::AppHandle;

use super::with_owner;

const CAPTURE_SETTINGS_KEY: &str = "ClipboardCaptureSettings";
const CAPTURE_DISABLED: isize = 1;
const TRANSIENT_AS_ORDINARY: isize = 2;
const PRIVATE_DEVICE_ONLY: isize = 4;

/// Device-local routing choices, sampled before each observed copy's payload.
/// A change applies to the next observation, not an already observed copy.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ClipboardCaptureSettings {
    pub(crate) enabled: bool,
    /// Generic transient metadata does not establish who produced a copy.
    /// This default routes it privately; the owner may choose ordinary intake.
    pub(crate) transient_as_private: bool,
    pub(crate) private_device_only: bool,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ClipboardSettings {
    pub(crate) capture: ClipboardCaptureSettings,
    pub(crate) retention: ClipboardRetention,
}

pub(super) fn capture_settings() -> ClipboardCaptureSettings {
    let flags = NSUserDefaults::standardUserDefaults()
        .integerForKey(&NSString::from_str(CAPTURE_SETTINGS_KEY));
    ClipboardCaptureSettings {
        enabled: flags & CAPTURE_DISABLED == 0,
        transient_as_private: flags & TRANSIENT_AS_ORDINARY == 0,
        private_device_only: flags & PRIVATE_DEVICE_ONLY != 0,
    }
}

fn store_capture_settings(settings: ClipboardCaptureSettings) {
    let flags = if settings.enabled {
        0
    } else {
        CAPTURE_DISABLED
    } | if settings.transient_as_private {
        0
    } else {
        TRANSIENT_AS_ORDINARY
    } | if settings.private_device_only {
        PRIVATE_DEVICE_ONLY
    } else {
        0
    };
    // One value keeps the routing choices coherent at observation time.
    NSUserDefaults::standardUserDefaults()
        .setInteger_forKey(flags, &NSString::from_str(CAPTURE_SETTINGS_KEY));
}

#[tauri::command]
pub(crate) fn clipboard_settings(app: AppHandle) -> Result<ClipboardSettings, String> {
    with_owner(&app, |vault, owner| {
        Ok(ClipboardSettings {
            capture: capture_settings(),
            retention: vault.clipboard_retention_as_owner(owner)?,
        })
    })
}

#[tauri::command]
pub(crate) fn set_clipboard_settings(
    app: AppHandle,
    settings: ClipboardSettings,
) -> Result<ClipboardSettings, String> {
    with_owner(&app, |vault, owner| {
        vault.set_clipboard_retention_as_owner(owner, &settings.retention)?;
        store_capture_settings(settings.capture);
        Ok(settings)
    })
}

#[tauri::command]
pub(crate) fn clipboard_entries(
    app: AppHandle,
    before: Option<(u64, EntityId)>,
    limit: usize,
) -> Result<Vec<ClipboardEntry>, String> {
    with_owner(&app, |vault, owner| {
        vault.clipboard_entries_as_owner(owner, before, limit)
    })
}

#[tauri::command]
pub(crate) fn clipboard_erase(
    app: AppHandle,
    selection: ClipboardErase,
) -> Result<ClipboardEraseReport, String> {
    with_owner(&app, |vault, owner| {
        vault.erase_clipboard_as_owner(owner, selection)
    })
}

/// Reads a derived question again, including after a missed quiet event.
#[tauri::command]
pub(crate) fn clipboard_secret_purpose_questions(
    app: AppHandle,
    clip: EntityId,
) -> Result<Vec<oneiron::secret_custody::SecretPurposeQuestion>, String> {
    with_owner(&app, |vault, owner| {
        vault.clipboard_secret_purpose_questions_as_owner(owner, clip)
    })
}

#[tauri::command]
pub(crate) fn set_secret_handle_purpose(
    app: AppHandle,
    handle: String,
    purpose: Option<String>,
) -> Result<oneiron::secret_custody::SecretHandlePurposeSet, String> {
    with_owner(&app, |vault, owner| {
        vault.set_secret_handle_purpose(owner, &handle, purpose.as_deref())
    })
}
