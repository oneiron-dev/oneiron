use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};
use objc2_foundation::{NSFileManager, NSFileSystemFreeSize, NSNumber, NSString};
use oneiron::EntityId;
use oneiron::authority::ActSurface;
use oneiron::secret_custody::{CustodyClass, CustodyTier};
use tauri::{AppHandle, Emitter, Manager, RunEvent};
use zeroize::Zeroizing;

use super::super::RekeyState;
use super::super::private_copy::{
    CopyClassification, PrivateCopyRegistration, capture_private_copy, classify_private_copy,
};
use super::controls::{ClipboardCaptureSettings, capture_settings};
use super::with_owner;

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const PRIVATE_COPY_NAME_PREFIX: &str = "private-copy-";
const SECRET_PURPOSE_EVENT: &str = "clipboard-secret-purpose";

// Not serializable or Debug: private bytes never become diagnostics or IPC.
enum CopyValue {
    Ordinary(Zeroizing<String>),
    Private(Zeroizing<Vec<u8>>),
}

struct Observation {
    count: isize,
    observed_at: u64,
    settings: ClipboardCaptureSettings,
    value: Option<CopyValue>,
}

pub(crate) fn start(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    // setup() calls this on the main thread after managing RekeyState. The
    // first count is a baseline only: no pre-launch payload or history read.
    let baseline = objc2::rc::autoreleasepool(|_| NSPasteboard::generalPasteboard().changeCount());
    let stopping = Arc::new(AtomicBool::new(false));
    let (wake, stop) = mpsc::channel();
    let on_exit = Arc::clone(&stopping);
    app.plugin(
        tauri::plugin::Builder::new("clipboard")
            .on_event(move |_, event| {
                if matches!(event, RunEvent::Exit) {
                    on_exit.store(true, Ordering::Release);
                    let _ = wake.send(());
                }
            })
            .build(),
    )?;
    let app = app.clone();
    // Exit signals the worker, including a pending main-thread reply wait.
    // Never join on the main thread: its queued reply may need that thread.
    let _worker = std::thread::Builder::new()
        .name("clipboard".to_owned())
        .spawn(move || watch(app, baseline, stopping, stop))?;
    Ok(())
}

fn watch(app: AppHandle, mut last: isize, stopping: Arc<AtomicBool>, stop: Receiver<()>) {
    let mut cleanup_at = Instant::now();
    let mut capture_failed = false;
    while !stopping.load(Ordering::Acquire) {
        match stop.recv_timeout(POLL_INTERVAL) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }
        let sampled = sample(&app, last, &stopping);
        match sampled {
            Ok(Some(observation)) => {
                let count = observation.count;
                if capture(&app, observation).is_ok() {
                    last = count;
                    capture_failed = false;
                } else if !capture_failed {
                    tracing::warn!(
                        reason = "capture_failed",
                        "Clipboard intake will retry the current copy"
                    );
                    capture_failed = true;
                }
            }
            Ok(None) => {}
            Err(()) => break,
        }
        if !stopping.load(Ordering::Acquire) && cleanup_at.elapsed() >= CLEANUP_INTERVAL {
            let free_bytes = filesystem_free_bytes(&app);
            match free_bytes.and_then(|free_bytes| {
                with_owner(&app, |vault, owner| {
                    vault.cleanup_clipboard_as_owner(owner, free_bytes)
                })
            }) {
                Ok(_) => {}
                Err(_) => tracing::warn!(
                    reason = "cleanup_failed",
                    "Clipboard cleanup did not complete"
                ),
            }
            cleanup_at = Instant::now();
        }
    }
}

fn sample(
    app: &AppHandle,
    last: isize,
    stopping: &Arc<AtomicBool>,
) -> Result<Option<Observation>, ()> {
    let (reply, received) = mpsc::sync_channel(1);
    let on_main = Arc::clone(stopping);
    app.run_on_main_thread(move || {
        if !on_main.load(Ordering::Acquire) {
            let observation = objc2::rc::autoreleasepool(|_| read_changed(last));
            let _ = reply.send(observation);
        }
    })
    .map_err(|_| ())?;
    // Only one sample is outstanding, even if the main thread is busy.
    loop {
        if stopping.load(Ordering::Acquire) {
            return Err(());
        }
        match received.recv_timeout(POLL_INTERVAL) {
            Ok(observation) => return Ok(observation),
            Err(RecvTimeoutError::Disconnected) => return Err(()),
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

fn read_changed(last: isize) -> Option<Observation> {
    let pasteboard = NSPasteboard::generalPasteboard();
    let count = pasteboard.changeCount();
    if count == last {
        return None;
    }
    let settings = capture_settings();
    let observed_at = crate::now_unix();
    let value = if !settings.enabled {
        None
    } else {
        let types = pasteboard.types()?;
        let types: Vec<String> = types.to_vec().iter().map(|kind| kind.to_string()).collect();
        let private = match classify_private_copy(&types) {
            CopyClassification::Private(_) => true,
            CopyClassification::TransientSourceUnknown => settings.transient_as_private,
            CopyClassification::Unmarked => false,
        };
        // SAFETY: this immutable AppKit string constant is provided by the
        // linked framework and is borrowed only on this main-thread frame.
        let text_type = unsafe { NSPasteboardTypeString };
        let value = if private {
            pasteboard
                .dataForType(text_type)
                .map(|data| CopyValue::Private(Zeroizing::new(data.to_vec())))
        } else {
            pasteboard
                .stringForType(text_type)
                .map(|text| CopyValue::Ordinary(Zeroizing::new(text.to_string())))
        };
        if value.is_none() && types.iter().any(|kind| kind == &text_type.to_string()) {
            // Advertised text was unavailable. Do not acknowledge the count
            // as a non-text copy or route a failed private read ordinarily.
            return None;
        }
        value
    };
    if pasteboard.changeCount() != count {
        // A copy raced classification/payload read. Drop and wipe the result;
        // retry the newest count instead of trusting old type evidence.
        return None;
    }
    Some(Observation {
        count,
        observed_at,
        settings,
        value,
    })
}

fn capture(app: &AppHandle, observation: Observation) -> Result<(), String> {
    match observation.value {
        None => Ok(()),
        Some(CopyValue::Ordinary(text)) => {
            let questions = with_owner(app, |vault, owner| {
                let clip = vault.capture_clipboard_text_as_owner(
                    owner,
                    ActSurface::ThisInstall,
                    &text,
                    observation.observed_at,
                )?;
                Ok(vault.clipboard_secret_purpose_questions_as_owner(owner, clip))
            })?;
            let delivery = questions.map_err(|_| ()).and_then(|questions| {
                if questions.is_empty() {
                    Ok(())
                } else {
                    app.emit_to(crate::MAIN_WINDOW, SECRET_PURPOSE_EVENT, questions)
                        .map_err(|_| ())
                }
            });
            if delivery.is_err() {
                // The clip and its existing found-key inbox notice are durable.
                // Owner IPC can read the question again without recapturing text.
                tracing::warn!(
                    reason = "purpose_delivery_failed",
                    "Clipboard purpose metadata remains available through owner controls"
                );
            }
            Ok(())
        }
        Some(CopyValue::Private(value)) => {
            let registration = PrivateCopyRegistration {
                name: format!("{PRIVATE_COPY_NAME_PREFIX}{}", EntityId::now().to_hex()),
                class: CustodyClass::CustodyPortable,
                device_only: observation.settings.private_device_only,
                rung: CustodyTier::T0Doored,
                bindings: Vec::new(),
                manifest: None,
            };
            capture_private_copy(app, registration, value, observation.observed_at).map(|_| ())
        }
    }
}

fn filesystem_free_bytes(app: &AppHandle) -> Result<u64, String> {
    let state = app.state::<RekeyState>();
    let path = state
        .vault_dir
        .to_str()
        .ok_or("the vault path is not UTF-8")?;
    objc2::rc::autoreleasepool(|_| {
        let attributes = NSFileManager::defaultManager()
            .attributesOfFileSystemForPath_error(&NSString::from_str(path))
            .map_err(|_| "the vault filesystem could not be observed".to_owned())?;
        // SAFETY: Foundation owns this immutable attribute-key constant for
        // the process lifetime; no object pointer escapes this frame.
        let key = unsafe { NSFileSystemFreeSize };
        attributes
            .objectForKey(key)
            .and_then(|value| {
                value
                    .downcast_ref::<NSNumber>()
                    .map(NSNumber::unsignedLongLongValue)
            })
            .ok_or_else(|| "the vault filesystem returned no free-byte count".to_owned())
    })
}
