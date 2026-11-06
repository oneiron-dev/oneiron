//! Owner-only private-copy viewing and the owner's OS-authentication override.
//!
//! The OS dialog holds neither the vault's writer lease nor the parent's
//! owner-act mutex. The final preference check and owner read share that mutex
//! with setting changes. These commands are not in the agent verb catalog.

mod capture;
pub(crate) use capture::{
    CopyClassification, PrivateCopyMarker, PrivateCopyRegistration, capture_private_copy,
    classify_private_copy,
};

use oneiron::secret_custody::{OwnerSecretReveal, RevealTarget};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use tauri::{AppHandle, Manager};

use super::{RekeyState, local_owner};

/// The one device-local setting. An absent key requires OS authentication.
const SKIP_AUTHENTICATION_KEY: &str = "PrivateCopySkipAuthentication";

#[derive(serde::Serialize)]
pub struct PrivateCopyViewSettings {
    skip_authentication: bool,
}

/// The actual owner reveal owns and wipes its value. Serialization borrows it;
/// only the invoking owner surface receives the bytes.
pub struct PrivateCopyView(OwnerSecretReveal);

impl Serialize for PrivateCopyView {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(serde::Serialize)]
        struct Receipt<'a> {
            reveal: String,
            handle: &'a str,
            decision: Option<String>,
            delivered_at: Option<u64>,
        }
        let receipt = &self.0.receipt;
        let mut output = serializer.serialize_struct("PrivateCopyView", 2)?;
        output.serialize_field("value", self.0.value.as_slice())?;
        output.serialize_field(
            "receipt",
            &Receipt {
                reveal: receipt.reveal.to_hex(),
                handle: &receipt.handle,
                decision: receipt.decision.map(|decision| decision.to_hex()),
                delivered_at: receipt.delivered_at,
            },
        )?;
        output.end()
    }
}

#[tauri::command]
pub fn private_copy_view_settings(app: AppHandle) -> Result<PrivateCopyViewSettings, String> {
    let state = app.state::<RekeyState>();
    let _owner_act = state
        .confirming
        .lock()
        .map_err(|_| "the owner-act state is unavailable".to_owned())?;
    Ok(PrivateCopyViewSettings {
        skip_authentication: skip_authentication(),
    })
}

/// Changing the explicit override is an owner act, not another OS dialog.
#[tauri::command]
pub fn set_private_copy_view_settings(
    app: AppHandle,
    skip_authentication: bool,
) -> Result<PrivateCopyViewSettings, String> {
    let state = app.state::<RekeyState>();
    let _owner_act = state
        .confirming
        .lock()
        .map_err(|_| "the owner-act state is unavailable".to_owned())?;
    let lease = state
        .vault
        .hold_writer_lease_for_owner_act()
        .map_err(|error| error.to_string())?;
    let _owner = local_owner(&state.vault, &lease)?;
    store_skip_authentication(skip_authentication);
    Ok(PrivateCopyViewSettings {
        skip_authentication: self::skip_authentication(),
    })
}

#[tauri::command]
pub async fn private_copy_view(
    app: AppHandle,
    handle: String,
    reason: String,
) -> Result<PrivateCopyView, String> {
    let target = RevealTarget::Handle(handle);
    match view_if_authorized(&app, &target, &reason, false)? {
        Some(view) => Ok(view),
        None => {
            authenticate_view().await?;
            // Genuine OS success is request-local, not a reusable grant or TTL.
            view_if_authorized(&app, &target, &reason, true)?
                .ok_or_else(|| "OS authentication did not authorize this view".to_owned())
        }
    }
}

/// `None` asks for OS authentication after this frame drops every guard.
fn view_if_authorized(
    app: &AppHandle,
    target: &RevealTarget,
    reason: &str,
    authenticated: bool,
) -> Result<Option<PrivateCopyView>, String> {
    let state = app.state::<RekeyState>();
    let _owner_act = state
        .confirming
        .lock()
        .map_err(|_| "the owner-act state is unavailable".to_owned())?;
    if !skip_authentication() && !authenticated {
        return Ok(None);
    }
    let lease = state
        .vault
        .hold_writer_lease_for_owner_act()
        .map_err(|error| error.to_string())?;
    let owner = local_owner(&state.vault, &lease)?;
    state
        .vault
        .reveal_secret_as_owner(&owner, target, reason)
        .map(|reveal| Some(PrivateCopyView(reveal)))
        .map_err(|error| error.to_string())
}

fn skip_authentication() -> bool {
    let key = objc2_foundation::NSString::from_str(SKIP_AUTHENTICATION_KEY);
    objc2_foundation::NSUserDefaults::standardUserDefaults().boolForKey(&key)
}

fn store_skip_authentication(skip: bool) {
    let key = objc2_foundation::NSString::from_str(SKIP_AUTHENTICATION_KEY);
    objc2_foundation::NSUserDefaults::standardUserDefaults().setBool_forKey(skip, &key);
}

async fn authenticate_view() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(|| {
        objc2::rc::autoreleasepool(|_| {
            use block2::RcBlock;
            use objc2::runtime::Bool;
            use objc2_foundation::{NSError, NSString};
            use objc2_local_authentication::{LAContext, LAPolicy};

            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            // SAFETY: LAContext inherits NSObject's AnyThread construction.
            // It and the reply stay on this blocking frame until completion.
            let context = unsafe { LAContext::new() };
            let reason = NSString::from_str(crate::copy::PRIVATE_COPY_VIEW_REASON);
            let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
                // The callback captures only a Send channel endpoint. No ObjC
                // pointer or vault state escapes its unspecified reply thread.
                let _ = sender.send(success.as_bool());
            });
            // SAFETY: the reply is sendable: its sole capture is SyncSender<bool>.
            // The reason is fixed and nonempty. Strong context and block references
            // remain alive through the receive; no owner-act guard is held here.
            unsafe {
                context.evaluatePolicy_localizedReason_reply(
                    LAPolicy::DeviceOwnerAuthentication,
                    &reason,
                    &reply,
                );
            }
            match receiver.recv() {
                Ok(true) => Ok(()),
                Ok(false) => Err("OS authentication was cancelled or failed".to_owned()),
                Err(_) => Err("OS authentication ended without a result".to_owned()),
            }
        })
    })
    .await
    .map_err(|_| "OS authentication could not finish".to_owned())?
}
