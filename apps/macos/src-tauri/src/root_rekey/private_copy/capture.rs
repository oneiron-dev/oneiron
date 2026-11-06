//! Types-only private-copy classification and an owned-value capture supplier.
//!
//! The caller supplies custody metadata and a wiping value buffer. Capture
//! proves the local owner and returns only native registration metadata and
//! the handle. Viewing requires the separate owner-view command.

use oneiron::secret_custody::{
    CustodyClass, CustodyTier, ManifestSource, OwnerSecretRegistration, PrivateCopySecret,
    RequestedBinding,
};
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use super::super::{RekeyState, local_owner};

// Confidential markers documented by https://nspasteboard.org/.
const CONCEALED_TYPE: &str = "org.nspasteboard.ConcealedType";
const ONE_PASSWORD_TYPE: &str = "com.agilebits.onepassword";
// This lifetime marker is shared by Enpass and non-secret text expanders.
const TRANSIENT_TYPE: &str = "org.nspasteboard.TransientType";

/// Which confidential marker the copy carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivateCopyMarker {
    Concealed,
    OnePassword,
}

/// Marker evidence only; this type neither captures nor routes a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyClassification {
    Private(PrivateCopyMarker),
    /// The generic transient marker establishes neither source nor privacy.
    TransientSourceUnknown,
    /// These known markers were absent, not proof that the copy is public.
    Unmarked,
}

/// Classifies types before any payload read. Confidential markers take
/// precedence over the generic transient marker.
#[must_use]
pub(crate) fn classify_private_copy(types: &[String]) -> CopyClassification {
    if types.iter().any(|kind| kind == CONCEALED_TYPE) {
        return CopyClassification::Private(PrivateCopyMarker::Concealed);
    }
    if types.iter().any(|kind| kind == ONE_PASSWORD_TYPE) {
        return CopyClassification::Private(PrivateCopyMarker::OnePassword);
    }
    if types.iter().any(|kind| kind == TRANSIENT_TYPE) {
        return CopyClassification::TransientSourceUnknown;
    }
    CopyClassification::Unmarked
}

/// Explicit caller metadata, forwarded unchanged without host defaults.
pub(crate) struct PrivateCopyRegistration {
    /// Nonempty, live-unique, at most 255 bytes and not in the engine's
    /// reserved cloud-registration namespace; the native door validates it.
    pub(crate) name: String,
    pub(crate) class: CustodyClass,
    pub(crate) device_only: bool,
    pub(crate) rung: CustodyTier,
    pub(crate) bindings: Vec<RequestedBinding>,
    pub(crate) manifest: Option<ManifestSource>,
}

/// Consumes and wipes the input value; the native door borrows it once and
/// returns only metadata and its actual handle. Capture has no OS dialog.
pub(crate) fn capture_private_copy(
    app: &AppHandle,
    registration: PrivateCopyRegistration,
    value: Zeroizing<Vec<u8>>,
    at: u64,
) -> Result<PrivateCopySecret, String> {
    let PrivateCopyRegistration {
        name,
        class,
        device_only,
        rung,
        bindings,
        manifest,
    } = registration;
    let state = app.state::<RekeyState>();
    let _owner_act = state
        .confirming
        .lock()
        .map_err(|_| "the owner-act state is unavailable".to_owned())?;
    let lease = state
        .vault
        .hold_writer_lease_for_owner_act()
        .map_err(|error| error.to_string())?;
    let owner = local_owner(&state.vault, &lease)?;
    let request = OwnerSecretRegistration {
        name: &name,
        class,
        device_only,
        rung,
        bindings,
        manifest,
        value: &*value,
    };
    state
        .vault
        .register_private_copy_as_owner(&owner, &request, at)
        .map_err(|error| error.to_string())
}
