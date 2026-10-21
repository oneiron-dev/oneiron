//! A request's credential in the owner's connection-pool pressure check
//! (FIX 7656). Once a request's slip or account key is accepted, the id it
//! is revoked by is attached to that request's counted body, which only the
//! owner's `/v1/owner/wire-health` shows. Nothing else of the credential is
//! kept. A refused credential attaches nothing, and attaching never fails
//! the request: outside a body the TCP listener counts, it does nothing.

use super::CoreAuth;
use crate::wire_telemetry::{PressureCredentialKey, attach_body_credential};

/// After a slip's fresh holder proof was admitted: its mint id.
pub(super) fn attach_slip(auth: &CoreAuth) {
    if let Some(slip) = auth.verified_slip() {
        let slip_id = slip
            .claims()
            .slip_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        attach_body_credential(PressureCredentialKey::Slip { slip_id });
    }
}

/// After the control plane's verdict accepted an account key: its key id.
pub(super) fn attach_account_key(key_id: &str) {
    attach_body_credential(PressureCredentialKey::AccountKey {
        key_id: key_id.to_owned(),
    });
}
