//! The vault-read error vocabulary and its stable engine codes. The error type itself is
//! defined in `oneiron-contracts`; the adapters' constructors live here.

use super::contract::{VaultReadMethod, VaultReadWireOp};

pub use oneiron_contracts::code_run::vault_read::{VaultReadError, VaultReadResult};

/// Stable engine code for accepted-route absence. A missing target and a
/// clamp-denied target normalize to this one code by design.
pub(super) const NOT_FOUND_ENGINE_CODE: &str = "NOT_FOUND";

/// Stable engine code for an engine-side failure, copied from the accepted API
/// error vocabulary.
pub(super) const INTERNAL_ENGINE_CODE: &str = "INTERNAL_SERVER_ERROR";

/// The adapters' own accessors on the shared error type, which `oneiron-contracts`
/// defines: a crate-local trait, because a foreign type takes no inherent impl here.
pub(super) trait VaultReadErrorExt {
    fn with_read_receipt(self, receipt: crate::claim::ScopedReadReceipt) -> Self;
    fn method(&self) -> VaultReadMethod;
}

impl VaultReadErrorExt for VaultReadError {
    fn with_read_receipt(mut self, receipt: crate::claim::ScopedReadReceipt) -> Self {
        if let Self::Engine { narrowing, .. } = &mut self {
            *narrowing = Some(Box::new(receipt));
        }
        self
    }

    fn method(&self) -> VaultReadMethod {
        match self {
            Self::InvalidRequest { method, .. }
            | Self::Transport { method, .. }
            | Self::ProtocolMismatch { method, .. }
            | Self::RuntimeUnavailable { method }
            | Self::Unimplemented { method, .. }
            | Self::Engine { method, .. } => *method,
        }
    }
}

pub(super) fn invalid_request(
    method: VaultReadMethod,
    field: &str,
    reason: &str,
) -> VaultReadError {
    VaultReadError::InvalidRequest {
        method,
        field: field.to_owned(),
        reason: reason.to_owned(),
    }
}

/// Accepted-route absence. A missing row and a clamp-denied row normalize here
/// identically; the adapter never distinguishes why the route answered absence.
pub(super) fn engine_absent(method: VaultReadMethod, field: &str) -> VaultReadError {
    VaultReadError::Engine {
        narrowing: None,
        method,
        engine_code: NOT_FOUND_ENGINE_CODE.to_owned(),
        message: format!("{field} was not found"),
    }
}

pub(super) fn engine_failure(method: VaultReadMethod, error: &crate::Error) -> VaultReadError {
    VaultReadError::Engine {
        narrowing: None,
        method,
        engine_code: INTERNAL_ENGINE_CODE.to_owned(),
        message: error.to_string(),
    }
}

pub(super) fn response_arm_mismatch(
    method: VaultReadMethod,
    received: VaultReadWireOp,
) -> VaultReadError {
    VaultReadError::ProtocolMismatch {
        method,
        message: format!(
            "expected response op {}, received {}",
            method.wire_op().as_str(),
            received.as_str()
        ),
    }
}
