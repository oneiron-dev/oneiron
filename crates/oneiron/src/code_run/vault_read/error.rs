//! The vault-read error vocabulary and its stable engine codes.

use serde::{Deserialize, Serialize};

use super::contract::{VaultReadAdapterKind, VaultReadMethod, VaultReadWireOp};

/// Result of every vault-read operation.
pub type VaultReadResult<T> = std::result::Result<T, VaultReadError>;

/// Stable engine code for accepted-route absence. A missing target and a
/// clamp-denied target normalize to this one code by design.
pub(super) const NOT_FOUND_ENGINE_CODE: &str = "NOT_FOUND";

/// Stable engine code for an engine-side failure, copied from the accepted API
/// error vocabulary.
pub(super) const INTERNAL_ENGINE_CODE: &str = "INTERNAL_SERVER_ERROR";

/// The one comparable typed failure taxonomy shared by every adapter.
///
/// Parity is structured-fields-only: compare `InvalidRequest` by
/// `{ method, field }` and `Engine` by `{ method, engine_code }`. Free-text
/// `reason`/`message` never gates parity.
///
/// This type deliberately does NOT embed [`crate::Error`]: the crate error
/// bridges to it with `#[from]`, and embedding would make the type recursive
/// and non-serializable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VaultReadError {
    /// The request failed the accepted route's own validation.
    #[error("invalid vault-read request for {method:?}: {field}: {reason}")]
    InvalidRequest {
        /// Method whose accepted validation rejected the request.
        method: VaultReadMethod,
        /// Accepted route field name that failed.
        field: String,
        /// Human-readable reason. Never compared for parity.
        reason: String,
    },
    /// The injected transport failed to complete a round trip.
    #[error("vault-read transport failed for {method:?}: {message}")]
    Transport {
        /// Method whose round trip failed.
        method: VaultReadMethod,
        /// Human-readable transport detail. Never compared for parity.
        message: String,
    },
    /// The response envelope or its operation tag violated the contract.
    #[error("vault-read protocol mismatch for {method:?}: {message}")]
    ProtocolMismatch {
        /// Method whose response failed contract decoding.
        method: VaultReadMethod,
        /// Human-readable protocol detail. Never compared for parity.
        message: String,
    },
    /// An M8-reserved runtime peer was called before the runtime exists.
    #[error("vault-read runtime unavailable for {method:?}")]
    RuntimeUnavailable {
        /// Runtime peer that is not available.
        method: VaultReadMethod,
    },
    /// The adapter exposes the method but cannot execute it yet.
    #[error("vault-read method {method:?} is unimplemented by {adapter:?}")]
    Unimplemented {
        /// Adapter that has no implementation for the method.
        adapter: VaultReadAdapterKind,
        /// Method that is unimplemented on that adapter.
        method: VaultReadMethod,
    },
    /// The engine refused or failed the accepted operation.
    #[error("vault-read engine failure for {method:?} ({engine_code}): {message}")]
    Engine {
        /// Method whose engine execution failed.
        method: VaultReadMethod,
        /// Stable code copied from the accepted API error vocabulary.
        engine_code: String,
        /// Human-readable engine detail. Never compared for parity.
        message: String,
    },
}

impl VaultReadError {
    pub(super) fn method(&self) -> VaultReadMethod {
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
        method,
        engine_code: NOT_FOUND_ENGINE_CODE.to_owned(),
        message: format!("{field} was not found"),
    }
}

pub(super) fn engine_failure(method: VaultReadMethod, error: &crate::Error) -> VaultReadError {
    VaultReadError::Engine {
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
