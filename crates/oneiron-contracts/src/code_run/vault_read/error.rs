//! The vault-read error vocabulary. `oneiron::code_run::vault_read` re-exports it; the
//! constructors the adapters use stay there.

use serde::{Deserialize, Serialize};

use super::contract::{VaultReadAdapterKind, VaultReadMethod};

/// Result of every vault-read operation.
pub type VaultReadResult<T> = std::result::Result<T, VaultReadError>;

/// The one comparable typed failure taxonomy shared by every adapter.
///
/// Parity is structured-fields-only: compare `InvalidRequest` by
/// `{ method, field }` and `Engine` by `{ method, engine_code }`. Free-text
/// `reason`/`message` never gates parity.
///
/// This type deliberately does NOT embed [`crate::Error`]: the crate error
/// bridges to it with `#[from]`, and embedding would make the type recursive
/// and non-serializable.
#[derive(Debug, Clone, PartialEq, thiserror::Error, Serialize, Deserialize)]
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
        /// Present when a completed read answered absence, not on failures before a read.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        narrowing: Option<Box<crate::claim::ScopedReadReceipt>>,
        /// Method whose engine execution failed.
        method: VaultReadMethod,
        /// Stable code copied from the accepted API error vocabulary.
        engine_code: String,
        /// Human-readable engine detail. Never compared for parity.
        message: String,
    },
}
