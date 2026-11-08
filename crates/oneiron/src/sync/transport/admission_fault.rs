//! How a window admission's error crosses the transport boundary (FIX 5926):
//! a fault reading this device's own store is [`TransportError::Storage`],
//! retried as the storage failure it is; every other admission error stays
//! the refusal of the peer's bytes. The far end's bytes that fail to apply
//! cross it the same way (FIX 22153).

use super::TransportError;
use crate::error::{Error, SecretError, StoreError, SyncEngineContext, SyncError};

/// Whether `error` is a window admission's fault reading this vault's own
/// state (FIX 5850), told by its typed engine context, never by its text.
pub(crate) fn is_window_admission_read_fault(error: &Error) -> bool {
    matches!(
        error,
        Error::Sync(SyncError::SyncEngineError {
            context: SyncEngineContext::WindowAdmissionRead,
            ..
        })
    )
}

/// Whether `error` is this vault's own fault, never the far end's bytes
/// (FIX 5926, FIX 22153): its store, disk or map, a local writer that moved
/// under it, its own index, its config, a store that does not open as this
/// build expects, a window it cannot find or holds busy, a live document
/// slot it waited for past the deadline, its own keystore or credential
/// custody that cannot open, or a window admission's read of its own state.
pub(crate) fn is_own_vault_fault(error: &Error) -> bool {
    is_window_admission_read_fault(error)
        || matches!(
            error,
            Error::Storage(_)
                | Error::Io(_)
                | Error::MapFull
                | Error::ConcurrentWrite(_)
                | Error::CorruptedIndex(_)
                | Error::InvalidConfig(_)
                | Error::Store(StoreError::EmbeddingModelChanged { .. })
                | Error::Store(StoreError::HnswConfigChanged { .. })
                | Error::Store(StoreError::StorageAbiVersionChanged { .. })
                | Error::Store(StoreError::StorageSchemaVersionChanged { .. })
                | Error::Store(StoreError::DbManifestMismatch { .. })
                | Error::Store(StoreError::VaultRootPreflight { .. })
                | Error::Sync(SyncError::WindowNotFound { .. })
                | Error::Sync(SyncError::WindowBusy { .. })
                | Error::Sync(SyncError::LiveDocumentWaitedOut)
                | Error::Secret(SecretError::KeystoreUnavailable(_))
                | Error::Secret(SecretError::CredentialCustodyUnavailable { .. })
        )
}

impl TransportError {
    /// The transport error of a window admission that failed with `error`:
    /// this device's own store fault as [`Self::Storage`], any other as the
    /// peer's refused payload, `refusal`.
    pub(crate) fn from_window_admission(error: &Error, refusal: &'static str) -> Self {
        if is_window_admission_read_fault(error) {
            Self::Storage(error.to_string())
        } else {
            Self::InvalidPayload(refusal)
        }
    }

    /// The transport error of the far end's bytes that failed to apply with
    /// `error` (FIX 22153): this vault's own fault ([`is_own_vault_fault`])
    /// as [`Self::Storage`], any other as the far end's refused payload,
    /// `refusal`.
    pub(crate) fn from_applied(error: &Error, refusal: &'static str) -> Self {
        if is_own_vault_fault(error) {
            Self::Storage(error.to_string())
        } else {
            Self::InvalidPayload(refusal)
        }
    }
}
