//! How a window admission's error crosses the transport boundary (FIX 5926):
//! a fault reading this device's own store is [`TransportError::Storage`],
//! retried as the storage failure it is; every other admission error stays
//! the refusal of the peer's bytes.

use super::TransportError;
use crate::error::{Error, SyncEngineContext, SyncError};

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
}
