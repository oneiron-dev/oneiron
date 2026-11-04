//! Typed guest document sharing over live Connect grants (ARCH-0043).
use serde::{Deserialize, Serialize};

use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};

pub use crate::guest_document_share::GuestDocumentShareRequest;

pub use crate::authority::{GuestDocumentContext, GuestDocumentEnvelope};

/// An embedded handle has no serving host's signing key or window manager.
pub fn guest_document_host_only<T, I>(
    _memory: &Memory<'_>,
    verb: &str,
    _input: &I,
) -> MemoryResult<T> {
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{verb} requires the serving host's guest document signer"),
        &[super::host::SERVED_CLIENT_HINT],
    ))
}
