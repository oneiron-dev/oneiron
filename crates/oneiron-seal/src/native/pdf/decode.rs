//! Strict loads with every stream decoded whole (Rule 5), each decode's
//! memory reserved before it is allocated (FIX 7654).
//!
//! The loader decodes object and cross-reference streams as it reads them.
//! Before a decode allocates or grows a buffer, the operation's memory
//! ledger admits the bytes (`SealResourceLimits::memory`); a refusal ends
//! the load as itself, never as a malformed PDF. None is refused on its
//! decoded size: each finished decode's length goes to the invocation's
//! counts, the largest kept, which the host measures against its
//! `seal_stream_decode_bytes` row. Only the PDF format bounds refuse.

use std::sync::Arc;

use lopdf::{DecodeAdmission, Document, LoadOptions};

use crate::api::SealResourceLimits;
use crate::error::{SealError, SealStage};
use crate::memory::SealMemoryRefusal;

/// Why a strict load gave no document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoadError {
    /// The bytes are not a PDF the strict loader reads.
    Malformed,
    /// The memory a decode needed was not reserved.
    Memory(SealMemoryRefusal),
}

impl LoadError {
    /// The seal's error: a memory refusal as itself, at `stage`; anything
    /// else as `malformed` says.
    pub(crate) fn seal_error(
        self,
        stage: SealStage,
        malformed: impl FnOnce() -> SealError,
    ) -> SealError {
        match self {
            Self::Memory(refusal) => refusal.seal_error(stage),
            Self::Malformed => malformed(),
        }
    }
}

/// A strict parse of `bytes`, each stream decoded whole, every decode's
/// memory admitted first by the ledger of the operation `limits` run under.
/// The decoder notes each finished decode's length in the invocation's
/// counts as it goes.
pub(crate) fn load_strict(
    bytes: &[u8],
    limits: &SealResourceLimits,
) -> Result<Document, LoadError> {
    let ledger = limits.memory.ledger().map_err(LoadError::Memory)?;
    let admission: Arc<dyn DecodeAdmission> = ledger.clone();
    Document::load_mem_with_options(
        bytes,
        LoadOptions {
            strict: true,
            decode_admission: Some(admission),
            ..LoadOptions::default()
        },
    )
    .map_err(|err| {
        ledger
            .refusal_of(&err)
            .map_or(LoadError::Malformed, LoadError::Memory)
    })
}
