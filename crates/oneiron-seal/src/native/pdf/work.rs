//! Shared types for the ported prepare/inspect PDF pipeline (FIX 7980/8157).
//!
//! The seal organ cannot reuse the engine's `render/*` code across the F4
//! fence, so the pipeline is ported here file by file, behavior-identical
//! except admission and bounds:
//! - admission: every buffer and decode goes through the call's operation
//!   [`MemoryLedger`], never the engine `Stage`;
//! - bounds: preparation uses PDF format bounds; inspection also carries
//!   its caller's configured per-stream codec bound. Both admit growth
//!   through the operation ledger before allocation.
//!
//! Port files (one per engine source): `work_preflight` (`render/preflight`),
//! `work_streams` (`render/streams`), `work_source` (`render/source`),
//! `work_present` (`render/presentation` page geometry only), `work_burn`
//! (`render/fields` + `render/appearance`), `work_evidence`
//! (`render/evidence` certificate only; the audit-chain replay stays
//! engine-side and its checked output is lent in). Call entries
//! (`inspect_in`/`prepare_in`) are added with the organ handlers.

use std::convert::Infallible;
use std::sync::Arc;

use oneiron_esign_render::{Admission, BurnError};

use crate::api::SealObservations;
use crate::error::{InputInvalidCode, SealError, SealStage};
use crate::memory::{MemoryLedger, SealMemoryRefusal};

/// Why the ported pipeline gave no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkError {
    /// A rejected input, mapped 1:1 to the seal's invalid codes.
    Invalid(InputInvalidCode),
    /// The memory a decode or buffer needed was not reserved.
    Memory(SealMemoryRefusal),
}

impl WorkError {
    /// The seal's error: a memory refusal as itself, at `stage`; anything
    /// else as the invalid code it names.
    pub(crate) fn seal_error(self, stage: SealStage) -> SealError {
        match self {
            Self::Memory(refusal) => refusal.seal_error(stage),
            Self::Invalid(code) => SealError::InputInvalid { code },
        }
    }
}

/// What the ported stages admit and count against: the call's operation
/// ledger plus the invocation's observation sink. Replaces the engine
/// `&Stage` in every ported signature.
pub(crate) struct WorkLimits<'a> {
    /// The operation ledger: decode admission and buffer admission.
    pub ledger: &'a Arc<MemoryLedger>,
    /// The invocation's counts (`Counter::*` via `note`).
    pub observed: &'a SealObservations,
    /// Inspection's caller-owned per-stream codec bound; preparation admits
    /// its streams without this bound.
    pub stream_decode_bytes: Option<usize>,
}

/// The shared renderer's admission over the call's operation ledger:
/// the moved drawing program admits against this exactly as the port did
/// against the ledger. It inherits the growth and insert policy; only the
/// three primitives are wired here.
pub(crate) struct LedgerAdmission<'a> {
    /// The operation ledger: decode admission and buffer admission.
    pub ledger: &'a Arc<MemoryLedger>,
}

impl Admission for LedgerAdmission<'_> {
    type Error = SealMemoryRefusal;

    fn admit_len<T>(&self, len: usize) -> Result<(), SealMemoryRefusal> {
        self.ledger.admit_len::<T>(len)
    }

    fn release_admitted(&self, bytes: u64) {
        self.ledger.release_admitted(bytes);
    }

    fn alloc_failed(bytes: usize) -> SealMemoryRefusal {
        SealMemoryRefusal::Floor {
            needed: u64::try_from(bytes).unwrap_or(u64::MAX),
            available: 0,
        }
    }
}

/// An admission refusal as the organ reads it: the ledger's refusal as
/// itself, or nothing for a pure call.
pub(crate) trait MapAdmit {
    /// The organ's error for this admission refusal.
    fn map_admit(self) -> WorkError;
}

impl MapAdmit for SealMemoryRefusal {
    fn map_admit(self) -> WorkError {
        WorkError::Memory(self)
    }
}

impl MapAdmit for Infallible {
    fn map_admit(self) -> WorkError {
        match self {}
    }
}

/// A copier failure as the organ reads it: the organ's own error, passed
/// through, or nothing for a copier-free call.
pub(crate) trait MapExternal {
    /// The organ's error for this copier failure.
    fn map_external(self) -> WorkError;
}

impl MapExternal for WorkError {
    fn map_external(self) -> WorkError {
        self
    }
}

impl MapExternal for Infallible {
    fn map_external(self) -> WorkError {
        match self {}
    }
}

/// A shared-renderer failure as the organ reads it, exactly as each burn
/// site reads it today: the display-size refusal as invalid geometry, the
/// raster-size refusal as too-large, a lopdf failure through the kept
/// refusal check, an admission refusal as itself, a copier failure passed
/// through, and each logic failure 1:1. The pure geometry checks cannot
/// take limits, so they pass none; they perform no lopdf reads, and a lopdf
/// failure without limits reads as a malformed PDF, as `lopdf_error` reads
/// one the ledger did not refuse.
pub(crate) fn map_leaf<A: MapAdmit, X: MapExternal>(
    limits: Option<&WorkLimits<'_>>,
    err: BurnError<A, X>,
) -> WorkError {
    match err {
        BurnError::Admit(refusal) => refusal.map_admit(),
        BurnError::External(external) => external.map_external(),
        BurnError::Lopdf(err) => match limits {
            Some(limits) => lopdf_error(limits, err),
            None => WorkError::Invalid(InputInvalidCode::MalformedPdf),
        },
        BurnError::DisplayTooLarge => WorkError::Invalid(InputInvalidCode::InvalidGeometry),
        BurnError::TooLarge => WorkError::Invalid(InputInvalidCode::TooLarge),
        BurnError::MalformedPdf => WorkError::Invalid(InputInvalidCode::MalformedPdf),
        BurnError::UnsupportedPdf => WorkError::Invalid(InputInvalidCode::UnsupportedPdf),
        BurnError::InvalidGeometry => WorkError::Invalid(InputInvalidCode::InvalidGeometry),
        BurnError::InvalidSignatureImage => {
            WorkError::Invalid(InputInvalidCode::InvalidSignatureImage)
        }
        BurnError::UnsupportedText => WorkError::Invalid(InputInvalidCode::UnsupportedText),
        BurnError::FieldOverflow => WorkError::Invalid(InputInvalidCode::FieldOverflow),
    }
}

/// A lopdf read failure as the organ reads it: a kept memory refusal as
/// itself, anything else as a malformed PDF, never the reverse.
fn lopdf_error(limits: &WorkLimits<'_>, err: lopdf::Error) -> WorkError {
    limits.ledger.refusal_of(&err).map_or(
        WorkError::Invalid(InputInvalidCode::MalformedPdf),
        WorkError::Memory,
    )
}

pub(crate) fn inspect_in(
    bytes: &[u8],
    limits: &WorkLimits<'_>,
) -> Result<Vec<super::work_present::PageGeometry>, WorkError> {
    super::work_prepare::inspect_in(bytes, limits)
}
pub(crate) fn prepare_in(
    original: &[u8],
    request: &super::work_prepare::WorkPrepareRequest<'_>,
    limits: &WorkLimits<'_>,
) -> Result<super::work_prepare::WorkPrepared, WorkError> {
    super::work_prepare::prepare_in(original, request, limits)
}
