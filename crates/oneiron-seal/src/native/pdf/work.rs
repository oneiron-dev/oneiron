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

use std::sync::Arc;

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
