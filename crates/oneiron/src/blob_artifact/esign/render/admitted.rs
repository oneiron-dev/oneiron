//! Core half of `blob_artifact::esign::render::admitted`: its store-layer items live in `oneiron_store::blob_artifact::esign::render::admitted` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::blob_artifact::esign::render::admitted::*;

use super::{PdfPreparationError, Result};
use lopdf::{DecodeAdmission, DecodeAdmissionError};
use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// One stage of an inspection on its host's memory: what it admits is
/// counted and given back when its last clone drops. A stage with no host
/// memory admits nothing.
#[derive(Clone)]
pub(super) struct Stage(Option<Arc<StageCount>>);

impl Stage {
    /// No host memory: nothing is admitted.
    pub(super) const UNADMITTED: Self = Self(None);

    /// The whole inspection's stage on `memory`.
    pub(super) fn on(memory: Arc<dyn InspectionMemory>) -> Self {
        Self(Some(Arc::new(StageCount {
            memory,
            admitted: AtomicU64::new(0),
        })))
    }

    /// A stage on the same memory whose allocations are freed before this
    /// one's.
    pub(super) fn nested(&self) -> Self {
        match &self.0 {
            Some(outer) => Self::on(Arc::clone(&outer.memory)),
            None => Self::UNADMITTED,
        }
    }

    /// Whether this stage admits to a host's memory: work that only sizes
    /// what it admits is skipped where it does not.
    pub(super) fn admits(&self) -> bool {
        self.0.is_some()
    }

    /// Admits `bytes` about to be allocated. A refusal ends the parse as
    /// lopdf's own refused admission does: the host reads its own refusal.
    pub(super) fn admit(&self, bytes: usize) -> Result<()> {
        match &self.0 {
            Some(count) => count.admit(bytes).map_err(|refusal| {
                PdfPreparationError::from(lopdf::Error::DecodeAdmission(refusal))
            }),
            None => Ok(()),
        }
    }

    /// The admission lopdf's load asks: this stage's.
    pub(super) fn decode_admission(&self) -> Option<Arc<dyn DecodeAdmission>> {
        self.0
            .clone()
            .map(|count| count as Arc<dyn DecodeAdmission>)
    }
}
