//! A PDF inspection's memory, admitted by its host before the parse
//! allocates it (FIX 8065).
//!
//! The host hands [`super::inspect_pdf_pages_admitted`] its
//! [`InspectionMemory`]. lopdf's own load asks it for its object tables,
//! stream copies and decodes ([`lopdf::DecodeAdmission`]); the preflight asks
//! it for its xref tables, its own decodes and its revision snapshots. A
//! [`Stage`] whose allocations are freed before the inspection ends (an
//! earlier revision's load, one structural stream's decode) gives what it
//! admitted back when it drops, so the host holds the parse's peak, not its
//! sum. A parse with no host memory admits nothing, as before.
use super::{PdfPreparationError, Result};
use lopdf::{DecodeAdmission, DecodeAdmissionError};
use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A host's memory for one PDF inspection.
pub trait InspectionMemory: Send + Sync {
    /// Admits `bytes` the parse is about to allocate.
    ///
    /// # Errors
    /// The host's refusal: the machine's floor, or its wait running out.
    fn admit(&self, bytes: u64) -> std::result::Result<(), DecodeAdmissionError>;

    /// Gives back `bytes` admitted before, whose allocations are freed.
    fn release(&self, bytes: u64);
}

/// What one entry of a `BTreeMap<K, V>` takes at most: its share of a node,
/// as lopdf admits its own maps (`decode_admission::btree_entry_bytes`). A
/// std node holds 11 entries and 12 edges, plus a parent link, two counters
/// and padding within 64 bytes, and every node but the root at least 5
/// entries.
pub(super) const fn btree_entry_bytes<K, V>() -> usize {
    (11 * (size_of::<K>() + size_of::<V>()) + 12 * size_of::<usize>() + 64).div_ceil(5)
}

/// One stage of an inspection on its host's memory: what it admits is
/// counted and given back when its last clone drops. A stage with no host
/// memory admits nothing.
#[derive(Clone)]
pub(super) struct Stage(Option<Arc<StageCount>>);

struct StageCount {
    memory: Arc<dyn InspectionMemory>,
    admitted: AtomicU64,
}

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

impl DecodeAdmission for StageCount {
    fn admit(&self, bytes: usize) -> std::result::Result<(), DecodeAdmissionError> {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.memory.admit(bytes)?;
        self.admitted.fetch_add(bytes, Ordering::Relaxed);
        Ok(())
    }
}

impl Drop for StageCount {
    fn drop(&mut self) {
        self.memory.release(*self.admitted.get_mut());
    }
}
