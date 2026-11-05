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
pub const fn btree_entry_bytes<K, V>() -> usize {
    (11 * (size_of::<K>() + size_of::<V>()) + 12 * size_of::<usize>() + 64).div_ceil(5)
}

pub struct StageCount {
    pub memory: Arc<dyn InspectionMemory>,
    pub admitted: AtomicU64,
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
