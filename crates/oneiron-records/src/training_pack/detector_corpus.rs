//! Moved from `crates/oneiron/src/training_pack/detector_corpus.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// The one label unit a head trains on; a window label never becomes a
/// target label.
pub const TARGET_UNIT: &str = "target";
