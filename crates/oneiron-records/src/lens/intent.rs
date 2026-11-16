//! Moved from `crates/oneiron/src/lens/intent.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Bound prompt storage before allocation or dispatch into a model runner.
pub const LENS_INTENT_MAX_BYTES: usize = 16_384;
