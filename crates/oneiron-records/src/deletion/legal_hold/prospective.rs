//! Moved from `crates/oneiron/src/deletion/legal_hold/prospective.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// One order generation: order id and generation.
pub type OrderKey = ([u8; 16], u64);
