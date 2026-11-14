//! Moved from `crates/oneiron/src/edit_distance/myers.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// What a relocated line costs against a rewritten one.
///
/// A move-paired character charges `2 · MOVE_DISCOUNT` (0.2) into the edit
/// mass where the delete-plus-insert it replaces would charge 2.0 — the
/// ratified tenth. Compile-time on purpose: this is part of the metric's definition,
/// not a dial an operator turns under a miner that already banked numbers
/// measured with the old one.
pub const MOVE_DISCOUNT: f32 = 0.1;
