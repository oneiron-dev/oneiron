//! Moved from `crates/oneiron/src/training_pack/target.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// The labels a question head trains on: one yes or no per target.
pub const QUESTION_LABEL_SCHEMA: &str = "oneiron.per-target-binary/1";

/// How a question head's input is written as text.
pub const QUESTION_RENDERER: &str = "oneiron.detector-target-text/1";
