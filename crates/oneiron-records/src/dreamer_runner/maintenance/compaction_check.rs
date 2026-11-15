//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/compaction_check.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// The maintenance facet a self-written landing's check rides.
pub const COMPACTION_CHECK_FACET: &str = "dreamer.compaction_check";

/// The payload key the declaration rides under.
pub const DECLARATION_KEY: &str = "declaration";
pub mod conversation;
