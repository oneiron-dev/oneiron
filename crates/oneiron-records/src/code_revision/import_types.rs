//! Moved from `crates/oneiron/src/code_revision/import_types.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::code_import_manifest::CodeImportAnchor;
pub use oneiron_store::code_revision_record::CodePathRetirement;
pub use oneiron_verb_wire::code_revision::import_types::CodeImportAcceptance;

/// The engine-owned predicate of an untouched-byte import approval.
pub const IMPORT_APPROVAL_PREDICATE: &str = "repo.import_approval";
