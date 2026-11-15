//! Moved from `crates/oneiron/src/repo_mutation/bundle.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// CALL BUNDLE-CHILD-OP: the hash domain of the deterministic document
/// operation a native bundle's file lowers to, from (proposal, index).
pub const BUNDLE_FILE_OPERATION_DOMAIN: &[u8] = b"oneiron:repo-bundle-file-op:v1";
