//! Moved from `crates/oneiron/src/secret_custody/found_keys.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::secret_record::write_records::FoundKeyAction;
pub use oneiron_store::secret_record::write_records::FoundKeySettled;

/// The scan's reason codes share this prefix; a key's kind is what follows.
pub const REASON_PREFIX: &str = "gate.secret_scan.";
