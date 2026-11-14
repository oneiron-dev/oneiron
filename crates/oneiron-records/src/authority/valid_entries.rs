//! Moved from `crates/oneiron/src/authority/valid_entries.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::AuthorityEntryHash;

/// A set of entry hashes that [`ValidEntries::difference`] takes away.
pub trait EntryHashSet {
    /// Whether `hash` is in the set.
    fn holds(&self, hash: &AuthorityEntryHash) -> bool;
}
