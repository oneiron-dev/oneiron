//! Moved from `crates/oneiron/src/sync/residence/search.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Where a paged residence search goes on: the offset into its final ranked
/// list, that list's revision, and the second its time words and recency
/// were read at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResidenceSearchCursor {
    pub offset: u64,
    pub revision: String,
    pub as_of: u64,
}
