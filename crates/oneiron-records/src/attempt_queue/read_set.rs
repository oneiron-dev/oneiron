//! Moved from `crates/oneiron/src/attempt_queue/read_set.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::attempt_record::AttemptReadSet;
pub use oneiron_store::attempt_read_producer::ReadSetProducer;
use std::collections::BTreeSet;

impl AttemptReadSet {
    /// Nothing declared or read yet: a known, empty set.
    fn new() -> Self {
        Self {
            rows: Some(Vec::new()),
            expected: BTreeSet::new(),
            reported: BTreeSet::new(),
        }
    }
}
