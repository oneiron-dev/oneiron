//! Moved from `crates/oneiron/src/store/idempotency_intent.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::sync_responses::IdempotencyEntry;
use heed::RwTxn;
use std::cell::RefCell;
use std::sync::Arc;

impl IdempotencyEntry {
    /// The status an intent row holds: no HTTP status is 0 (FIX 9527).
    pub const INTENT_STATUS: u16 = 0;

    /// Whether this entry is an intent that no outcome settled and no erase
    /// took.
    #[must_use]
    pub fn is_open_intent(&self) -> bool {
        self.status == Self::INTENT_STATUS && !self.erased
    }
}
