//! Moved from `crates/oneiron/src/code_view/erase.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::code_view::ViewReceipt;
use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

impl ViewReceipt {
    /// The source holders whose erase retires this view.
    fn source_holders(&self) -> Vec<EntityId> {
        let mut holders: Vec<_> = self
            .base
            .iter()
            .flat_map(|(repo, tested)| [*repo, *tested])
            .collect();
        holders.extend(self.run.as_ref().map(|stamp| stamp.repo));
        holders
    }
}
