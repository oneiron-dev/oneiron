//! Moved from `crates/oneiron/src/context_board/people.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeSet;

/// The `people` block one vault contributes to the cached prefix, and the
/// persons it made resident.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeoplePrefix {
    pub vault: String,
    pub rows: Vec<String>,
    pub more: usize,
    pub resident: BTreeSet<EntityId>,
}

impl PeoplePrefix {
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!("<people vault={}>", self.vault);
        for row in &self.rows {
            out.push('\n');
            out.push_str(row);
        }
        // The overflow points at the verb that pages the rest (ARCH-0067).
        if self.more > 0 {
            out.push_str(&format!(
                "\nmore: +{} \u{b7} vault.people.list({}, page)",
                self.more, self.vault
            ));
        }
        out.push_str("\n</people>");
        out
    }
}
