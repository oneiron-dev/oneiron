//! Moved from `crates/oneiron/src/clipboard/retention.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The three owner cleanup arms. Only low-disk cleanup is enabled initially.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClipboardRetention {
    pub max_text_bytes: Option<u64>,
    pub low_disk: bool,
    pub older_than_days: Option<u32>,
}

impl Default for ClipboardRetention {
    fn default() -> Self {
        Self {
            max_text_bytes: None,
            low_disk: true,
            older_than_days: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClipboardCleanupReport {
    pub erased: Vec<EntityId>,
    /// Masked clip-text bytes selected under the policy, not measured freed
    /// filesystem pages, other vault content or secret-custody bytes.
    pub selected_text_bytes: u64,
}
