//! Moved from `crates/oneiron/src/authority/owner_choice.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;

/// One choice as a surface shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OwnerChoiceHead<P> {
    /// The choice's authority entry hash.
    pub act: AuthorityEntryHash,
    /// The carrier: the machine whose install key signed it.
    pub machine: EntityId,
    /// The value chosen; `None` for a clear.
    pub choice: Option<P>,
    /// Its advisory time, for display only.
    pub at: u64,
}
