//! Moved from `crates/oneiron/src/conversation/session.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::conversation::*;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    #[default]
    Direct,
    Group,
    Council,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPresence {
    pub mode: SessionMode,
    /// Who is here now, earliest arrival first.
    pub active_participant_ids: Vec<EntityId>,
}
