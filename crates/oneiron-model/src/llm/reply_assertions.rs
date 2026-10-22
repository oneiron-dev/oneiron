//! The typed records one reply cited or created (OF-063, FIX 3416), carried
//! on its terminal.
//!
//! Only the host fills this, and only from evidence it holds for THIS reply:
//! a typed tool citation it served, or a record a write made for the reply
//! once that write committed. A model never fills it, it is never parsed
//! from the reply's prose, a provider's list is never taken for it, and no
//! prompt source or read set becomes one. Every raw provider boundary
//! initializes it empty. The engine judges each `id` under the writer's own
//! read when the reply is saved; the coordinates here are the record's, not
//! a display schema.

use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// One record a reply names: its registry entity type and its id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplyAssertionRecord {
    /// The record's registry entity type.
    pub entity_type: u8,
    /// The record's id, 32 lower hex on the wire.
    pub id: EntityId,
}

/// The records one reply cited and created, as its host gathered them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplyAssertions {
    /// Records a typed tool citation named for this reply.
    #[serde(default)]
    pub cited: Vec<ReplyAssertionRecord>,
    /// Records a committed write made for this reply.
    #[serde(default)]
    pub created: Vec<ReplyAssertionRecord>,
}

impl ReplyAssertions {
    /// Whether the reply names no record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cited.is_empty() && self.created.is_empty()
    }

    /// Notes `record` as cited, once.
    pub fn cite(&mut self, record: ReplyAssertionRecord) {
        if !self.cited.contains(&record) {
            self.cited.push(record);
        }
    }

    /// Notes `record` as created, once. The caller's write has committed.
    pub fn create(&mut self, record: ReplyAssertionRecord) {
        if !self.created.contains(&record) {
            self.created.push(record);
        }
    }
}
