//! Moved from `crates/oneiron/src/batch/secret_scan/lift_history/accounting.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Serialize, Deserialize)]
pub enum Source {
    Unmapped,
    Entity(EntityId),
    Multi(Vec<EntityId>),
}

impl Source {
    pub fn of_set(mut ids: Vec<EntityId>) -> Self {
        ids.sort_unstable();
        ids.dedup();
        match ids.len() {
            0 => Self::Unmapped,
            1 => Self::Entity(ids[0]),
            _ => Self::Multi(ids),
        }
    }

    pub fn entities(&self) -> &[EntityId] {
        match self {
            Self::Unmapped => &[],
            Self::Entity(id) => std::slice::from_ref(id),
            Self::Multi(ids) => ids,
        }
    }

    pub fn kept_by(&self, keep: &dyn Fn(EntityId) -> bool) -> bool {
        self.entities().iter().all(|id| keep(*id))
    }
}
