//! Moved from `crates/oneiron/src/store/sync_responses.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Who owns a host row's response, as the host stamps it in the write that
/// keeps the row: the actor that asked, the subject the response is about,
/// and the rows it was made from. A payer is never one. Each is absent when
/// the host could not name it, and the row is kept all the same.
#[doc(hidden)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseStamps {
    #[serde(default)]
    pub actor: Option<EntityId>,
    #[serde(default)]
    pub subject: Option<EntityId>,
    #[serde(default)]
    pub sources: Vec<EntityId>,
}

impl ResponseStamps {
    /// Every owner the stamps name, each once.
    pub fn ids(&self) -> Vec<EntityId> {
        let mut ids: Vec<EntityId> = self
            .actor
            .iter()
            .chain(self.subject.iter())
            .chain(self.sources.iter())
            .copied()
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}
