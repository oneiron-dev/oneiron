//! Moved from `crates/oneiron/src/gate/fanout_policy.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::gate::consult_fanout_values::ConsultFanOutScope;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The precedence row is itself vault policy. The stricter option ignores
/// holder overrides; neither option permits a child to exceed the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FanoutPrecedence {
    NestedNarrowing,
    MostRestrictive,
}

impl FanoutPrecedence {
    pub fn stricter(self, other: Self) -> Self {
        if self == Self::MostRestrictive || other == Self::MostRestrictive {
            Self::MostRestrictive
        } else {
            Self::NestedNarrowing
        }
    }
}

pub fn canonical_ref(id: &str) -> Option<EntityId> {
    EntityId::from_hex(id)
        .ok()
        .filter(|parsed| parsed.to_hex() == id)
}

impl ConsultFanOutScope {
    pub fn level(&self) -> u8 {
        if self.thread_ref.is_some() {
            3
        } else if self.subproject_ref.is_some() {
            2
        } else if self.project_ref.is_some() {
            1
        } else {
            0
        }
    }

    pub fn is_valid(&self) -> bool {
        (self.subproject_ref.is_none() || self.project_ref.is_some())
            && (self.thread_ref.is_none() || self.subproject_ref.is_some())
            && [
                self.project_ref.as_deref(),
                self.subproject_ref.as_deref(),
                self.thread_ref.as_deref(),
            ]
            .into_iter()
            .flatten()
            .all(|id| canonical_ref(id).is_some())
    }

    fn includes(&self, row: &Self) -> bool {
        row.project_ref
            .as_ref()
            .is_none_or(|id| self.project_ref.as_ref() == Some(id))
            && row
                .subproject_ref
                .as_ref()
                .is_none_or(|id| self.subproject_ref.as_ref() == Some(id))
            && row
                .thread_ref
                .as_ref()
                .is_none_or(|id| self.thread_ref.as_ref() == Some(id))
    }
}
