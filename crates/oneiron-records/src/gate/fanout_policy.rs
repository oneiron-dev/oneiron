//! Moved from `crates/oneiron/src/gate/fanout_policy.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

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
