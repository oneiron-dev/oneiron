//! Moved from `crates/oneiron/src/skill_optimize/gate/project_goal.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::gate::*;
use crate::workspace_roster::project::goal::GoalAxis;
use crate::workspace_roster::project::goal::GoalPreference;
use oneiron_contracts::limit_ask::EngineLimit;
use serde::Deserialize;
use serde::Serialize;
use std::collections::VecDeque;

/// One rung of the responsible-role chain a tradeoff ask climbs. Live people
/// and live bound agents are members (ROLES-EVERYWHERE): a pick by either
/// becomes the role's preference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TradeoffRole {
    /// The person who authored the goal's tradeoff preferences.
    Author(EntityId),
    /// The live people on a project's effective board: the humans who set
    /// its goal.
    Board {
        project: EntityId,
        people: BTreeSet<EntityId>,
    },
    /// The vault's live owners, where every chain ends.
    VaultOwner(BTreeSet<EntityId>),
}

impl TradeoffRole {
    /// Whether `person` answers for this role.
    #[must_use]
    pub fn holds(&self, person: &EntityId) -> bool {
        match self {
            Self::Author(author) => author == person,
            Self::Board { people, .. } | Self::VaultOwner(people) => people.contains(person),
        }
    }

    pub fn first(&self) -> Option<EntityId> {
        match self {
            Self::Author(author) => Some(*author),
            Self::Board { people, .. } | Self::VaultOwner(people) => people.first().copied(),
        }
    }

    /// Whether `other` is this rung as the chain stands at another read: the
    /// same kind and, for a board, the same project, whoever holds it now.
    pub fn same_rung(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Author(_), Self::Author(_)) | (Self::VaultOwner(_), Self::VaultOwner(_)) => true,
            (Self::Board { project, .. }, Self::Board { project: now, .. }) => project == now,
            _ => false,
        }
    }
}
