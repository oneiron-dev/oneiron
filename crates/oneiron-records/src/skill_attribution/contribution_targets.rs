//! Moved from `crates/oneiron/src/skill_attribution/contribution_targets.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// What one contribution check measures. A loaded skill's checks order
/// before a used edge's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionTarget {
    /// A skill the run loaded: its step with and without the skill's body.
    LoadedSkill(EntityId),
    /// A derived-from edge the run actually used: its step with and without
    /// the edge's source.
    UsedEdge { derived: EntityId, source: EntityId },
}

impl ContributionTarget {
    /// The entity whose exposure the fork without it leaves out: the skill,
    /// or the edge's source.
    #[must_use]
    pub const fn removed(self) -> EntityId {
        match self {
            Self::LoadedSkill(skill) => skill,
            Self::UsedEdge { source, .. } => source,
        }
    }

    /// The target as a check key spells it: the skill's hex, or the edge's
    /// two ends' hex joined by `>`.
    fn spelled(self) -> String {
        match self {
            Self::LoadedSkill(skill) => skill.to_hex(),
            Self::UsedEdge { derived, source } => {
                format!("{}>{}", derived.to_hex(), source.to_hex())
            }
        }
    }

    /// The target's bytes in an identity hash: a tag, then its ids.
    fn bytes(self) -> Vec<u8> {
        match self {
            Self::LoadedSkill(skill) => [b"s".as_slice(), skill.as_bytes().as_slice()].concat(),
            Self::UsedEdge { derived, source } => [
                b"e".as_slice(),
                derived.as_bytes().as_slice(),
                source.as_bytes().as_slice(),
            ]
            .concat(),
        }
    }
}

/// The used edge an ancestor check measured, as recorded: each end `None`
/// once that entity is erased (FIX 8988).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckedEdge {
    pub derived: Option<EntityId>,
    pub source: Option<EntityId>,
}
