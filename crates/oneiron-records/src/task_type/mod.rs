//! Moved from `crates/oneiron/src/task_type/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::task_type::placement::PLACEMENT_SKILL_ID;
use oneiron_base::error::Error;
pub use oneiron_verb_wire::receipt::task_type_ref::ROOT_TYPE_NODE;
use serde::Deserialize;
use serde::Serialize;

/// The root node id: every unsure placement lands here.
pub const ROOT_NODE_ID: &str = "root";

/// The derived-id domain of a node's [`EntityId`] spelling
/// ([`TaskTypeNode::entity_id`]). Parts: the node id.
pub const TYPE_NODE_ID_DOMAIN: &[u8] = b"oneiron.task_type.node.v1";

/// The tree version [`TaskTypeTree::seeded`] starts at.
pub const SEEDED_TREE_VERSION: u64 = 1;

/// A leaf with fewer receipts than this borrows its parent's prior.
pub const THIN_LEAF_MIN_RECEIPTS: u64 = 8;

/// Decision runs each side needs before a disagreement can split a type.
pub const SPLIT_MIN_RUNS_PER_WINNER: u64 = 3;

/// Held-out runs a leaf needs before it can be promoted upstream.
pub const PROMOTE_MIN_HELD_OUT_RUNS: u64 = 8;

pub fn invalid_type_ref(reason: &'static str) -> Error {
    Error::InvariantViolation(reason)
}

/// A decision read from the tree. Splits follow disagreement on one of
/// these axes — never topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAxis {
    WinningPattern,
    WinningModel,
    TrustedCritic,
}

impl DecisionAxis {
    pub const ALL: [Self; 3] = [
        Self::WinningPattern,
        Self::WinningModel,
        Self::TrustedCritic,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WinningPattern => "winning_pattern",
            Self::WinningModel => "winning_model",
            Self::TrustedCritic => "trusted_critic",
        }
    }

    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|axis| axis.as_str() == token)
    }
}

/// One observed decision outcome under a type: `winner` won on `axis`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionObservation {
    pub axis: DecisionAxis,
    pub winner: String,
}

impl DecisionObservation {
    #[must_use]
    pub fn new(axis: DecisionAxis, winner: impl Into<String>) -> Self {
        Self {
            axis,
            winner: winner.into(),
        }
    }
}

/// Which tree this is: the one vault tree, or one project's fork of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TreeScope {
    Vault,
    Project {
        /// Lower-hex project entity id, when the fork names one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project_ref: Option<String>,
        /// The vault tree version this fork was cut from.
        forked_from_version: u64,
        /// True when the fork was seeded at the project's birth (a domain
        /// known to be different), false when divergent receipts earned it.
        seeded_at_birth: bool,
    },
}

/// A node whose receipts disagree on one decision: the upkeep split input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitCandidate {
    pub node_id: String,
    pub axis: DecisionAxis,
    pub winners: Vec<String>,
}

/// The decision a split keys on, in the vocabulary OF-540's payoff
/// projector reports per-type winner disagreement in. Splits and merges
/// key on this, never on topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitDecision {
    Pattern,
    Model,
    Critic,
}

impl SplitDecision {
    pub const ALL: [Self; 3] = [Self::Pattern, Self::Model, Self::Critic];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pattern => "pattern",
            Self::Model => "model",
            Self::Critic => "critic",
        }
    }

    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.as_str() == token)
    }

    /// The tree-internal decision axis this names.
    #[must_use]
    pub const fn axis(self) -> DecisionAxis {
        match self {
            Self::Pattern => DecisionAxis::WinningPattern,
            Self::Model => DecisionAxis::WinningModel,
            Self::Critic => DecisionAxis::TrustedCritic,
        }
    }
}

impl From<DecisionAxis> for SplitDecision {
    fn from(axis: DecisionAxis) -> Self {
        match axis {
            DecisionAxis::WinningPattern => Self::Pattern,
            DecisionAxis::WinningModel => Self::Model,
            DecisionAxis::TrustedCritic => Self::Critic,
        }
    }
}
pub mod placement;
