//! Actor-free role ranks, ask acts, and holder kinds.

use serde::{Deserialize, Serialize};

/// How far up a chain a role sits: an ask climbs from its role toward the owners.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RoleRank {
    Responsible,
    Board,
    Owner,
}

/// What an answer to an ask authorises. An e-signature or a person-authorised payment
/// resolves only to a natural person, whoever else holds the role.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AskAct {
    #[default]
    Judgment,
    ESignature,
    Payment,
}

impl AskAct {
    /// Whether only a natural person may answer.
    #[must_use]
    pub fn person_only(self) -> bool {
        matches!(self, Self::ESignature | Self::Payment)
    }
}

/// Whether a role holder is a natural person or a bound agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HolderKind {
    Person,
    Agent,
}
