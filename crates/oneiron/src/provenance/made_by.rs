//! Rule A provenance vocabulary shared by text commits and retrieval.

use crate::claim::{ClaimBody, ClaimSource};
use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// How a row was made. This is not a scope key or a relevance multiplier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MadeByClass {
    Stated,
    Concluded,
}

/// Caller-selected provenance slice. Unknown provenance never matches a slice.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MadeByPredicate {
    Stated,
    Concluded,
    #[default]
    All,
}

impl MadeByPredicate {
    #[must_use]
    pub fn matches(self, class: Option<MadeByClass>) -> bool {
        match self {
            Self::All => true,
            Self::Stated => class == Some(MadeByClass::Stated),
            Self::Concluded => class == Some(MadeByClass::Concluded),
        }
    }
}

impl ClaimBody {
    /// Provenance class offered to rerank and explain without changing scores.
    #[must_use]
    pub fn made_by_class(&self) -> Option<MadeByClass> {
        self.source.map(|source| match source {
            ClaimSource::Inferred | ClaimSource::Generated => MadeByClass::Concluded,
            ClaimSource::UserStated
            | ClaimSource::Observed
            | ClaimSource::Imported
            | ClaimSource::ToolOutput => MadeByClass::Stated,
        })
    }
}

/// Role of an input row in the derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MadeByInputRole {
    Input,
    Prompt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MadeByInput {
    #[serde(with = "super::entity_ref_wire")]
    pub row: EntityId,
    pub role: MadeByInputRole,
}

/// The process identity and replay-key parameters; the actor is not the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MadeByProcess {
    #[serde(with = "super::entity_ref_wire")]
    pub actor: EntityId,
    pub class: MadeByClass,
    pub identity: String,
    pub version: String,
    pub params_hash: String,
}

impl MadeByProcess {
    pub(crate) fn is_valid(&self) -> bool {
        [&self.identity, &self.version, &self.params_hash]
            .iter()
            .all(|value| !value.is_empty() && value.len() <= 256)
    }
}

/// The initiating task or ask, not a free-text label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MadeByTrigger {
    /// The initiating TASK row.
    Task(#[serde(with = "super::entity_ref_wire")] EntityId),
    /// The TURN row that carries the initiating ask.
    Ask(#[serde(with = "super::entity_ref_wire")] EntityId),
}

/// One commit's derivation envelope. Document and operation span live on its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MadeBy {
    pub inputs: Vec<MadeByInput>,
    pub process: MadeByProcess,
    pub at: u64,
    pub trigger: Option<MadeByTrigger>,
}
