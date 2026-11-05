//! The provenance class a stored claim offers to readers.
use super::ClaimBody;
use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::claim::ClaimSource;
use serde::{Deserialize, Serialize};

/// How a row was made. This is not a scope key or a relevance multiplier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MadeByClass {
    Stated,
    Concluded,
}

impl MadeByClass {
    /// The class of a row a writer wrote itself: a person states, and any
    /// other actor concludes.
    #[must_use]
    pub const fn of_writer(class: EdgeActorClass) -> Self {
        match class {
            EdgeActorClass::Human => Self::Stated,
            EdgeActorClass::Agent | EdgeActorClass::System => Self::Concluded,
        }
    }

    /// The class a claim of `source` carries.
    #[must_use]
    pub const fn of_source(source: ClaimSource) -> Self {
        match source {
            ClaimSource::Inferred | ClaimSource::Generated => Self::Concluded,
            ClaimSource::UserStated
            | ClaimSource::Observed
            | ClaimSource::Imported
            | ClaimSource::ToolOutput => Self::Stated,
        }
    }
}

impl ClaimBody {
    /// Provenance class offered to rerank and explain without changing scores.
    #[must_use]
    pub fn made_by_class(&self) -> Option<MadeByClass> {
        self.source.map(MadeByClass::of_source)
    }
}
