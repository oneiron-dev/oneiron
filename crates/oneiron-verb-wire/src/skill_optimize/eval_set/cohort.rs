//! Moved from `crates/oneiron/src/skill_optimize/eval_set/cohort.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeSet;

/// The decision to retire one cohort: its bounded reason, who made it, and
/// the exposure the retiring writer read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, try_from = "StoredCohortRetirement")]
pub struct CohortRetirement {
    pub reason: String,
    pub author: EvalCohortRetirementAuthor,
    pub exposure: EvalExposureCounts,
}

/// Who retired a cohort, as the retiring writer checked them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvalCohortRetirementAuthor {
    /// The eval-authoring skill's plan, applied on its Coach attempt.
    Skill {
        attempt: EntityId,
        skill: EntityId,
        revision: String,
    },
    /// The vault owner, on its own proof.
    Owner { person: EntityId },
    /// An agent, on the live owner Grant that listed the verb.
    Agent { agent: EntityId, grant: EntityId },
}

/// A kept retirement as stored. A row retired before retirements named
/// their author holds the skill, revision and attempt flat: it reads as
/// the skill's. Any other mix of the two is refused.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCohortRetirement {
    reason: String,
    exposure: EvalExposureCounts,
    #[serde(default)]
    author: Option<EvalCohortRetirementAuthor>,
    #[serde(default)]
    skill: Option<EntityId>,
    #[serde(default)]
    revision: Option<String>,
    #[serde(default)]
    attempt: Option<EntityId>,
}

impl TryFrom<StoredCohortRetirement> for CohortRetirement {
    type Error = &'static str;

    fn try_from(stored: StoredCohortRetirement) -> std::result::Result<Self, Self::Error> {
        let author = match (stored.author, stored.skill, stored.revision, stored.attempt) {
            (Some(author), None, None, None) => author,
            (None, Some(skill), Some(revision), Some(attempt)) => {
                EvalCohortRetirementAuthor::Skill {
                    attempt,
                    skill,
                    revision,
                }
            }
            _ => return Err("a cohort retirement names one whole author"),
        };
        Ok(Self {
            reason: stored.reason,
            author,
            exposure: stored.exposure,
        })
    }
}

/// What a serving of a sealed cohort was for. There is no search, authoring
/// or rubric-fit kind: those never read sealed rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvalExposureKind {
    /// One candidate scored against the cohort.
    Candidate,
    /// One query served from it.
    Query,
    /// One promotion decided on it.
    Promotion,
}

/// One counted serving of a cohort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalExposure {
    pub id: EntityId,
    pub cohort: EntityId,
    pub kind: EvalExposureKind,
    /// The run, campaign or proposal the serving was for.
    pub consumer: String,
    /// The candidate or model pin that was measured, when one was.
    pub candidate_pin: Option<String>,
    pub at: u64,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct EvalExposureCounts {
    pub candidates: u64,
    pub queries: u64,
    pub promotions: u64,
}

impl EvalExposureCounts {
    /// Whether the cohort has served anything.
    #[must_use]
    pub const fn served(&self) -> bool {
        self.candidates > 0 || self.queries > 0 || self.promotions > 0
    }
}
