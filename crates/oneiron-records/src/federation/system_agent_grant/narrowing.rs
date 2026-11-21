//! Moved from `crates/oneiron/src/federation/system_agent_grant/narrowing.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::federation::grant_scope;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// One vault function a system agent's grant keeps running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemFunction {
    /// The Dreamer turns new conversations into memory.
    Consolidation,
    /// The Dreamer archives weak, quiet memories so recall stays sharp.
    RecallUpkeep,
    /// The Coach checks how the vault's agents are doing.
    CoachChecks,
    /// The Coach runs the jobs the engine.controls classes tune.
    EngineControlsJobs,
}

impl SystemFunction {
    /// The Steward verbs this function needs: a narrowing that drops any of
    /// them breaks it.
    #[must_use]
    pub const fn needs(self) -> &'static [&'static str] {
        match self {
            Self::Consolidation => &[
                grant_scope::STEWARD_READ_VERB,
                grant_scope::STEWARD_DERIVE_VERB,
            ],
            // The archive takes back what the Dreamer landed, so it is judged
            // by the landing verdict: without `derive` it archives nothing.
            Self::RecallUpkeep => &[
                grant_scope::STEWARD_READ_VERB,
                grant_scope::STEWARD_DERIVE_VERB,
                grant_scope::STEWARD_ARCHIVE_VERB,
            ],
            Self::CoachChecks => &[grant_scope::STEWARD_READ_VERB],
            Self::EngineControlsJobs => &grant_scope::ENGINE_CONTROLS_VERBS,
        }
    }

    /// What stops, in one plain sentence, for the warning.
    #[must_use]
    pub const fn what_breaks(self) -> &'static str {
        match self {
            Self::Consolidation => {
                "Consolidation stops: new conversations are no longer turned into memory."
            }
            Self::RecallUpkeep => {
                "Recall upkeep stops: weak, quiet memories are no longer archived, so recall gets noisier."
            }
            Self::CoachChecks => {
                "Coach checks stop: the Coach no longer checks how the vault's agents are doing."
            }
            Self::EngineControlsJobs => {
                "Engine-control jobs stop: schedules, budgets and recipes are no longer tuned for you."
            }
        }
    }
}

/// One narrowing the owner applied, as the record keeps it: that he chose
/// it, what the grant held before and after, and the breaks he confirmed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemAgentNarrowing {
    /// The owner who applied it.
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub owner: EntityId,
    /// The grant his signed revoke took back.
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub revoked: EntityId,
    /// The narrower grant his signed mint gave; `None` when he revoked it whole.
    #[serde(default, with = "oneiron_contracts::serialize::entity_ref::optional")]
    pub minted: Option<EntityId>,
    /// The verbs the grant held before.
    pub before: BTreeSet<String>,
    /// The verbs it holds after.
    pub after: BTreeSet<String>,
    /// The breaks he confirmed (empty when the narrowing stops none of the
    /// agent's functions).
    pub confirmed: Vec<SystemFunction>,
}
