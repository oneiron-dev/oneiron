//! Moved from `crates/oneiron/src/skill_optimize/gate/project_goal.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::gate::*;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::skill_optimize::gate::project_goal::TradeoffRole;
use oneiron_verb_wire::workspace_roster::project::goal::GoalPreference;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::sync::OnceLock;

/// A preference the loop learned and proposes for a project's goal record.
/// It never writes the record: the goal-intake interview may fold it into
/// the next revision, and a new goal claim leaves it as history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalRevisionProposal {
    pub project: EntityId,
    /// The goal claim in force when the pick was made.
    pub goal_claim: EntityId,
    pub preference: GoalPreference,
    pub question_digest: String,
    pub picked_by: EntityId,
    pub at: u64,
}
