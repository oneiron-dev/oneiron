//! Moved from `crates/oneiron/src/workspace_roster/project/mint.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::project::invalid;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::edge::EdgeKind;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron_base::registry::ENTITY_TYPE_MESSAGE;
use oneiron_base::registry::ENTITY_TYPE_PERSON;
use oneiron_base::registry::ENTITY_TYPE_SKILL;
use oneiron_base::registry::ENTITY_TYPE_TURN;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::record_layout::EntityMetadataHeader;
use oneiron_contracts::temporal::TimeRange;
use oneiron_store::consent_bound::ActionClass;
use oneiron_store::consent_bound::ActionEnvelope;
use oneiron_store::consent_bound::ActorBound;
use oneiron_store::consent_bound::GrantBound;
use oneiron_store::gate_decision::types::GateDecisionId;
use oneiron_store::ports::records::EdgeDirection;
use serde::Deserialize;
use serde::Serialize;

/// The goal is data for the leader, not instructions in its prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectGoalRecord {
    pub project_id: String,
    pub goal: String,
    pub why: String,
    pub axes: Vec<String>,
}

/// The share is expressed against the root project's budget, never a grant
/// to spend more than the parent has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectBudgetShare {
    pub project_id: String,
    pub parent_id: String,
    pub share_bps: u16,
}
