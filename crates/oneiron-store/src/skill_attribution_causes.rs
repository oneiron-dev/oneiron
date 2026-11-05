//! The ledger of the labels the attribution judge settled on each attempt's
//! terminal outcome (`SKILL_ATTRIBUTION_CAUSE` rows), and the erase that
//! forgets an erased actor or skill on them. Skill attribution
//! (`skill_attribution::causes`) writes and reads the ledger; the row's
//! side-table declaration names its erase hook.
use serde::{Deserialize, Serialize};

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// [`CAUSES`]'s stored row. The label is the judge's stable wire token.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CauseRow {
    pub source: EntityId,
    pub sequence: u64,
    pub receipt: String,
    /// `None` once the actor is erased: the label stays with its receipt.
    pub actor: Option<EntityId>,
    /// `None` once the skill is erased (FIX 8265), as the actor's slot.
    pub skill: Option<EntityId>,
    pub label: String,
    pub share: f32,
    pub judge_revision: Option<String>,
    pub at: u64,
}
