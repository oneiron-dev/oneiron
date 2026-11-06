//! Batch entity-put materialization: the `apply_put` chokepoint and its row-staging helpers.

use std::collections::BTreeSet;

use crate::write_envelope::task_body::TaskRole;
use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_SKILL;
use oneiron_contracts::entity_id::EntityId;

use crate::long_interval::LONG_INTERVAL_THRESHOLD_SECS;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::record_layout::EntityMetadataHeader;

/// The final `BatchOp::Put` this batch stages for one entity: where it lands
/// in op order, its type byte, and — for a TASK only — the body its role is
/// decoded from. Non-TASK bodies are not retained: the type byte is all the
/// tree validator ever asks of them, so a non-TASK domain is never forced
/// through `TaskRole` decoding.
#[derive(Debug, Clone)]
pub struct BatchEntityPut {
    pub seq: usize,
    pub entity_type: u8,
    pub task_body: Option<Vec<u8>>,
}

/// One entity as the batch LEAVES it — the state `ChildOf` validation answers
/// "does this parent exist, and what role does it carry" against.
///
/// Final state, not pre-state: a parent created anywhere in the same batch
/// exists, and a parent the batch deletes without re-putting does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveEntity {
    Missing,
    NonTask(u8),
    Task(TaskRole),
}

pub struct AppliedPut {
    pub portable_agent_source: Option<(EntityId, Vec<u8>)>,
    /// Revision companions a PROJECT put captured, for the batch to write next.
    pub project_revisions: Vec<(EntityId, Vec<u8>)>,
    /// Projects whose frontier the batch end refreshes.
    pub touched_projects: BTreeSet<EntityId>,
    pub pending_embedding_token: Option<Vec<u8>>,
    pub cleared_pending_embedding: bool,
    pub had_vector_mutation: bool,
    pub is_lexical_query_hint_claim: bool,
    /// Shell-edge sources an ONE-1604-D1 dominance eviction orphaned, for the
    /// caller's explicit-source reconciliation. Empty on every other path.
    pub evicted_shell_sources: BTreeSet<EntityId>,
}

pub fn decode_previous_skill_record(
    old_type: u8,
    old_record: &[u8],
) -> Result<Option<crate::write_envelope::skill_record::SkillRecord>> {
    if old_type != ENTITY_TYPE_SKILL {
        return Ok(None);
    }
    let prior_body = &old_record[ENTITY_METADATA_HEADER_LEN..];
    match crate::write_envelope::skill_record::decode_skill_record(prior_body) {
        Ok(record) => Ok(Some(record)),
        Err(error) => Err(error),
    }
}
