//! Batch entity-put materialization: the `apply_put` chokepoint and its row-staging helpers.

use crate::write_envelope::task_body::TaskRole;
use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_SKILL;

use crate::long_interval::LONG_INTERVAL_THRESHOLD_SECS;
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

pub fn decode_previous_skill_record(
    old_type: u8,
    prior_body: &[u8],
) -> Result<Option<crate::write_envelope::skill_record::SkillRecord>> {
    if old_type != ENTITY_TYPE_SKILL {
        return Ok(None);
    }
    match crate::write_envelope::skill_record::decode_skill_record(prior_body) {
        Ok(record) => Ok(Some(record)),
        Err(error) => Err(error),
    }
}
