//! Batch entity-put materialization: the `apply_put` chokepoint and its row-staging helpers.

mod apply;
mod claim_admission;
mod connector_key_guard;
mod lexical_hint;
mod owned_body;
mod put_entity_update;
mod put_staging;
mod request;

use std::collections::BTreeSet;

use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::habit::TaskRole;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::store::Store;

use self::put_entity_update::{validate_local_skill_create, validate_skill_body_overwrite};
use self::put_staging::{stage_claim_projection, stage_optional_side_row};
use super::agent_definition_create::validate_local_agent_definition_create;
use super::{
    AuthorityLogKeyOccupant, BaseWriteOrigin, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader,
    LONG_INTERVAL_THRESHOLD_SECS, apply_short_id_plan, authority_observation_secs_for_write,
    check_authority_log_store_key, delete_short_id_rows_for_id,
    evict_authority_log_store_key_squatter, index_thread_claim_subject,
    lexical_query_hint_claim_id, parse_entity_metadata, plan_short_id_update_hashed,
    reject_overlay_member_base_write, validate_immutable_task_record,
    validate_replicated_authority_log_for_local_vault,
};

pub(super) use self::apply::apply_put;
pub(crate) use self::claim_admission::put_target_admitted_in;
#[cfg(test)]
pub(crate) use self::put_staging::wiped_rows;
pub(crate) use self::put_staging::{delete_entity_index_rows, stage_entity_index_rows};
pub(super) use self::put_staging::{stage_edge_rows, stage_entity_body_row};
pub(super) use self::request::{ClaimCandidateRequest, PutContext, PutOptions, PutRequest, PutRow};

/// The final `BatchOp::Put` this batch stages for one entity: where it lands
/// in op order, its type byte, and — for a TASK only — the body its role is
/// decoded from. Non-TASK bodies are not retained: the type byte is all the
/// tree validator ever asks of them, so a non-TASK domain is never forced
/// through `TaskRole` decoding.
#[derive(Debug, Clone)]
pub(super) struct BatchEntityPut {
    pub(super) seq: usize,
    pub(super) entity_type: u8,
    pub(super) task_body: Option<Vec<u8>>,
}

/// One entity as the batch LEAVES it — the state `ChildOf` validation answers
/// "does this parent exist, and what role does it carry" against.
///
/// Final state, not pre-state: a parent created anywhere in the same batch
/// exists, and a parent the batch deletes without re-putting does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EffectiveEntity {
    Missing,
    NonTask(u8),
    Task(TaskRole),
}

pub(super) struct AppliedPut {
    pub(super) portable_agent_source: Option<(EntityId, Vec<u8>)>,
    /// Revision companions a PROJECT put captured, for the batch to write next.
    pub(super) project_revisions: Vec<(EntityId, Vec<u8>)>,
    /// Projects whose frontier the batch end refreshes.
    pub(super) touched_projects: BTreeSet<EntityId>,
    pub(super) pending_embedding_token: Option<Vec<u8>>,
    pub(super) cleared_pending_embedding: bool,
    pub(super) had_vector_mutation: bool,
    pub(super) is_lexical_query_hint_claim: bool,
    /// Shell-edge sources an ONE-1604-D1 dominance eviction orphaned, for the
    /// caller's explicit-source reconciliation. Empty on every other path.
    pub(super) evicted_shell_sources: BTreeSet<EntityId>,
}

// The ledger is immutable birth identity, never a second text plane. This
// shared guard covers local writes and replicated/window rematerialization.
fn validate_note_birth_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    data: &[u8],
) -> Result<()> {
    crate::note::decode_note_body_in_txn(store, txn, data)?;
    if let Some(old) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
        && old.get(ENTITY_METADATA_HEADER_LEN..) != Some(data)
    {
        return Err(Error::Record(RecordError::InvalidNoteBody(
            "NOTE birth body is immutable",
        )));
    }
    Ok(())
}

fn decode_previous_skill_record(
    old_type: u8,
    old_record: &[u8],
) -> Result<Option<crate::skill::SkillRecord>> {
    if old_type != ENTITY_TYPE_SKILL {
        return Ok(None);
    }
    let prior_body = &old_record[ENTITY_METADATA_HEADER_LEN..];
    match crate::skill::decode_skill_record(prior_body) {
        Ok(record) => Ok(Some(record)),
        Err(error) => Err(error),
    }
}
