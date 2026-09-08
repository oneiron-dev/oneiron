//! Batch entity-put materialization: the `apply_put` chokepoint and its row-staging helpers.

mod apply;
mod put_entity_update;
mod put_staging;

use std::collections::BTreeSet;

use crate::entity_id::EntityId;
use crate::habit::TaskRole;

use self::put_entity_update::{validate_local_skill_create, validate_skill_body_overwrite};
use self::put_staging::stage_optimizer_birth_marker_row;
use super::agent_definition_create::validate_local_agent_definition_create;
use super::{
    AuthorityLogKeyOccupant, BaseWriteOrigin, CompanionRetiredHistoryOverlay,
    ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, LONG_INTERVAL_THRESHOLD_SECS,
    StagedClaimGateOutcome, apply_short_id_plan, authority_observation_secs_for_write,
    check_authority_log_store_key, delete_short_id_rows_for_id,
    evict_authority_log_store_key_squatter, gate_staging, index_thread_claim_subject,
    lexical_query_hint_claim_id, parse_entity_metadata, plan_short_id_update,
    reject_overlay_member_base_write, validate_companion_register_put,
    validate_replicated_authority_log_for_local_vault, validate_task_checkin_immutable,
};

pub(super) use self::apply::apply_put;
pub(crate) use self::put_staging::delete_entity_index_rows;
pub(super) use self::put_staging::{
    stage_edge_rows, stage_entity_body_row, stage_entity_index_rows,
};

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
    pub(super) pending_embedding_token: Option<Vec<u8>>,
    pub(super) cleared_pending_embedding: bool,
    pub(super) had_vector_mutation: bool,
    pub(super) is_lexical_query_hint_claim: bool,
    /// Shell-edge sources an ONE-1604-D1 dominance eviction orphaned, for the
    /// caller's explicit-source reconciliation. Empty on every other path.
    pub(super) evicted_shell_sources: BTreeSet<EntityId>,
}
