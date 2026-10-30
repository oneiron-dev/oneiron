//! The `apply_put` entity-put chokepoint: validation, claim gate, type dispatch, and staging.

use std::collections::BTreeSet;

use super::put_staging::{PutCarrierContext, stage_project_put, validate_put_carriers};
use heed::RwTxn;

use super::request::{PutContext, PutRequest, PutRow, Replication};
use super::{
    AppliedPut, AuthorityLogKeyOccupant, ENTITY_METADATA_HEADER_LEN, apply_short_id_plan,
    authority_observation_secs_for_write, check_authority_log_store_key,
    delete_short_id_rows_for_id, evict_authority_log_store_key_squatter, parse_entity_metadata,
    plan_short_id_update_hashed, reject_overlay_member_base_write, stage_claim_projection,
    stage_entity_body_row, stage_entity_index_rows, stage_optional_side_row,
    validate_immutable_task_record, validate_local_agent_definition_create,
    validate_local_skill_create, validate_replicated_authority_log_for_local_vault,
    validate_skill_body_overwrite,
};
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, RecordError, RegistryError, Result};
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_COMM_RECORD, ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_DIAGNOSTIC,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
    ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_SKILL, ENTITY_TYPE_TASK,
};
use crate::side_table::HexId;
use crate::skill_hub::validate_refinement_admission;
use crate::store::Store;

mod admission;
mod audit;
mod authority;
mod claim;
mod dispatch;
mod old_record;
mod projections;
mod rewrite;

// One door stages every effect of a put inside its write transaction.
pub(in crate::batch) fn apply_put(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    request: PutRequest<'_>,
) -> Result<AppliedPut> {
    let data = request.row.data;
    let admission::Admission {
        fixed,
        mut owners,
        mut dispatch,
        mut revision,
        incoming_claim_body,
        project_revisions,
        mut portable_agent_source,
    } = admission::admit_put(store, wtxn, request)?;
    let data = owners.normalized_policy.as_deref().unwrap_or(data);
    let data = owners.project.as_deref().unwrap_or(data);
    let dispatch::DispatchCarry {
        task_body_without_streaks,
        pad_stored_body,
        hub_origin_marker,
        agent_id_pin,
    } = self::dispatch::dispatch_put_type(
        store,
        wtxn,
        data,
        &fixed,
        &mut dispatch,
        &mut revision,
        incoming_claim_body,
    )?;
    owners.task_body_without_streaks = task_body_without_streaks;
    owners.pad_stored_body = pad_stored_body;
    let rewrite::Rewrite {
        evicted_shell_sources,
        short_id_plan,
        authority_first_seen_key,
        escalated_skill_body,
    } = rewrite::rewrite_put_body(
        store,
        wtxn,
        data,
        &fixed,
        &mut dispatch,
        &revision,
        &owners.task_body_without_streaks,
        &owners.pad_stored_body,
    )?;
    owners.escalated_skill_body = escalated_skill_body;
    let data = owners.escalated_skill_body.as_deref().unwrap_or(data);
    let data = owners.task_body_without_streaks.as_deref().unwrap_or(data);
    let data = owners.pad_stored_body.as_deref().unwrap_or(data);
    let old_record::OldRecord {
        body_changed,
        consolidation_dirty,
        stored_before,
        previous_skill_record,
        optimizer_birth_marker,
    } = old_record::apply_old_record(
        store,
        wtxn,
        data,
        &fixed,
        &dispatch,
        &mut portable_agent_source,
    )?;
    audit::audit_and_stage_body(
        store,
        wtxn,
        data,
        &fixed,
        &dispatch,
        body_changed,
        &previous_skill_record,
        audit::StagedMarkers {
            hub_origin_marker,
            optimizer_birth_marker,
            agent_id_pin,
        },
    )?;
    projections::stage_put_projections(
        store,
        wtxn,
        data,
        &fixed,
        &dispatch,
        &revision,
        body_changed,
        consolidation_dirty,
        stored_before,
        &previous_skill_record,
        short_id_plan,
        authority_first_seen_key,
        evicted_shell_sources,
        project_revisions,
        portable_agent_source,
    )
}
