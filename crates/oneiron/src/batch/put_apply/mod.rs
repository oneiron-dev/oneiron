//! Core half of `batch::put_apply`: its store-layer items live in `oneiron_store::batch::put_apply` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::batch::put_apply::*;

pub(super) use self::apply::{apply_put, apply_put_beside};
pub(crate) use self::claim_admission::put_target_admitted_in;
use self::put_entity_update::{validate_local_skill_create, validate_skill_body_overwrite};
#[cfg(test)]
pub(crate) use self::put_staging::wiped_rows;
pub(crate) use self::put_staging::{delete_entity_index_rows, stage_entity_index_rows};
use self::put_staging::{stage_claim_projection, stage_optional_side_row};
pub(super) use self::put_staging::{stage_edge_rows, stage_entity_body_row};
pub(super) use self::request::{
    ClaimCandidateRequest, PutContext, PutOptions, PutRequest, PutRow, VerifiedOwnDeviceLane,
};
use super::agent_definition_create::validate_local_agent_definition_create;
use super::{
    AuthorityLogKeyOccupant, BaseWriteOrigin, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader,
    LONG_INTERVAL_THRESHOLD_SECS, apply_short_id_plan, authority_observation_secs_for_write,
    check_authority_log_store_key, delete_short_id_rows_for_id,
    evict_authority_log_store_key_squatter, index_thread_claim_subject,
    lexical_query_hint_claim_id, parse_entity_metadata, plan_short_id_update_hashed,
    reject_overlay_member_base_write, validate_immutable_task_record,
    validate_replicated_authority_log_beside_for_local_vault,
    validate_replicated_authority_log_for_local_vault,
};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::store::Store;
use crate::write_envelope::task_body::TaskRole;
use std::collections::BTreeSet;

mod apply;
mod claim_admission;
mod connector_key_guard;
mod lexical_hint;
mod owned_body;
mod put_entity_update;
mod put_staging;
mod request;

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
