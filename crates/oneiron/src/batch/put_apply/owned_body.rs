//! Refuse generic body writes that bypass a storage-owned document or conversation ledger.

use crate::error::Result;
use crate::store::Store;
use crate::{EntityId, TimeRange};
use heed::RoTxn;

pub(super) fn guard_storage_owned_body(
    store: &Store,
    wtxn: &RoTxn<'_>,
    id: &EntityId,
    metadata: (u8, TimeRange, u64),
    data: &[u8],
    replicated: bool,
    #[cfg(feature = "sync")] skill_state_write: Option<&crate::skill::SkillStateWrite>,
) -> Result<()> {
    let (entity_type, _, _) = metadata;
    crate::conversation_dag::guard_record_put(store, wtxn, id, metadata, data, replicated)?;
    if crate::store::project_kind::is_project_type(store, entity_type) {
        store
            .project_writes
            .guard_goal_pointer_put(store, wtxn, *id, data, replicated)?;
    }
    crate::scope_summary::validate_summary_put(store, wtxn, id, entity_type, data, replicated)?;
    crate::origin::lfs::guard_lfs_asset_put(store, wtxn, id, entity_type, data)?;
    #[cfg(feature = "sync")]
    let (document_metadata, document_data) = match skill_state_write {
        Some(request) => {
            if entity_type != crate::registry::ENTITY_TYPE_SKILL || replicated {
                return Err(crate::error::Error::InvariantViolation(
                    "native SKILL state request differs from its applying put",
                ));
            }
            request.recheck_final(store, wtxn, id, data)?;
            let (occurred, learned_at) = request.snapshot().physical_times()?;
            (
                (entity_type, occurred, learned_at),
                request.snapshot().physical_body(),
            )
        }
        None => (metadata, data),
    };
    #[cfg(not(feature = "sync"))]
    let (document_metadata, document_data) = (metadata, data);
    crate::entity_doc::guard_record_put(store, wtxn, id, document_metadata, document_data)?;
    if entity_type == crate::registry::ENTITY_TYPE_CONVERSATION {
        crate::conversation::validate_put_in_txn(store, wtxn, *id, data, replicated)?;
    }
    Ok(())
}
