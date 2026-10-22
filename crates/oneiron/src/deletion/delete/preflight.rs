//! What the delete rail admits before any legal hold is read, as one check
//! a caller that decides before the rail runs can make in its own writer
//! (FIX 1465). It calls the rail's own checks, in the rail's order, and
//! adds none: an owner's delete accepted as pending runs later through the
//! rail, so it must pass now what the rail would refuse then.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, RegistryError, Result};

use super::super::tombstone::DeleteReason;

impl Vault {
    /// The delete rail's admission of `id` under `reason` that no legal hold
    /// decides, read in `txn`: an actor, a shared LFS chunk, a room record
    /// with no room door, an e-sign event, a ruling, a task fact, an
    /// audience edit (a privacy erase erases one instead), a goal, a pack
    /// map carrier, a live merge source under a hard purge, a maintenance
    /// kind, and a record a live brief share still names. `gated` is the
    /// rail's owner gate.
    pub(crate) fn delete_admission_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        reason: DeleteReason,
        gated: bool,
    ) -> Result<()> {
        crate::dreamer_runner::authority::guard_actor_delete(id)?;
        crate::origin::lfs::reject_direct_lfs_chunk_delete(&self.store, txn, id)?;
        self.require_room_delete_gate(txn, id, None, false)?;
        crate::blob_artifact::esign::reject_event_delete(&self.store, txn, id)?;
        crate::federation::reject_ruling_delete(&self.store, txn, id)?;
        crate::task_authority::reject_fact_delete(&self.store, txn, id)?;
        if reason != DeleteReason::GdprDelete {
            crate::workspace_roster::reject_audience_edit_delete(&self.store, txn, id)?;
        }
        crate::workspace_roster::precheck_goal_delete(&self.store, txn, *id, gated)?;
        self.store.guard_pack_map_carrier_delete_in_txn(txn, id)?;
        if reason.active_store_hard_purge_v1() {
            self.guard_active_merge_hard_delete_in_txn(txn, id)?;
        }
        if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, id)?
            && let Some(&entity_type) = raw.first()
            && (crate::batch::delete_door_protected(entity_type)
                || crate::workspace_roster::is_project_revision_type(&self.store, entity_type))
        {
            return Err(Error::Registry(RegistryError::MaintenanceKindNotWritable(
                entity_type,
            )));
        }
        if matches!(
            reason,
            DeleteReason::UserDelete | DeleteReason::UserHardDelete
        ) && !crate::share::active_brief_shares_for(
            &self.store,
            txn,
            id,
            self.store.clock.now_recorded_at(),
        )?
        .is_empty()
        {
            return Err(Error::InvariantViolation(
                "active brief share requires confirmed delete",
            ));
        }
        Ok(())
    }
}
