use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::legal_hold::HoldActor;

use super::super::gate::{GatedDeletion, reverify_deletion_authority_before_publication};
use super::super::rendezvous::{DeleteRendezvous, signal_delete_rendezvous};
use super::super::tombstone::DeleteReason;
use super::{DeleteEntityOutcome, PendingConfirmedErase};
use crate::error::RegistryError;

/// What the delete guards decided: the headerful leg's header, or an outcome
/// that ends the delete before any writer opens.
pub(super) enum DeleteGuard {
    Proceed {
        requested_at: u64,
        header: EntityMetadataHeader,
    },
    Done(DeleteEntityOutcome),
}

impl Vault {
    /// Refuses a protected, held or unsafe delete before any tombstone can be
    /// published; a headerless id runs the headerless leg instead.
    pub(super) fn delete_guard_phase(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: &Option<GatedDeletion<'_>>,
        allow_replay_test: bool,
        due: Option<&PendingConfirmedErase>,
    ) -> Result<DeleteGuard> {
        crate::dreamer_runner::authority::guard_actor_delete(id)?;
        {
            let rtxn = self.store.env.read_txn()?;
            crate::origin::lfs::reject_direct_lfs_chunk_delete(&self.store, &rtxn, id)?;
            self.require_room_delete_gate(&rtxn, id, gate.as_ref(), allow_replay_test)?;
        }
        if reason == DeleteReason::ArchivedByCleanup {
            return Err(Error::InvariantViolation(
                "cleanup archives require the cleanup proposal/decision door",
            ));
        }
        crate::blob_artifact::esign::reject_event_delete(
            &self.store,
            &self.store.env.read_txn()?,
            id,
        )?;
        // A privacy erase keeps a thread audience edit its live root folds,
        // made by no one (FIX 5639); any other delete of it refuses below.
        if reason == DeleteReason::GdprDelete
            && let Some(outcome) = crate::workspace_roster::erase_audience_edit(
                self,
                id,
                gate.as_ref()
                    .map_or(HoldActor::UNATTRIBUTED, GatedDeletion::hold_actor),
                |txn| reverify_deletion_authority_before_publication(gate.as_ref(), txn),
            )?
        {
            return Ok(DeleteGuard::Done(outcome));
        }
        {
            let txn = self.store.env.read_txn()?;
            crate::federation::reject_ruling_delete(&self.store, &txn, id)?;
            crate::task_authority::reject_fact_delete(&self.store, &txn, id)?;
            crate::workspace_roster::reject_audience_edit_delete(&self.store, &txn, id)?;
            crate::workspace_roster::precheck_goal_delete(&self.store, &txn, *id, gate.is_some())?;
            self.store.guard_pack_map_carrier_delete_in_txn(&txn, id)?;
        }
        signal_delete_rendezvous(
            self,
            DeleteRendezvous::AfterProtectedRecordPrecheck,
            id,
            None,
        );
        // Refuse a held record, whoever deletes it (a soft scrub destroys
        // body bytes too), and an unsafe explicit hard purge, before any
        // tombstone can be published. The plain `delete_entity` door now
        // defaults to a soft tombstone; an explicitly requested purge is
        // never downgraded.
        {
            let txn = self.store.env.read_txn()?;
            let actor = gate
                .as_ref()
                .map_or(HoldActor::UNATTRIBUTED, GatedDeletion::hold_actor)
                .privacy(reason == DeleteReason::GdprDelete);
            // A due confirmed erase that no longer waits ends here, before
            // any writer, and a hold names the owner its row records.
            let actor = match due {
                Some(due) => due.prove_in(self, &txn, id)?,
                None => actor,
            };
            self.store.reject_legal_holds_in_txn(&txn, &[*id], &actor)?;
            // A pad is held by its world's holds too (OF-470), refused as
            // this actor (FIX 3059).
            crate::world_keys::reject_held_pad_world_as_in_txn(&self.store, &txn, &[*id], &actor)?;
            if reason.active_store_hard_purge_v1() {
                self.guard_active_merge_hard_delete_in_txn(&txn, id)?;
            }
        }
        let requested_at = self.store.clock.now_recorded_at();
        let Some(header) = self.read_entity_header(id)? else {
            return self
                .delete_entity_without_header(id, reason, requested_at, gate.as_ref(), due)
                .map(DeleteGuard::Done);
        };
        if crate::batch::delete_door_protected(header.entity_type)
            || crate::workspace_roster::is_project_revision_type(&self.store, header.entity_type)
        {
            return Err(Error::Registry(RegistryError::MaintenanceKindNotWritable(
                header.entity_type,
            )));
        }
        if reason == DeleteReason::UserDelete {
            let rtxn = self.store.env.read_txn()?;
            if crate::deletion::topology_delete_reservation_in_txn(&self.store, &rtxn, id)?
                .is_some()
                && crate::ports::EntityStoreRead::port_entity_raw(&self.store, &rtxn, id)?
                    .is_some_and(|raw| raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN)
            {
                // A previous soft scrub already committed its propagation
                // marker and request-bound reservation. A second UserDelete
                // must not mint a conflicting request or withdraw that intent.
                return Ok(DeleteGuard::Done(DeleteEntityOutcome::missing()));
            }
        }
        Ok(DeleteGuard::Proceed {
            requested_at,
            header,
        })
    }
}
