//! Public and gated delete entry points plus the headerful orchestration state machine.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::super::gate::{GatedDeletion, reverify_deletion_authority_before_publication};
use super::super::tombstone::DeleteReason;
use super::guard::DeleteGuard;
use super::{
    ConfirmedEraseOutcome, DeleteEntityOptions, DeleteEntityOutcome, PendingConfirmedErase,
};

impl Vault {
    /// Plain deletion retains a tombstone shell. Use `delete_entity_with_options`
    /// to request irreversible active-store purge explicitly.
    pub fn delete_entity(&self, id: &EntityId) -> Result<bool> {
        self.delete_entity_with_options(id, DeleteEntityOptions::default())
    }

    /// `purge` selects the ARCH-0038 hard tier; false is a shell-keeping
    /// user-delete. Hosts must display an impact preview before a confirmed
    /// purge of shared content.
    pub fn delete_entity_with_options(
        &self,
        id: &EntityId,
        options: DeleteEntityOptions,
    ) -> Result<bool> {
        let reason = if options.purge {
            DeleteReason::UserHardDelete
        } else {
            DeleteReason::UserDelete
        };
        Ok(self.delete_entity_with_reason(id, reason)?.existed)
    }

    /// Deletes an entity according to the pinned ARCH-0038 reason behavior.
    /// A refusal a hold made in any of its writers is logged before it
    /// returns, whatever it returns.
    pub fn delete_entity_with_reason(
        &self,
        id: &EntityId,
        reason: DeleteReason,
    ) -> Result<DeleteEntityOutcome> {
        let deleted = self.delete_entity_through_dependents(id, reason, None, None);
        self.store.flush_legal_hold_refusals_settled();
        deleted
    }

    /// Facade delete seam carrying an owner gate evaluated before TXN1.
    ///
    /// `gate` carries BOTH the decision record and the authority re-check: the
    /// record is minted from a read snapshot this call has already dropped, so
    /// every destructive transaction below re-proves the owner binding against
    /// its OWN view before tearing anything.
    pub(crate) fn delete_entity_with_reason_gated(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: GatedDeletion<'_>,
    ) -> Result<DeleteEntityOutcome> {
        let deleted = self.delete_entity_through_dependents(id, reason, Some(gate), None);
        self.store.flush_legal_hold_refusals_settled();
        deleted
    }

    /// The delete of an owner erase come due (FIX 6337), under the reason
    /// its request `generation` keeps (FIX 1465): run as
    /// [`Self::delete_entity_with_reason`] runs one, except that the first
    /// writer that would publish or tear the record re-proves that this
    /// request still waits, and a hold's refusal names the owner its row
    /// records. None waiting, or a newer request, cancels it: nothing is
    /// published or torn.
    pub(crate) fn delete_confirmed_erase(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        generation: EntityId,
    ) -> Result<ConfirmedEraseOutcome> {
        let due = PendingConfirmedErase::new(generation);
        let deleted = self.delete_entity_through_dependents(id, reason, None, Some(&due));
        self.store.flush_legal_hold_refusals_settled();
        due.outcome(deleted)
    }

    /// One delete and its dependent walks. Its caller logs the refusals once
    /// every writer here has ended.
    fn delete_entity_through_dependents(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: Option<GatedDeletion<'_>>,
        due: Option<&PendingConfirmedErase>,
    ) -> Result<DeleteEntityOutcome> {
        let outcome = self.delete_entity_with_reason_impl(id, reason, gate, false, due)?;
        // The dependents past the first batch go before the delete returns.
        self.finish_dependent_walks()?;
        while self.collect_lfs_garbage(32)? != 0 {}
        // A masked Git copy whose sources this delete moved is retired once
        // nothing owns it (FIX 7608, FIX 9107); a failure is logged.
        crate::origin::secret_projection::disposal::collect_after_delete(self);
        // A working view of an erased source goes with its unshared blobs
        // (FIX 9722); a failure is logged and the next pass retries.
        crate::code_view::collect_after_delete(self);
        #[cfg(unix)]
        self.collect_released_result_bodies(256)?;
        self.finish_gate_decision_retirements_after_commit();
        // FIX 10466: the bodies and keys of the snapshots this erase retired,
        // unless a publication holds their files (housekeeping retries).
        self.try_finish_inference_snapshot_retirements_after_commit();
        Ok(outcome)
    }

    /// Mechanical ARCH-0038 deletion of a room record without the actor-bound
    /// room door: for replay reason transitions and for legacy fixtures that
    /// hold no policy manifest (where the door fails closed). Never evidence
    /// of room authority.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn delete_room_record_unchecked_for_test(
        &self,
        id: &EntityId,
        reason: DeleteReason,
    ) -> Result<DeleteEntityOutcome> {
        let outcome = self.delete_entity_with_reason_impl(id, reason, None, true, None)?;
        self.finish_dependent_walks()?;
        while self.collect_lfs_garbage(32)? != 0 {}
        #[cfg(unix)]
        self.collect_released_result_bodies(256)?;
        self.finish_gate_decision_retirements_after_commit();
        Ok(outcome)
    }

    pub(super) fn require_room_delete_gate(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        gate: Option<&GatedDeletion<'_>>,
        allow_replay_test: bool,
    ) -> Result<()> {
        if allow_replay_test {
            return Ok(());
        }
        // The owner pin survives removal of the ChildOf row and body scrub.
        let room = crate::conversation_dag::room_turn_owner(&self.store, txn, id)?.or(
            crate::conversation::room_message_owner_in(&self.store, txn, *id)?,
        );
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, id)?
        else {
            if room.is_none()
                || (room.is_some()
                    && gate
                        .and_then(GatedDeletion::room_authority)
                        .map(|(id, _)| id)
                        == room)
            {
                return Ok(());
            }
            return Err(Error::Record(crate::error::RecordError::ConversationDenied));
        };
        if raw.first() != Some(&crate::registry::ENTITY_TYPE_TURN)
            && raw.first() != Some(&crate::registry::ENTITY_TYPE_MESSAGE)
        {
            return Ok(());
        }
        let body = raw
            .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("room deletion header"))?;
        if room.is_none() && crate::conversation_dag::record_kind(body)?.is_none() {
            return Ok(());
        }
        if room.is_some()
            && gate
                .and_then(GatedDeletion::room_authority)
                .map(|(id, _)| id)
                == room
        {
            return Ok(());
        }
        Err(Error::Record(crate::error::RecordError::ConversationDenied))
    }

    /// Under the single LMDB writer, refuse live grants and fence the target
    /// before either headerful or headerless tombstone publication. Fully
    /// absent IDs never reach this method.
    pub(super) fn reserve_user_brief_delete(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: Option<&GatedDeletion<'_>>,
    ) -> Result<()> {
        if matches!(
            reason,
            DeleteReason::UserDelete | DeleteReason::UserHardDelete
        ) {
            let mut txn = self.store.env.write_txn()?;
            reverify_deletion_authority_before_publication(gate, &txn)?;
            crate::workspace_roster::precheck_goal_delete(&self.store, &txn, *id, gate.is_some())?;
            if !crate::share::active_brief_shares_for(
                &self.store,
                &txn,
                id,
                self.store.clock.now_recorded_at(),
            )?
            .is_empty()
            {
                return Err(Error::InvariantViolation(
                    "active brief share requires confirmed delete",
                ));
            }
            crate::share::reserve_brief_delete(&self.store, &mut txn, id)?;
            txn.commit()?;
        }
        Ok(())
    }

    /// Deletes `id` under `reason` through the headerful leg, or the headerless leg when
    /// it has no header: its tombstone publishes, its store purges, and a hard purge writes
    /// its receipt.
    fn delete_entity_with_reason_impl(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: Option<GatedDeletion<'_>>,
        allow_replay_test: bool,
        due: Option<&PendingConfirmedErase>,
    ) -> Result<DeleteEntityOutcome> {
        let guard = self.delete_guard_phase(id, reason, &gate, allow_replay_test, due)?;
        let (requested_at, header) = match guard {
            DeleteGuard::Done(outcome) => return Ok(outcome),
            DeleteGuard::Proceed {
                requested_at,
                header,
            } => (requested_at, header),
        };
        let plan = self.delete_plan_phase(id, reason, &gate, requested_at, header)?;
        if !reason.active_store_hard_purge_v1() {
            return self.delete_soft_arm_phase(
                id,
                reason,
                &gate,
                allow_replay_test,
                due,
                header,
                plan.tombstone,
                &plan.gate_decision,
                &plan.turn_program_details,
                &plan.window_label,
                &plan.captured,
            );
        }
        let hard = self.delete_hard_setup_phase(
            id,
            reason,
            &gate,
            allow_replay_test,
            due,
            header,
            plan.tombstone,
            &plan.gate_decision,
            &plan.window_label,
            &plan.captured,
        )?;
        self.delete_receipt_phase(
            id,
            reason,
            &gate,
            allow_replay_test,
            due,
            requested_at,
            header,
            plan.request_uuid,
            plan.tombstone,
            &plan.gate_decision,
            &plan.turn_program_details,
            &plan.window_label,
            &plan.captured,
            hard.crdt_persisted,
            hard.authority_settled,
            hard.soft_complete_at,
        )
    }
}
