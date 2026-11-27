//! Public and gated delete entry points plus the headerful orchestration state machine.

use std::collections::BTreeSet;

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::super::gate::{
    GatedDeletion, reverify_deletion_authority_before_publication,
    reverify_owner_proof_before_publication,
};
use super::super::tombstone::DeleteReason;
use super::guard::DeleteGuard;
use super::{DeleteEntityOptions, DeleteEntityOutcome};

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
    pub fn delete_entity_with_reason(
        &self,
        id: &EntityId,
        reason: DeleteReason,
    ) -> Result<DeleteEntityOutcome> {
        self.delete_entity_through_dependents(id, reason, None, None)
    }

    /// [`Self::delete_entity_with_reason`] as the vault owner's own act: the
    /// same delete, ungated as before, whose every writer before publication
    /// (and, when nothing publishes, the first destructive one) re-proves
    /// `owner` against its own view, where a gated delete re-proves its gate;
    /// a soft delete's publication re-proves it after its scrub, and the
    /// owner's delete of their own PERSON there takes that PERSON as live.
    /// A request admitted on an owner credential that is revoked, or whose
    /// person stops owning this vault, before a writer re-proves it gets the
    /// owner door's refusal from that writer, which tears and publishes
    /// nothing (FIX MEMORY-DELETE-OWNER-PROOF-NOT-REVALIDATED-AT-COMMIT). The
    /// carrier marks a sync publication commits before its publish
    /// transaction re-prove nothing, for this delete as for a gated one (FIX
    /// PUBLISH-REFUSAL-KEEPS-CARRIER-SUPPRESSION).
    pub fn delete_entity_with_reason_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        reason: DeleteReason,
    ) -> Result<DeleteEntityOutcome> {
        match self.delete_entity_through_dependents(id, reason, None, Some(owner)) {
            // The owner, on their own proof, learns `restricted` for a
            // record they chose to restrict (Q1 = A); any other absence
            // passes through.
            Err(Error::EntityNotFound) => Err(self
                .restricted_owner_delete_refusal(owner, id)
                .unwrap_or(Error::EntityNotFound)),
            outcome => outcome,
        }
    }

    /// [`Self::delete_entity_with_reason_as_owner`] with the answer's entries:
    /// the owner's HTTP delete answer lists what it leaves exactly as
    /// `vault.delete` does.
    pub fn delete_entity_as_owner_with_remaining(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
        reason: DeleteReason,
    ) -> Result<(DeleteEntityOutcome, Vec<crate::memory::RemainingNotice>)> {
        let outcome = self.delete_entity_with_reason_as_owner(owner, id, reason)?;
        let remaining = super::remaining::delete_remaining(
            self,
            reason,
            outcome.sweep_key.as_deref(),
            &outcome.released_file_digests,
        );
        Ok((outcome, remaining))
    }

    /// Owner-on-own-proof only (Q1 = A): the delete or erase rail refused
    /// `id` with absence, so re-prove `owner` and re-probe for a cooperative
    /// restriction on it in a read txn of its own. `Some(Error::RecordRestricted)`
    /// when one stands, so the owner learns `restricted`; `None` when the
    /// absence stands, the proof does not re-prove, or the probe itself fails,
    /// so the caller passes the absence through. Never called from the agent
    /// or role arms, nor from any in-txn check: those keep absence.
    pub(crate) fn restricted_owner_delete_refusal(
        &self,
        owner: &AuthenticatedOwner,
        id: &EntityId,
    ) -> Option<Error> {
        let txn = self.store.env.read_txn().ok()?;
        owner.revalidate_in_txn(self, &txn).ok()?;
        crate::store::legal_hold::cooperative_restriction_active_in_txn(&self.store, &txn, id)
            .ok()?
            .then_some(Error::RecordRestricted)
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
        self.delete_entity_through_dependents(id, reason, Some(gate), None)
    }

    /// One delete and its dependent walks.
    fn delete_entity_through_dependents(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: Option<GatedDeletion<'_>>,
        owner: Option<&AuthenticatedOwner>,
    ) -> Result<DeleteEntityOutcome> {
        self.delete_entity_through_dependents_across(id, reason, gate, owner, || {})
    }

    /// [`Self::delete_entity_through_dependents`] with `between` run in the
    /// gap between the guard phase's dropped read snapshot and the plan's
    /// first write: the deterministic race point the last-bound-owner
    /// regression drives a binding change through (round-1 P1 of #7900).
    fn delete_entity_through_dependents_across(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: Option<GatedDeletion<'_>>,
        owner: Option<&AuthenticatedOwner>,
        between: impl FnOnce(),
    ) -> Result<DeleteEntityOutcome> {
        let outcome =
            self.delete_entity_with_reason_impl_across(id, reason, gate, false, owner, between);
        // A fence its erase committed reaches key custody now (FIX 11211).
        self.store.journal_staged_fence_facts();
        let outcome = outcome?;
        // The delete has committed, so every step below runs even when an
        // earlier one fails (ARCH-0038, delete-rail progress after a partial
        // failure). A failed step keeps its queue row and the next pass
        // resumes it. The first error still reaches the caller, so a confirmed
        // erase records this delete as failed, as before.
        let mut first_error: Option<Error> = None;
        let mut keep_error = |error: Error, step: &'static str| {
            tracing::warn!(
                kind = ?error.kind(),
                step,
                "a step after a committed delete failed; the next pass retries"
            );
            first_error.get_or_insert(error);
        };
        // The dependents past the first batch go before the delete returns.
        if let Err(error) = self.finish_dependent_walks() {
            keep_error(error, "dependent walks");
        }
        loop {
            match self.collect_lfs_garbage(32) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) => {
                    keep_error(error, "lfs garbage");
                    break;
                }
            }
        }
        // A masked Git copy whose sources this delete moved is retired once
        // nothing owns it (FIX 7608, FIX 9107); a failure is logged.
        crate::origin::secret_projection::disposal::collect_after_delete(self);
        // A working view of an erased source goes with its unshared blobs
        // (FIX 9722); a failure is logged and the next pass retries.
        crate::code_view::collect_after_delete(self);
        // An erased mail message's opened attachments go with it (FIX 12559).
        crate::mail_pack::collect_after_delete(self);
        // An erased AG-UI capture's asset goes with it (L2-15-CAPTURE-SUBJECT).
        crate::ingest::collect_capture_asset_erases(self);
        #[cfg(unix)]
        if let Err(error) = self.collect_released_result_bodies(256) {
            keep_error(error, "released result bodies");
        }
        self.finish_gate_decision_retirements_after_commit();
        // FIX 10466: the bodies and keys of the snapshots this erase retired,
        // unless a publication holds their files (housekeeping retries).
        self.try_finish_inference_snapshot_retirements_after_commit();
        first_error.map_or(Ok(outcome), Err)
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
    /// absent IDs never reach this method. A user delete gets its hold on the
    /// fence, which [`crate::deletion::conclude_brief_delete`] ends with the
    /// delete's outcome.
    pub(super) fn reserve_user_brief_delete(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: Option<&GatedDeletion<'_>>,
        owner: Option<&AuthenticatedOwner>,
    ) -> Result<Option<crate::deletion::BriefDeleteFence<'_>>> {
        if matches!(
            reason,
            DeleteReason::UserDelete | DeleteReason::UserHardDelete | DeleteReason::OwnerErase
        ) {
            self.retract_brief_shares_unconfirmed(id, gate)?;
            let txn = self.store.env.write_txn()?;
            reverify_deletion_authority_before_publication(gate, &txn)?;
            reverify_owner_proof_before_publication(self, owner, &txn)?;
            self.store.delete_guards.precheck_goal_delete(
                &self.store,
                &txn,
                *id,
                gate.is_some(),
            )?;
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
            return self
                .store
                .brief_delete_fences
                .reserve(&self.store, txn, id)
                .map(Some);
        }
        Ok(None)
    }

    /// With the owner's `deletion.brief_share.require_confirmed` off, the owner's own delete first
    /// revokes `id`'s live brief shares, each in its own write as the confirmed door does, so the
    /// reservation that follows finds none and the delete goes on. The default keeps every share,
    /// and the reservation sends the delete to the confirmed door. So does a delete by anyone the
    /// owner rule of [`Vault::revoke_share`] does not admit for every share (an agent may stop
    /// only a share it issued), and a proof-free delete, which names no actor to revoke as. A
    /// revoke stands if a later phase of the delete fails, as the confirmed door's does; each
    /// revoke's writer reads the delete's authority again first.
    fn retract_brief_shares_unconfirmed(
        &self,
        id: &EntityId,
        gate: Option<&GatedDeletion<'_>>,
    ) -> Result<()> {
        let Some(gate) = gate else {
            return Ok(());
        };
        let actor = gate.write_actor();
        let now = self.store.clock.now_recorded_at();
        let shares = {
            let txn = self.store.env.read_txn()?;
            // The key first: at its default no grant is scanned twice.
            if super::super::setting_keys::BRIEF_SHARE_REQUIRES_CONFIRMED
                .read_in_txn(self, &txn, &[], None)?
                .value
            {
                return Ok(());
            }
            let shares = crate::share::active_brief_shares_for(&self.store, &txn, id, now)?;
            if shares.is_empty()
                || !crate::share::owner_revokes_every_share_in_txn(self, &txn, &actor)?
            {
                return Ok(());
            }
            reverify_deletion_authority_before_publication(Some(gate), &txn)?;
            shares
        };
        // Each retraction reads the delete's authority again in its own
        // writer: a check that changed since the read above (an honour
        // setting's answer the owner replaced) stops it before the grant
        // changes (review round 2 of #9902).
        for (share_id, _) in shares {
            self.revoke_share_checked(&share_id, &actor, now, |txn| {
                reverify_deletion_authority_before_publication(Some(gate), txn)
            })?;
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
        owner: Option<&AuthenticatedOwner>,
    ) -> Result<DeleteEntityOutcome> {
        self.delete_entity_with_reason_impl_across(
            id,
            reason,
            gate,
            allow_replay_test,
            owner,
            || {},
        )
    }

    /// [`Self::delete_entity_with_reason_impl`] with `between` run after the
    /// guard phase's read snapshot and before the plan's first write, or the
    /// headerless leg's scope probe. No writer is held at the gap, so
    /// `between` may commit (a binding change the write transactions below
    /// must then see). Production passes an empty step; the `test_doors` race
    /// door passes the test's.
    fn delete_entity_with_reason_impl_across(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: Option<GatedDeletion<'_>>,
        allow_replay_test: bool,
        owner: Option<&AuthenticatedOwner>,
        between: impl FnOnce(),
    ) -> Result<DeleteEntityOutcome> {
        let guard = self.delete_guard_phase(id, reason, &gate, allow_replay_test, owner)?;
        between();
        let (requested_at, header) = match guard {
            DeleteGuard::Done(outcome) => return Ok(outcome),
            DeleteGuard::Headerless { requested_at } => {
                return self.delete_entity_without_header(
                    id,
                    reason,
                    requested_at,
                    gate.as_ref(),
                    owner,
                );
            }
            DeleteGuard::Proceed {
                requested_at,
                header,
            } => (requested_at, header),
        };
        let fence = self.delete_reserve_phase(id, reason, &gate, owner)?;
        let outcome = self.delete_entity_reserved(
            id,
            reason,
            &gate,
            allow_replay_test,
            owner,
            requested_at,
            header,
        );
        crate::deletion::conclude_brief_delete(fence, &self.store, outcome)
    }

    /// [`Self::delete_entity_with_reason_impl_across`] past its reservation:
    /// plans the delete, then runs its soft arm, or its hard setup and its
    /// receipt. Its outcome concludes the reservation's hold.
    #[expect(clippy::too_many_arguments)]
    fn delete_entity_reserved(
        &self,
        id: &EntityId,
        reason: DeleteReason,
        gate: &Option<GatedDeletion<'_>>,
        allow_replay_test: bool,
        owner: Option<&AuthenticatedOwner>,
        requested_at: u64,
        header: EntityMetadataHeader,
    ) -> Result<DeleteEntityOutcome> {
        let plan = self.delete_plan_phase(id, reason, gate, requested_at, header)?;
        if !reason.active_store_hard_purge_v1() {
            return self.delete_soft_arm_phase(
                id,
                reason,
                gate,
                allow_replay_test,
                owner,
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
            gate,
            allow_replay_test,
            owner,
            header,
            plan.tombstone,
            &plan.gate_decision,
            &plan.window_label,
            &plan.captured,
        )?;
        let mut outcome = self.delete_receipt_phase(
            id,
            reason,
            gate,
            allow_replay_test,
            owner,
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
        )?;
        outcome.released_file_digests = outcome
            .released_file_digests
            .into_iter()
            .chain(hard.released_file_digests)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(outcome)
    }

    /// [`Self::delete_entity`] with `between` run in the gap between the
    /// guard phase's dropped read snapshot and the plan's first write (the
    /// `_across` split's test entry; round-1 P1 of #7900). The `test_doors`
    /// race door is its only caller.
    #[cfg(oneiron_test_support)]
    pub(crate) fn delete_entity_across(
        &self,
        id: &EntityId,
        between: impl FnOnce(),
    ) -> Result<bool> {
        self.delete_entity_through_dependents_across(
            id,
            DeleteReason::UserDelete,
            None,
            None,
            between,
        )
        .map(|outcome| outcome.existed)
    }
}
