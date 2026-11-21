//! The pending owner-key move a device confirms, on the shared act it runs
//! for (row HOSTED-OWNER-MOVE-TWO-PHASE; Engine RULING
//! OWNERKEY-HOSTED-MOVE-NEXT-STEP = A, ANSWER OWNERKEY-TWO-PHASE-SIGNER = A).
//! A `remove_owner` or `transfer_ownership` act whose move would end an
//! owner-key holder's keys, run where no key proves the revokes (a managed
//! host), is refused and stays pending; the refusal names the act and the
//! executor's next step. The executor's device takes the act's plan
//! ([`Vault::owner_key_move_plan`]), signs it
//! ([`Vault::sign_owner_key_move_as`]), and the server runs the act with
//! those rows ([`Vault::execute_completed_shared_act_with_owner_key_revokes`]),
//! which land with the move in its one writer. An Owner's own leave is a
//! `remove_owner` act naming themselves, confirmed the same way.

use super::*;
use crate::authority::OwnerKeyMovePlan;
use crate::error::{OwnerKeyMoveStep, RecordError};

/// The member whose Owner standing `act` ends: a `remove_owner` act's
/// target, or a `transfer_ownership` act's starter, unless they keep Owner.
/// `None` for every other act.
pub(super) fn owner_standing_ends(act: &PendingAuthorityAct) -> Result<Option<EntityId>> {
    match SharedActKind::parse(&act.act) {
        Some(SharedActKind::RemoveOwner) => {
            let plan: RemoveOwnerPlan = decode(&act.payload)?;
            if plan.target_keeps == Some(Role::Owner) {
                return Ok(None);
            }
            hex_id(&plan.target).map(Some)
        }
        Some(SharedActKind::TransferOwnership) => {
            let plan: TransferOwnershipPlan = decode(&act.payload)?;
            if plan.from_keeps == Some(Role::Owner) {
                return Ok(None);
            }
            hex_id(&plan.from).map(Some)
        }
        _ => Ok(None),
    }
}

impl Vault {
    /// The plan a device confirms the pending act `act_id` with (row
    /// HOSTED-OWNER-MOVE-TWO-PHASE): the move it runs ends a member's Owner
    /// standing, and `executor`, a live Owner who may run the act, signs its
    /// owner-key revokes on a device of theirs. A plan is answered only once
    /// the act has completed on the store clock, so a confirm exists only
    /// for a move that is due, never inside its objection window (REVIEW2
    /// #9093 P2-1). A frontier join the plan needs is signed by `slips` (or
    /// this install's live host issuer) and kept; nothing else is written.
    ///
    /// # Errors
    /// An executor who is not a live person; an act that is unknown,
    /// already executed, not yet completed, ends no Owner standing, or that
    /// `executor` may not run now; the log's.
    pub fn owner_key_move_plan(
        &self,
        executor: &AuthenticatedOwner,
        act_id: &str,
        slips: Option<&HostSlipIssuer>,
    ) -> Result<OwnerKeyMovePlan> {
        let own_issuer = self.membership_issuer(slips);
        let mut txn = self.store.env.write_txn()?;
        let actor = executor.revalidate_person_in_txn(self, &txn)?;
        let act = self
            .pending_authority_act_in_txn(&txn, act_id)?
            .ok_or_else(invalid)?;
        if act.execution.is_some() {
            return Err(invalid());
        }
        if !self.authority_act_completed_in_txn(&txn, &act)? {
            return Err(Error::ConcurrentWrite("authority act not completed"));
        }
        let member = owner_standing_ends(&act)?.ok_or_else(invalid)?;
        check_vault(self, &txn, act.vault_id)?;
        let own_issuer = self.executing_host_issuer_in_txn(&txn, own_issuer)?;
        let issuer = slips.or(own_issuer.as_ref());
        let now = crate::ports::recorded_at_in_txn(&self.store, &mut txn)?;
        self.act_executors_in_txn(&txn, &act, actor, now)?;
        let plan = self.owner_key_move_plan_in_txn(&mut txn, issuer, actor, member, &act.id)?;
        txn.commit()?;
        Ok(plan)
    }

    /// [`Self::execute_completed_shared_act`] with a device's confirm
    /// (row HOSTED-OWNER-MOVE-TWO-PHASE): `owner_key_revokes`, the rows
    /// [`Self::sign_owner_key_move_as`] answered for the act's plan, land in
    /// the act's writer before its move runs, judged again there, so the
    /// revokes and the move commit together or not at all. No rows is the
    /// plain run. A run the owner-key refusal stops names the act and
    /// `executor`'s next step: confirm it on a device of theirs, or enrol an
    /// owner key on one first.
    ///
    /// # Errors
    /// As [`Self::execute_completed_shared_act`]; for rows that are not the
    /// act's confirm, or a plan gone stale, the integrity refusal, writing
    /// nothing.
    pub fn execute_completed_shared_act_with_owner_key_revokes(
        &self,
        executor: &AuthenticatedOwner,
        act_id: &str,
        slips: Option<&HostSlipIssuer>,
        owner_key_revokes: &[Vec<u8>],
    ) -> Result<SharedActExecution> {
        self.execute_shared_act_in_writer(executor, act_id, slips, owner_key_revokes)
            .map_err(|error| self.owner_key_move_refusal(executor, act_id, error))
    }

    /// `error`, the owner-key refusal of the act `act_id`'s move, with the
    /// act and `executor`'s next step; any other error as it is.
    fn owner_key_move_refusal(
        &self,
        executor: &AuthenticatedOwner,
        act_id: &str,
        error: Error,
    ) -> Error {
        let member = match &error {
            Error::Record(RecordError::OwnerKeyMoveRefused {
                member,
                step: OwnerKeyMoveStep::Unavailable,
                act: None,
            }) => *member,
            _ => return error,
        };
        Error::Record(RecordError::OwnerKeyMoveRefused {
            member,
            step: self
                .executor_owner_key_move_step(executor)
                .unwrap_or(OwnerKeyMoveStep::Unavailable),
            act: Some(act_id.to_owned()),
        })
    }

    /// What `executor` does next about a refused owner-key move.
    fn executor_owner_key_move_step(
        &self,
        executor: &AuthenticatedOwner,
    ) -> Result<OwnerKeyMoveStep> {
        let txn = self.store.env.read_txn()?;
        let actor = executor.revalidate_person_in_txn(self, &txn)?;
        self.owner_key_move_step_in_txn(&txn, actor)
    }
}
