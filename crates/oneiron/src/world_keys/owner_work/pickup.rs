//! The executor's pickup: every owner work request naming this install, each
//! rechecked and done in a writer transaction of its own.

use super::record::eligible_readers;
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, EffectiveRead, OwnerWorkBody, OwnerWorkOutcome,
    OwnerWorkRefusal, OwnerWorkRequest,
};
use crate::error::{Error, Result};
use crate::world_keys::{MachineSecret, recipients};
use crate::{EntityId, Vault};

/// The refusal a request gets once its target's revision moved past the
/// act's `seen` (CALLS OWNER_WORK_STALE): a newer act carries its own work,
/// or did it in its own commit, and no work is done for settings the owner
/// did not see.
const OWNER_WORK_STALE: OwnerWorkRefusal = OwnerWorkRefusal::StaleRevision;

/// What one drain did with the requests naming this install.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OwnerWorkDrain {
    /// Done and answered, in the work's own commit.
    pub enacted: usize,
    /// Refused and answered, for a reason the result names.
    pub refused: usize,
    /// Left for a later drain: no secret, key or pad here, a frontier too
    /// wide for one record, readers still unwrapped, or the drain stopped.
    pub pending: usize,
    /// Whose transaction failed; each stays pending.
    pub failed: usize,
}

/// What one request's transaction did.
enum Ran {
    Answered(OwnerWorkOutcome),
    Pending,
    /// It is answered already, or no longer this install's.
    Gone,
}

impl Vault {
    /// Runs the owner work requests that name this install as executor and
    /// have no result yet, in entry-hash order, each in a writer transaction
    /// of its own, checking `keep_running` before each (CALLS
    /// OWNER_WORK_PICKUP: after an authority catch-up and on the served
    /// lifecycle tick, never on a timer of its own). The machine secret is
    /// read first, outside every transaction: with no keystore, slot or
    /// secret here every request stays pending, and nothing is taken over.
    ///
    /// Each request is read again and rechecked in its transaction: its
    /// world is live, its owner still a live vault owner, its target's
    /// revision still the one the act saw, and this install still an
    /// eligible reader; otherwise it is answered refused. The key work and
    /// its result commit together, signed with this install's key. A key
    /// work that leaves a reader unwrapped stays pending, its progress
    /// committed.
    pub fn run_pending_owner_work(
        &self,
        keep_running: impl Fn() -> bool,
    ) -> Result<OwnerWorkDrain> {
        let mut drain = OwnerWorkDrain::default();
        let pending: Vec<AuthorityEntryHash> = {
            let txn = self.store.env.read_txn()?;
            let Some(machine) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
                return Ok(drain);
            };
            self.authority_view_readonly_in_txn(&txn)?
                .pending_owner_work_for(machine)
                .map(|(hash, _)| hash)
                .collect()
        };
        if pending.is_empty() {
            return Ok(drain);
        }
        let Ok(secret) = self.machine_secret_outside_txn() else {
            drain.pending = pending.len();
            return Ok(drain);
        };
        for (index, request) in pending.iter().enumerate() {
            if !keep_running() {
                drain.pending += pending.len() - index;
                break;
            }
            match self.with_write_txn(|txn| self.run_owner_work_in_txn(txn, *request, &secret)) {
                Ok(Ran::Answered(OwnerWorkOutcome::Enacted)) => drain.enacted += 1,
                Ok(Ran::Answered(OwnerWorkOutcome::Refused { .. })) => drain.refused += 1,
                Ok(Ran::Pending) => drain.pending += 1,
                Ok(Ran::Gone) => {}
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "an owner work request failed on this install; it stays pending"
                    );
                    drain.failed += 1;
                }
            }
        }
        Ok(drain)
    }

    /// One request, read again in the caller's write transaction.
    fn run_owner_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        hash: AuthorityEntryHash,
        secret: &MachineSecret,
    ) -> Result<Ran> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let Some(request) = fold
            .pending_owner_work_for(secret.machine)
            .find_map(|(pending, request)| (pending == hash).then_some(*request))
        else {
            return Ok(Ran::Gone);
        };
        let outcome = match request.work {
            OwnerWorkBody::WorldKey => self.world_key_work_in_txn(txn, &fold, &request, secret)?,
        };
        let Some(outcome) = outcome else {
            return Ok(Ran::Pending);
        };
        self.append_owner_work_result_in_txn(txn, hash, secret.machine, outcome)?;
        Ok(Ran::Answered(outcome))
    }

    /// A world's key work: mint its first key, or wrap its current key to
    /// every reader the settings allow, as the act's owner. `None` leaves it
    /// pending: this install holds no wrap, pad or secret it needs, or a
    /// reader is still unwrapped.
    fn world_key_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        request: &OwnerWorkRequest,
        secret: &MachineSecret,
    ) -> Result<Option<OwnerWorkOutcome>> {
        let world = request.act.target;
        if let Some(reason) = self.world_key_refusal(txn, fold, request, secret.machine)? {
            return Ok(Some(OwnerWorkOutcome::Refused { reason }));
        }
        match self.ensure_world_key_in_txn(txn, request.act.owner, world, secret) {
            Ok(_) => {}
            // Key possession: every refusal comes before the first write.
            Err(Error::Secret(_)) => return Ok(None),
            Err(error) => return Err(error),
        }
        let after = self.authority_view_readonly_in_txn(txn)?;
        Ok(self
            .world_key_work_complete(txn, &after, world)?
            .then_some(OwnerWorkOutcome::Enacted))
    }

    /// The first recheck a world key request fails in this transaction.
    fn world_key_refusal(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        request: &OwnerWorkRequest,
        executor: EntityId,
    ) -> Result<Option<OwnerWorkRefusal>> {
        let world = request.act.target;
        Ok(if !self.world_row_live_in_txn(txn, world)? {
            Some(OwnerWorkRefusal::WorldNotLive)
        } else if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &request.act.owner)? {
            Some(OwnerWorkRefusal::OwnerNotLive)
        } else if fold.world_policy_revision(world).0 != request.act.seen {
            Some(OWNER_WORK_STALE)
        } else if !eligible_readers(fold, world).any(|reader| reader == executor) {
            Some(OwnerWorkRefusal::ExecutorNotReader)
        } else {
            None
        })
    }

    /// Whether a world's key work is done on `fold` (CALLS
    /// OWNER_WORK_COMPLETION): the world reads everywhere, so no key counts
    /// for it, or every reader its settings allow and this install's pinned
    /// root hold a counted wrap of its current key, the test the settings
    /// door's receipt uses. That every replica holds the wraps is the sync's.
    fn world_key_work_complete(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        world: EntityId,
    ) -> Result<bool> {
        if fold.world_privacy(world).read == EffectiveRead::Everywhere {
            return Ok(true);
        }
        let root = self.pinned_root_recipient_in_txn(txn, fold)?;
        Ok(fold.current_world_key(world).is_some_and(|current| {
            recipients(fold, world, root)
                .iter()
                .all(|(to, _)| current.wraps.contains_key(to))
        }))
    }
}
