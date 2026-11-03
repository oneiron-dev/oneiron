//! The executor's pickup: every owner work request naming this install, each
//! rechecked and done in a writer transaction of its own.

use super::record::eligible_readers;
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, CustodyChange, EffectiveRead, OwnerWorkBody,
    OwnerWorkOutcome, OwnerWorkRefusal, OwnerWorkRequest, WorldKeyMode,
};
use crate::error::{Error, Result};
use crate::world_keys::reassert::{ReassertIncomplete, WORLD_KEY_REASSERT_INCOMPLETE};
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

/// Whether a request's pickup reads this install's hybrid secret: a world's
/// key work and a root change open keys with it, a bundle publication waits
/// for it as it always has, and a custody register, rotate or bind's holder
/// opens its protected input with it. A revoke needs no byte, a rewrap
/// with no input seals the value its holder holds, and an export secret
/// reads only the custody leaf it seals (FIX 11845).
fn reads_machine_secret(work: &OwnerWorkBody) -> bool {
    !matches!(
        work,
        OwnerWorkBody::Custody {
            change: CustodyChange::Revoke,
            ..
        } | OwnerWorkBody::Custody {
            change: CustodyChange::Rewrap,
            input: None,
            ..
        } | OwnerWorkBody::ExportSecret(_)
    )
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
    /// lifecycle tick, never on a timer of its own). First every admitted
    /// custody revoke is settled here, byte-free (`settle_revoked_custody`
    /// in `crate::secret_custody`), each kept custody input whose request is
    /// answered is forgotten, and so is each kept export secret copy whose
    /// secret ended (FIX 12064), and each revoke this install owes the owner's
    /// other machines is carried once it can sign (FIX 4851). A wait a root
    /// request's pickup committed is cleared once the fold holds that
    /// request cancelled or superseded, byte-free (FIX 5582). The machine
    /// secret is read outside every transaction, and only when a request's
    /// kind reads it: with no keystore, slot or secret here each such
    /// request stays pending, and nothing is taken over. A custody revoke,
    /// a rewrap with no input, or an export secret reads none.
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
        if let Err(error) = self.settle_revoked_custody() {
            tracing::warn!(
                kind = ?error.kind(),
                "admitted custody revokes were not settled on this install"
            );
        }
        if let Err(error) = self.settle_custody_inputs() {
            tracing::warn!(
                kind = ?error.kind(),
                "answered custody inputs were not forgotten on this install"
            );
        }
        // A kept export secret copy goes with its secret (FIX 12064).
        if let Err(error) = self.settle_export_outputs() {
            tracing::warn!(
                kind = ?error.kind(),
                "ended secrets' export copies were not forgotten on this install"
            );
        }
        // A custody transition or input that arrived before its request
        // stands now that the request is in.
        #[cfg(feature = "sync")]
        self.reapply_custody_in_live_windows();
        // A revoke this install could not carry when the owner made it is
        // carried once it can sign (CALLS CUSTODY_REVOKE_PENDING_CARRY).
        self.carry_owed_revokes();
        // A restore's credentials pending on their source's evidence are
        // judged again on it (FIX-LIST 10671).
        self.resolve_pending_credential_restores_logged();
        // A root request's wait ends with the request, whether or not any
        // work names this install now (FIX 5582).
        if let Err(error) = self.settle_root_request_waits() {
            tracing::warn!(
                kind = ?error.kind(),
                "an ended root request's wait was not cleared on this install"
            );
        }
        let (machine, pending): (EntityId, Vec<(AuthorityEntryHash, bool)>) = {
            let txn = self.store.env.read_txn()?;
            let Some(machine) = crate::identity::read_machine_id_in_txn(self, &txn)? else {
                return Ok(drain);
            };
            let pending = self
                .authority_view_readonly_in_txn(&txn)?
                .pending_owner_work_for(machine)
                .map(|(hash, request)| (hash, reads_machine_secret(&request.work)))
                .collect();
            (machine, pending)
        };
        if pending.is_empty() {
            return Ok(drain);
        }
        // The keys load before any transaction opens: the install key every
        // result is signed with, and the hybrid secret only for the kinds
        // that read it.
        let _ = self.load_install_signing_if_minted();
        let secret = if pending.iter().any(|(_, reads)| *reads) {
            self.machine_secret_outside_txn().ok()
        } else {
            None
        };
        for (index, (request, reads)) in pending.iter().enumerate() {
            if !keep_running() {
                drain.pending += pending.len() - index;
                break;
            }
            let secret = secret.as_ref();
            if *reads && secret.is_none() {
                drain.pending += 1;
                continue;
            }
            let ran = self
                .with_write_txn(|txn| self.run_owner_work_in_txn(txn, *request, machine, secret));
            match ran {
                Ok(Ran::Answered(
                    OwnerWorkOutcome::Enacted { .. } | OwnerWorkOutcome::Sealed { .. },
                )) => drain.enacted += 1,
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
        // A custody change enacted here rides the live windows now, not at
        // their next rematerialization.
        #[cfg(feature = "sync")]
        if drain.enacted > 0 {
            self.refresh_custody_in_live_windows();
        }
        Ok(drain)
    }

    /// One request, read again in the caller's write transaction, by
    /// `machine`, this install, with its hybrid `secret` when the request's
    /// kind reads one (the drain passes it then).
    fn run_owner_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        hash: AuthorityEntryHash,
        machine: EntityId,
        secret: Option<&MachineSecret>,
    ) -> Result<Ran> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let Some(request) = fold
            .pending_owner_work_for(machine)
            .find_map(|(pending, request)| (pending == hash).then_some(request))
        else {
            return Ok(Ran::Gone);
        };
        let outcome = match (&request.work, secret) {
            (OwnerWorkBody::WorldKey { mode }, Some(secret)) => {
                self.world_key_work_in_txn(txn, &fold, hash, request, *mode, secret)?
            }
            (OwnerWorkBody::Root { change, .. }, Some(secret)) => {
                self.root_work_in_txn(txn, &fold, hash, request, *change, secret)?
            }
            (OwnerWorkBody::PublishBundle { home }, Some(_)) => {
                self.publish_bundle_work_in_txn(txn, &fold, request, *home, machine)?
            }
            (OwnerWorkBody::Custody { .. }, secret) => {
                self.custody_work_in_txn(txn, &fold, hash, request, secret)?
            }
            (OwnerWorkBody::ExportSecret(work), _) => {
                self.export_secret_work_in_txn(txn, &fold, hash, request, work)?
            }
            (
                OwnerWorkBody::WorldKey { .. }
                | OwnerWorkBody::Root { .. }
                | OwnerWorkBody::PublishBundle { .. },
                None,
            ) => None,
        };
        let Some(outcome) = outcome else {
            return Ok(Ran::Pending);
        };
        self.append_owner_work_result_in_txn(txn, hash, machine, outcome.clone())?;
        Ok(Ran::Answered(outcome))
    }

    /// A world's key work, as the vault owner its key binds
    /// ([`OwnerWorkRequest::key_owner`]), each record naming the request
    /// signed as entry `hash`. In Ensure mode: mint the world's
    /// first key, or wrap its current key to every reader the settings
    /// allow. In Reassert mode: first wrap again each key this install
    /// wrapped itself, from its own records and keeping each id, then the
    /// same (CALLS WORLD_KEY_REASSERT_MODE). `None` leaves it pending: this
    /// install holds no wrap, pad, record or secret it needs, the world's
    /// edits outgrow one record, or a reader is still unwrapped (CALLS
    /// WORLD_KEY_REASSERT_INCOMPLETE).
    fn world_key_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        hash: AuthorityEntryHash,
        request: &OwnerWorkRequest,
        mode: WorldKeyMode,
        secret: &MachineSecret,
    ) -> Result<Option<OwnerWorkOutcome>> {
        let world = request.act.target;
        if let Some(reason) = self.world_key_refusal(txn, fold, request, secret.machine)? {
            return Ok(Some(OwnerWorkOutcome::Refused { reason }));
        }
        if mode == WorldKeyMode::Reassert
            && !self
                .reassert_held_world_keys_in_txn(txn, world, secret, Some(hash))?
                .ensures()
        {
            return Ok(match WORLD_KEY_REASSERT_INCOMPLETE {
                ReassertIncomplete::Pending => None,
            });
        }
        match self.ensure_world_key_or_wide_in_txn(
            txn,
            request.key_owner(),
            world,
            secret,
            Some(hash),
        ) {
            Ok(Ok(_)) => {}
            // A frontier too wide for one record waits for a merge.
            Ok(Err(_wide)) => return Ok(None),
            // Key possession: every refusal comes before the first write.
            Err(Error::Secret(_)) => return Ok(None),
            Err(error) => return Err(error),
        }
        let after = self.authority_view_readonly_in_txn(txn)?;
        Ok(self
            .world_key_work_complete(txn, &after, world)?
            .then_some(OwnerWorkOutcome::enacted()))
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
        let key_owner = request.key_owner();
        Ok(if !self.world_row_live_in_txn(txn, world)? {
            Some(OwnerWorkRefusal::WorldNotLive)
        } else if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &key_owner)? {
            Some(OwnerWorkRefusal::OwnerNotLive)
        } else if fold.world_policy_revision(world).0 != request.revision() {
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
