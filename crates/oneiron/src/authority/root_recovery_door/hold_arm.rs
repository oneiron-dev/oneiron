//! The root's door's box arm with a wait (WAYBACK-RECOVERY-HOLD-WIRE = A):
//! one `RecoveryHold` signed by R in place of the vouch. The request is
//! judged in full before this install's owner signing slot takes a fresh
//! key or R's seed moves (row RECOVERY-HOLD-BOX-PATH-WRITES-BEFORE-CHECKS),
//! and a hold is answered again only for the owner whose hold it is.

use oneiron_keystore::{KeystoreSlot, SlotKind};

use super::*;

/// The hold writer's judgment of one request (`judge_hold_in_txn`).
struct JudgedHold {
    /// The fold the judgment read, before any hold row.
    fold: AuthorityView,
    /// The hold row's body.
    body: RecoveryHold,
    /// The writer's second on this install's clock.
    now: u64,
    /// This install's successor key, for [`RootSuccessor::ThisInstall`]: a
    /// fresh one is still in memory only.
    install: Option<InstallSuccessor>,
}

impl Vault {
    /// The box arm with a wait: the vouch writer's checks (R live in the
    /// transaction, the owner revalidated, the lost keys filtered, the
    /// successor input built, the kit-only refusal), the landing's write
    /// judged now and rolled back, then one `RecoveryHold` entry signed by R
    /// with `lands_at` on this install's clock, and no enrolment and no
    /// revocation. The first write judges the request in full, and only a
    /// request that passed settles the successor key and commits its
    /// pending slot record there; R's released seed goes to this install's
    /// keystore slot for that successor before the hold's transaction, and
    /// leaves it again when that transaction fails, with its record. A
    /// second call while this install's hold for the same successor waits
    /// answers the same held attempt, and writes no second hold, when that
    /// hold is the acting owner's: another owner's live hold for the
    /// successor key refuses the call and keeps its seed.
    ///
    /// The door asks for the person at this device as the vouch arm does
    /// (an important act, [`Vault::owner_presence`]): after it revalidated
    /// the owner's proof on a read, before it readies this install's signing
    /// keys and before the PIN step or slot lock, so a refused confirm writes
    /// nothing and leaves this install's machine as it was. A second call
    /// that answers a waiting hold asks again: each call is the person's act.
    pub(super) fn hold_with_root_key(
        &self,
        (owner, authority): (&AuthenticatedOwner, &ActAuthority),
        signer: &RecoveryAuthoritySigner,
        successor: RootSuccessor,
        lost: &[AuthorityKey],
        end: HoldEnd,
    ) -> Result<RootRecovery> {
        // The key that proved the owner is held, never lost: refused before
        // anything is readied, as at the vouch arm (REVIEW-9487 P1 1).
        if owner
            .proving_owner_key()
            .is_some_and(|key| lost.contains(key))
        {
            return Err(authority_refused(PROVING_KEY_NAMED_LOST));
        }
        // The proof, the keystore and the confirm come before anything is
        // readied, in the vouch arm's order (REVIEW-10128 P1 1 and 2).
        let actor = self.owner_key_act_owner(authority)?;
        if matches!(successor, RootSuccessor::ThisInstall) {
            self.device_keystore()?;
        }
        let _asked = self.owner_presence(
            OwnerActImportance::Important,
            owner_presence_reasons::RECOVER_OWNER_ROOT,
        )?;
        // Preparing this install's signing keys writes, so its slot is made
        // ready before any transaction opens, as at the vouch arm.
        let machine = self.prepare_install_signing()?;
        let install = match successor {
            RootSuccessor::ThisInstall => Some(self.device_owner_signing_slot()?),
            RootSuccessor::Device(_) => None,
        };
        // One attempt at a time, and no landing run beside it: the seed slot
        // is keyed by the successor alone (row
        // RECOVERY-HOLD-SEED-SLOT-PER-ATTEMPT). Taken before the PIN's step
        // and the slot lock; a landing run takes it alone.
        let _attempt = self
            .store
            .recovery_hold_lock
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        // This install's slot is read, renewed and its successor named in
        // the hold under the owner signing slot lock, after the device PIN's
        // step, in the order the vouch arm takes them (REVIEW-9487 P1 2, row
        // OCS-OWNER-PIN): no other door of this process renews the slot
        // between the pending write that settles the successor and the
        // hold's commit.
        let device_pin = self.device_pin();
        let _step = device_pin.as_deref().map(DevicePin::step);
        let slot_lock = install.is_some().then(|| {
            self.store
                .owner_signing_slot_lock
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        });
        let candidate = match (&successor, &install) {
            (RootSuccessor::Device(input), _) => input.public_key,
            (RootSuccessor::ThisInstall, Some(slot)) => slot.key()?.public_key(),
            (RootSuccessor::ThisInstall, None) => return Err(invalid_authority()),
        };
        let seed = signer.released_seed();
        let expected = signer.public_key();
        let root_key = signer.authority_key();
        let (vault_id, live) = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
            let live =
                self.live_hold_for_successor_in_txn(&txn, machine, &candidate, &root_key, actor)?;
            (vault_id, live)
        };
        if let Some((hold, lands_at, seed_here)) = live {
            // This R's own live hold whose slot another seed took: the
            // record, then R's seed, as for a new attempt; it lands at its
            // own second.
            if !seed_here {
                let mut pending = self.store.env.write_txn()?;
                self.put_recovery_hold_slot_pending_in_txn(&mut pending, &candidate)?;
                pending.commit()?;
                let slot = self.recovery_hold_slot(&vault_id, machine, &candidate);
                self.put_recovery_hold_seed(&slot, &seed, &expected)?;
            }
            return Ok(RootRecovery::Held { hold, lands_at });
        }
        // The first write judges the request in full (the hold writer's
        // checks and the landing's rehearsal), and only a request that
        // passed settles the successor and commits its pending record (row
        // RECOVERY-HOLD-BOX-PATH-WRITES-BEFORE-CHECKS): a refused call leaves
        // this install's slot and the pending table as they were. The record
        // commits before any seed moves, so a crash between the keystore
        // put and the hold commit still leaves the slot on the sweep's list.
        // When the roster names this install's slot key revoked, the slot
        // takes a fresh key here, once the roster is read in a write (as in
        // the vouch writer), so a run that read before another run's
        // recovery committed never drops that run's live successor, and R's
        // seed enters only a slot whose record is committed. No landing run
        // reaps the record or the seed before the hold names them: it waits
        // for the recovery-hold lock.
        let successor_key = {
            let mut pending = self.store.env.write_txn()?;
            let judged = self.judge_hold_in_txn(
                &mut pending,
                (owner, signer),
                &successor,
                install.as_ref(),
                lost,
                (end, machine),
            )?;
            let successor_key = judged.body.enrolment.public_key;
            let renewal = match (judged.install, &install) {
                (Some(InstallSuccessor::Fresh(fresh)), Some(slot)) => {
                    Some((slot, slot.renew(&fresh)?.1))
                }
                _ => None,
            };
            let recorded = self
                .put_recovery_hold_slot_pending_in_txn(&mut pending, &successor_key)
                .and_then(|()| pending.commit().map_err(crate::Error::from));
            if let Err(error) = recorded {
                if let Some((slot, renewal)) = renewal {
                    slot.put_back(renewal);
                }
                return Err(error);
            }
            successor_key
        };
        let slot = self.recovery_hold_slot(&vault_id, machine, &successor_key);
        let mut created = Vec::new();
        if self.put_recovery_hold_seed(&slot, &seed, &expected)? {
            created.push(slot);
        }
        let outcome = self.hold_write_with_root_key(
            (owner, signer),
            &successor,
            install.as_ref(),
            lost,
            (end, machine),
            successor_key,
        );
        let (answer, held) = match outcome {
            Ok(written) => written,
            Err(error) => {
                self.forget_created_hold_slots(&created);
                return Err(error);
            }
        };
        // The successor is held once the slot lock is let go: a hold asks
        // every signer held for its root, and a signer's answer may read the
        // slot (REVIEW-9678 P1).
        drop(slot_lock);
        if let Some(key) = held {
            self.hold_checkpoint_root_signer(Arc::new(key));
        }
        Ok(answer)
    }

    /// Deletes the seed slots a failed hold write made, best-effort, then
    /// in one write the pending records of the slots it emptied: a record
    /// goes only after its slot is deleted. A slot whose delete failed
    /// keeps its record, so the landing run's sweep deletes it later (no
    /// hold names it); a record whose drop failed names an empty slot,
    /// which the sweep drops.
    fn forget_created_hold_slots(&self, created: &[KeystoreSlot]) {
        let successors: Vec<[u8; 32]> = created
            .iter()
            .filter(|slot| self.delete_recovery_hold_seed(slot).is_ok())
            .filter_map(|slot| match slot.kind {
                SlotKind::RecoveryHold(successor) => Some(successor),
                _ => None,
            })
            .collect();
        if !successors.is_empty()
            && let Ok(mut pending) = self.store.env.write_txn()
        {
            for successor in &successors {
                let _ = self.drop_recovery_hold_slot_pending_in_txn(&mut pending, successor);
            }
            let _ = pending.commit();
        }
    }

    /// The hold writer's judgment of the request in `txn`, a write
    /// transaction the caller commits or drops: the preset is not kit-only,
    /// R is live, the owner's proof revalidates, every lost key is one the
    /// root's key may revoke, the successor's enrolment input is built (this
    /// install's fresh key in memory only, never in its slot), and the
    /// landing's own write, run in a savepoint that is aborted, passes: a
    /// hold whose revocations or enrolment the fold refuses now (the holding
    /// machine, the carrier, R as predecessor, the binding) is refused with
    /// the landing's refusal before its wait (row
    /// RECOVERY-HOLD-ENROLMENT-PREFLIGHT). The hold attempt's first write
    /// runs it before anything is settled, and the hold write runs it again
    /// before its row.
    fn judge_hold_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        (owner, signer): (&AuthenticatedOwner, &RecoveryAuthoritySigner),
        successor: &RootSuccessor,
        install: Option<&OwnerSigningSlot>,
        lost: &[AuthorityKey],
        (end, machine): (HoldEnd, EntityId),
    ) -> Result<JudgedHold> {
        let root_key = signer.authority_key();
        let sign = |transcript: &[u8]| signer.sign_authority_transcript(transcript);
        // The checks the vouch writer makes, in its order.
        if self.recovery_preset_in_txn(txn)?.is_nobody_but_me() {
            return Err(authority_refused(RELEASED_UNDER_KIT_ONLY));
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if !live_owner_key(&fold, &root_key) {
            return Err(authority_refused(ROOT_KEY_NOT_LIVE));
        }
        let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
        let named = match successor {
            RootSuccessor::Device(input) => Some(AuthorityKey::Ed25519(input.public_key)),
            RootSuccessor::ThisInstall => None,
        };
        let lost = self.lost_keys_in_txn(txn, &fold, actor, (&root_key, named.as_ref()), lost)?;
        let (input, install) = match (successor, install) {
            (RootSuccessor::Device(input), _) => (input.clone(), None),
            (RootSuccessor::ThisInstall, Some(slot)) => {
                let (input, key) = this_install_successor(&fold, actor, machine, slot)?;
                (input, Some(key))
            }
            (RootSuccessor::ThisInstall, None) => return Err(invalid_authority()),
        };
        let now = self.instant_in_write_txn(txn)?.secs();
        let body = RecoveryHold {
            owner: actor,
            enrolment: RecoveryHoldEnrolment {
                machine: input.machine,
                public_key: input.public_key,
                proof: input.proof,
            },
            lost: lost.into_iter().collect(),
            lands_at: end.lands_at(now),
        };
        let mut rehearsal = self.store.env.nested_write_txn(txn)?;
        let rehearsed = self.write_recovery_hold_landing_in_txn(
            &mut rehearsal,
            &fold,
            (&body, &root_key),
            &sign,
        );
        rehearsal.abort();
        rehearsed?;
        Ok(JudgedHold {
            fold,
            body,
            now,
            install,
        })
    }

    /// [`Self::hold_with_root_key`]'s writer half: the judgment again, the
    /// hold row and the commit, for `successor_key`, the successor the
    /// first write settled and whose slot holds R's seed. It never renews
    /// this install's slot. It answers the held attempt and this install's
    /// successor key, which the caller holds once it let the slot lock go.
    fn hold_write_with_root_key(
        &self,
        (owner, signer): (&AuthenticatedOwner, &RecoveryAuthoritySigner),
        successor: &RootSuccessor,
        install: Option<&OwnerSigningSlot>,
        lost: &[AuthorityKey],
        (end, machine): (HoldEnd, EntityId),
        successor_key: [u8; 32],
    ) -> Result<(RootRecovery, Option<OwnerRootSigner>)> {
        let root_key = signer.authority_key();
        let sign = |transcript: &[u8]| signer.sign_authority_transcript(transcript);
        let mut txn = self.store.env.write_txn()?;
        let judged = self.judge_hold_in_txn(
            &mut txn,
            (owner, signer),
            successor,
            install,
            lost,
            (end, machine),
        )?;
        // A slot key that moved since the first write (another door
        // re-keyed this install) is not the successor R's seed and its
        // record name: nothing is written, and the next call starts over.
        if judged.body.enrolment.public_key != successor_key {
            return Err(invalid_authority());
        }
        let held = match judged.install {
            Some(InstallSuccessor::Kept(key)) => Some(key),
            Some(InstallSuccessor::Fresh(_)) => return Err(invalid_authority()),
            None => None,
        };
        let lands_at = judged.body.lands_at;
        let hold =
            self.append_recovery_hold_in_txn(&mut txn, &root_key, &sign, judged.body, judged.now)?;
        let rows = self.mark_authority_rows_counted_since_in_txn(&mut txn, &judged.fold)?;
        txn.commit()?;
        self.note_committed_authority_rows(rows);
        Ok((RootRecovery::Held { hold, lands_at }, held))
    }
}
