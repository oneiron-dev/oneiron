//! A recovery hold's lazy landing: once its wait is over, the held enrolment
//! and revocations land as ordinary owner-key rows (WAYBACK-RECOVERY-HOLD-WIRE = A).

use super::*;
use crate::authority::{adopted_evidence, history_transfer};

impl Vault {
    /// Lands this install's due recovery holds, one writer transaction per
    /// hold: a hold whose seed slot is here. In the transaction the hold is
    /// folded again on this install's clock: Due (by this install's own
    /// `instant_in_txn`, or an `ItIsMe`) with R and the held owner live
    /// revokes each lost key the root door's rule still admits and then
    /// enrols the held input (predecessor R, kind `Device`), all signed by
    /// R from the slot, as
    /// the root door's vouch orders them (a self-hosted owner whose lost
    /// key held their binding is bound again by the enrolment), marks the
    /// rows for the live mirror, commits, announces them, then deletes the
    /// slot. `Cancelled`, `Void` and a successor already on the roster
    /// delete the slot and its pending record, while this run's writer is
    /// held, and report the state; they write no authority row. `Waiting`
    /// is nothing. A terminal hold whose successor a waiting or due retry
    /// names leaves the slot to that retry and is not reported. A hold with
    /// no row here keeps its slot: its write may still be committing. With
    /// no keystore installed no slot is here, so the run lands nothing;
    /// with no hold and no pending slot record it writes nothing at all.
    /// Before any of that, one sweep reaps the seed slots a crash orphaned:
    /// for each pending slot record, a slot that holds no seed loses its
    /// record, and a seed no hold names is deleted with its record. The run
    /// holds the vault's recovery-hold lock throughout, as the root door's
    /// hold attempt does from its reuse check to its hold's commit, so it
    /// never reaps an attempt's slot before its hold names it, and no
    /// attempt puts a seed between its reads and its deletes. The root
    /// door's box arm calls it first; the
    /// host's poll of a waiting recovery calls it too (the keystore is
    /// installed after each open, so an open never lands).
    ///
    /// # Errors
    /// A hold's write that the fold does not count; the store's, the
    /// clock's and the keystore's.
    pub fn land_due_recovery_holds(&self) -> Result<Vec<RecoveryHoldLanding>> {
        match self.device_keystore() {
            Ok(_) => {}
            Err(Error::Secret(SecretError::KeystoreUnavailable(_))) => return Ok(Vec::new()),
            Err(other) => return Err(other),
        }
        let _run = self
            .store
            .recovery_hold_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (vault_id, views, pending) = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
            (
                vault_id,
                self.recovery_holds_in_txn(&txn)?,
                self.recovery_hold_slots_pending_in_txn(&txn)?,
            )
        };
        if views.is_empty() && pending.is_empty() {
            return Ok(Vec::new());
        }
        let machine = self.prepare_install_signing()?;
        // The orphan sweep: a seed the door put before a crash left a
        // pending record and no hold. Under one write transaction, a record
        // whose slot holds no seed is dropped; one whose seed no hold
        // (stored or carried, any state) names is deleted with its record;
        // a hold's own slot is left for the landing loop below. It commits
        // only when it reaped something.
        if !pending.is_empty() {
            let mut sweep = self.store.env.write_txn()?;
            let fold = self.authority_view_readonly_in_txn(&sweep)?;
            let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
            let named: BTreeSet<[u8; 32]> = self
                .recovery_holds_in_txn(&sweep)?
                .into_iter()
                .filter_map(|view| match view.successor_key {
                    AuthorityKey::Ed25519(successor) => Some(successor),
                    _ => None,
                })
                .collect();
            let mut reaped = false;
            for successor in &pending {
                let slot = self.recovery_hold_slot(&vault_id, machine, successor);
                if self.read_recovery_hold_seed(&slot)?.is_none() {
                    self.drop_recovery_hold_slot_pending_in_txn(&mut sweep, successor)?;
                    reaped = true;
                } else if !named.contains(successor) {
                    self.delete_recovery_hold_seed(&slot)?;
                    self.drop_recovery_hold_slot_pending_in_txn(&mut sweep, successor)?;
                    reaped = true;
                }
            }
            if reaped {
                sweep.commit()?;
            }
        }
        let mut landings = Vec::new();
        for view in views {
            let AuthorityKey::Ed25519(successor) = view.successor_key else {
                continue;
            };
            let slot = self.recovery_hold_slot(&vault_id, machine, &successor);
            // Holds for one successor share its slot, so the first terminal
            // hold in view order cleans and reports it, and a later terminal
            // hold for that successor finds it empty here and reports
            // nothing: a run reports one cleanup per successor.
            let Some(seed) = self.read_recovery_hold_seed(&slot)? else {
                continue;
            };
            let mut txn = self.store.env.write_txn()?;
            let in_txn = self.recovery_holds_in_txn(&txn)?;
            let Some(state) = in_txn
                .iter()
                .find(|found| found.hold == view.hold)
                .map(|found| found.state)
            else {
                continue;
            };
            // A retry for the same successor owns the seed slot now: only a
            // terminal hold with no live attempt for its successor cleans
            // it.
            let retry_owns = in_txn.iter().any(|found| {
                found.hold != view.hold
                    && matches!(
                        found.state,
                        RecoveryHoldState::Waiting | RecoveryHoldState::Due
                    )
                    && found.successor_key == view.successor_key
            });
            match state {
                RecoveryHoldState::Waiting => {}
                RecoveryHoldState::Landed
                | RecoveryHoldState::Cancelled
                | RecoveryHoldState::Void => {
                    // The retry owns the slot: nothing here is this hold's
                    // to clean, and the retry reports for itself.
                    if retry_owns {
                        continue;
                    }
                    // The slot goes while this writer is held, so no hold
                    // naming it commits between the read above and the
                    // delete; the record goes after its slot.
                    self.delete_recovery_hold_seed(&slot)?;
                    self.drop_recovery_hold_slot_pending_in_txn(&mut txn, &successor)?;
                    txn.commit()?;
                    landings.push(RecoveryHoldLanding {
                        hold: view.hold,
                        state,
                        enrollment: None,
                        revoked: Vec::new(),
                    });
                    continue;
                }
                RecoveryHoldState::Due => {
                    let history = history_transfer::history_in_txn(self, &txn)?;
                    let evidence = adopted_evidence::adopted_evidence_in_txn(&self.store, &txn)?;
                    let row = match history.get(&view.hold) {
                        Some((_, row)) => row,
                        None => match evidence.as_deref().and_then(|held| held.body(&view.hold)) {
                            Some(row) => row,
                            None => continue,
                        },
                    };
                    let AuthorityOp::RecoveryHold(hold) = &row.op else {
                        continue;
                    };
                    let root_key = row.signer_key().clone();
                    // The slot is keyed by the successor alone, so a hold
                    // another root key signed for the same successor may
                    // have put its seed here: the slot is that hold's, and
                    // this one signs only with its own R.
                    let slot_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
                    if root_key != AuthorityKey::Ed25519(slot_key) {
                        continue;
                    }
                    let fold = self.authority_view_readonly_in_txn(&txn)?;
                    let root_live = fold
                        .roster
                        .get(&root_key)
                        .is_some_and(|device| !device.revoked);
                    let owner_live = self.recovery_hold_owner_is_live_in_txn(&txn, &hold.owner)?;
                    if !root_live || !owner_live {
                        // As in the terminal arms above.
                        if retry_owns {
                            continue;
                        }
                        self.delete_recovery_hold_seed(&slot)?;
                        self.drop_recovery_hold_slot_pending_in_txn(&mut txn, &successor)?;
                        txn.commit()?;
                        landings.push(RecoveryHoldLanding {
                            hold: view.hold,
                            state: RecoveryHoldState::Void,
                            enrollment: None,
                            revoked: Vec::new(),
                        });
                        continue;
                    }
                    let sign = |transcript: &[u8]| {
                        RecoveryAuthoritySigner::sign_transcript_with_seed(&seed, transcript)
                    };
                    let (enrollment, revoked) = self.write_recovery_hold_landing_in_txn(
                        &mut txn,
                        &fold,
                        (hold, &root_key),
                        &sign,
                    )?;
                    let rows = self.mark_authority_rows_counted_since_in_txn(&mut txn, &fold)?;
                    txn.commit()?;
                    self.note_committed_authority_rows(rows);
                    self.delete_recovery_hold_seed(&slot)?;
                    let mut cleanup = self.store.env.write_txn()?;
                    self.drop_recovery_hold_slot_pending_in_txn(&mut cleanup, &successor)?;
                    cleanup.commit()?;
                    landings.push(RecoveryHoldLanding {
                        hold: view.hold,
                        state: RecoveryHoldState::Landed,
                        enrollment: Some(enrollment),
                        revoked,
                    });
                    continue;
                }
            }
            drop(txn);
        }
        Ok(landings)
    }

    /// The landing's write for `hold`, which `root_key` (R) signed, in
    /// `txn`, whose fold before the write is `fold`: each lost key the hold
    /// names that the root door's rule still admits in `fold` is revoked (a
    /// live owner key of the hold's owner, never R and never the successor:
    /// [`Vault::revocable_lost_keys_in_txn`]; row
    /// RECOVERY-HOLD-LOST-KEY-RULE-AT-FOLD), then the held input is enrolled
    /// for the hold's owner (predecessor R, kind `Device`), all signed by
    /// `sign`. A lost key revoked since the hold, or one the door would
    /// have refused (R itself, say, in a hold R signed by hand), is passed
    /// over. The lost keys go first, as at the root door's
    /// vouch: the enrolment binds a self-hosted owner whose lost key held
    /// their binding. Answers the enrolment and the revocations in the
    /// order written; the caller marks the rows and commits. The root
    /// door's hold writer runs it first in a savepoint it aborts, so a hold
    /// whose landing the fold would refuse is never written (row
    /// RECOVERY-HOLD-ENROLMENT-PREFLIGHT); the landing judges again here.
    ///
    /// # Errors
    /// The revocations' and the enrolment's refusals
    /// ([`Vault::enrol_owner_signing_key_as`]); the store's.
    pub(in crate::authority) fn write_recovery_hold_landing_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        (hold, root_key): (&RecoveryHold, &AuthorityKey),
        sign: &dyn Fn(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<(OwnerKeyEnrollmentReceipt, Vec<AuthorityEntryHash>)> {
        let successor = hold.successor_key();
        let revocable = self.revocable_lost_keys_in_txn(
            txn,
            fold,
            hold.owner,
            (root_key, Some(&successor)),
            &hold.lost,
        )?;
        let mut revoked = Vec::with_capacity(revocable.len());
        for key in &hold.lost {
            if !revocable.contains(key) {
                continue;
            }
            let signer = EntrySigner::Key(root_key, sign);
            revoked.push(self.append_revoke_device_in_txn(txn, signer, key.clone())?);
        }
        let mut sign_enrolment = |_: &AuthorityFold, transcript: &[u8]| sign(transcript);
        let enrollment = self.enrol_owner_signing_key_for_actor_in_txn(
            txn,
            hold.owner,
            ActSurface::ThisInstall,
            OwnerKeyEnrollment {
                machine: hold.enrolment.machine,
                public_key: hold.enrolment.public_key,
                proof: hold.enrolment.proof.clone(),
            },
            EnrolledOwnerKeyKind::Device,
            root_key.clone(),
            &mut sign_enrolment,
        )?;
        Ok((enrollment, revoked))
    }
}
