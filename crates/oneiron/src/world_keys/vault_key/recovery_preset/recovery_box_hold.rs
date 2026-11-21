//! The recovery box's kit-only hold: the box's seam, its pending marker, and
//! the hold's release when the switch fails (pass 27 kit-only).

use super::*;

/// The recovery box's hold for kit-only (BOX-KIT-ONLY-HOLD = A): the engine
/// calls it through this trait, and OPUS-WAYBACK-BOX builds the HTTP
/// implementation on the server. Target kit-only calls `hold_kit_only(true)`
/// after the no-write checks pass and before the write txn opens; its error
/// refuses the switch with nothing written but the marker, after one
/// best-effort `hold_kit_only(false)` while the vault still reads `Standard`,
/// since an error can follow a hold that reached the box. Target `Standard` calls
/// `hold_kit_only(false)` after the commit; its failure answers
/// [`RecoveryPresetChange::box_release_pending`], never an error. A switch
/// refused before the hold makes no hold call; one that fails after it sends
/// `hold_kit_only(false)` once, best-effort, while the vault still reads
/// `Standard`, and answers the first error. The marker [`RecoveryBoxHoldPending`]
/// stays set, and a managed boot resends the hold.
///
/// On a hosted vault the box's wait is the recovery wait
/// (WAYBACK-BOX-WAIT-ENGINE-HOLD-ONE-WAIT = A): the vault reports its
/// `recovery.wait` to the box ([`Vault::report_recovery_wait_to_box`]), the
/// box waits that long before it releases the root's authority key, and the
/// root's door then lands at the box's release time
/// ([`crate::authority::RootMaterial::ReleasedAfterBoxWait`]).
pub trait RecoveryBoxHold {
    /// Holds kit-only (`true`) or releases it (`false`) on the recovery box.
    fn hold_kit_only(&self, kit_only: bool) -> Result<()>;

    /// Tells the recovery box the vault's recovery wait: the box waits
    /// `wait` before it releases the root's authority key, read when a
    /// release opens. Until the vault reports, the box waits 24 hours.
    fn report_recovery_wait(&self, wait: std::time::Duration) -> Result<()>;
}

/// No recovery box: every hold and every report answers `Ok`. The preset
/// doors' callers pass it until OPUS-WAYBACK-BOX wires the HTTP hold.
pub struct NoRecoveryBox;

impl RecoveryBoxHold for NoRecoveryBox {
    fn hold_kit_only(&self, _kit_only: bool) -> Result<()> {
        Ok(())
    }

    fn report_recovery_wait(&self, _wait: std::time::Duration) -> Result<()> {
        Ok(())
    }
}

/// Whether the recovery box's kit-only hold may not match the recovery preset: set before a
/// switch into 'Nobody but me' asks the box to hold, and by a switch out of it; cleared once
/// the box answered. A managed boot resends the hold that matches the preset when it is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryBoxHoldPending {
    /// The hold the switch asked for.
    pub target_kit_only: bool,
    /// A fresh random id per switch, compared by the clear.
    pub attempt: u64,
}

impl Vault {
    /// Reports this vault's recovery wait ([`Vault::recovery_wait_in_txn`])
    /// to the recovery box. A managed boot calls it once, and so does every
    /// change of the wait once it commits. An error changes nothing here:
    /// the caller logs it, the box keeps its last value (24 hours until the
    /// first report), and the next boot reports again.
    ///
    /// # Errors
    /// The store's, and the box's answer.
    pub fn report_recovery_wait_to_box(&self, box_hold: &dyn RecoveryBoxHold) -> Result<()> {
        let wait = {
            let txn = self.store.env.read_txn()?;
            self.recovery_wait_in_txn(&txn)?
        };
        box_hold.report_recovery_wait(wait)
    }

    /// The box-hold-pending marker, if set: the hold a switch asked for and its attempt. A
    /// managed boot resends the hold that matches the preset when it is set.
    pub fn recovery_box_hold_pending(&self) -> Result<Option<RecoveryBoxHoldPending>> {
        let txn = self.store.env.read_txn()?;
        BOX_HOLD_PENDING.get(&self.store, &txn, &())
    }

    /// Clears the box-hold-pending marker only when its stored attempt equals `attempt`; true
    /// when it deleted. A heal never clears the marker of a switch that started while it ran.
    pub fn clear_recovery_box_hold_pending(&self, attempt: u64) -> Result<bool> {
        self.with_write_txn(|txn| self.clear_recovery_box_hold_pending_in_txn(txn, attempt))
    }

    /// [`Self::recovery_box_hold_pending`]'s write, in the caller's write txn.
    pub(crate) fn put_recovery_box_hold_pending_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        pending: &RecoveryBoxHoldPending,
    ) -> Result<()> {
        BOX_HOLD_PENDING.put(&self.store, txn, &(), pending)
    }

    /// [`Self::clear_recovery_box_hold_pending`] in the caller's write txn.
    pub(crate) fn clear_recovery_box_hold_pending_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: u64,
    ) -> Result<bool> {
        match BOX_HOLD_PENDING.get(&self.store, txn, &())? {
            Some(stored) if stored.attempt == attempt => {
                BOX_HOLD_PENDING.delete(&self.store, txn, &())
            }
            _ => Ok(false),
        }
    }

    /// Holds the recovery box at kit-only before a switch's write. A hold
    /// that answers `Err` may still have reached the box (a lost answer, a
    /// timeout), so the refusal first releases the box as
    /// [`Self::release_box_hold_on_failure`] does: once, best-effort, while
    /// the vault still reads `Standard`. The caller's box-hold-pending
    /// marker stays in every case, since a late hold can land after that
    /// release, and a managed boot resends the hold the preset needs
    /// (REVIEW2 #8799 P3-1). The answer is the hold's error.
    pub(super) fn hold_recovery_box_kit_only(&self, box_hold: &dyn RecoveryBoxHold) -> Result<()> {
        match box_hold.hold_kit_only(true) {
            Ok(()) => Ok(()),
            Err(error) => self.release_box_hold_on_failure(Err(error), true, None, box_hold),
        }
    }

    /// `result`, with the recovery box released first when it is an error
    /// and the door held the box for kit-only ([RECOVERY-BOX-HOLD-ORPHAN]).
    /// After `hold_kit_only(true)` answered, a failed switch (a refusal in
    /// the write, a failed commit) leaves the box holding kit-only while the
    /// vault stays as it was. So the box follows the stored preset again: a
    /// vault still on `Standard` sends `hold_kit_only(false)` once,
    /// best-effort. A vault already on kit-only (re-entering it, or turning
    /// "any 2 pieces" on) keeps the hold, and a preset that cannot be read
    /// sends nothing. After an `Ok` release the marker of `attempt` is cleared
    /// (a failure there is logged and never changes the answer); after an `Err`
    /// the marker stays, and a managed boot resends the hold. The answer stays
    /// the first error. `attempt` is `None` when no marker was written.
    pub(super) fn release_box_hold_on_failure<T>(
        &self,
        result: Result<T>,
        held_box: bool,
        attempt: Option<u64>,
        box_hold: &dyn RecoveryBoxHold,
    ) -> Result<T> {
        if result.is_err() && held_box {
            match self.recovery_preset() {
                Ok(RecoveryPreset::Standard) => match box_hold.hold_kit_only(false) {
                    Ok(()) => {
                        if let Some(attempt) = attempt {
                            if let Err(error) = self.clear_recovery_box_hold_pending(attempt) {
                                tracing::warn!(
                                    kind = ?error.kind(),
                                    "a recovery preset switch failed after the recovery box held kit-only; the box is released but clearing its marker did not go through"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            kind = ?error.kind(),
                            "a recovery preset switch failed after the recovery box held kit-only; its release did not go through"
                        );
                    }
                },
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    "a recovery preset switch failed after the recovery box held kit-only; the preset is unreadable, so the hold stays"
                ),
            }
        }
        result
    }
}
