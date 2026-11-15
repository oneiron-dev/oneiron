//! The recovery box's kit-only hold: the box's seam, its pending marker, and
//! the hold's release when the switch fails (pass 27 kit-only).

use super::*;

/// The recovery box's hold for kit-only (BOX-KIT-ONLY-HOLD = A): the engine
/// calls it through this trait, and OPUS-WAYBACK-BOX builds the HTTP
/// implementation on the server. Target kit-only calls `hold_kit_only(true)`
/// after the no-write checks pass and before the write txn opens; its error
/// refuses the switch with nothing written. Target `Standard` calls
/// `hold_kit_only(false)` after the commit; its failure answers
/// [`RecoveryPresetChange::box_release_pending`], never an error. A switch
/// refused before the hold makes no hold call; one that fails after it sends
/// `hold_kit_only(false)` once, best-effort, while the vault still reads
/// `Standard`, and answers the first error. The marker [`RecoveryBoxHoldPending`]
/// stays set, and a managed boot resends the hold.
pub trait RecoveryBoxHold {
    /// Holds kit-only (`true`) or releases it (`false`) on the recovery box.
    fn hold_kit_only(&self, kit_only: bool) -> Result<()>;
}

/// No recovery box: every hold answers `Ok`. The preset doors' callers pass
/// it until OPUS-WAYBACK-BOX wires the HTTP hold.
pub struct NoRecoveryBox;

impl RecoveryBoxHold for NoRecoveryBox {
    fn hold_kit_only(&self, _kit_only: bool) -> Result<()> {
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
