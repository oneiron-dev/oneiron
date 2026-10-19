//! The training purge (TRAINING-LINK = C, TL-5, the engine half): before an
//! erase destroys the vault, every scope it ever used is purged at the
//! intake.
//!
//! The first call records the purge in one writer: one `purge_scope`
//! control per month the vault used, each riding that month's own scope at
//! its next ordinal and naming no other scope, so no control links two
//! months. From then on the offer pass prepares and releases nothing;
//! controls still spool and receipts still apply. The purge is done once the
//! intake's `removed` receipt for every one of its controls is in; the
//! writer that applies the last of them stages the training link key's
//! retirement, finished after it commits. A `rejected` receipt leaves it
//! pending. Nothing here has a time limit, and a vault that never used a
//! scope needs no purge and holds no key to retire.

use oneiron_vault_contract::conversation_training::TrainingReceiptStatusV2;
use oneiron_vault_contract::{
    TRAINING_PURGE_RECEIPT_PENDING, TRAINING_PURGE_REJECTED, TRAINING_PURGE_UNSENT,
    TrainingPurgeState, TrainingPurgeStateWire,
};

use crate::Vault;
use crate::error::{Error, Result};

use super::custody::{self, ControlChange, PurgeState};
use super::lifecycle::TrainingControlId;

impl Vault {
    /// TL-5's door, the supervisor's `training_purge`: records the purge on
    /// its first call and answers where it stands on every call. `done` once
    /// the intake's `removed` receipt for every purge control is in;
    /// `pending` until then, by name (`purge_rejected` while the intake
    /// rejected one, else `purge_unsent` while one is not yet written, else
    /// `receipt_pending`); `not_needed` for a vault that never used a scope.
    /// It never times out.
    ///
    /// # Errors
    /// Storage faults, and a purge control its state names that is gone.
    pub fn training_purge(&self) -> Result<TrainingPurgeStateWire> {
        let controls = self.record_training_purge()?;
        if controls.is_empty() {
            return Ok(TrainingPurgeStateWire {
                state: TrainingPurgeState::NotNeeded,
                reason: None,
            });
        }
        let txn = self.store.env.read_txn()?;
        let (mut rejected, mut unsent, mut done) = (false, false, true);
        for id in controls {
            let row = custody::control(self, &txn, id)?
                .ok_or(Error::CorruptedIndex("publisher training purge control"))?;
            let status = row.receipt.map(|mark| mark.status);
            rejected |= status == Some(TrainingReceiptStatusV2::Rejected);
            unsent |= !row.spooled;
            done &= status == Some(TrainingReceiptStatusV2::Removed);
        }
        if done {
            return Ok(TrainingPurgeStateWire {
                state: TrainingPurgeState::Done,
                reason: None,
            });
        }
        let reason = if rejected {
            TRAINING_PURGE_REJECTED
        } else if unsent {
            TRAINING_PURGE_UNSENT
        } else {
            TRAINING_PURGE_RECEIPT_PENDING
        };
        Ok(TrainingPurgeStateWire {
            state: TrainingPurgeState::Pending,
            reason: Some(reason.to_owned()),
        })
    }

    /// Records the purge (TL-5), idempotently, in one writer: the purge's
    /// controls when it is already recorded; otherwise one `purge_scope`
    /// control per month used, each riding that month's scope at its next
    /// ordinal, and the purge set over them, which stops every new offer. A
    /// vault that never used a scope sets the purge over no control: nothing
    /// is purged and no key retires, but no first offer starts before the
    /// destroy either.
    ///
    /// # Errors
    /// Storage faults.
    pub(crate) fn record_training_purge(&self) -> Result<Vec<TrainingControlId>> {
        let ids = |purge: &PurgeState| -> Vec<TrainingControlId> {
            purge
                .controls
                .iter()
                .copied()
                .map(TrainingControlId)
                .collect()
        };
        {
            let txn = self.store.env.read_txn()?;
            if let Some(purge) = custody::state(self, &txn)?.purge {
                return Ok(ids(&purge));
            }
        }
        self.with_write_txn_grouped(|txn| {
            let state = custody::state(self, txn)?;
            if let Some(purge) = state.purge {
                return Ok(ids(&purge));
            }
            let now = crate::unix_seconds_now();
            let mut controls = Vec::with_capacity(state.months.len());
            for month in state.months.keys() {
                let id =
                    custody::record_control_in(self, txn, month, ControlChange::PurgeScope, now)?;
                controls.push(id.0);
            }
            // Recording the controls moved the counters: read them again.
            let mut state = custody::state(self, txn)?;
            let purge = PurgeState {
                controls,
                recorded_at: now,
            };
            let recorded = ids(&purge);
            state.purge = Some(purge);
            custody::put_state_in(self, txn, &state)?;
            Ok(recorded)
        })
    }
}
