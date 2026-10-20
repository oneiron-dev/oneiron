//! The training purge (TRAINING-LINK = C, TL-5, the engine half): before an
//! erase destroys the vault, every scope it ever used is purged at the
//! intake.
//!
//! The first call records the purge in one writer: one `purge_scope`
//! control per (month, link generation) the vault used that holds a hosted
//! submission (or none at all), each riding that pair's own scope at its
//! next ordinal and naming no other scope, so no control links two months.
//! An anonymous-only scope (TL-6) records none: its pieces are purged by
//! their C. A generation whose key a restore lost (FIX 5892) is purged as
//! any other: the control carries no code. From then on the offer pass
//! prepares and releases nothing; controls still spool and receipts still
//! apply. The same writer sets the withdrawal intent of every anonymous
//! piece of every scope and generation, held, withheld and never-published
//! ones included: their C is stored, so none needs a key.
//!
//! The purge is done by one predicate ([`purge_progress`], CALLS
//! TL6_PURGE_PREDICATE), which the spool, the key's retirement rule and
//! `training_purge` all read, over every row, never one page: every purge
//! control needs the intake's `removed` receipt, and every anonymous piece
//! its own signed `removed`. An anonymous-only vault waits on no V2 control
//! receipt; a mixed history needs both. `unknown`, `rejected` and a piece
//! never answered are pending. The writer that makes it hold (a V2
//! receipt's, a piece receipt's, or the purge's own when every anonymous
//! piece was removed before it) stages the training link key's retirement,
//! finished after it commits. A `rejected` receipt leaves it pending.
//! Nothing here has a time limit, and a vault that never used a scope needs
//! no purge and holds no key to retire.

use std::collections::BTreeSet;

use oneiron_vault_contract::conversation_training::TrainingReceiptStatusV2;
use oneiron_vault_contract::{
    TRAINING_PURGE_RECEIPT_PENDING, TRAINING_PURGE_REJECTED, TRAINING_PURGE_UNSENT,
    TrainingPurgeState, TrainingPurgeStateWire,
};

use crate::Vault;
use crate::error::{Error, Result};

use super::anonymous::{TrainingPieceState, TrainingTransport};
use super::custody::{self, ControlChange, PurgeState, SUBMISSION, SUBMISSIONS};
use super::lifecycle::TrainingControlId;

/// Where a recorded purge stands, by its one predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PurgeProgress {
    /// Done: every purge control has its `removed` receipt, and every
    /// anonymous piece its signed `removed`.
    pub(super) done: bool,
    /// The intake rejected a purge control.
    rejected: bool,
    /// A purge control is not yet written, or an anonymous piece holds no
    /// signed receipt yet.
    unsent: bool,
    /// A purge control the state names is gone: damaged custody.
    missing: bool,
}

/// CALLS TL6_PURGE_PREDICATE, the purge's one predicate (TL-5, TL-6): where
/// it stands over every submission and every purge control, read whole in
/// `txn`; `None` while no purge is recorded. Every purge control (one per
/// scope holding a hosted submission) needs its `removed`; every anonymous
/// piece needs its own signed `removed`, and `unknown`, `rejected` or no
/// answer yet leave it pending.
///
/// # Errors
/// Storage faults.
pub(super) fn purge_progress(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<PurgeProgress>> {
    let Some(purge) = custody::state(vault, txn)?.purge else {
        return Ok(None);
    };
    let mut progress = PurgeProgress {
        done: true,
        rejected: false,
        unsent: false,
        missing: false,
    };
    for row in SUBMISSIONS.iter_from(&vault.store, txn, &SUBMISSION)? {
        let (_, row) = row?;
        if row.transport == TrainingTransport::Anonymous
            && row.anonymous.state != Some(TrainingPieceState::Removed)
        {
            progress.done = false;
            progress.unsent |= row.anonymous.state.is_none();
        }
    }
    for id in purge.controls {
        let Some(row) = custody::control(vault, txn, TrainingControlId(id))? else {
            progress.done = false;
            progress.missing = true;
            continue;
        };
        let status = row.receipt.map(|mark| mark.status);
        progress.rejected |= status == Some(TrainingReceiptStatusV2::Rejected);
        progress.unsent |= !row.spooled;
        progress.done &= status == Some(TrainingReceiptStatusV2::Removed);
    }
    Ok(Some(progress))
}

/// The (month, generation) scopes that hold anonymous pieces and no hosted
/// submission (TL-6): the purge records no control for them, since their
/// pieces are purged by their C.
fn anonymous_only_scopes(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<BTreeSet<(String, u32)>> {
    let mut hosted = BTreeSet::new();
    let mut anonymous = BTreeSet::new();
    for row in SUBMISSIONS.iter_from(&vault.store, txn, &SUBMISSION)? {
        let (_, row) = row?;
        let scope = (row.month, row.generation);
        match row.transport {
            TrainingTransport::Hosted => {
                hosted.insert(scope);
            }
            TrainingTransport::Anonymous => {
                anonymous.insert(scope);
            }
        }
    }
    anonymous.retain(|scope| !hosted.contains(scope));
    Ok(anonymous)
}

impl Vault {
    /// TL-5's door, the supervisor's `training_purge`: records the purge on
    /// its first call and answers where it stands on every call. `done` once
    /// the purge's one predicate holds ([`purge_progress`]): every purge
    /// control has its `removed` receipt, and every anonymous piece its
    /// signed `removed`; `pending` until then, by name (`purge_rejected`
    /// while the intake rejected a purge control, else `purge_unsent` while
    /// one is not yet written or a piece holds no signed receipt, else
    /// `receipt_pending`); `not_needed` for a vault that never used a scope.
    /// An anonymous-only vault has no purge control, so its pieces alone
    /// answer. It never times out.
    ///
    /// # Errors
    /// Storage faults, and a purge control its state names that is gone.
    pub fn training_purge(&self) -> Result<TrainingPurgeStateWire> {
        self.record_training_purge()?;
        let (used, progress) = {
            let txn = self.store.env.read_txn()?;
            let used = !custody::state(self, &txn)?.months.is_empty();
            (used, purge_progress(self, &txn)?)
        };
        if !used {
            return Ok(TrainingPurgeStateWire {
                state: TrainingPurgeState::NotNeeded,
                reason: None,
            });
        }
        let progress = progress.ok_or(Error::InvariantViolation(
            "a recorded training purge reads as none",
        ))?;
        if progress.missing {
            return Err(Error::CorruptedIndex("publisher training purge control"));
        }
        if progress.done {
            return Ok(TrainingPurgeStateWire {
                state: TrainingPurgeState::Done,
                reason: None,
            });
        }
        let reason = if progress.rejected {
            TRAINING_PURGE_REJECTED
        } else if progress.unsent {
            TRAINING_PURGE_UNSENT
        } else {
            TRAINING_PURGE_RECEIPT_PENDING
        };
        Ok(TrainingPurgeStateWire {
            state: TrainingPurgeState::Pending,
            reason: Some(reason.to_owned()),
        })
    }

    /// Records the purge (TL-5), idempotently, in one writer, unless it is
    /// recorded already: one `purge_scope` control per month used that holds
    /// a hosted submission (or none at all), each riding that month's scope
    /// at its next ordinal, and the purge set over them, which stops every
    /// new offer; and every anonymous piece's withdrawal intent (TL-6), whose
    /// anonymous-only scope records no control. When every anonymous piece
    /// was removed before the erase and no control is pending, the purge
    /// holds as it is recorded, and this writer stages the training link
    /// key's retirement, finished after it commits. A vault that never used
    /// a scope sets the purge over no control: nothing is purged and no key
    /// retires, but no first offer starts before the destroy either.
    ///
    /// # Errors
    /// Storage faults.
    pub(crate) fn record_training_purge(&self) -> Result<()> {
        {
            let txn = self.store.env.read_txn()?;
            if custody::state(self, &txn)?.purge.is_some() {
                return Ok(());
            }
        }
        let staged = self.with_write_txn_grouped(|txn| {
            let state = custody::state(self, txn)?;
            if state.purge.is_some() {
                return Ok(false);
            }
            let now = crate::unix_seconds_now();
            let anonymous_only = anonymous_only_scopes(self, txn)?;
            let mut controls = Vec::with_capacity(state.months.len());
            // Every (month, generation) the vault used, orphaned ones too: a
            // purge carries no code, so a lost key never stops it. An
            // anonymous-only scope records none: its pieces go by their C.
            for entry in &state.months {
                if anonymous_only.contains(&(entry.month.clone(), entry.generation)) {
                    continue;
                }
                let pair = (entry.month.as_str(), entry.generation);
                let id =
                    custody::record_control_in(self, txn, pair, ControlChange::PurgeScope, now)?
                        .ok_or(Error::InvariantViolation(
                            "a training purge control was not recorded",
                        ))?;
                controls.push(id.0);
            }
            // Recording the controls moved the counters: read them again.
            let mut state = custody::state(self, txn)?;
            state.purge = Some(PurgeState {
                controls,
                recorded_at: now,
            });
            custody::put_state_in(self, txn, &state)?;
            // TL-6: every anonymous piece of every scope and generation is
            // withdrawn under its stored C, which needs no key.
            for (id, mut row) in custody::submissions(self, txn)? {
                if row.transport == TrainingTransport::Anonymous && !row.anonymous.withdraw {
                    row.anonymous.withdraw = true;
                    custody::put_submission_in(self, txn, id, &row)?;
                }
            }
            // Every anonymous piece removed already and no control pending:
            // the purge holds now, and the key may retire after this commit.
            if state.months.is_empty() || !custody::purge_removed(self, txn)? {
                return Ok(false);
            }
            self.store
                .stage_training_link_retirement_in_txn(txn, state.link_generation)?;
            Ok(true)
        })?;
        if staged {
            self.finish_training_link_retirement_after_commit();
        }
        Ok(())
    }
}
