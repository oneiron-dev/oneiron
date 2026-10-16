//! One executor run's fold ledger (ARCH-0067 §2.2), where the run's rows are:
//! base, or its off-record room's overlay, through the route it captured at
//! entry. Node-local like the run's coverage rows: a fold is the run's own
//! view of its log, never a synced record. No read or write of it keeps the
//! words of a fold a withdrawn record reached (Docs Q23).

use crate::code_run::ExecutorStorage;
use crate::compaction::{
    FOLD_LEDGERS as FOLDS, FoldLedger, FoldRecord, fence_withdrawn_folds_in, land_folds_in_base,
    land_folds_in_overlay,
};
use crate::session_overlay::RouteTarget;
use crate::{EntityId, Error, Result};

impl ExecutorStorage<'_> {
    /// The run's fold ledger, empty before its first fold verb, without the
    /// words of any fold a withdrawn record reached.
    pub(crate) fn code_run_folds(&self, run_id: EntityId) -> Result<FoldLedger> {
        match self {
            Self::Canonical(vault) => {
                let txn = vault.store.env.read_txn()?;
                let mut ledger = FOLDS.get(&vault.store, &txn, &run_id)?.unwrap_or_default();
                fence_withdrawn_folds_in(&vault.store, &txn, run_id, &mut ledger)?;
                Ok(ledger)
            }
            Self::Session(binding) => binding.answered(|| {
                let view = binding.session.read_view()?;
                let txn = view.read().base().env.read_txn()?;
                let mut ledger = FOLDS.get(&view, &txn, &run_id)?.unwrap_or_default();
                fence_withdrawn_folds_in(&view, &txn, run_id, &mut ledger)?;
                Ok(ledger)
            }),
        }
    }

    /// Reads the ledger, lets `change` edit it, and writes it back in one
    /// step: a ledger that moved between the read and the write refuses the
    /// write, and nothing commits. The write drops the words of any fold a
    /// withdrawn record reached.
    pub(crate) fn update_code_run_folds<T>(
        &self,
        run_id: EntityId,
        change: impl FnOnce(&mut FoldLedger) -> T,
    ) -> Result<T> {
        match self {
            Self::Canonical(vault) => {
                let mut txn = vault.store.env.write_txn()?;
                let mut ledger = FOLDS.get(&vault.store, &txn, &run_id)?.unwrap_or_default();
                fence_withdrawn_folds_in(&vault.store, &txn, run_id, &mut ledger)?;
                let answer = change(&mut ledger);
                FOLDS.put(&vault.store, &mut txn, &run_id, &ledger)?;
                txn.commit()?;
                Ok(answer)
            }
            Self::Session(binding) => binding.answered(|| {
                let current = binding.session.side_table_get(&FOLDS, &run_id)?;
                let mut ledger = current.clone().unwrap_or_default();
                {
                    let view = binding.session.read_view()?;
                    let txn = view.read().base().env.read_txn()?;
                    fence_withdrawn_folds_in(&view, &txn, run_id, &mut ledger)?;
                }
                let answer = change(&mut ledger);
                binding.session.side_table_compare_and_put_routed(
                    &binding.route,
                    &FOLDS,
                    &run_id,
                    &ledger,
                    |stored| {
                        if stored == current.as_ref() {
                            Ok(())
                        } else {
                            Err(Error::InvariantViolation(
                                "the run's fold ledger moved under its write",
                            ))
                        }
                    },
                )?;
                Ok(answer)
            }),
        }
    }

    /// Lands one fold batch in one write: every accepted fold in `landed`
    /// becomes visible at once, and each failed mark keeps why. In base, a
    /// fold that keeps its words becomes a dependent of each of its sources,
    /// in the same transaction. A session-bound run lands on the route it
    /// captured at entry: in its room's overlay, or, for a room on record, in
    /// base under the room's saver, as its epoch summaries do.
    pub(crate) fn land_code_run_folds(
        &self,
        run_id: EntityId,
        landed: Vec<FoldRecord>,
        failed: &[(u64, String)],
    ) -> Result<()> {
        match self {
            Self::Canonical(vault) => vault.with_write_txn_grouped(|wtxn| {
                let mut ledger = FOLDS.get(&vault.store, wtxn, &run_id)?.unwrap_or_default();
                land_folds_in_base(&vault.store, wtxn, run_id, &mut ledger, landed, failed)?;
                FOLDS.put(&vault.store, wtxn, &run_id, &ledger)
            }),
            Self::Session(binding) => binding.answered(|| match binding.route.target() {
                RouteTarget::Overlay => {
                    binding
                        .session
                        .overlay_write_routed(&binding.route, |wtxn, _| {
                            let view = binding.session.read_view()?;
                            let mut ledger = FOLDS.get(&view, wtxn, &run_id)?.unwrap_or_default();
                            land_folds_in_overlay(&view, wtxn, &mut ledger, landed, failed)?;
                            FOLDS.put(&view, wtxn, &run_id, &ledger)
                        })
                }
                RouteTarget::Base | RouteTarget::Discard => binding
                    .session
                    .executor_land_base_epoch(&binding.route, |vault, landing| {
                        vault.with_write_txn_grouped(|wtxn| {
                            landing(wtxn)?;
                            // Composed: the run's ledger may still be the
                            // overlay row an earlier off-record run of the
                            // same room wrote.
                            let view = binding.session.read_view()?;
                            let mut ledger = FOLDS.get(&view, wtxn, &run_id)?.unwrap_or_default();
                            land_folds_in_base(
                                &vault.store,
                                wtxn,
                                run_id,
                                &mut ledger,
                                landed,
                                failed,
                            )?;
                            FOLDS.put(&vault.store, wtxn, &run_id, &ledger)
                        })
                    }),
            }),
        }
    }
}
