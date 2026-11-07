//! One executor run's fold ledger (ARCH-0067 §2.2), where the run's rows are:
//! base, or its off-record room's overlay, through the route it captured at
//! entry. Node-local like the run's coverage rows: a fold is the run's own
//! view of its log, never a synced record. No read or write of it keeps the
//! words of a fold a withdrawn record reached (Docs Q23). A continuation's
//! child begins with its source's ledger at the cut, landed again as its own
//! (FIX 4198, [`seed_code_run_folds_in_txn`]).

use crate::code_run::ExecutorStorage;
use crate::compaction::{
    FOLD_LEDGERS as FOLDS, FoldLedger, FoldRecord, fence_withdrawn_folds_in, land_folds_in_base,
    land_folds_in_overlay,
};
use crate::session_overlay::RouteTarget;
use crate::store::Store;
use crate::{EntityId, Error, Result};

impl ExecutorStorage<'_> {
    /// The run's fold ledger, empty before its first fold verb, without the
    /// words of any fold a withdrawn record reached.
    pub(crate) fn code_run_folds(&self, run_id: EntityId) -> Result<FoldLedger> {
        match self {
            Self::Canonical(vault) => {
                let txn = vault.store.env.read_txn()?;
                base_code_run_folds_in_txn(&vault.store, &txn, run_id)
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
    /// in the same transaction, and a self-written one declares its Dreamer
    /// check there too (FIX 4465 B). A session-bound run lands on the route
    /// it captured at entry: in its room's overlay, or, for a room on record,
    /// in base under the room's saver, as its epoch summaries do. A room's
    /// overlay fold declares no check: nothing of the room reaches base.
    /// Returns each fold the write committed, in landing order (FIX 17594):
    /// a fold the ledger already held is no new one.
    pub(crate) fn land_code_run_folds(
        &self,
        run_id: EntityId,
        landed: Vec<FoldRecord>,
        failed: &[(u64, String)],
    ) -> Result<Vec<u64>> {
        match self {
            Self::Canonical(vault) => vault.with_write_txn_grouped(|wtxn| {
                let mut ledger = FOLDS.get(&vault.store, wtxn, &run_id)?.unwrap_or_default();
                let before = ledger.folds.len();
                let checked = self_written(&ledger, &landed);
                land_folds_in_base(&vault.store, wtxn, run_id, &mut ledger, landed, failed)?;
                declare_fold_checks_in_txn(vault, wtxn, &ledger, &checked)?;
                FOLDS.put(&vault.store, wtxn, &run_id, &ledger)?;
                Ok(committed_folds(&ledger, before))
            }),
            Self::Session(binding) => binding.answered(|| match binding.route.target() {
                RouteTarget::Overlay => {
                    binding
                        .session
                        .overlay_write_routed(&binding.route, |wtxn, _| {
                            let view = binding.session.read_view()?;
                            let mut ledger = FOLDS.get(&view, wtxn, &run_id)?.unwrap_or_default();
                            let before = ledger.folds.len();
                            land_folds_in_overlay(&view, wtxn, &mut ledger, landed, failed)?;
                            FOLDS.put(&view, wtxn, &run_id, &ledger)?;
                            Ok(committed_folds(&ledger, before))
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
                            let before = ledger.folds.len();
                            let checked = self_written(&ledger, &landed);
                            land_folds_in_base(
                                &vault.store,
                                wtxn,
                                run_id,
                                &mut ledger,
                                landed,
                                failed,
                            )?;
                            declare_fold_checks_in_txn(vault, wtxn, &ledger, &checked)?;
                            FOLDS.put(&vault.store, wtxn, &run_id, &ledger)?;
                            Ok(committed_folds(&ledger, before))
                        })
                    }),
            }),
        }
    }
}

/// `run_id`'s base ledger as `txn` holds it, empty before its first fold
/// verb, without the words of any fold a withdrawn record reached.
pub(super) fn base_code_run_folds_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    run_id: EntityId,
) -> Result<FoldLedger> {
    let mut ledger = FOLDS.get(store, txn, &run_id)?.unwrap_or_default();
    fence_withdrawn_folds_in(store, txn, run_id, &mut ledger)?;
    Ok(ledger)
}

/// Seeds `child`'s base ledger, a continuation's, from `inherited`, its
/// source `source`'s ledger at the cut, in `txn` (FIX 4198). Handles,
/// `last`, marks, unfolds and the compact ask stay as they stood. Each fold
/// lands again through [`land_folds_in_base`]: one that keeps its words
/// becomes a dependent of each of its sources as `child`'s fold. Words a
/// withdrawn record reached, at the source or since, stay withdrawn. No
/// Dreamer check is declared: an inherited fold carries no receipt. A
/// ledger `child` holds already refuses, so the seed never writes over the
/// child's own folds.
pub(super) fn seed_code_run_folds_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    source: EntityId,
    child: EntityId,
    mut inherited: FoldLedger,
) -> Result<()> {
    if FOLDS.contains(store, txn, &child)? {
        return Err(Error::ConcurrentWrite("code-run continuation fold seed"));
    }
    fence_withdrawn_folds_in(store, txn, source, &mut inherited)?;
    let folds = std::mem::take(&mut inherited.folds);
    land_folds_in_base(store, txn, child, &mut inherited, folds, &[])?;
    if inherited == FoldLedger::default() {
        return Ok(());
    }
    FOLDS.put(store, txn, &child, &inherited)
}

/// The folds a landing added to `ledger` past its first `before`: what the
/// write committed, in landing order. [`FoldLedger::land`] only appends.
fn committed_folds(ledger: &FoldLedger, before: usize) -> Vec<u64> {
    ledger
        .folds
        .iter()
        .skip(before)
        .map(|record| record.fold)
        .collect()
}

/// The folds of `landed` this write adds that a self writer wrote.
fn self_written(ledger: &FoldLedger, landed: &[FoldRecord]) -> Vec<u64> {
    landed
        .iter()
        .filter(|record| record.execution.is_some() && ledger.fold(record.fold).is_none())
        .map(|record| record.fold)
        .collect()
}

/// Declares the Dreamer check of each of `folds` that landed with its words,
/// in the landing's own write under a key the fold fixes (FIX 4465 B).
fn declare_fold_checks_in_txn(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    ledger: &FoldLedger,
    folds: &[u64],
) -> Result<()> {
    for fold in folds {
        let Some(record) = ledger.fold(*fold) else {
            continue;
        };
        if let (Some(execution), Some(_)) = (&record.execution, &record.summary) {
            crate::dreamer_runner::maintenance::declare_compaction_check_in_txn(
                vault,
                wtxn,
                crate::compaction::CompactionLanding::Fold { fold: *fold },
                execution,
            )?;
        }
    }
    Ok(())
}
