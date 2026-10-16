//! One executor run's fold ledger (ARCH-0067 §2.2), where the run's rows are:
//! base, or its off-record room's overlay, through the route it captured at
//! entry. Node-local like the run's coverage rows: a fold is the run's own
//! view of its log, never a synced record.

use crate::code_run::ExecutorStorage;
use crate::compaction::FoldLedger;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::{EntityId, Error, Result};

/// One ledger per run, keyed by run id.
const FOLDS: SideTable<EntityId, FoldLedger, Raw> = SideTable::new(&side_table::CODE_RUN_FOLDS);

impl RawValue for FoldLedger {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        serde_json::to_vec(self).map_err(|_| Error::CorruptedIndex("code-run fold ledger").into())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        serde_json::from_slice(bytes)
            .map_err(|_| Error::CorruptedIndex("code-run fold ledger").into())
    }
}

impl ExecutorStorage<'_> {
    /// The run's fold ledger, empty before its first fold verb.
    pub(crate) fn code_run_folds(&self, run_id: EntityId) -> Result<FoldLedger> {
        let ledger = match self {
            Self::Canonical(vault) => {
                let txn = vault.store.env.read_txn()?;
                FOLDS.get(&vault.store, &txn, &run_id)?
            }
            Self::Session(binding) => {
                binding.answered(|| binding.session.side_table_get(&FOLDS, &run_id))?
            }
        };
        Ok(ledger.unwrap_or_default())
    }

    /// Reads the ledger, lets `change` edit it, and writes it back in one
    /// step: a ledger that moved between the read and the write refuses the
    /// write, and nothing commits.
    pub(crate) fn update_code_run_folds<T>(
        &self,
        run_id: EntityId,
        change: impl FnOnce(&mut FoldLedger) -> T,
    ) -> Result<T> {
        match self {
            Self::Canonical(vault) => {
                let mut txn = vault.store.env.write_txn()?;
                let mut ledger = FOLDS.get(&vault.store, &txn, &run_id)?.unwrap_or_default();
                let answer = change(&mut ledger);
                FOLDS.put(&vault.store, &mut txn, &run_id, &ledger)?;
                txn.commit()?;
                Ok(answer)
            }
            Self::Session(binding) => binding.answered(|| {
                let current = binding.session.side_table_get(&FOLDS, &run_id)?;
                let mut ledger = current.clone().unwrap_or_default();
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
}
