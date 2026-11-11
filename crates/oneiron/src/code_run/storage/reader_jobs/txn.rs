//! The common transaction and read door for one run's reader ledger.

use super::*;

impl ExecutorStorage<'_> {
    /// One transaction of the run's reader rows on its route: a canonical
    /// run's in one vault write transaction, a session-bound run's in its
    /// room's routed one, answered as its participant stands. Nothing the
    /// closure holds outlives the transaction, as the vault's grouped write
    /// door requires.
    pub(crate) fn reader_txn<T>(
        &self,
        f: impl FnOnce(&mut ReaderTxn<'_, '_>) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Canonical(vault) => {
                let vault: &Vault = vault;
                vault.with_write_txn_grouped(|txn| {
                    f(&mut ReaderTxn {
                        txn,
                        read: RoutedDbs::Base(vault),
                        write: RoutedDbs::Base(vault),
                        spend: SpendBook::new(vault),
                        staged: BTreeMap::new(),
                        vault: Some(vault),
                        settled: Vec::new(),
                    })
                })
            }
            Self::Session(binding) => {
                let spend = binding.session.spend_book();
                let (answer, settled) = binding.answered(|| {
                    binding
                        .session
                        .routed_reader_txn(&binding.route, |txn, read, write| {
                            let mut tx = ReaderTxn {
                                txn,
                                read,
                                write,
                                spend,
                                staged: BTreeMap::new(),
                                vault: None,
                                settled: Vec::new(),
                            };
                            let answer = f(&mut tx)?;
                            let keys = tx.staged.into_keys().collect();
                            Ok(((answer, tx.settled), keys))
                        })
                })?;
                for (wait, reply, origins, now_ms) in settled {
                    self.deliver_wait(wait, &reply, None, origins.as_ref(), now_ms)?;
                }
                Ok(answer)
            }
        }
    }

    /// One read of the run's reader rows through its route's view.
    pub(in crate::code_run::storage) fn reader_read<T>(
        &self,
        f: impl FnOnce(&RoTxn<'_>, RoutedDbs<'_>) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Canonical(vault) => {
                let txn = vault.store.env.read_txn()?;
                f(&txn, RoutedDbs::Base(vault))
            }
            Self::Session(binding) => binding.answered(|| binding.session.routed_side_read(f)),
        }
    }
}
