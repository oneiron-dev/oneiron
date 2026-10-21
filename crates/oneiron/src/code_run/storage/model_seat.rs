//! A run's model-seat pin on the route its run captured (FIX 2594): the
//! read and the write the seat birth makes of its pin row, so a session
//! run's pin, task hash, why and receipt stay in its room and go where its
//! room's other rows go. The rows and their codec are the seat's own
//! (`llm::seat`); this file only routes the transactions, through the
//! session's own transaction seam.

use heed::{RoTxn, RwTxn};

use super::ExecutorStorage;
use crate::side_table::RoutedDbs;
use crate::{Result, Vault};

impl ExecutorStorage<'_> {
    /// One read of the run's seat pin through its route's view: a canonical
    /// run's in the base vault, a session-bound run's over its room's
    /// overlay and base, answered as its participant stands.
    pub(crate) fn seat_pin_read<T>(
        &self,
        read: impl FnOnce(&RoTxn<'_>, RoutedDbs<'_>) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Canonical(vault) => {
                let vault: &Vault = vault;
                let txn = vault.store.env.read_txn()?;
                read(&txn, RoutedDbs::Base(vault))
            }
            Self::Session(binding) => binding.answered(|| binding.session.routed_side_read(read)),
        }
    }

    /// One write of the run's seat pin on its route: `write` reads through
    /// the first view and writes through the second. A session-bound run's
    /// writes its room's overlay while the room is off record, and base
    /// only while the room is on record and its saver holds; nothing it
    /// writes lands in base otherwise.
    pub(crate) fn seat_pin_write<T>(
        &self,
        write: impl FnOnce(&mut RwTxn<'_>, RoutedDbs<'_>, RoutedDbs<'_>) -> Result<T>,
    ) -> Result<T> {
        match self {
            Self::Canonical(vault) => {
                let vault: &Vault = vault;
                vault.with_write_txn_grouped(|txn| {
                    write(txn, RoutedDbs::Base(vault), RoutedDbs::Base(vault))
                })
            }
            Self::Session(binding) => {
                binding.answered(|| binding.session.routed_side_txn(&binding.route, write))
            }
        }
    }
}
