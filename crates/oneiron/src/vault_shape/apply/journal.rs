//! Every apply's journal: one row per apply, keyed by the frontier of the
//! plan it lands, written after each item so a torn apply resumes where it
//! stopped. Beside the receipt, the row keeps the rows that receipt stands
//! on (FIX 3411, 3513): what the first apply's re-plan read, the seed
//! revision it stored, and every live read and landing of each apply since.
//! A resumed apply lists them beside its own reads, never planning again.
use super::ShapeApplyReceipt;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::vault_shape::live::ShapeSources;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Every apply's journal, keyed by the frontier of the plan it lands.
const JOURNAL: SideTable<String, ShapeApplyJournal, Named> =
    SideTable::new(&side_table::VAULT_SHAPE_APPLY);

/// One apply's journal row: its receipt, as `vault.shape.apply` answers it,
/// and the rows that receipt stands on, which no answer carries.
#[derive(Serialize, Deserialize)]
struct ShapeApplyJournal {
    receipt: ShapeApplyReceipt,
    /// Every row the apply's reads and landings listed so far; `None` once
    /// one of them ran a read whose rows it does not follow.
    sources: Option<BTreeSet<EntityId>>,
}

/// Lists in `sources` the rows a journal stands on; a journal whose rows
/// are unknown leaves them unknown.
fn stand_on(sources: &mut ShapeSources, stored: Option<BTreeSet<EntityId>>) {
    match stored {
        Some(rows) => rows.into_iter().for_each(|id| sources.list(id)),
        None => sources.unknown(),
    }
}

impl Vault {
    /// The journal of the apply landing the plan at `frontier`.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub fn shape_apply(&self, frontier: &str) -> Result<Option<ShapeApplyReceipt>> {
        let txn = self.store.env.read_txn()?;
        Ok(JOURNAL
            .get(&self.store, &txn, &frontier.to_owned())?
            .map(|journal| journal.receipt))
    }

    /// Every apply with an item still pending or waiting for the owner.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub fn open_shape_applies(&self) -> Result<Vec<ShapeApplyReceipt>> {
        let txn = self.store.env.read_txn()?;
        Ok(JOURNAL
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, journal)| journal.receipt)
            .filter(|receipt| !receipt.done)
            .collect())
    }

    /// The journal of the apply landing the plan at `frontier`, listing in
    /// `sources` the rows it stands on, for an apply that resumes it.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub(super) fn resume_shape_apply(
        &self,
        frontier: &str,
        sources: &mut ShapeSources,
    ) -> Result<Option<ShapeApplyReceipt>> {
        let txn = self.store.env.read_txn()?;
        let Some(journal) = JOURNAL.get(&self.store, &txn, &frontier.to_owned())? else {
            return Ok(None);
        };
        stand_on(sources, journal.sources);
        Ok(Some(journal.receipt))
    }

    /// The rows the journal at `frontier` stands on, gathered for a landing
    /// that extends them.
    ///
    /// # Errors
    ///
    /// A read failure.
    pub(super) fn shape_apply_sources(&self, frontier: &str) -> Result<ShapeSources> {
        let txn = self.store.env.read_txn()?;
        let mut sources = ShapeSources::on();
        if let Some(journal) = JOURNAL.get(&self.store, &txn, &frontier.to_owned())? {
            stand_on(&mut sources, journal.sources);
        }
        Ok(sources)
    }

    /// Records `receipt`, and settles its run rows to match, in one writer.
    /// The rows the journal stands on stay as recorded.
    pub(in crate::vault_shape) fn put_shape_apply(
        &self,
        receipt: &ShapeApplyReceipt,
        now: u64,
    ) -> Result<()> {
        self.put_shape_apply_listing(receipt, &ShapeSources::on(), now)
    }

    /// [`Self::put_shape_apply`], adding the rows `sources` lists to those
    /// the journal stands on.
    pub(super) fn put_shape_apply_listing(
        &self,
        receipt: &ShapeApplyReceipt,
        sources: &ShapeSources,
        now: u64,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            self.put_shape_journal_in_txn(txn, receipt, sources)?;
            self.settle_shape_run_in_txn(txn, receipt, now)
        })
    }

    /// Writes `receipt` as its journal row in `txn`, standing on the rows
    /// the row already stood on and those `sources` lists. Once either is
    /// unknown, so are the row's.
    pub(super) fn put_shape_journal_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        receipt: &ShapeApplyReceipt,
        sources: &ShapeSources,
    ) -> Result<()> {
        let stored = JOURNAL.get(&self.store, txn, &receipt.frontier)?;
        let sources = match (stored, sources.listed()) {
            (None, listed) => listed.cloned(),
            (
                Some(ShapeApplyJournal {
                    sources: Some(mut rows),
                    ..
                }),
                Some(listed),
            ) => {
                rows.extend(listed.iter().copied());
                Some(rows)
            }
            (Some(_), _) => None,
        };
        let journal = ShapeApplyJournal {
            receipt: receipt.clone(),
            sources,
        };
        JOURNAL.put(&self.store, txn, &receipt.frontier, &journal)
    }
}
