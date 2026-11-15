//! One adapter's checkpoint rows, declared once (UC-10): the side tables its
//! compartments hold, how a capture places their rows, the check a restored
//! part passes, and how a no-one-form part joins back. The shared capture,
//! `owns`, check, framing and restore iterate the row, so an adapter states
//! only what varies (its owner rule, its field split and join, its gates);
//! the skeleton every getter repeats today is here once.
//!
//! An adapter is a plain value in a static table, not a trait and not a
//! macro: its tables are `&'static dyn` [`AdapterTable`] rows, and each step
//! that varies is a fn pointer. A capture reads [`Store`], the one target
//! every checkpoint capture reads, so a fn pointer can name it.
//!
//! Nothing uses these yet: the adapters move onto them one family at a
//! time, each pinned to the bytes its own getter gives today.
#![allow(
    dead_code,
    reason = "UC-10 PRs 3-5 move the getters onto the descriptor; until then only the test door uses it"
)]

use heed::{RoTxn, RwTxn};

use super::{
    ActorPart, Captured, OpenedOwnerRows, OwnerRef, OwnerRows, Restored, RowLocator, TypedRow,
    bad_part, check_row, frame_owner, no_join, restore_parts, restore_parts_keyed, typed_rows,
};
use crate::error::{Error, Result};
use crate::side_table::{SideCodec, SideKey, SideTable, SideTableDecl};
use crate::store::{ManifestDbs, Store};

/// An adapter's own capture: it reads its tables with state one table's rows
/// hand the next (a set of snapshots, a map of dependencies).
pub(crate) type OwnCapture = fn(&Store, &RoTxn<'_>, &mut Captured) -> Result<()>;

/// An adapter's own check of a restored part, in place of its tables' codecs.
pub(crate) type OwnCheck = fn(&RowLocator, &[u8]) -> Result<()>;

/// The owner a row's own key names.
pub(crate) type RowOwner = fn(&RowLocator) -> Option<OwnerRef>;

/// A join that answers a no-one-form part's value with its opened actor
/// parts put back, or `None` when the family's no-one rule leaves it out.
pub(crate) type JoinRow =
    fn(&RoTxn<'_>, &RowLocator, &[u8], &[&ActorPart]) -> Result<Option<Vec<u8>>>;

/// A join that answers the row's own locator as well, for a part whose key
/// names an actor and whose locator does not ([`restore_parts_keyed`]).
pub(crate) type JoinKeyed =
    fn(&RoTxn<'_>, &RowLocator, &[u8], &[&ActorPart]) -> Result<Option<(RowLocator, Vec<u8>)>>;

/// One side table an adapter's compartments hold.
pub(crate) trait AdapterTable: Sync {
    /// The table's declaration: the database and key prefix of its rows.
    fn decl(&self) -> &'static SideTableDecl;

    /// Refuses `value` at `at` unless it is a row of this table its own
    /// codec reads.
    fn check(&self, at: &RowLocator, value: &[u8]) -> Result<()>;

    /// Places each of this table's rows in `out`, in key order.
    fn capture(&self, store: &Store, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()>;
}

/// A table each of whose rows `place` places alone: owned exact, split by
/// its actors, kept as structure or left unclassified. A row its codec does
/// not read is unclassified before `place` sees it ([`typed_rows`]).
pub(crate) struct PlacedTable<K, V, C> {
    pub(crate) table: SideTable<K, V, C>,
    pub(crate) place: fn(&mut Captured, TypedRow<K, V>) -> Result<()>,
}

impl<K: SideKey, V, C: SideCodec<V>> AdapterTable for PlacedTable<K, V, C> {
    fn decl(&self) -> &'static SideTableDecl {
        self.table.decl()
    }

    fn check(&self, at: &RowLocator, value: &[u8]) -> Result<()> {
        check_row(self.table, at, value)
    }

    fn capture(&self, store: &Store, txn: &RoTxn<'_>, out: &mut Captured) -> Result<()> {
        for row in typed_rows(store, txn, self.table, out)? {
            (self.place)(out, row)?;
        }
        Ok(())
    }
}

/// A table whose rows its adapter's own capture ([`Capture::Own`]) places;
/// the row still names it for `owns` and the check.
pub(crate) struct CapturedByAdapter<K, V, C>(pub(crate) SideTable<K, V, C>);

impl<K: SideKey, V, C: SideCodec<V>> AdapterTable for CapturedByAdapter<K, V, C> {
    fn decl(&self) -> &'static SideTableDecl {
        self.0.decl()
    }

    fn check(&self, at: &RowLocator, value: &[u8]) -> Result<()> {
        check_row(self.0, at, value)
    }

    fn capture(&self, _: &Store, _: &RoTxn<'_>, _: &mut Captured) -> Result<()> {
        Err(Error::InvariantViolation(
            "a table its adapter's own capture places sits in a by-table capture",
        ))
    }
}

/// How an adapter's capture reads its tables.
#[derive(Clone, Copy)]
pub(crate) enum Capture {
    /// Each listed table places its own rows, in the listed order.
    ByTable,
    /// The adapter's own capture reads them, with state shared between
    /// tables; its tables are [`CapturedByAdapter`] rows.
    Own(OwnCapture),
}

/// The check a restored part passes before the restore-only sink writes it.
#[derive(Clone, Copy)]
pub(crate) enum Check {
    /// The first listed table whose declaration names the part checks it
    /// with its codec; a part no listed table names refuses.
    ByTable,
    /// The adapter's own check, which may refuse what a codec reads (a value
    /// that must be empty).
    Own(OwnCheck),
}

/// How a restore joins an opened no-one-form part back.
#[derive(Clone, Copy)]
pub(crate) enum Join {
    /// The adapter splits no actor out, so a no-one-form part is not its
    /// own and refuses ([`no_join`]).
    NoSplit,
    /// The part's value, joined at its own locator.
    Row(JoinRow),
    /// The part's row, joined at the locator its join answers.
    Keyed(JoinKeyed),
}

/// One adapter's checkpoint rows.
pub(crate) struct Adapter {
    /// The tables its compartments hold, in capture order. A part belongs to
    /// the first listed table whose declaration names it.
    pub(crate) tables: &'static [&'static dyn AdapterTable],
    pub(crate) capture: Capture,
    pub(crate) check: Check,
    /// When set, a restored part must be a row of the compartment it opened
    /// from: the owner its own key names is that compartment's.
    pub(crate) row_owner: Option<RowOwner>,
    pub(crate) join: Join,
}

impl Adapter {
    /// Every row of this adapter's tables in `txn`, by owner.
    pub(crate) fn capture(&self, store: &Store, txn: &RoTxn<'_>) -> Result<Captured> {
        let mut out = Captured::default();
        self.capture_into(store, txn, &mut out)?;
        Ok(out)
    }

    /// [`Self::capture`] into `out`, for a parent adapter that holds this
    /// one's rows among its own.
    pub(crate) fn capture_into(
        &self,
        store: &Store,
        txn: &RoTxn<'_>,
        out: &mut Captured,
    ) -> Result<()> {
        match self.capture {
            Capture::ByTable => {
                for table in self.tables {
                    table.capture(store, txn, out)?;
                }
                Ok(())
            }
            Capture::Own(capture) => capture(store, txn, out),
        }
    }

    fn table_of(&self, at: &RowLocator) -> Option<&'static dyn AdapterTable> {
        self.tables
            .iter()
            .copied()
            .find(|table| at.in_table(table.decl()))
    }

    /// Whether a part at `at` is a row of one of this adapter's tables.
    pub(crate) fn owns(&self, at: &RowLocator) -> bool {
        self.table_of(at).is_some()
    }

    /// Refuses `value` at `at` unless this adapter's check reads it.
    pub(crate) fn check(&self, at: &RowLocator, value: &[u8]) -> Result<()> {
        match self.check {
            Check::ByTable => self.table_of(at).ok_or_else(bad_part)?.check(at, value),
            Check::Own(check) => check(at, value),
        }
    }

    /// The bundle framing of `rows`' parts in this adapter's tables.
    pub(crate) fn bytes_for_owner(&self, rows: &OwnerRows) -> Result<Vec<u8>> {
        frame_owner(rows, |at| self.owns(at))
    }

    /// Puts `opened`'s rows back through the restore-only sink: each part
    /// checked, each no-one-form part through this adapter's join.
    pub(crate) fn restore_in_txn(
        &self,
        dbs: &impl ManifestDbs,
        txn: &mut RwTxn<'_>,
        opened: OpenedOwnerRows,
    ) -> Result<Restored> {
        let owner = OwnerRef {
            subtype: opened.subtype,
            owner32: opened.owner32,
        };
        let check = |at: &RowLocator, value: &[u8]| self.check_restored(owner, at, value);
        match self.join {
            Join::NoSplit => restore_parts(dbs, txn, &opened, check, no_join),
            Join::Row(join) => restore_parts(dbs, txn, &opened, check, join),
            Join::Keyed(join) => restore_parts_keyed(dbs, txn, &opened, check, join),
        }
    }

    fn check_restored(&self, owner: OwnerRef, at: &RowLocator, value: &[u8]) -> Result<()> {
        self.check(at, value)?;
        match self.row_owner {
            Some(row_owner) if row_owner(at) != Some(owner) => Err(bad_part()),
            _ => Ok(()),
        }
    }
}
