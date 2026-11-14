//! The descriptors by which one run's result is read in another run
//! (ARCH-0079 #reader-forks): the source a parent delegates to its child,
//! and the finding a child reports to its parent.
//!
//! Each descriptor carries the origins of its result (FIX 7084): the worlds,
//! the row scopes and the rows whose scopes conflicted that the read-world
//! ledger of the run that made it held when the descriptor was made, or
//! `None` when they are unknown. A later read of the result by another run
//! notes these frozen origins. It never reads the source run's ledger as it
//! stands then.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::federation::Scope;
use crate::{EntityId, Result};

#[doc(hidden)]
pub use oneiron_records::code_run::reader::origins::{
    DelegatedSource, ReaderFindingRef, ResultOrigins,
};

/// A union of origins while it is built (FIX 7084): every world added, and
/// each row's scope while every scope added for the row is the same. A row
/// added under two different scopes, or added as conflicted, has no scope,
/// whatever is added after, and the origins the union finishes as hold it
/// as conflicted.
#[derive(Debug, Default)]
pub(crate) struct OriginsUnion {
    worlds: BTreeSet<EntityId>,
    row_scopes: BTreeMap<EntityId, Scope>,
    conflicted: BTreeSet<EntityId>,
}

impl OriginsUnion {
    pub(crate) fn add_world(&mut self, world: EntityId) {
        self.worlds.insert(world);
    }

    /// Adds `scope` as one proof of the scope of `row`.
    pub(crate) fn add_row_scope(&mut self, row: EntityId, scope: &Scope) {
        if self.conflicted.contains(&row) {
            return;
        }
        match self.row_scopes.entry(row) {
            Entry::Vacant(slot) => {
                slot.insert(scope.clone());
            }
            Entry::Occupied(held) if held.get() != scope => {
                held.remove();
                self.conflicted.insert(row);
            }
            Entry::Occupied(_) => {}
        }
    }

    /// Adds `row` as conflicted: proofs of it gave different scopes, so it
    /// has no scope, whatever is added after.
    pub(crate) fn add_conflicted_row(&mut self, row: EntityId) {
        self.row_scopes.remove(&row);
        self.conflicted.insert(row);
    }

    /// Adds every world, row scope and conflicted row of `origins`.
    pub(crate) fn add(&mut self, origins: &ResultOrigins) {
        self.worlds.extend(origins.worlds.iter().copied());
        for row in &origins.conflicted_rows {
            self.add_conflicted_row(*row);
        }
        for (row, scope) in &origins.row_scopes {
            self.add_row_scope(*row, scope);
        }
    }

    /// The origins the union holds, its conflicted rows with them.
    pub(crate) fn finish(self) -> ResultOrigins {
        ResultOrigins {
            worlds: self.worlds,
            row_scopes: self.row_scopes,
            conflicted_rows: self.conflicted,
        }
    }
}
