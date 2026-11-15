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

/// The result one child reads, as its parent's spawn resolved it: the
/// parent's occurrence of it (`owner` and `path`), its handle, the range of
/// its body the child may read, in the parent's offsets, and the rows the
/// parent's results were served from (`None` when one answer kept no set).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedSource {
    pub owner: EntityId,
    pub path: String,
    pub handle: String,
    pub range: (u64, u64),
    pub rows: Option<Vec<EntityId>>,
    /// The origins the delegating run's ledger held when it delegated the
    /// result (FIX 7084); `None` when they are unknown. A host's input has
    /// none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origins: Option<ResultOrigins>,
}

/// A child's finding: one of its own stored JSON results, by its occurrence
/// in the child run and its handle, its size, and the rows the child's
/// results were served from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderFindingRef {
    pub owner: EntityId,
    pub path: String,
    pub handle: String,
    pub bytes: u64,
    pub rows: Option<Vec<EntityId>>,
    /// The origins the child's ledger held when it reported the finding, or,
    /// for a summary, the union of its members' origins (FIX 7084); `None`
    /// when they are unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origins: Option<ResultOrigins>,
}

impl ReaderFindingRef {
    /// The exact child occurrence the parent reads, independent of shared bytes.
    pub(crate) fn reference(&self) -> Result<String> {
        let occurrence = crate::code_run::ResultOccurrence::owned(self.owner, &self.path)?;
        Ok(format!("occurrence:{}", occurrence.id().to_hex()))
    }

    /// Whether `other` reports the same result as this finding, its origins
    /// aside (FIX 7084): a report of it again is a replay, and the origins
    /// frozen at its first report stay with it.
    pub(crate) fn reports_same(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.path == other.path
            && self.handle == other.handle
            && self.bytes == other.bytes
            && self.rows == other.rows
    }
}

/// The origins of one run's results as its read-world ledger held them when
/// a descriptor of one of them was made (FIX 7084): every world a row served
/// to the run sat in, the scope of each served row whose every proof agrees,
/// and each served row whose proofs disagree. A row with no proof is in
/// neither. The union is conservative: it may hold more than the one result
/// used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultOrigins {
    pub worlds: BTreeSet<EntityId>,
    pub row_scopes: BTreeMap<EntityId, Scope>,
    /// The served rows whose proofs gave different scopes (FIX 7084): no
    /// scope of them is proved, whatever another proof says. A row here has
    /// no scope in `row_scopes`.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub conflicted_rows: BTreeSet<EntityId>,
}

impl ResultOrigins {
    /// The origins of a result made from `sources` alone: the union of
    /// theirs ([`OriginsUnion`]). `None` when the origins of any source are
    /// unknown, and when there is no source: no proof is made from nothing.
    pub(crate) fn of_sources(sources: &[DelegatedSource]) -> Option<Self> {
        if sources.is_empty() {
            return None;
        }
        let mut union = OriginsUnion::default();
        for source in sources {
            union.add(source.origins.as_ref()?);
        }
        Some(union.finish())
    }
}

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
