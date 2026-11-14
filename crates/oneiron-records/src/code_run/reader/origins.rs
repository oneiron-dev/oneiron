//! Moved from `crates/oneiron/src/code_run/reader/origins.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::Scope;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::btree_map::Entry;

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
    pub fn reference(&self) -> Result<String> {
        let occurrence = store::result_manifest::ResultOccurrence::owned(self.owner, &self.path)?;
        Ok(format!("occurrence:{}", occurrence.id().to_hex()))
    }

    /// Whether `other` reports the same result as this finding, its origins
    /// aside (FIX 7084): a report of it again is a replay, and the origins
    /// frozen at its first report stay with it.
    pub fn reports_same(&self, other: &Self) -> bool {
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
    pub fn of_sources(sources: &[DelegatedSource]) -> Option<Self> {
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
