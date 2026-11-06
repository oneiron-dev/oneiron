//! The descriptors by which one run's result is read in another run
//! (ARCH-0079 #reader-forks): the source a parent delegates to its child,
//! and the finding a child reports to its parent.

use serde::{Deserialize, Serialize};

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
}

impl ReaderFindingRef {
    /// The exact child occurrence the parent reads, independent of shared bytes.
    pub(crate) fn reference(&self) -> Result<String> {
        let occurrence = crate::code_run::ResultOccurrence::owned(self.owner, &self.path)?;
        Ok(format!("occurrence:{}", occurrence.id().to_hex()))
    }
}
