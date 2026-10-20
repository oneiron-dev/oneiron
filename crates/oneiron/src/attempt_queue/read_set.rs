//! FIX 6934: the rows an attempt's inputs were read from, recorded by the
//! host code that read them while the attempt runs and frozen onto its
//! terminal pack receipt. Capture only: nothing here admits, bounds or
//! refuses work.

use serde::{Deserialize, Serialize};

use super::{AttemptId, AttemptQueue, AttemptRecord, decode_record};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::skill_optimize::union_source_rows;

/// What an attempt's producers recorded of the rows its inputs were read
/// from. `rows` is the complete set, sorted and deduplicated; `Some([])`
/// when they read no vault row; `None`, unknown, once any producer recorded
/// an unknown set. An attempt no producer recorded keeps no read set at
/// all, which its receipt keeps as unknown too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptReadSet {
    pub rows: Option<Vec<EntityId>>,
}

impl AttemptRecord {
    /// The complete set of rows this attempt's producers recorded its inputs
    /// read from; `None`, unknown, when none recorded one or any recorded an
    /// unknown set.
    #[must_use]
    pub(crate) fn source_rows(&self) -> Option<&[EntityId]> {
        self.read_set.as_ref()?.rows.as_deref()
    }
}

impl AttemptQueue<'_> {
    /// Unions `rows` into the read set of live attempt `id`, in the caller's
    /// transaction. A second record unions with the first; an unknown set
    /// keeps the whole set unknown. `false` when no live attempt is `id`: a
    /// closed attempt's receipt is already minted, so nothing is recorded.
    pub(crate) fn record_attempt_sources_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        rows: Option<Vec<EntityId>>,
    ) -> Result<bool> {
        let Some(raw_record) = self.store.attempt_records.get(txn, id.as_bytes())? else {
            return Ok(false);
        };
        let mut record = decode_record(&raw_record, id)?;
        if !record.state.is_pending() {
            return Ok(false);
        }
        let rows = match record.read_set.take() {
            Some(held) => union_source_rows([held.rows, rows]),
            None => union_source_rows([rows]),
        };
        record.read_set = Some(AttemptReadSet { rows });
        let encoded = self.encode_in_txn(txn, &mut record)?;
        self.store
            .attempt_records
            .put(txn, record.id.as_bytes(), &encoded)?;
        Ok(true)
    }
}

impl Vault {
    /// Records the rows host code read attempt `attempt`'s inputs from
    /// (FIX 6934): the ids of the rows it actually read, never ids a caller
    /// named. Pass `None` when the set read is not known complete; it keeps
    /// the attempt's whole set unknown. `false` when no live attempt is
    /// `attempt`, and nothing is recorded.
    pub fn record_attempt_sources(
        &self,
        attempt: AttemptId,
        rows: Option<Vec<EntityId>>,
    ) -> Result<bool> {
        self.with_write_txn_grouped(|txn| {
            AttemptQueue::new(self).record_attempt_sources_in_txn(txn, attempt, rows)
        })
    }
}
