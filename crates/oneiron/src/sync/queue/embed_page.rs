//! A resumable physical-row read for provider-independent vector catch-up.

use std::ops::Bound;

use super::{EMBED_PREFIX, QueuedEmbedJob, SyncQueue, codec};
use crate::{Error, Result};

pub(crate) struct EmbedQueueRow {
    pub(crate) key: Vec<u8>,
    pub(crate) job: Option<QueuedEmbedJob>,
}

impl SyncQueue {
    /// Reads one physical embed row after `after`, without leasing or removing
    /// anything. A malformed row still advances the caller's cursor.
    pub(crate) fn next_embed_job(&self, after: Option<&[u8]>) -> Result<Option<EmbedQueueRow>> {
        let txn = self.vault.store.env.read_txn()?;
        let lower = after.map_or(Bound::Included(EMBED_PREFIX), Bound::Excluded);
        let mut rows = self
            .vault
            .store
            .sync_queue
            .range(&txn, &(lower, Bound::Unbounded))?;
        let Some(row) = rows.next() else {
            return Ok(None);
        };
        let (key, value) = row?;
        if !key.starts_with(EMBED_PREFIX) {
            return Ok(None);
        }
        let job = match codec::decode_embed_job_row(&key, &value) {
            Ok(job) => Some(job),
            Err(Error::CorruptedIndex(_)) => None,
            Err(error) => return Err(error),
        };
        Ok(Some(EmbedQueueRow {
            key: key.to_vec(),
            job,
        }))
    }
}
