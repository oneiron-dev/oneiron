//! A fresh row held to its own due instant (FIX 5957): the readiness a
//! retry's backoff gives the try it mints, given at enqueue to work whose
//! payload names when it is due.

use super::AttemptQueue;
use crate::attempt_queue::encoding::{ready_key, waiting_on_backoff};
use crate::attempt_queue::{AttemptRecord, AttemptState};
use crate::error::Result;

impl AttemptQueue<'_> {
    /// Holds `record`, a row this transaction just enqueued, until `due`: it
    /// waits [`AttemptState::Scheduled`] at that instant, so every claim (the
    /// oldest ready, by kind, by id) passes it over until the claim's clock
    /// reaches `due`, as it does a retry's backoff. Nothing is dropped or
    /// refused: a row that is not `Queued`, already waits on an instant, or is
    /// due by its own creation comes back as it was.
    pub(crate) fn defer_enqueued_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        mut record: AttemptRecord,
        due: u64,
    ) -> Result<AttemptRecord> {
        if record.state != AttemptState::Queued
            || waiting_on_backoff(&record)
            || due <= record.created_at
        {
            return Ok(record);
        }
        self.delete_ready_entry_for_record(txn, &record)?;
        record.state = AttemptState::Scheduled;
        record.scheduled_at = Some(due);
        let encoded = self.encode_in_txn(txn, &mut record)?;
        self.store
            .attempt_records
            .put(txn, record.id.as_bytes(), &encoded)?;
        self.store
            .attempt_ready
            .put(txn, &ready_key(due, record.id), record.id.as_bytes())?;
        Ok(record)
    }
}
