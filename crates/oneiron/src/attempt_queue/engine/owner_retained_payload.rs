//! An owner-retained row's payload rewritten in place (FIX 6755): the one
//! door through which an owner-retained kind's owner changes what a pending
//! row carries without minting a successor, so a tagging marker's class can
//! move while the row keeps its place in the queue.

use super::AttemptQueue;
use crate::attempt_queue::AttemptRecord;
use crate::attempt_queue::encoding::decode_record;
use crate::error::{Error, Result};

/// A replace naming a row that is gone, settled or changed since it was read.
const ERR_PAYLOAD_REPLACE_STALE: &str = "owner-retained payload replace names a changed row";

impl AttemptQueue<'_> {
    /// Rewrites the payload of the pending owner-retained row `current` was
    /// read from, in the caller's write transaction, and returns the row as
    /// written. The row must still be the one `current` read: in the
    /// owner-retained range, of an owner-retained kind, pending, and with
    /// its kind, dedupe key, actor scope and payload unchanged; anything else
    /// is refused and nothing is written.
    ///
    /// Everything else the row holds stays: its id, state, placement, lease
    /// owner and generation, its ready or scheduled instant, its retry link,
    /// and every index entry, none of which reads the payload. Only
    /// `updated_at` moves, to the job clock, and the row is put through the
    /// queue's admitted encoder.
    pub(crate) fn replace_owner_retained_payload_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        current: &AttemptRecord,
        payload: Vec<u8>,
    ) -> Result<AttemptRecord> {
        let id = current.id;
        let Some(raw) = self.store.attempt_records.get(wtxn, id.as_bytes())? else {
            return Err(Error::InvariantViolation(ERR_PAYLOAD_REPLACE_STALE));
        };
        let mut record = decode_record(&raw, id)?;
        if !crate::attempt_queue::owner_retained_kind(&record.kind)
            || !crate::attempt_queue::owner_retained_id(&record.id)
            || !record.state.is_pending()
            || record.kind != current.kind
            || record.dedupe_key != current.dedupe_key
            || record.dedupe_actor_ref != current.dedupe_actor_ref
            || record.payload != current.payload
        {
            return Err(Error::InvariantViolation(ERR_PAYLOAD_REPLACE_STALE));
        }
        record.payload = payload;
        record.updated_at = crate::ports::job_recorded_at_in_txn(self.store, wtxn)?;
        let encoded = self.encode_in_txn(wtxn, &mut record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        Ok(record)
    }
}
