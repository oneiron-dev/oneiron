//! A running row's payload rewritten in place by the worker holding its
//! lease (FIX 9792): the one door through which a try records, in its own
//! payload, what its execution bound it to, without settling the row,
//! extending its lease or moving it in the queue.

use super::AttemptQueue;
use crate::attempt_queue::AttemptRecord;
use crate::attempt_queue::encoding::decode_record;
use crate::error::{Error, Result};

/// A replace naming a row that is gone, settled, resulted or changed since
/// it was read.
const ERR_LEASED_PAYLOAD_STALE: &str = "leased payload replace names a changed row";

impl AttemptQueue<'_> {
    /// Rewrites the payload of the running row `current` was read from, in
    /// the caller's write transaction, for the worker holding `lease_owner`
    /// at generation `attempt_count`, and returns the row as written. The
    /// row must still be running under that lease and generation, carry no
    /// result, and be the row `current` read: its kind, task, run, dedupe
    /// key, actor scope and payload unchanged. Anything else is refused and
    /// nothing is written.
    ///
    /// Only the payload changes. The id, state, placement, lease owner and
    /// generation, the claimed and updated instants (the lease-expiry clock
    /// reads `updated_at`), events and every index entry stay. The row goes
    /// through the queue's admitted encoder, which first removes an erased
    /// target's copies from it.
    pub(crate) fn replace_leased_payload_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        current: &AttemptRecord,
        lease_owner: &str,
        attempt_count: u32,
        payload: Vec<u8>,
    ) -> Result<AttemptRecord> {
        let id = current.id;
        let Some(raw) = self.store.attempt_records.get(wtxn, id.as_bytes())? else {
            return Err(Error::InvariantViolation(ERR_LEASED_PAYLOAD_STALE));
        };
        let mut record = decode_record(&raw, id)?;
        Self::check_result_lease(
            &record,
            lease_owner,
            attempt_count,
            "replace_leased_payload",
        )?;
        if record.result_ref.is_some()
            || record.kind != current.kind
            || record.task_ref != current.task_ref
            || record.run_id != current.run_id
            || record.dedupe_key != current.dedupe_key
            || record.dedupe_actor_ref != current.dedupe_actor_ref
            || record.payload != current.payload
        {
            return Err(Error::InvariantViolation(ERR_LEASED_PAYLOAD_STALE));
        }
        record.payload = payload;
        let encoded = self.encode_in_txn(wtxn, &mut record)?;
        self.store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &encoded)?;
        Ok(record)
    }
}
