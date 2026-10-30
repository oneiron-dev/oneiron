//! The read-only half of the generic claim scan (FIX 11664): what a claim
//! would lease, repair and hold, read without taking the writer.

use crate::attempt_queue::encoding::{decode_ready_key, decode_record, ready_at, ready_key};
use crate::attempt_queue::types::{AttemptId, AttemptRecord};
use crate::error::Result;

use super::super::AttemptQueue;
use super::ClaimKindReadScan;

impl AttemptQueue<'_> {
    /// The scan of [`Self::claim_matching_in_txn`], read through `txn`: the
    /// index repairs and holds it makes up to the first row it leases, and
    /// that row with its ready key and id, not yet leased. Writes nothing, so a
    /// read transaction can tell an idle claim before any writer is taken.
    pub(super) fn claim_matching_scan_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        lease_owner: &str,
        kind_filter: Option<&str>,
        now: u64,
        cutoff: u64,
    ) -> Result<(
        ClaimKindReadScan,
        Option<(Vec<u8>, AttemptId, AttemptRecord)>,
    )> {
        let mut scan = ClaimKindReadScan::default();
        for row in self.store.attempt_ready.iter(txn)? {
            let (key, value) = row?;
            let Ok((key_ready_at, key_id)) = decode_ready_key(&key) else {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            let Ok(id) = AttemptId::from_bytes(&value) else {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            if id != key_id {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            }
            let Some(raw_record) = self.store.attempt_records.get(txn, id.as_bytes())? else {
                scan.stale_missing_record_ids.insert(id);
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            };
            let record = decode_record(&raw_record, id)?;
            if !record.state.is_ready_indexed() {
                scan.stale_ready_keys.push(key.to_vec());
                continue;
            }
            let record_ready_at = ready_at(&record);
            if record_ready_at != key_ready_at {
                scan.stale_ready_keys.push(key.to_vec());
                if record_ready_at > cutoff {
                    scan.ready_replacements
                        .push((ready_key(record_ready_at, id), id));
                    continue;
                }
            } else if record_ready_at > cutoff {
                continue;
            }
            if kind_filter.is_some_and(|kind| record.kind != kind)
                || !record.accepts_worker(lease_owner)
            {
                if record_ready_at != key_ready_at {
                    scan.ready_replacements
                        .push((ready_key(record_ready_at, id), id));
                }
                continue;
            }
            if !crate::task_verb::task_dispatch_ready(
                self.store,
                txn,
                record.task_ref.as_deref(),
                now,
            )? {
                continue;
            }
            // OF-368: a TASK whose comment is unattached is paused, not
            // leased, so no claim walks past it again until a reattach.
            if let Some(hold) = self.annotation_hold_for_row_in_txn(txn, &record)? {
                scan.held.push((id, hold));
                continue;
            }
            return Ok((scan, Some((key.to_vec(), id, record))));
        }
        Ok((scan, None))
    }
}
