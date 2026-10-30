//! FIX 6108: the payload of an attempt still waiting to be claimed, replaced
//! in place by the door that rebinds the work it carries to a live
//! instrument. The row keeps its id, state, schedule, indexes and dedupe
//! entry; only its payload and `updated_at` move, and with them a Dreamer
//! row's run-tree parent entry when the new payload names another parent.

use super::AttemptQueue;
use super::telemetry::invalid_transition;
use super::types::{AttemptId, AttemptRecord, AttemptState};
use crate::error::Result;

/// The action a refused replacement names.
const REPLACE_ACTION: &str = "replace_waiting_payload";

impl AttemptQueue<'_> {
    /// Replaces, in the caller's writer, the payload of attempt `id`, of
    /// `kind`, while it waits to be claimed: queued, scheduled or paused,
    /// with no lease. A leased, settled, missing or other-kind row is
    /// refused as an invalid transition, and the caller aborts its writer.
    pub(crate) fn replace_waiting_payload_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: AttemptId,
        kind: &str,
        payload: Vec<u8>,
        now: u64,
    ) -> Result<AttemptRecord> {
        let Some(mut record) = self.get_in_txn(txn, id)? else {
            return Err(invalid_transition(REPLACE_ACTION, "missing"));
        };
        if record.kind != kind {
            return Err(invalid_transition(REPLACE_ACTION, "other_kind"));
        }
        if record.lease_owner.is_some()
            || !matches!(
                record.state,
                AttemptState::Queued | AttemptState::Scheduled | AttemptState::Paused
            )
        {
            return Err(invalid_transition(REPLACE_ACTION, record.state.as_str()));
        }
        let from = crate::run_tree::effective_parent(&record);
        record.payload = payload;
        record.updated_at = now;
        super::index::move_parent_child_in_txn(
            self.store,
            txn,
            record.id,
            from,
            crate::run_tree::effective_parent(&record),
        )?;
        let encoded = self.encode_in_txn(txn, &mut record)?;
        self.store
            .attempt_records
            .put(txn, record.id.as_bytes(), &encoded)?;
        Ok(record)
    }
}
