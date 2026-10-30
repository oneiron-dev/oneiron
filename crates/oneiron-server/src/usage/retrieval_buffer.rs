//! The recall doors' retrieval-meter rows, buffered in memory and written in
//! one grouped write per flush (FIX 11011).
//!
//! A recall answers from reads alone: pushing its row takes only the buffer's
//! lock and never touches the vault, so metering adds no write txn to the call.
//! A worker writes what is buffered every [`RETRIEVAL_FLUSH_SECS`], and serve's
//! stop writes the rest; an empty buffer takes no write.
//!
//! The buffer is capped at [`RETRIEVAL_BUFFER_ROWS`]: past it a push drops the
//! oldest row and counts it, per its owner and vault, so a stalled flush bounds
//! memory instead of growing it. A flush that fails puts its batch back at the
//! front, still under the cap, so a write that fails loses nothing by itself.
//!
//! A crash loses at most one tick of rows: the rows still buffered, and the
//! drop counts with them, never reach the vault. The ledger undercounts by
//! them, and by the dropped counts it did write; it never overcharges.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use super::ledger::UsageLedger;
use super::meters::MeterRow;

/// Rows the buffer holds before a flush writes them: past it a push drops the
/// oldest row and counts it, so the buffer never grows past this.
pub const RETRIEVAL_BUFFER_ROWS: usize = 65_536;

/// Seconds between retrieval-meter flushes.
pub const RETRIEVAL_FLUSH_SECS: u64 = 5;

/// What one flush takes from the buffer: the pending rows, oldest first, and
/// the rows dropped since the last take, counted per owner and vault.
#[derive(Debug, Default)]
pub struct RetrievalMeterBatch {
    pub rows: Vec<MeterRow>,
    pub dropped: Vec<(String, String, u64)>,
}

impl RetrievalMeterBatch {
    /// Whether the batch holds nothing: flushing it takes no write.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.dropped.is_empty()
    }
}

/// The pending rows and the drop counts, under the buffer's one lock.
#[derive(Debug, Default)]
struct Pending {
    rows: VecDeque<MeterRow>,
    dropped: BTreeMap<(String, String), u64>,
}

/// Recall's retrieval meter rows, buffered in memory and written in one grouped write per flush.
pub struct RetrievalMeterBuffer {
    pending: Mutex<Pending>,
    flusher_started: AtomicBool,
    ledger: UsageLedger,
}

impl RetrievalMeterBuffer {
    /// `ledger` is where flushes write: the server's own usage ledger.
    pub fn new(ledger: UsageLedger) -> Self {
        Self {
            pending: Mutex::default(),
            flusher_started: AtomicBool::new(false),
            ledger,
        }
    }

    /// Buffers one retrieval row. Takes only the buffer's lock and never
    /// touches the vault, so a recall never waits on a write. At the cap the
    /// oldest row drops and is counted, under its owner and vault.
    pub fn push(&self, row: MeterRow) {
        let mut pending = lock(&self.pending);
        if pending.rows.len() >= RETRIEVAL_BUFFER_ROWS
            && let Some(oldest) = pending.rows.pop_front()
        {
            count_dropped(&mut pending.dropped, &oldest.owner, &oldest.vault_id, 1);
        }
        pending.rows.push_back(row);
    }

    /// Empties the buffer: the pending rows, oldest first, and the drop counts since the last take.
    pub fn take(&self) -> RetrievalMeterBatch {
        let mut pending = lock(&self.pending);
        let rows: VecDeque<MeterRow> = std::mem::take(&mut pending.rows);
        let dropped: BTreeMap<(String, String), u64> = std::mem::take(&mut pending.dropped);
        RetrievalMeterBatch {
            rows: rows.into_iter().collect(),
            dropped: dropped
                .into_iter()
                .map(|((owner, vault_id), count)| (owner, vault_id, count))
                .collect(),
        }
    }

    /// Puts a failed flush's batch back at the front, oldest first, still under
    /// the cap: its counts join the counts, and rows that no longer fit count
    /// as dropped, oldest first. A write that fails loses nothing by itself.
    pub fn put_back(&self, batch: RetrievalMeterBatch) {
        let mut pending = lock(&self.pending);
        for (owner, vault_id, count) in batch.dropped {
            count_dropped(&mut pending.dropped, &owner, &vault_id, count);
        }
        if batch.rows.is_empty() {
            return;
        }
        let mut rows: VecDeque<MeterRow> = batch.rows.into_iter().collect();
        rows.append(&mut pending.rows);
        while rows.len() > RETRIEVAL_BUFFER_ROWS {
            if let Some(oldest) = rows.pop_front() {
                count_dropped(&mut pending.dropped, &oldest.owner, &oldest.vault_id, 1);
            }
        }
        pending.rows = rows;
    }

    /// Writes what is buffered in one grouped write; an empty buffer takes no
    /// write. On failure the batch goes back for the next flush.
    pub(crate) fn flush(&self) {
        let batch = self.take();
        if batch.is_empty() {
            return;
        }
        if let Err(error) =
            self.ledger
                .record_meters(&batch.rows, &batch.dropped, super::keys::now_secs())
        {
            self.put_back(batch);
            tracing::warn!(
                ?error,
                "a retrieval meter flush failed; its rows stay buffered for the next one"
            );
        }
    }

    /// Claims the flush worker start: true once, for the caller that starts it.
    pub(crate) fn claim_flusher(&self) -> bool {
        !self.flusher_started.swap(true, Ordering::AcqRel)
    }
}

impl Drop for RetrievalMeterBuffer {
    /// Serve's stop flush: what the periodic worker has not written goes in one
    /// grouped write, while the ledger's vault is still open.
    fn drop(&mut self) {
        self.flush();
    }
}

fn lock(pending: &Mutex<Pending>) -> std::sync::MutexGuard<'_, Pending> {
    pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn count_dropped(
    dropped: &mut BTreeMap<(String, String), u64>,
    owner: &str,
    vault_id: &str,
    count: u64,
) {
    dropped
        .entry((owner.to_owned(), vault_id.to_owned()))
        .and_modify(|held| *held = held.saturating_add(count))
        .or_insert(count);
}
