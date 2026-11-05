//! Retry custody for automatic settlements whose durable staging failed.
use std::collections::VecDeque;
use std::mem::size_of;

use crate::byte_line::{ByteLine, HeldBytes};
use crate::usage::{UnpricedReason, UsageError};
use crate::wire_telemetry::LimitQuestions;

use super::VaultUsage;

/// A work quantum, not a queue limit: every retained payload keeps its place.
const SETTLEMENT_RETRY_ROWS: usize = 128;

pub(super) struct PendingSettlements {
    // Payload and deque allocations drop before their charge.
    rows: VecDeque<Vec<u8>>,
    payload_bytes: usize,
    held: HeldBytes,
}

impl PendingSettlements {
    pub(super) fn new(line: &ByteLine) -> Self {
        Self {
            rows: VecDeque::new(),
            payload_bytes: 0,
            held: line.empty(),
        }
    }

    fn charge(&mut self, line: &ByteLine, questions: &LimitQuestions) {
        let bytes = self
            .payload_bytes
            .saturating_add(self.rows.capacity().saturating_mul(size_of::<Vec<u8>>()));
        // These facts have already happened. The existing retained line charges
        // already-made state without a new wait, refusal or eviction (FIX 5991).
        line.charge(&mut self.held, bytes, questions);
    }

    fn push(&mut self, raw: Vec<u8>, line: &ByteLine, questions: &LimitQuestions) {
        self.payload_bytes = self.payload_bytes.saturating_add(raw.capacity());
        self.rows.push_back(raw);
        self.charge(line, questions);
    }
}

impl VaultUsage {
    pub(super) fn record_settlement(&self, raw: Vec<u8>, idempotency_key: &str) {
        match self.try_settlement(&raw) {
            Ok(()) => {}
            Err(UsageError::IdempotencyConflict) => {
                tracing::warn!(vault_id = %self.vault_id, %idempotency_key,
                    "settled usage conflicts with the first payload; the first stands");
            }
            Err(error) => {
                self.pending_settlements
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(raw, &self.retained, &self.questions);
                tracing::error!(vault_id = %self.vault_id, %idempotency_key, ?error,
                    "served usage is retained in memory for retry, NOT durable: pending staging failed");
            }
        }
    }

    /// Ok means either a recorded event or a durable pending row owns the facts.
    fn try_settlement(&self, raw: &[u8]) -> Result<(), UsageError> {
        self.ledger.stage_settlement(raw)?;
        match self.ledger.record_staged_settlement(raw) {
            Ok(recorded) if recorded.unpriced == Some(UnpricedReason::PriceOverflow) => {
                tracing::warn!(vault_id = %self.vault_id, replayed = recorded.replayed,
                    reason = "price_overflow",
                    "a settled call was recorded without a representable price");
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(vault_id = %self.vault_id, ?error,
                    "a durably staged usage settlement remains pending for retry");
            }
        }
        Ok(())
    }

    /// Existing tick: one durable page and one memory work quantum. Stop/drop:
    /// also retry every memory-only payload in the taken snapshot once, while
    /// the vault is open. A failed retry keeps the SAME bytes and charge.
    pub(crate) fn flush_settlements(&self, stopping: bool) {
        let mut cursor = self
            .settlement_cursor
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Err(error) =
            self.ledger
                .drain_settlement_page(&self.vault_id, &mut cursor, SETTLEMENT_RETRY_ROWS)
        {
            tracing::warn!(vault_id = %self.vault_id, ?error,
                "pending usage settlements remain durable for a later pass");
        }
        *self
            .settlement_cursor
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = cursor;

        // Neither the queue mutex nor the byte-line mutex spans a grouped write.
        let mut batch = {
            let mut queued = self
                .pending_settlements
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            std::mem::replace(&mut *queued, PendingSettlements::new(&self.retained))
        };
        let attempts = if stopping {
            batch.rows.len()
        } else {
            batch.rows.len().min(SETTLEMENT_RETRY_ROWS)
        };
        for _ in 0..attempts {
            let Some(raw) = batch.rows.pop_front() else {
                break;
            };
            match self.try_settlement(&raw) {
                Err(UsageError::IdempotencyConflict) => {
                    tracing::warn!(vault_id = %self.vault_id,
                        "retained usage conflicts with the first payload; the first stands");
                }
                Err(error) => {
                    tracing::error!(vault_id = %self.vault_id, ?error,
                        "usage staging still failed; exact payload remains in memory, NOT durable");
                    batch.rows.push_back(raw);
                    continue;
                }
                Ok(()) => {}
            }
            batch.payload_bytes = batch.payload_bytes.saturating_sub(raw.capacity());
            drop(raw);
            batch.charge(&self.retained, &self.questions);
        }
        if !batch.rows.is_empty() {
            let mut queued = self
                .pending_settlements
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            batch.payload_bytes = batch.payload_bytes.saturating_add(queued.payload_bytes);
            batch.rows.append(&mut queued.rows);
            batch.charge(&self.retained, &self.questions);
            *queued = batch;
        }
    }
}

impl Drop for VaultUsage {
    fn drop(&mut self) {
        self.flush_settlements(true);
        let pending = self
            .pending_settlements
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .rows
            .len();
        if pending != 0 {
            tracing::error!(vault_id = %self.vault_id, pending,
                "usage meter dropped with memory-only settlements: persistent staging never succeeded");
        }
    }
}
