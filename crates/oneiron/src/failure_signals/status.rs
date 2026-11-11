//! Content-free delivery diagnostics from the existing durable queues and
//! direct-dispatch receipts. Reading status never sends, settles or purges.

use serde::Serialize;

use super::{COUNTS, FAILURE_SIGNALS_CHANNEL, code_fix, decode_count};
use crate::outbound::connector_actor_id;
use crate::receipt::latest_direct_dispatch_receipt_in_txn;
use crate::{Error, Result, Vault};

/// Stored work, not a promise that each row is currently export-eligible.
/// A carried batch's frozen shares are already in these queues and are not
/// added a second time. An ambiguous send removes its counts but keeps its
/// code-fix records until an acknowledged delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FailureSignalWaiting {
    pub count_rows: u64,
    pub signal_count: u64,
    pub code_fix_records: u64,
}

/// The newest durable material-result receipt by its recorded timestamp,
/// then receipt id to make equal timestamps deterministic. Replays keep
/// their first material observation; this is not current connectivity or a
/// record of an idle pass or a failure before a receipt could be committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FailureSignalBatchReceipt {
    pub occurred_at: u64,
    pub outcome: String,
}

/// One read-only store snapshot. Counts remain visible when exports are off
/// until the sender's ordinary reconciliation removes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FailureSignalDeliveryStatus {
    pub exports_enabled: bool,
    pub waiting: FailureSignalWaiting,
    pub last_batch_receipt: Option<FailureSignalBatchReceipt>,
}

impl Vault {
    /// Reads delivery diagnostics without touching delivery, consent or the
    /// grant clock. Only quantities and the closed pipeline outcome leave
    /// this read; receipt fields and code-fix bodies do not.
    pub fn failure_signal_delivery_status(&self) -> Result<FailureSignalDeliveryStatus> {
        let txn = self.store.env.read_txn()?;
        let mut waiting = FailureSignalWaiting {
            count_rows: 0,
            signal_count: 0,
            code_fix_records: code_fix::stored_code_fix_records_in_txn(self, &txn)?,
        };
        for row in COUNTS.iter_from(&self.store, &txn, &[])? {
            let count = decode_count(&row?.1)?;
            waiting.count_rows += 1;
            waiting.signal_count = waiting
                .signal_count
                .checked_add(count.count())
                .ok_or(Error::ArithmeticOverflow("failure signal status count"))?;
        }
        let sender = connector_actor_id(FAILURE_SIGNALS_CHANNEL)?.to_hex();
        let last_batch_receipt =
            latest_direct_dispatch_receipt_in_txn(self, &txn, |logical_ref, receipt| {
                receipt.actor.as_deref() == Some(sender.as_str())
                    && logical_ref
                        .strip_prefix("failure_signals:batch:")
                        .is_some_and(|id| {
                            id.len() == 32
                                && id.bytes().all(|byte| {
                                    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
                                })
                        })
            })?
            .map(|receipt| FailureSignalBatchReceipt {
                occurred_at: receipt.occurred_at,
                outcome: receipt.outcome,
            });
        Ok(FailureSignalDeliveryStatus {
            exports_enabled: self.config.failure_signals.exports(),
            waiting,
            last_batch_receipt,
        })
    }
}
