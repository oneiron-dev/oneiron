//! Send receipt persistence inside a caller-owned transaction.

use super::kernel::{FIELD_TASK_REF, FIELD_TRANSPORT_DISPATCHED, ReceiptRecord};
use super::ledgers::{DurableSendReceipt, SendReceiptOutcome, decode_durable_send_receipt};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::{SEND_RECEIPT_RECORD_VERSION, Store};

/// Transaction-composable persistence. Each dispatch attempt must have its own
/// `receipt_id`; a repeated identity cannot replace different audit evidence.
/// The caller owns commit/abort and must abort on error. Returns false only
/// when the TASK already has a delivered receipt.
pub(crate) fn persist_send_receipt_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    mut receipt: ReceiptRecord,
    outcome: SendReceiptOutcome,
    transport_dispatched: bool,
    delivered_idempotency: Option<(EntityId, &str)>,
) -> Result<bool> {
    let existing = store.get_send_receipt_by_task_in_txn(wtxn, &task_ref)?;
    if let Some(raw) = existing.as_deref() {
        let existing = decode_durable_send_receipt(task_ref.as_bytes(), raw)?;
        if existing.outcome == SendReceiptOutcome::Delivered {
            return Ok(false);
        }
    }
    receipt
        .fields
        .insert(FIELD_TASK_REF.to_owned(), task_ref.to_hex());
    receipt.fields.insert(
        FIELD_TRANSPORT_DISPATCHED.to_owned(),
        transport_dispatched.to_string(),
    );
    let durable = DurableSendReceipt {
        version: SEND_RECEIPT_RECORD_VERSION,
        task_ref: task_ref.to_hex(),
        outcome,
        transport_dispatched,
        receipt,
    };
    let encoded = rmp_serde::to_vec_named(&durable)
        .map_err(|_| Error::InvariantViolation("send receipt encode failed"))?;
    store.append_send_receipt_in_txn(wtxn, &task_ref, &durable.receipt.receipt_id, &encoded)?;
    if existing.is_some() {
        store.set_send_receipt_in_txn(wtxn, &task_ref, &encoded)?;
    } else {
        store.put_send_receipt_in_txn(wtxn, &task_ref, &encoded)?;
    }
    if outcome == SendReceiptOutcome::Delivered
        && let Some((actor_ref, idempotency_key)) = delivered_idempotency
    {
        store.put_delivered_send_idempotency_in_txn(wtxn, &actor_ref, idempotency_key, &task_ref)?;
    }
    Ok(true)
}
