//! Ordinary outbound receipts for hosts that call dispatch directly.
//!
//! The scheduled connector-task executor already writes send audit rows.
//! Direct host dispatchers opt into this canonical receipt-family projector
//! rather than inventing a connector-specific audit ledger.

use serde::{Deserialize, Serialize};

use super::{ReceiptKind, ReceiptRecord};
use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

const DIRECT: SideTable<[u8; 32], DirectReceipt, Named> =
    SideTable::new(&side_table::OUTBOUND_DIRECT_RECEIPT);
const VERSION: u8 = 2;

#[derive(Serialize, Deserialize)]
struct DirectReceipt {
    version: u8,
    logical_ref: String,
    receipt: ReceiptRecord,
}

/// A delivered replay remains one logical receipt; negative dispatches are
/// distinct when their actionable result changes. In particular, a connect
/// failure and a later uncertain send both say `failed`, but their delivery
/// certainty and retry instructions are different evidence. Clock stamps and
/// gate-decision IDs and policy traces are intentionally not identity: a
/// replay may omit the original gate decision, but it must not add a thinner
/// duplicate just because its observation time or provenance changed.
fn evidence(receipt: &ReceiptRecord) -> String {
    if receipt.outcome == "delivered_to_channel" {
        return receipt.outcome.clone();
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:direct-outbound-result:v2");
    for value in [
        Some(receipt.outcome.as_str()),
        receipt
            .fields
            .get("delivery_may_have_occurred")
            .map(String::as_str),
        receipt.fields.get("retry_state").map(String::as_str),
        receipt.fields.get("intent_state").map(String::as_str),
        receipt.fields.get("gate_outcome").map(String::as_str),
        receipt.fields.get("hold_reason").map(String::as_str),
        receipt.fields.get("suppression_reason").map(String::as_str),
        receipt.fields.get("provider_ref").map(String::as_str),
    ] {
        match value {
            Some(value) => {
                hasher.update(&[1]);
                hasher.update(&(value.len() as u64).to_le_bytes());
                hasher.update(value.as_bytes());
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    format!("{}:{}", receipt.outcome, hasher.finalize().to_hex())
}

fn key(logical_ref: &str, receipt: &ReceiptRecord) -> [u8; 32] {
    let result = evidence(receipt);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:direct-outbound-receipt:v2");
    hasher.update(&(logical_ref.len() as u64).to_le_bytes());
    hasher.update(logical_ref.as_bytes());
    hasher.update(&(result.len() as u64).to_le_bytes());
    hasher.update(result.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Stores the first receipt for each material result of a logical dispatch.
/// A later uncertain result does not hide behind an earlier definite failure;
/// a delivered replay still has one logical outcome and cannot mint a new row. The pipeline result, not a host-authored
/// imitation, supplies the receipt body.
pub(crate) fn record(vault: &Vault, mut receipt: ReceiptRecord) -> Result<()> {
    if receipt.receipt_kind != ReceiptKind::Outbound {
        return Err(Error::InvariantViolation("direct dispatch receipt kind"));
    }
    let logical_ref = receipt.receipt_id.clone();
    let key = key(&logical_ref, &receipt);
    receipt.receipt_id = format!("{}:{}", logical_ref, evidence(&receipt));
    let row = DirectReceipt {
        version: VERSION,
        logical_ref,
        receipt,
    };
    vault.with_write_txn(|txn| {
        if !DIRECT.contains(&vault.store, txn, &key)? {
            DIRECT.put(&vault.store, txn, &key, &row)?;
        }
        Ok(())
    })
}

/// Existing outbound receipt-family source, alongside connector-send audits.
pub(super) fn receipts(vault: &Vault) -> Result<Vec<ReceiptRecord>> {
    let txn = vault.store.env.read_txn()?;
    DIRECT
        .iter_raw_from(&vault.store, &txn, &[])?
        .map(|entry| {
            let (key_bytes, raw) = entry?;
            let row = DIRECT
                .decode_value(&raw)
                .map_err(|_| Error::CorruptedIndex("direct dispatch receipt"))?;
            if row.version != VERSION
                || row.receipt.receipt_kind != ReceiptKind::Outbound
                || row.receipt.receipt_id
                    != format!("{}:{}", row.logical_ref, evidence(&row.receipt))
                || key_bytes.as_slice() != key(&row.logical_ref, &row.receipt)
            {
                return Err(Error::CorruptedIndex("direct dispatch receipt"));
            }
            Ok(row.receipt)
        })
        .collect()
}
