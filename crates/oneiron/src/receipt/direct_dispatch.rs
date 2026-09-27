//! Ordinary outbound receipts for hosts that call dispatch directly.
//!
//! The scheduled connector-task executor already writes send audit rows.
//! Direct host dispatchers opt into this canonical receipt-family projector
//! rather than inventing a connector-specific audit ledger.

use serde::{Deserialize, Serialize};

use super::{ReceiptKind, ReceiptRecord};
use crate::Vault;
use crate::error::{Error, Result};

const PREFIX: &[u8] = b"outbound_direct_receipt:v2:";
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
    for value in evidence_fields(receipt) {
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

fn evidence_fields(receipt: &ReceiptRecord) -> [Option<&str>; 8] {
    [
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
    ]
}

/// A dispatch that never reached the sink (a restart replay of an intent the
/// ledger already abandoned, say) has no execution evidence. It is a thinner
/// duplicate when an earlier row of the same logical dispatch already states
/// every result field it states.
fn thinner_duplicate(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    logical_ref: &str,
    receipt: &ReceiptRecord,
) -> Result<bool> {
    if receipt.fields.contains_key("delivery_may_have_occurred") {
        return Ok(false);
    }
    let fields = evidence_fields(receipt);
    for row in vault.store.vault_meta.prefix_iter(txn, PREFIX)? {
        let (_, raw) = row?;
        let row: DirectReceipt = rmp_serde::from_slice(&raw)
            .map_err(|_| Error::CorruptedIndex("direct dispatch receipt"))?;
        if row.logical_ref == logical_ref
            && fields
                .iter()
                .zip(evidence_fields(&row.receipt))
                .all(|(new, old)| new.is_none() || *new == old)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn key(logical_ref: &str, receipt: &ReceiptRecord) -> Vec<u8> {
    let result = evidence(receipt);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:direct-outbound-receipt:v2");
    hasher.update(&(logical_ref.len() as u64).to_le_bytes());
    hasher.update(logical_ref.as_bytes());
    hasher.update(&(result.len() as u64).to_le_bytes());
    hasher.update(result.as_bytes());
    [PREFIX, hasher.finalize().as_bytes()].concat()
}

/// Stores the first receipt for each material result of a logical dispatch.
/// A later uncertain result does not hide behind an earlier definite failure;
/// a delivered replay still has one logical outcome and cannot mint a new row,
/// and neither can a replay that only restates a stored result with less
/// evidence. The pipeline result, not a host-authored imitation, supplies the
/// receipt body.
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
    let bytes = rmp_serde::to_vec_named(&row)
        .map_err(|_| Error::InvariantViolation("direct dispatch receipt encoding"))?;
    vault.with_write_txn(|txn| {
        if vault.store.vault_meta.get(txn, &key)?.is_none()
            && !thinner_duplicate(vault, txn, &row.logical_ref, &row.receipt)?
        {
            vault.store.vault_meta.put(txn, &key, &bytes)?;
        }
        Ok(())
    })
}

/// Existing outbound receipt-family source, alongside connector-send audits.
pub(super) fn receipts(vault: &Vault) -> Result<Vec<ReceiptRecord>> {
    let txn = vault.store.env.read_txn()?;
    vault
        .store
        .vault_meta
        .prefix_iter(&txn, PREFIX)?
        .map(|row| {
            let (key_bytes, raw) = row?;
            let row: DirectReceipt = rmp_serde::from_slice(&raw)
                .map_err(|_| Error::CorruptedIndex("direct dispatch receipt"))?;
            if row.version != VERSION
                || row.receipt.receipt_kind != ReceiptKind::Outbound
                || row.receipt.receipt_id
                    != format!("{}:{}", row.logical_ref, evidence(&row.receipt))
                || key_bytes.as_ref() != key(&row.logical_ref, &row.receipt)
            {
                return Err(Error::CorruptedIndex("direct dispatch receipt"));
            }
            Ok(row.receipt)
        })
        .collect()
}
