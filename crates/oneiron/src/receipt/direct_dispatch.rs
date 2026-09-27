//! Ordinary outbound receipts for hosts that call dispatch directly.
//!
//! The scheduled connector-task executor already writes send audit rows.
//! Direct host dispatchers opt into this canonical receipt-family projector
//! rather than inventing a connector-specific audit ledger.

use serde::{Deserialize, Serialize};

use super::{ReceiptKind, ReceiptRecord};
use crate::Vault;
use crate::error::{Error, Result};

const PREFIX: &[u8] = b"outbound_direct_receipt:v1:";
const VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
struct DirectReceipt {
    version: u8,
    logical_ref: String,
    receipt: ReceiptRecord,
}

fn key(logical_ref: &str, outcome: &str) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron:direct-outbound-receipt:v1");
    hasher.update(&(logical_ref.len() as u64).to_le_bytes());
    hasher.update(logical_ref.as_bytes());
    hasher.update(&(outcome.len() as u64).to_le_bytes());
    hasher.update(outcome.as_bytes());
    [PREFIX, hasher.finalize().as_bytes()].concat()
}

/// Stores the first result for one logical dispatch/outcome pair. Negative
/// outcomes remain visible if a later retry delivers; a delivered replay
/// does not mint another row or debit. The pipeline result, not a host-authored
/// imitation, supplies the receipt body.
pub(crate) fn record(vault: &Vault, mut receipt: ReceiptRecord) -> Result<()> {
    if receipt.receipt_kind != ReceiptKind::Outbound {
        return Err(Error::InvariantViolation("direct dispatch receipt kind"));
    }
    let logical_ref = receipt.receipt_id.clone();
    let key = key(&logical_ref, &receipt.outcome);
    receipt.receipt_id = format!("{}:{}", logical_ref, receipt.outcome);
    let row = DirectReceipt {
        version: VERSION,
        logical_ref,
        receipt,
    };
    let bytes = rmp_serde::to_vec_named(&row)
        .map_err(|_| Error::InvariantViolation("direct dispatch receipt encoding"))?;
    vault.with_write_txn(|txn| {
        if vault.store.vault_meta.get(txn, &key)?.is_none() {
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
                || row.receipt.receipt_id != format!("{}:{}", row.logical_ref, row.receipt.outcome)
                || key_bytes.as_ref() != key(&row.logical_ref, &row.receipt.outcome)
            {
                return Err(Error::CorruptedIndex("direct dispatch receipt"));
            }
            Ok(row.receipt)
        })
        .collect()
}
