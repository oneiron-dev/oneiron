//! Replicated, immutable observation of a suppressed outbound intent.
//!
//! The effect ledger remains device-local authority; this ASSET is the synced
//! receipt surface, not permission for a peer to mutate the local send queue.

use serde::{Deserialize, Serialize};

use super::{MAX_RECEIPT_QUERY_SCAN, ReceiptKind, ReceiptRecord, ReceiptScan};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::outbound_intent_ledger::IntentId;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::temporal::TimeRange;

const MAGIC: &[u8] = b"oneiron:outbound-suppression:v1\0";
const LOCAL_PREFIX: &[u8] = b"outbound:suppression_receipt:v1:";

pub(crate) fn suppression_receipt_id(id: &IntentId) -> String {
    format!(
        "outbound:suppression:{}",
        crate::entity_id::bytes_to_hex_lower(id)
    )
}

fn local_key(id: &IntentId) -> Vec<u8> {
    let mut key = LOCAL_PREFIX.to_vec();
    key.extend_from_slice(id);
    key
}

#[derive(Serialize, Deserialize)]
struct SuppressionAsset {
    intent_id: IntentId,
    receipt: ReceiptRecord,
}

fn asset_id(intent_id: &IntentId) -> Result<EntityId> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.outbound.suppression.asset.v1\0");
    hash.update(intent_id);
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId::from_bytes(bytes)
}

fn decode(id: EntityId, body: &[u8]) -> Result<Option<SuppressionAsset>> {
    let Some(raw) = body.strip_prefix(MAGIC) else {
        return Ok(None);
    };
    let asset: SuppressionAsset = rmp_serde::from_slice(raw)
        .map_err(|_| Error::CorruptedIndex("outbound suppression asset"))?;
    if asset_id(&asset.intent_id)? != id
        || asset.receipt.receipt_kind != ReceiptKind::Outbound
        || asset.receipt.outcome != "suppressed"
        || asset.receipt.receipt_id != suppression_receipt_id(&asset.intent_id)
        || asset.receipt.fields.get("suppression").map(String::as_str) != Some("dedupe")
        || !asset.receipt.fields.contains_key("dedupe_key")
    {
        return Err(Error::CorruptedIndex("outbound suppression asset binding"));
    }
    Ok(Some(asset))
}

pub(crate) fn put_suppression_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    intent_id: &IntentId,
    receipt: &ReceiptRecord,
    now: u64,
) -> Result<()> {
    let id = asset_id(intent_id)?;
    if vault.store.port_entity_record(txn, &id)?.is_some() {
        return Err(Error::CorruptedIndex(
            "outbound suppression asset id occupied",
        ));
    }
    let mut body = MAGIC.to_vec();
    body.extend(
        rmp_serde::to_vec_named(&SuppressionAsset {
            intent_id: *intent_id,
            receipt: receipt.clone(),
        })
        .map_err(|_| Error::InvariantViolation("outbound suppression encode"))?,
    );
    if vault
        .store
        .vault_meta
        .get(txn, &local_key(intent_id))?
        .is_some()
    {
        return Err(Error::CorruptedIndex(
            "outbound suppression local receipt occupied",
        ));
    }
    vault
        .batch_in()
        .put(
            &id,
            ENTITY_TYPE_ASSET,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &body,
        )
        .apply(txn)?;
    let encoded = rmp_serde::to_vec_named(receipt)
        .map_err(|_| Error::InvariantViolation("outbound suppression receipt encode"))?;
    vault
        .store
        .vault_meta
        .put(txn, &local_key(intent_id), &encoded)?;
    Ok(())
}

pub(crate) fn suppression_for_intent(vault: &Vault, intent_id: &IntentId) -> Result<ReceiptRecord> {
    let id = asset_id(intent_id)?;
    let txn = vault.store.env.read_txn()?;
    let row = vault
        .store
        .port_entity_record(&txn, &id)?
        .ok_or(Error::CorruptedIndex("outbound suppression asset missing"))?;
    if row.entity_type != ENTITY_TYPE_ASSET {
        return Err(Error::CorruptedIndex("outbound suppression asset type"));
    }
    let asset =
        decode(id, &row.body)?.ok_or(Error::CorruptedIndex("outbound suppression asset shape"))?;
    let local = vault
        .store
        .vault_meta
        .get(&txn, &local_key(intent_id))?
        .ok_or(Error::CorruptedIndex(
            "outbound suppression local receipt missing",
        ))?;
    let receipt: ReceiptRecord = rmp_serde::from_slice(&local)
        .map_err(|_| Error::CorruptedIndex("outbound suppression local receipt"))?;
    if receipt != asset.receipt {
        return Err(Error::CorruptedIndex(
            "outbound suppression local/replicated mismatch",
        ));
    }
    Ok(receipt)
}

pub(super) fn scan_suppression_receipts(vault: &Vault) -> Result<ReceiptScan> {
    let txn = vault.store.env.read_txn()?;
    let mut receipts = Vec::new();
    let mut scanned = 0;
    for row in vault
        .store
        .port_entity_ids_by_type(&txn, ENTITY_TYPE_ASSET, None)?
    {
        scanned += 1;
        if scanned > MAX_RECEIPT_QUERY_SCAN {
            return Err(Error::IndexOverflow("outbound suppression asset scan"));
        }
        let id = row?;
        let stored = vault
            .store
            .port_entity_record(&txn, &id)?
            .ok_or(Error::CorruptedIndex("outbound suppression asset index"))?;
        if stored.entity_type != ENTITY_TYPE_ASSET {
            return Err(Error::CorruptedIndex(
                "outbound suppression asset type index",
            ));
        }
        if let Some(asset) = decode(id, &stored.body)? {
            if let Some(local) = vault
                .store
                .vault_meta
                .get(&txn, &local_key(&asset.intent_id))?
            {
                let receipt: ReceiptRecord = rmp_serde::from_slice(&local)
                    .map_err(|_| Error::CorruptedIndex("outbound suppression local receipt"))?;
                if receipt != asset.receipt {
                    return Err(Error::CorruptedIndex(
                        "outbound suppression local/replicated mismatch",
                    ));
                }
            }
            receipts.push(asset.receipt);
        }
    }
    Ok(ReceiptScan::from_complete_records(receipts))
}
