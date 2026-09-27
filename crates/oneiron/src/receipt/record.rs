//! First-class, replicated immutable terminal outbound receipt record.
//!
//! The effect ledger remains device-local send authority. The record is
//! synced audit evidence, never a permit to execute a transport.

use serde::{Deserialize, Serialize};

use super::{MAX_RECEIPT_QUERY_SCAN, ReceiptKind, ReceiptRecord, ReceiptScan};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::outbound_intent_ledger::IntentId;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_RECEIPT_RECORD;
use crate::store::Store;
use crate::temporal::TimeRange;

const LOCAL_PREFIX: &[u8] = b"outbound:suppression_receipt:v1:";
const INDEX_PREFIX: &[u8] = b"outbound:suppression_index:v1:";

fn index_key(id: &EntityId) -> Vec<u8> {
    let mut key = INDEX_PREFIX.to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

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
struct ReceiptRecordEnvelope {
    intent_id: IntentId,
    receipt: ReceiptRecord,
}

/// A body checked against its deterministic record id and terminal outcome.
/// Only this checked shape may enter the synced audit index.
struct ValidatedReceiptRecord(ReceiptRecordEnvelope);

fn record_id(intent_id: &IntentId) -> Result<EntityId> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron.outbound.receipt_record.v1\0");
    hash.update(intent_id);
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId::from_bytes(bytes)
}

fn decode(id: EntityId, body: &[u8]) -> Result<ReceiptRecordEnvelope> {
    let asset: ReceiptRecordEnvelope = rmp_serde::from_slice(body)
        .map_err(|_| Error::CorruptedIndex("outbound suppression record"))?;
    if record_id(&asset.intent_id)? != id
        || asset.receipt.receipt_kind != ReceiptKind::Outbound
        || asset.receipt.outcome != "suppressed"
        || asset.receipt.receipt_id != suppression_receipt_id(&asset.intent_id)
        || asset.receipt.fields.get("suppression").map(String::as_str) != Some("dedupe")
        || !asset.receipt.fields.contains_key("dedupe_key")
    {
        return Err(Error::CorruptedIndex("outbound suppression record binding"));
    }
    Ok(asset)
}

/// Canonical capture may not let a CRDT tombstone erase a locally validated
/// audit event. Resolve under its one read snapshot; absence is ordinary, but
/// a missing index or a mismatch with the CRDT carrier is local corruption.
pub(crate) fn validated_local_record_for_canonical(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    expected: Option<&[u8]>,
) -> Result<Option<Vec<u8>>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        if expected.is_some() {
            return Err(Error::CorruptedIndex(
                "canonical receipt record not materialized",
            ));
        }
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("canonical receipt record header"))?;
    if header.entity_type != ENTITY_TYPE_RECEIPT_RECORD {
        if expected.is_some() {
            return Err(Error::CorruptedIndex(
                "canonical receipt record type mismatch",
            ));
        }
        return Ok(None);
    }
    if expected.is_some_and(|candidate| candidate != raw.as_ref()) {
        return Err(Error::CorruptedIndex(
            "canonical receipt record carrier diverged",
        ));
    }
    let decoded = decode(*id, &raw[ENTITY_METADATA_HEADER_LEN..])?;
    if header.occurred_start != header.occurred_end
        || header.occurred_start != header.learned_at
        || header.occurred_start != decoded.receipt.occurred_at
        || store.vault_meta.get(txn, &index_key(id))?.as_deref()
            != Some(decoded.intent_id.as_slice())
    {
        return Err(Error::CorruptedIndex(
            "canonical receipt record/index binding",
        ));
    }
    Ok(Some(raw.into_owned()))
}

/// Incoming bytes have no store dependency. Relabel ONLY this untrusted
/// decode failure as a remote rejection; the same decoder reading an already
/// stored row still reports local `CorruptedIndex` and fails closed.
fn decode_incoming(id: EntityId, data: &[u8]) -> Result<ValidatedReceiptRecord> {
    decode(id, data).map(ValidatedReceiptRecord).map_err(|_| {
        Error::Record(RecordError::InvalidSuppressionReceiptBody(
            "malformed or mismatched carrier",
        ))
    })
}

/// Stateless half of shared local/replicated admission. Other RECEIPT_RECORDs are
/// opaque; a body claiming this domain must decode and bind its exact ID.
#[cfg(feature = "sync")]
pub(crate) fn validate_receipt_record_body(id: &EntityId, data: &[u8]) -> Result<()> {
    decode_incoming(*id, data).map(|_| ())
}

pub(crate) fn validate_receipt_record_time(
    id: &EntityId,
    data: &[u8],
    occurred_at: u64,
) -> Result<()> {
    let validated = decode_incoming(*id, data)?;
    if validated.0.receipt.occurred_at != occurred_at {
        return Err(Error::Record(RecordError::InvalidSuppressionReceiptBody(
            "receipt time and entity envelope disagree",
        )));
    }
    Ok(())
}

/// The one RECEIPT_RECORD put door covers both a malformed new carrier and an ordinary
/// body replacing an already committed carrier (including same-ID replay).
pub(crate) fn validate_receipt_record_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    data: &[u8],
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    if entity_type == ENTITY_TYPE_RECEIPT_RECORD {
        validate_receipt_record_time(id, data, occurred.start)?;
        if occurred.start != occurred.end || learned_at != occurred.start {
            return Err(Error::Record(RecordError::InvalidSuppressionReceiptBody(
                "receipt time and entity envelope disagree",
            )));
        }
    }
    if let Some(prior) = store.entities.get(txn, id.as_bytes())? {
        let header = EntityMetadataHeader::parse(&prior)
            .ok_or(Error::CorruptedIndex("outbound suppression prior header"))?;
        if header.entity_type == ENTITY_TYPE_RECEIPT_RECORD {
            // A corrupt STORED carrier is never blamed on an incoming peer.
            decode(*id, &prior[ENTITY_METADATA_HEADER_LEN..])?;
            if entity_type != ENTITY_TYPE_RECEIPT_RECORD
                || prior.get(ENTITY_METADATA_HEADER_LEN..) != Some(data)
                || header.occurred_start != occurred.start
                || header.occurred_end != occurred.end
                || header.learned_at != learned_at
            {
                return Err(Error::Record(RecordError::SuppressionReceiptDivergence));
            }
        }
    }
    Ok(())
}

/// Rebuildable projection index: the normal RECEIPT_RECORD materializer calls this for
/// local writes and for every replicated RECEIPT_RECORD it accepts. Its keys enumerate
/// only suppression observations, never unrelated content RECEIPT_RECORDs.
pub(crate) fn stage_receipt_record_index(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    data: &[u8],
) -> Result<()> {
    if entity_type != ENTITY_TYPE_RECEIPT_RECORD {
        return Ok(());
    }
    let asset = decode_incoming(*id, data)?.0;
    let key = index_key(id);
    if let Some(previous) = store.vault_meta.get(txn, &key)?
        && previous.as_ref() != asset.intent_id.as_slice()
    {
        return Err(Error::CorruptedIndex("outbound suppression index binding"));
    }
    store.vault_meta.put(txn, &key, &asset.intent_id)?;
    Ok(())
}

pub(crate) fn put_suppression_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    intent_id: &IntentId,
    receipt: &ReceiptRecord,
    now: u64,
) -> Result<()> {
    let id = record_id(intent_id)?;
    if vault.store.port_entity_record(txn, &id)?.is_some() {
        return Err(Error::CorruptedIndex(
            "outbound suppression record id occupied",
        ));
    }
    let body = rmp_serde::to_vec_named(&ReceiptRecordEnvelope {
        intent_id: *intent_id,
        receipt: receipt.clone(),
    })
    .map_err(|_| Error::InvariantViolation("outbound suppression encode"))?;
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
    crate::batch::apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        vec![crate::batch::BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_RECEIPT_RECORD,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            data: body,
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )?;
    let encoded = rmp_serde::to_vec_named(receipt)
        .map_err(|_| Error::InvariantViolation("outbound suppression receipt encode"))?;
    vault
        .store
        .vault_meta
        .put(txn, &local_key(intent_id), &encoded)?;
    Ok(())
}

pub(crate) fn suppression_for_intent(vault: &Vault, intent_id: &IntentId) -> Result<ReceiptRecord> {
    let id = record_id(intent_id)?;
    let txn = vault.store.env.read_txn()?;
    let row = vault
        .store
        .port_entity_record(&txn, &id)?
        .ok_or(Error::CorruptedIndex("outbound suppression record missing"))?;
    if row.entity_type != ENTITY_TYPE_RECEIPT_RECORD {
        return Err(Error::CorruptedIndex("outbound suppression record type"));
    }
    let asset = decode(id, &row.body)?;
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
    for (scanned, row) in vault
        .store
        .vault_meta
        .prefix_iter(&txn, INDEX_PREFIX)?
        .enumerate()
    {
        if scanned >= MAX_RECEIPT_QUERY_SCAN {
            return Err(Error::IndexOverflow("outbound suppression receipt scan"));
        }
        let (key, value) = row?;
        let id_bytes: [u8; 16] = key
            .get(INDEX_PREFIX.len()..)
            .and_then(|suffix| suffix.try_into().ok())
            .ok_or(Error::CorruptedIndex("outbound suppression index key"))?;
        let id = EntityId::from_bytes(id_bytes)?;
        let indexed_intent: IntentId = value
            .as_ref()
            .try_into()
            .map_err(|_| Error::CorruptedIndex("outbound suppression index value"))?;
        let stored = vault
            .store
            .port_entity_record(&txn, &id)?
            .ok_or(Error::CorruptedIndex("outbound suppression record index"))?;
        if stored.entity_type != ENTITY_TYPE_RECEIPT_RECORD {
            return Err(Error::CorruptedIndex(
                "outbound suppression record type index",
            ));
        }
        let asset = decode(id, &stored.body)?;
        if asset.intent_id != indexed_intent {
            return Err(Error::CorruptedIndex("outbound suppression index target"));
        }
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
    Ok(ReceiptScan::from_complete_records(receipts))
}
