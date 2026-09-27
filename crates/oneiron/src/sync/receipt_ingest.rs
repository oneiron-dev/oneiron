//! ONE-1881: one validated, writer-locked receive path for terminal receipts.
//!
//! Both Observer B and forward rematerialization call this BEFORE generic
//! delete-wins or exact-byte shortcuts. The LMDB row, index, tombstone
//! quarantine, and false `dt:` neutralization share the same write txn.

use loro::LoroMap;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_RECEIPT_RECORD;
use crate::sync::loro_support::tombstone_values_for_id;
use crate::sync::quarantine::{QuarantineContainer, quarantine_rejected_op_in_txn};
use crate::temporal::TimeRange;

/// The only remote bytes that may claim a protected receipt identity. Invalid
/// bytes do not gain tombstone immunity from their type header alone.
pub(crate) fn validate_envelope(id: &EntityId, blob: &[u8]) -> Result<EntityMetadataHeader> {
    let header = EntityMetadataHeader::parse(blob).ok_or(Error::Record(
        crate::error::RecordError::InvalidSuppressionReceiptBody("invalid entity envelope"),
    ))?;
    if header.entity_type != ENTITY_TYPE_RECEIPT_RECORD
        || header.occurred_start != header.occurred_end
        || header.learned_at != header.occurred_start
    {
        return Err(Error::Record(
            crate::error::RecordError::InvalidSuppressionReceiptBody(
                "receipt envelope is inconsistent",
            ),
        ));
    }
    crate::receipt::validate_receipt_record_time(
        id,
        &blob[ENTITY_METADATA_HEADER_LEN..],
        header.occurred_start,
    )?;
    Ok(header)
}

pub(crate) fn ingest_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    tombstones_map: &LoroMap,
    window_key: &str,
    id: &EntityId,
    blob: &[u8],
) -> Result<bool> {
    let header = validate_envelope(id, blob)?;
    let existing = vault
        .store
        .entities
        .get(&*wtxn, id.as_bytes())?
        .map(std::borrow::Cow::into_owned);
    let exact = existing
        .as_ref()
        .is_some_and(|stored| stored.as_slice() == blob);
    if !exact {
        vault
            .batch_in()
            .put_replicated(
                id,
                ENTITY_TYPE_RECEIPT_RECORD,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
                &blob[ENTITY_METADATA_HEADER_LEN..],
            )
            .apply(wtxn)?;
    } else {
        // Exact echoes still prove that the stored carrier and its index agree.
        let raw = existing
            .as_ref()
            .ok_or(Error::CorruptedIndex("exact receipt disappeared"))?;
        crate::receipt::validate_receipt_record_body(id, &raw[ENTITY_METADATA_HEADER_LEN..])
            .map_err(|_| Error::CorruptedIndex("stored receipt record"))?;
        crate::receipt::stage_receipt_record_index(
            &vault.store,
            wtxn,
            id,
            ENTITY_TYPE_RECEIPT_RECORD,
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )?;
    }
    let rejection = Error::Registry(crate::error::RegistryError::MaintenanceKindNotWritable(
        ENTITY_TYPE_RECEIPT_RECORD,
    ));
    for tombstone in tombstone_values_for_id(tombstones_map, id) {
        quarantine_rejected_op_in_txn(
            vault,
            wtxn,
            window_key,
            QuarantineContainer::Tombstones,
            &id.to_hex(),
            &rejection,
            &tombstone,
        )?;
    }
    vault.neutralize_delete_protected_marker_in_txn(wtxn, id, ENTITY_TYPE_RECEIPT_RECORD)?;
    Ok(!exact)
}

/// A locally validated receipt dominates a divergent CRDT carrier at its ID.
/// This is an outbound audit repair, not an authority grant or a send replay.
pub(crate) fn local_receipt_dominates(
    vault: &Vault,
    window_key: &super::types::WindowKey,
    entities_map: &LoroMap,
    id: &EntityId,
    raw: &[u8],
) -> Result<bool> {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Err(Error::CorruptedIndex("local receipt envelope"));
    };
    if header.entity_type != ENTITY_TYPE_RECEIPT_RECORD {
        return Ok(false);
    }
    validate_envelope(id, raw).map_err(|_| Error::CorruptedIndex("local receipt record"))?;
    let Some(remote) = crate::sync::loro_support::map_get_bytes(entities_map, &id.to_hex()) else {
        return Ok(false);
    };
    if remote == raw {
        return Ok(false);
    }
    let rejection = match validate_envelope(id, &remote) {
        Ok(_) => Error::Record(crate::error::RecordError::SuppressionReceiptDivergence),
        Err(error) => error,
    };
    super::quarantine::quarantine_rejected_op(
        vault,
        window_key.as_str(),
        QuarantineContainer::Entities,
        &id.to_hex(),
        &rejection,
        &remote,
    )?;
    Ok(true)
}
