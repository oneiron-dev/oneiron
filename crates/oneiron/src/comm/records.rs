//! COMM_RECORD event/gate/receipt storage, MessagePack codec and shared value helpers.

use super::claims::{CommError, CommResult};
use super::note_comm_record_family_scan;
use crate::Vault;
use crate::batch::{BatchOp, apply_ops};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_COMM_RECORD;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::temporal::TimeRange;

/// The event-sequence counter: a singleton row, little-endian (not the
/// door's usual big-endian `u64`), so it keeps a custom `RawValue` rather
/// than the built-in one.
const EVENT_SEQUENCE: SideTable<(), EventSequence, Raw> =
    SideTable::new(&side_table::COMM_EVENT_SEQUENCE);

struct EventSequence(u64);

impl RawValue for EventSequence {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.to_le_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let bytes: [u8; 8] = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex("comm event sequence"))?;
        Ok(Self(u64::from_le_bytes(bytes)))
    }
}

pub(super) use crate::write_envelope::communication_record::CommEventKind;
pub(super) use crate::write_envelope::communication_record::CommRecord;
pub(super) use crate::write_envelope::communication_record::decode_comm_record;
pub(super) use crate::write_envelope::communication_record::elided_string;
pub(super) use crate::write_envelope::communication_record::elided_u64;
pub(super) use crate::write_envelope::communication_record::encode_comm_record;
pub(super) use crate::write_envelope::communication_record::encode_value;
pub(super) use crate::write_envelope::communication_record::invalid_claim;
pub(super) use crate::write_envelope::communication_record::required_bool;
pub(super) use crate::write_envelope::communication_record::required_entity_ref;
pub(super) use crate::write_envelope::communication_record::required_string;
pub(super) use crate::write_envelope::communication_record::required_u64;
pub(super) use crate::write_envelope::communication_record::validate_channel_class;
pub(crate) use crate::write_envelope::communication_record::validate_key_string;
pub(super) use crate::write_envelope::communication_record::validate_keys;
pub(super) use crate::write_envelope::communication_record::validate_keys_with_optional;
pub(super) use crate::write_envelope::communication_record::validate_send_ref;
pub(super) use crate::write_envelope::communication_record::value_map;

/// Re-reads one COMM_RECORD by id. `None` covers every way a snapshot id can
/// stop naming a record of this family: deleted, retyped, or undecodable.
pub(super) fn read_comm_record_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: EntityId,
) -> CommResult<Option<CommRecord>> {
    let Some(raw) = vault.store.port_entity_record(rtxn, &id)? else {
        return Ok(None);
    };

    if raw.entity_type != ENTITY_TYPE_COMM_RECORD {
        return Ok(None);
    }
    Ok(decode_comm_record(&raw.body).ok())
}

pub(super) fn comm_records_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> CommResult<Vec<(EntityId, CommRecord)>> {
    note_comm_record_family_scan();
    let mut records = Vec::new();
    for entry in vault
        .store
        .port_entity_ids_by_type(rtxn, ENTITY_TYPE_COMM_RECORD, None)?
    {
        let id = entry?;
        let Some(record) = read_comm_record_in_txn(vault, rtxn, id)? else {
            continue;
        };
        records.push((id, record));
    }
    Ok(records)
}

pub(super) fn put_comm_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    record: &CommRecord,
) -> CommResult<()> {
    let mutation_recorded_at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let occurred_at = record.occurred_at();
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_COMM_RECORD,
            occurred: TimeRange {
                start: occurred_at,
                end: occurred_at,
            },
            learned_at: mutation_recorded_at,
            row_version: None,
            data: encode_comm_record(record)?,
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
    Ok(())
}

pub(super) fn next_event_sequence_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
) -> CommResult<u64> {
    let current = EVENT_SEQUENCE
        .get(&vault.store, &*wtxn, &())?
        .map_or(0, |sequence| sequence.0);
    let next = current.checked_add(1).ok_or(CommError::InvalidRecord)?;
    EVENT_SEQUENCE.put(&vault.store, wtxn, &(), &EventSequence(next))?;
    Ok(next)
}

/// Validates one COMM_RECORD body at the replicated write door (FED-001).
pub(crate) use crate::write_envelope::communication_record::validate_comm_record_body_bytes;
