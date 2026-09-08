//! COMM_RECORD event/gate/receipt storage, MessagePack codec and shared value helpers.

use std::io::Cursor;

use rmpv::Value;

use super::claims::{
    COMM_SCHEMA_VERSION, CommError, CommResult, KEY_CHANNEL_CLASS, KEY_OCCURRED_AT, KEY_PARTY_REF,
    KEY_SCHEMA_VERSION, KEY_THREAD_REF,
};
use super::consent::{MAX_SEND_REF_BYTES, OPT_OUT_CLEAR_REASON};
use super::note_comm_record_family_scan;
use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_COMM_RECORD;
use crate::temporal::TimeRange;
use crate::vault::entity_id_from_type_index_key;

const COMM_RECORD_KEYS: [&str; 15] = [
    "schema_version",
    "record_kind",
    "sequence",
    "event_kind",
    "party_ref",
    "channel_class",
    "thread_ref",
    "occurred_at",
    "projected",
    "claim_ref",
    "gate_status",
    "outcome",
    "view_bytes",
    "entry_count",
    "actor_ref",
];

const RECORD_KIND_EVENT: &str = "event";

const RECORD_KIND_GATE: &str = "gate";

const RECORD_KIND_RECEIPT: &str = "receipt";

const GATE_STATUS_PENDING: &str = "pending";

const GATE_STATUS_CONSUMED: &str = "consumed";

const MAX_KEY_BYTES: usize = 512;

const EVENT_SEQUENCE_KEY: &[u8] = b"comm.event_sequence.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CommEventKind {
    SendSucceeded,
    InboundStop,
    ThreadJoined,
    ThreadLeft,
}

impl CommEventKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SendSucceeded => "send_succeeded",
            Self::InboundStop => "inbound_stop",
            Self::ThreadJoined => "thread_joined",
            Self::ThreadLeft => "thread_left",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "send_succeeded" => Some(Self::SendSucceeded),
            "inbound_stop" => Some(Self::InboundStop),
            "thread_joined" => Some(Self::ThreadJoined),
            "thread_left" => Some(Self::ThreadLeft),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) enum CommRecord {
    Event {
        sequence: u64,
        kind: CommEventKind,
        party_ref: EntityId,
        channel_class: Option<String>,
        thread_ref: Option<String>,
        occurred_at: u64,
        projected: bool,
    },
    Gate {
        party_ref: EntityId,
        channel_class: String,
        claim_ref: EntityId,
        created_at: u64,
        pending: bool,
    },
    Receipt {
        party_ref: EntityId,
        channel_class: String,
        occurred_at: u64,
        outcome: String,
        actor_ref: EntityId,
    },
}

impl CommRecord {
    fn occurred_at(&self) -> u64 {
        match self {
            Self::Event { occurred_at, .. } | Self::Receipt { occurred_at, .. } => *occurred_at,
            Self::Gate { created_at, .. } => *created_at,
        }
    }
}

pub(super) fn encode_comm_record(record: &CommRecord) -> CommResult<Vec<u8>> {
    let mut values = vec![Value::Nil; COMM_RECORD_KEYS.len()];
    values[0] = Value::from(COMM_SCHEMA_VERSION);
    match record {
        CommRecord::Event {
            sequence,
            kind,
            party_ref,
            channel_class,
            thread_ref,
            occurred_at,
            projected,
        } => {
            values[1] = Value::from(RECORD_KIND_EVENT);
            values[2] = Value::from(*sequence);
            values[3] = Value::from(kind.as_str());
            values[4] = Value::from(party_ref.to_hex());
            values[5] = channel_class.as_deref().map_or(Value::Nil, Value::from);
            values[6] = thread_ref.as_deref().map_or(Value::Nil, Value::from);
            values[7] = Value::from(*occurred_at);
            values[8] = Value::Boolean(*projected);
        }
        CommRecord::Gate {
            party_ref,
            channel_class,
            claim_ref,
            created_at,
            pending,
        } => {
            values[1] = Value::from(RECORD_KIND_GATE);
            values[4] = Value::from(party_ref.to_hex());
            values[5] = Value::from(channel_class.as_str());
            values[7] = Value::from(*created_at);
            values[9] = Value::from(claim_ref.to_hex());
            values[10] = Value::from(if *pending {
                GATE_STATUS_PENDING
            } else {
                GATE_STATUS_CONSUMED
            });
            values[11] = Value::from(OPT_OUT_CLEAR_REASON);
        }
        CommRecord::Receipt {
            party_ref,
            channel_class,
            occurred_at,
            outcome,
            actor_ref,
        } => {
            values[1] = Value::from(RECORD_KIND_RECEIPT);
            values[4] = Value::from(party_ref.to_hex());
            values[5] = Value::from(channel_class.as_str());
            values[7] = Value::from(*occurred_at);
            values[11] = Value::from(outcome.as_str());
            values[14] = Value::from(actor_ref.to_hex());
        }
    }
    let map = Value::Map(
        COMM_RECORD_KEYS
            .iter()
            .zip(values)
            .map(|(key, value)| (Value::from(*key), value))
            .collect(),
    );
    encode_value(&map).map_err(CommError::from)
}

pub(super) fn decode_comm_record(bytes: &[u8]) -> CommResult<CommRecord> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| CommError::InvalidRecord)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(CommError::InvalidRecord);
    }
    let entries = value_map(&value).map_err(|_| CommError::InvalidRecord)?;
    validate_keys(entries, &COMM_RECORD_KEYS).map_err(|_| CommError::InvalidRecord)?;
    if required_u64(entries, KEY_SCHEMA_VERSION).map_err(|_| CommError::InvalidRecord)?
        != COMM_SCHEMA_VERSION
    {
        return Err(CommError::InvalidRecord);
    }
    let kind = required_string(entries, "record_kind").map_err(|_| CommError::InvalidRecord)?;
    let party_ref =
        required_entity_ref(entries, KEY_PARTY_REF).map_err(|_| CommError::InvalidRecord)?;
    match kind {
        RECORD_KIND_EVENT => {
            let event_kind = required_string(entries, "event_kind")
                .ok()
                .and_then(CommEventKind::parse)
                .ok_or(CommError::InvalidRecord)?;
            let channel_class = optional_string(entries, KEY_CHANNEL_CLASS)
                .map_err(|_| CommError::InvalidRecord)?;
            if let Some(channel_class) = &channel_class {
                validate_channel_class(channel_class).map_err(|_| CommError::InvalidRecord)?;
            }
            let thread_ref =
                optional_string(entries, KEY_THREAD_REF).map_err(|_| CommError::InvalidRecord)?;
            if let Some(thread_ref) = &thread_ref {
                validate_key_string(thread_ref).map_err(|_| CommError::InvalidRecord)?;
            }
            // Enforce the exact per-variant field shape: a send/STOP carries a
            // channel_class and no thread_ref; a thread event carries a
            // thread_ref and no channel_class. Cross-populated bodies are
            // rejected at the door (fail-closed) rather than silently accepted.
            match event_kind {
                CommEventKind::SendSucceeded | CommEventKind::InboundStop
                    if channel_class.is_some() && thread_ref.is_none() => {}
                CommEventKind::ThreadJoined | CommEventKind::ThreadLeft
                    if thread_ref.is_some() && channel_class.is_none() => {}
                _ => return Err(CommError::InvalidRecord),
            }
            Ok(CommRecord::Event {
                sequence: required_u64(entries, "sequence")
                    .map_err(|_| CommError::InvalidRecord)?,
                kind: event_kind,
                party_ref,
                channel_class,
                thread_ref,
                occurred_at: required_u64(entries, KEY_OCCURRED_AT)
                    .map_err(|_| CommError::InvalidRecord)?,
                projected: required_bool(entries, "projected")
                    .map_err(|_| CommError::InvalidRecord)?,
            })
        }
        RECORD_KIND_GATE => {
            let channel_class = required_string(entries, KEY_CHANNEL_CLASS)
                .map_err(|_| CommError::InvalidRecord)?
                .to_owned();
            validate_channel_class(&channel_class).map_err(|_| CommError::InvalidRecord)?;
            Ok(CommRecord::Gate {
                party_ref,
                channel_class,
                claim_ref: required_entity_ref(entries, "claim_ref")
                    .map_err(|_| CommError::InvalidRecord)?,
                created_at: required_u64(entries, KEY_OCCURRED_AT)
                    .map_err(|_| CommError::InvalidRecord)?,
                pending: match required_string(entries, "gate_status")
                    .map_err(|_| CommError::InvalidRecord)?
                {
                    GATE_STATUS_PENDING => true,
                    GATE_STATUS_CONSUMED => false,
                    _ => return Err(CommError::InvalidRecord),
                },
            })
        }
        RECORD_KIND_RECEIPT => {
            let channel_class = required_string(entries, KEY_CHANNEL_CLASS)
                .map_err(|_| CommError::InvalidRecord)?
                .to_owned();
            validate_channel_class(&channel_class).map_err(|_| CommError::InvalidRecord)?;
            Ok(CommRecord::Receipt {
                party_ref,
                channel_class,
                occurred_at: required_u64(entries, KEY_OCCURRED_AT)
                    .map_err(|_| CommError::InvalidRecord)?,
                outcome: required_string(entries, "outcome")
                    .map_err(|_| CommError::InvalidRecord)?
                    .to_owned(),
                actor_ref: required_entity_ref(entries, "actor_ref")
                    .map_err(|_| CommError::InvalidRecord)?,
            })
        }
        _ => Err(CommError::InvalidRecord),
    }
}

pub(super) fn value_map(value: &Value) -> Result<&[(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid_claim("comm claim value must be a map")),
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    let mut matches = entries
        .iter()
        .filter_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value));
    let value = matches
        .next()
        .ok_or_else(|| invalid_claim("comm value missing required key"))?;
    if matches.next().is_some() {
        return Err(invalid_claim("comm value contains duplicate key"));
    }
    Ok(value)
}

pub(super) fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    required_value(entries, key)?
        .as_str()
        .ok_or_else(|| invalid_claim("comm value string invalid"))
}

fn optional_string(entries: &[(Value, Value)], key: &str) -> Result<Option<String>> {
    let value = required_value(entries, key)?;
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        value
            .as_str()
            .map(|value| Some(value.to_owned()))
            .ok_or_else(|| invalid_claim("comm optional string invalid"))
    }
}

/// A key that may be ELIDED entirely — absence IS the value, and `nil` is not
/// an accepted spelling of it. Duplicates are refused exactly like
/// [`required_value`], so an absent-or-once contract cannot be forged by
/// writing the key twice.
fn elided_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a Value>> {
    let mut matches = entries
        .iter()
        .filter_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value));
    let Some(value) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(invalid_claim("comm value has duplicate key"));
    }
    Ok(Some(value))
}

pub(super) fn elided_string<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
) -> Result<Option<&'a str>> {
    elided_value(entries, key)?
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid_claim("comm value string invalid"))
        })
        .transpose()
}

pub(super) fn elided_u64(entries: &[(Value, Value)], key: &str) -> Result<Option<u64>> {
    elided_value(entries, key)?
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| invalid_claim("comm value integer invalid"))
        })
        .transpose()
}

pub(super) fn required_u64(entries: &[(Value, Value)], key: &str) -> Result<u64> {
    required_value(entries, key)?
        .as_u64()
        .ok_or_else(|| invalid_claim("comm value integer invalid"))
}

pub(super) fn required_bool(entries: &[(Value, Value)], key: &str) -> Result<bool> {
    match required_value(entries, key)? {
        Value::Boolean(value) => Ok(*value),
        _ => Err(invalid_claim("comm value boolean invalid")),
    }
}

pub(super) fn required_entity_ref(entries: &[(Value, Value)], key: &str) -> Result<EntityId> {
    EntityId::from_hex(required_string(entries, key)?)
        .map_err(|_| invalid_claim("comm entity reference invalid"))
}

pub(super) fn validate_keys(entries: &[(Value, Value)], expected: &[&str]) -> Result<()> {
    if entries.len() != expected.len() {
        return Err(invalid_claim("comm value key set invalid"));
    }
    for expected_key in expected {
        required_value(entries, expected_key)?;
    }
    if entries
        .iter()
        .any(|(key, _)| key.as_str().is_none_or(|key| !expected.contains(&key)))
    {
        return Err(invalid_claim("comm value key set invalid"));
    }
    Ok(())
}

/// [`validate_keys`] with a set of keys that may be elided. Every required key
/// must appear exactly once, every optional key at most once, and nothing else
/// may appear at all — unknown keys are never ignored.
pub(super) fn validate_keys_with_optional(
    entries: &[(Value, Value)],
    required: &[&str],
    optional: &[&str],
) -> Result<()> {
    for required_key in required {
        required_value(entries, required_key)?;
    }
    for optional_key in optional {
        elided_value(entries, optional_key)?;
    }
    if entries.iter().any(|(key, _)| {
        key.as_str()
            .is_none_or(|key| !required.contains(&key) && !optional.contains(&key))
    }) {
        return Err(invalid_claim("comm value key set invalid"));
    }
    Ok(())
}

pub(super) fn validate_key_string(value: &str) -> Result<()> {
    if value.trim() != value || value.is_empty() || value.len() > MAX_KEY_BYTES {
        return Err(invalid_claim("comm key string invalid"));
    }
    Ok(())
}

/// One-shot binding token: nonblank, at most 256 bytes, no NUL. It is compared
/// to `ExternalEffectGateInput.send_ref` by BYTE equality, so it is stored
/// exactly as minted — no trimming, no case folding.
pub(super) fn validate_send_ref(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_SEND_REF_BYTES || value.as_bytes().contains(&0)
    {
        return Err(invalid_claim("comm.send_override send_ref is invalid"));
    }
    Ok(())
}

pub(super) fn validate_channel_class(value: &str) -> Result<()> {
    validate_key_string(value)?;
    if value != value.to_ascii_lowercase() {
        return Err(invalid_claim("comm channel_class must be normalized"));
    }
    Ok(())
}

pub(super) fn decode_entity_id(raw: &[u8]) -> Result<EntityId> {
    let bytes: [u8; ENTITY_ID_LEN] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("comm entity reference"))?;
    EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex("comm entity reference"))
}

pub(super) fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| Error::InvariantViolation("comm MessagePack encode failed"))?;
    Ok(bytes)
}

pub(super) fn invalid_claim(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

/// Re-reads one COMM_RECORD by id. `None` covers every way a snapshot id can
/// stop naming a record of this family: deleted, retyped, or undecodable.
pub(super) fn read_comm_record_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: EntityId,
) -> CommResult<Option<CommRecord>> {
    let Some(raw) = vault.store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_COMM_RECORD {
        return Ok(None);
    }
    Ok(decode_comm_record(&raw[ENTITY_METADATA_HEADER_LEN..]).ok())
}

pub(super) fn comm_records_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> CommResult<Vec<(EntityId, CommRecord)>> {
    note_comm_record_family_scan();
    let mut records = Vec::new();
    for entry in vault
        .store
        .type_index
        .prefix_iter(rtxn, &[ENTITY_TYPE_COMM_RECORD])?
    {
        let (key, _) = entry?;
        let id = entity_id_from_type_index_key(&key)?;
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
            learned_at: crate::unix_seconds_now(),
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
    let current = vault
        .store
        .vault_meta
        .get(&*wtxn, EVENT_SEQUENCE_KEY)?
        .map(|raw| {
            let bytes: [u8; 8] = raw
                .as_ref()
                .try_into()
                .map_err(|_| CommError::InvalidRecord)?;
            Ok::<u64, CommError>(u64::from_le_bytes(bytes))
        })
        .transpose()?
        .unwrap_or(0);
    let next = current.checked_add(1).ok_or(CommError::InvalidRecord)?;
    vault
        .store
        .vault_meta
        .put(wtxn, EVENT_SEQUENCE_KEY, &next.to_le_bytes())?;
    Ok(next)
}

/// Validates one COMM_RECORD body at the replicated write door (FED-001).
pub(crate) fn validate_comm_record_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_comm_record(bytes)
        .map(|_| ())
        .map_err(|_| Error::InvalidCommRecordBody("body failed validation"))
}
