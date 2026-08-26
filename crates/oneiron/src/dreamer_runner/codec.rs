//! MessagePack row codecs, LMDB key builders, and validators for the
//! private Dreamer runner rows.

use std::io::Cursor;

use rmpv::Value;

use crate::attempt_queue::AttemptId;
use crate::error::{Error, Result};

use super::constants::{
    DREAMER_ATTEMPT_PAYLOAD_KEYS, DREAMER_ATTEMPT_PAYLOAD_SCHEMA_VERSION, DREAMER_BUDGET_KEYS,
    DREAMER_BUDGET_RESERVATION_KEYS, DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION,
    DREAMER_BUDGET_SCHEMA_VERSION, DREAMER_HOME_NODE_DESIGNATION_KEYS,
    DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION, DREAMER_PARKED_KEYS,
    DREAMER_PARKED_SCHEMA_VERSION, DREAMER_PRIVATE_BUDGET_PREFIX,
    DREAMER_PRIVATE_BUDGET_RESERVATION_PREFIX, DREAMER_PRIVATE_PARKED_PREFIX,
    DREAMER_PRIVATE_RUN_TREE_PREFIX, DREAMER_RUN_TREE_KEYS, DREAMER_RUN_TREE_SCHEMA_VERSION,
    KEY_ATTEMPT_ID, KEY_ATTEMPT_TYPE, KEY_BUDGET_ID, KEY_CLASS, KEY_CREATED_AT, KEY_ELECTED_AT,
    KEY_INPUT, KEY_NODE_ID, KEY_PARENT_ATTEMPT, KEY_PARK_OWNER, KEY_PARKED_AT, KEY_REASON,
    KEY_REMAINING_UNITS, KEY_RESERVED_UNITS, KEY_SCHEMA_VERSION, KEY_TOTAL_UNITS, KEY_UPDATED_AT,
    MAX_DREAMER_ATTEMPT_TYPE_LEN, MAX_DREAMER_BUDGET_ID_LEN, MAX_DREAMER_PARK_OWNER_LEN,
    MAX_DREAMER_PARK_REASON_LEN,
};
use super::types::{
    DreamerAttemptPayload, DreamerBudgetRecord, DreamerBudgetReservation, DreamerHomeNodeClass,
    DreamerHomeNodeDesignation, DreamerParkedAttemptRecord, DreamerRunTreeRecord,
};

/// Encodes a Dreamer attempt payload in canonical MessagePack field order.
pub fn encode_dreamer_attempt_payload(payload: &DreamerAttemptPayload) -> Result<Vec<u8>> {
    validate_attempt_type(&payload.attempt_type)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_ATTEMPT_PAYLOAD_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT_TYPE),
            Value::from(payload.attempt_type.as_str()),
        ),
        (Value::from(KEY_INPUT), payload.input.clone()),
        (
            Value::from(KEY_PARENT_ATTEMPT),
            encode_optional_attempt_id(payload.parent_attempt),
        ),
    ]);
    encode_value(&value, "dreamer attempt payload MessagePack encode failed")
}

/// Decodes and validates a Dreamer attempt payload.
pub fn decode_dreamer_attempt_payload(bytes: &[u8]) -> Result<DreamerAttemptPayload> {
    let value = decode_value(bytes)?;
    decode_dreamer_attempt_payload_value(&value)
}

pub(super) fn encode_home_node_designation(record: &DreamerHomeNodeDesignation) -> Result<Vec<u8>> {
    validate_home_node_designation(record)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION),
        ),
        (Value::from(KEY_NODE_ID), Value::from(record.node_id)),
        (Value::from(KEY_CLASS), Value::from(record.class.as_str())),
        (Value::from(KEY_ELECTED_AT), Value::from(record.elected_at)),
    ]);
    encode_value(&value, "dreamer home-node MessagePack encode failed")
}

pub(super) fn decode_home_node_designation(bytes: &[u8]) -> Result<DreamerHomeNodeDesignation> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer home-node row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut node_id = None;
    let mut class = None;
    let mut elected_at = None;
    let mut seen = [false; DREAMER_HOME_NODE_DESIGNATION_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer home-node keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_HOME_NODE_DESIGNATION_KEYS).ok_or(
            invalid_dreamer_runner("dreamer home-node key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer home-node key"));
        }
        seen[index] = true;

        match DREAMER_HOME_NODE_DESIGNATION_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer home-node schema_version must be an integer",
                )?);
            }
            KEY_NODE_ID => {
                node_id = Some(expect_u64(
                    value,
                    "dreamer home-node node_id must be an integer",
                )?);
            }
            KEY_CLASS => {
                let parsed = expect_string(value, "dreamer home-node class must be a string")?;
                class = Some(
                    DreamerHomeNodeClass::parse(&parsed)
                        .ok_or(invalid_dreamer_runner("invalid dreamer home-node class"))?,
                );
            }
            KEY_ELECTED_AT => {
                elected_at = Some(expect_u64(
                    value,
                    "dreamer home-node elected_at must be an integer",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_HOME_NODE_DESIGNATION_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer home-node schema_version",
    ))?;
    if schema_version != DREAMER_HOME_NODE_DESIGNATION_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer home-node schema_version",
        ));
    }
    let record = DreamerHomeNodeDesignation {
        node_id: node_id.ok_or(invalid_dreamer_runner("missing dreamer home-node node_id"))?,
        class: class.ok_or(invalid_dreamer_runner("missing dreamer home-node class"))?,
        elected_at: elected_at.ok_or(invalid_dreamer_runner(
            "missing dreamer home-node elected_at",
        ))?,
    };
    validate_home_node_designation(&record)?;
    Ok(record)
}

pub(super) fn decode_dreamer_attempt_payload_value(value: &Value) -> Result<DreamerAttemptPayload> {
    let entries = expect_map(value, "dreamer attempt payload must be a MessagePack map")?;
    let mut schema_version = None;
    let mut attempt_type = None;
    let mut input = None;
    let mut parent_attempt = None;
    let mut seen = [false; DREAMER_ATTEMPT_PAYLOAD_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer attempt payload keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_ATTEMPT_PAYLOAD_KEYS).ok_or(
            invalid_dreamer_runner("dreamer attempt payload key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner(
                "duplicate dreamer attempt payload key",
            ));
        }
        seen[index] = true;

        match DREAMER_ATTEMPT_PAYLOAD_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer attempt payload schema_version must be an integer",
                )?);
            }
            KEY_ATTEMPT_TYPE => {
                let parsed = expect_string(value, "dreamer job_type must be a string")?;
                validate_attempt_type(&parsed)?;
                attempt_type = Some(parsed);
            }
            KEY_INPUT => input = Some(value.clone()),
            KEY_PARENT_ATTEMPT => parent_attempt = Some(decode_optional_attempt_id(value)?),
            _ => unreachable!("index resolved from DREAMER_ATTEMPT_PAYLOAD_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer attempt payload schema_version",
    ))?;
    if schema_version != DREAMER_ATTEMPT_PAYLOAD_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer attempt payload schema_version",
        ));
    }

    Ok(DreamerAttemptPayload {
        attempt_type: attempt_type.ok_or(invalid_dreamer_runner("missing dreamer job_type"))?,
        input: input.ok_or(invalid_dreamer_runner("missing dreamer attempt input"))?,
        parent_attempt: parent_attempt
            .ok_or(invalid_dreamer_runner("missing dreamer parent_job"))?,
    })
}

pub(super) fn encode_budget_record(record: &DreamerBudgetRecord) -> Result<Vec<u8>> {
    validate_budget_id(&record.budget_id)?;
    validate_budget_record(record)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_BUDGET_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_BUDGET_ID),
            Value::from(record.budget_id.as_str()),
        ),
        (
            Value::from(KEY_TOTAL_UNITS),
            Value::from(record.total_units),
        ),
        (
            Value::from(KEY_REMAINING_UNITS),
            Value::from(record.remaining_units),
        ),
        (
            Value::from(KEY_RESERVED_UNITS),
            Value::from(record.reserved_units),
        ),
        (Value::from(KEY_UPDATED_AT), Value::from(record.updated_at)),
    ]);
    encode_value(&value, "dreamer budget MessagePack encode failed")
}

pub(super) fn decode_budget_record(bytes: &[u8]) -> Result<DreamerBudgetRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer budget must be a MessagePack map")?;
    let mut schema_version = None;
    let mut budget_id = None;
    let mut total_units = None;
    let mut remaining_units = None;
    let mut reserved_units = None;
    let mut updated_at = None;
    let mut seen = [false; DREAMER_BUDGET_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer budget keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_BUDGET_KEYS)
            .ok_or(invalid_dreamer_runner("dreamer budget key is not pinned"))?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer budget key"));
        }
        seen[index] = true;

        match DREAMER_BUDGET_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer budget schema_version must be an integer",
                )?);
            }
            KEY_BUDGET_ID => {
                let parsed = expect_string(value, "dreamer budget_id must be a string")?;
                validate_budget_id(&parsed)?;
                budget_id = Some(parsed);
            }
            KEY_TOTAL_UNITS => {
                total_units = Some(expect_u64(value, "dreamer total_units must be an integer")?);
            }
            KEY_REMAINING_UNITS => {
                remaining_units = Some(expect_u64(
                    value,
                    "dreamer remaining_units must be an integer",
                )?);
            }
            KEY_RESERVED_UNITS => {
                reserved_units = Some(expect_u64(
                    value,
                    "dreamer reserved_units must be an integer",
                )?);
            }
            KEY_UPDATED_AT => {
                updated_at = Some(expect_u64(value, "dreamer updated_at must be an integer")?);
            }
            _ => unreachable!("index resolved from DREAMER_BUDGET_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer budget schema_version",
    ))?;
    if schema_version != DREAMER_BUDGET_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer budget schema_version",
        ));
    }

    let record = DreamerBudgetRecord {
        budget_id: budget_id.ok_or(invalid_dreamer_runner("missing dreamer budget_id"))?,
        total_units: total_units.ok_or(invalid_dreamer_runner("missing dreamer total_units"))?,
        remaining_units: remaining_units
            .ok_or(invalid_dreamer_runner("missing dreamer remaining_units"))?,
        reserved_units: reserved_units
            .ok_or(invalid_dreamer_runner("missing dreamer reserved_units"))?,
        updated_at: updated_at.ok_or(invalid_dreamer_runner("missing dreamer updated_at"))?,
    };
    validate_budget_record(&record)?;
    Ok(record)
}

pub(super) fn encode_budget_reservation(record: &DreamerBudgetReservation) -> Result<Vec<u8>> {
    validate_budget_reservation(record)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_BUDGET_ID),
            Value::from(record.budget_id.as_str()),
        ),
        (
            Value::from(KEY_ATTEMPT_ID),
            encode_attempt_id(record.attempt_id),
        ),
        (
            Value::from(KEY_RESERVED_UNITS),
            Value::from(record.reserved_units),
        ),
        (Value::from(KEY_CREATED_AT), Value::from(record.created_at)),
        (Value::from(KEY_UPDATED_AT), Value::from(record.updated_at)),
    ]);
    encode_value(
        &value,
        "dreamer budget reservation MessagePack encode failed",
    )
}

pub(super) fn decode_budget_reservation(bytes: &[u8]) -> Result<DreamerBudgetReservation> {
    let value = decode_value(bytes)?;
    let entries = expect_map(
        &value,
        "dreamer budget reservation must be a MessagePack map",
    )?;
    let mut schema_version = None;
    let mut budget_id = None;
    let mut attempt_id = None;
    let mut reserved_units = None;
    let mut created_at = None;
    let mut updated_at = None;
    let mut seen = [false; DREAMER_BUDGET_RESERVATION_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer budget reservation keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_BUDGET_RESERVATION_KEYS).ok_or(
            invalid_dreamer_runner("dreamer budget reservation key is not pinned"),
        )?;
        if seen[index] {
            return Err(invalid_dreamer_runner(
                "duplicate dreamer budget reservation key",
            ));
        }
        seen[index] = true;

        match DREAMER_BUDGET_RESERVATION_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer budget reservation schema_version must be an integer",
                )?);
            }
            KEY_BUDGET_ID => {
                let parsed = expect_string(value, "dreamer budget_id must be a string")?;
                validate_budget_id(&parsed)?;
                budget_id = Some(parsed);
            }
            KEY_ATTEMPT_ID => {
                attempt_id = Some(decode_attempt_id(value)?);
            }
            KEY_RESERVED_UNITS => {
                reserved_units = Some(expect_u64(
                    value,
                    "dreamer reserved_units must be an integer",
                )?);
            }
            KEY_CREATED_AT => {
                created_at = Some(expect_u64(value, "dreamer created_at must be an integer")?);
            }
            KEY_UPDATED_AT => {
                updated_at = Some(expect_u64(value, "dreamer updated_at must be an integer")?);
            }
            _ => unreachable!("index resolved from DREAMER_BUDGET_RESERVATION_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer budget reservation schema_version",
    ))?;
    if schema_version != DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer budget reservation schema_version",
        ));
    }

    let record = DreamerBudgetReservation {
        budget_id: budget_id.ok_or(invalid_dreamer_runner("missing dreamer budget_id"))?,
        attempt_id: attempt_id.ok_or(invalid_dreamer_runner("missing dreamer job_id"))?,
        reserved_units: reserved_units
            .ok_or(invalid_dreamer_runner("missing dreamer reserved_units"))?,
        created_at: created_at.ok_or(invalid_dreamer_runner("missing dreamer created_at"))?,
        updated_at: updated_at.ok_or(invalid_dreamer_runner("missing dreamer updated_at"))?,
    };
    validate_budget_reservation(&record)?;
    Ok(record)
}

pub(super) fn encode_run_tree_record(record: &DreamerRunTreeRecord) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_RUN_TREE_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT_ID),
            encode_attempt_id(record.attempt_id),
        ),
        (
            Value::from(KEY_PARENT_ATTEMPT),
            encode_optional_attempt_id(record.parent_attempt),
        ),
        (Value::from(KEY_CREATED_AT), Value::from(record.created_at)),
    ]);
    encode_value(&value, "dreamer run-tree MessagePack encode failed")
}

pub(super) fn decode_run_tree_record(bytes: &[u8]) -> Result<DreamerRunTreeRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer run-tree row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut attempt_id = None;
    let mut parent_attempt = None;
    let mut created_at = None;
    let mut seen = [false; DREAMER_RUN_TREE_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer run-tree keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_RUN_TREE_KEYS)
            .ok_or(invalid_dreamer_runner("dreamer run-tree key is not pinned"))?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer run-tree key"));
        }
        seen[index] = true;

        match DREAMER_RUN_TREE_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer run-tree schema_version must be an integer",
                )?);
            }
            KEY_ATTEMPT_ID => attempt_id = Some(decode_attempt_id(value)?),
            KEY_PARENT_ATTEMPT => parent_attempt = Some(decode_optional_attempt_id(value)?),
            KEY_CREATED_AT => {
                created_at = Some(expect_u64(
                    value,
                    "dreamer run-tree created_at must be an integer",
                )?);
            }
            _ => unreachable!("index resolved from DREAMER_RUN_TREE_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer run-tree schema_version",
    ))?;
    if schema_version != DREAMER_RUN_TREE_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer run-tree schema_version",
        ));
    }

    Ok(DreamerRunTreeRecord {
        attempt_id: attempt_id.ok_or(invalid_dreamer_runner("missing dreamer run-tree job_id"))?,
        parent_attempt: parent_attempt.ok_or(invalid_dreamer_runner(
            "missing dreamer run-tree parent_job",
        ))?,
        created_at: created_at.ok_or(invalid_dreamer_runner(
            "missing dreamer run-tree created_at",
        ))?,
    })
}

pub(super) fn encode_parked_record(record: &DreamerParkedAttemptRecord) -> Result<Vec<u8>> {
    validate_park_reason(&record.reason)?;
    validate_park_owner(&record.park_owner)?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(DREAMER_PARKED_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_ATTEMPT_ID),
            encode_attempt_id(record.attempt_id),
        ),
        (Value::from(KEY_REASON), Value::from(record.reason.as_str())),
        (
            Value::from(KEY_PARK_OWNER),
            Value::from(record.park_owner.as_str()),
        ),
        (Value::from(KEY_PARKED_AT), Value::from(record.parked_at)),
    ]);
    encode_value(&value, "dreamer parked row MessagePack encode failed")
}

pub(super) fn decode_parked_record(bytes: &[u8]) -> Result<DreamerParkedAttemptRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer parked row must be a MessagePack map")?;
    let mut schema_version = None;
    let mut attempt_id = None;
    let mut reason = None;
    let mut park_owner = None;
    let mut parked_at = None;
    let mut seen = [false; DREAMER_PARKED_KEYS.len()];

    for (key, value) in entries {
        let key = expect_key(key, "dreamer parked row keys must be strings")?;
        let index = pinned_key_index(key, &DREAMER_PARKED_KEYS).ok_or(invalid_dreamer_runner(
            "dreamer parked row key is not pinned",
        ))?;
        if seen[index] {
            return Err(invalid_dreamer_runner("duplicate dreamer parked row key"));
        }
        seen[index] = true;

        match DREAMER_PARKED_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(expect_u64(
                    value,
                    "dreamer parked row schema_version must be an integer",
                )?);
            }
            KEY_ATTEMPT_ID => attempt_id = Some(decode_attempt_id(value)?),
            KEY_REASON => {
                let parsed = expect_string(value, "dreamer parked reason must be a string")?;
                validate_park_reason(&parsed)?;
                reason = Some(parsed);
            }
            KEY_PARK_OWNER => {
                let parsed = expect_string(value, "dreamer parked park_owner must be a string")?;
                validate_park_owner(&parsed)?;
                park_owner = Some(parsed);
            }
            KEY_PARKED_AT => {
                parked_at = Some(expect_u64(value, "dreamer parked_at must be an integer")?);
            }
            _ => unreachable!("index resolved from DREAMER_PARKED_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_dreamer_runner(
        "missing dreamer parked row schema_version",
    ))?;
    if schema_version != DREAMER_PARKED_SCHEMA_VERSION {
        return Err(invalid_dreamer_runner(
            "unsupported dreamer parked row schema_version",
        ));
    }

    Ok(DreamerParkedAttemptRecord {
        attempt_id: attempt_id.ok_or(invalid_dreamer_runner("missing dreamer parked job_id"))?,
        reason: reason.ok_or(invalid_dreamer_runner("missing dreamer parked reason"))?,
        park_owner: park_owner
            .ok_or(invalid_dreamer_runner("missing dreamer parked park_owner"))?,
        parked_at: parked_at.ok_or(invalid_dreamer_runner("missing dreamer parked_at"))?,
    })
}

pub(super) fn encode_value(value: &Value, reason: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(reason))?;
    Ok(out)
}

pub(super) fn decode_value(bytes: &[u8]) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_dreamer_runner("dreamer runner row is not valid MessagePack"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_dreamer_runner(
            "trailing bytes after dreamer runner row",
        ));
    }
    Ok(value)
}

pub(super) fn encode_attempt_id(attempt_id: AttemptId) -> Value {
    Value::Binary(attempt_id.as_bytes().to_vec())
}

pub(super) fn decode_attempt_id(value: &Value) -> Result<AttemptId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_dreamer_runner("dreamer attempt id must be binary"));
    };
    AttemptId::from_bytes(bytes)
}

pub(super) fn encode_optional_attempt_id(attempt_id: Option<AttemptId>) -> Value {
    attempt_id.map_or(Value::Nil, encode_attempt_id)
}

pub(super) fn decode_optional_attempt_id(value: &Value) -> Result<Option<AttemptId>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_attempt_id(value).map(Some)
}

pub(super) fn expect_map<'a>(
    value: &'a Value,
    reason: &'static str,
) -> Result<&'a [(Value, Value)]> {
    let Value::Map(entries) = value else {
        return Err(invalid_dreamer_runner(reason));
    };
    Ok(entries)
}

pub(super) fn expect_key<'a>(value: &'a Value, reason: &'static str) -> Result<&'a str> {
    value.as_str().ok_or(invalid_dreamer_runner(reason))
}

pub(super) fn expect_string(value: &Value, reason: &'static str) -> Result<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(invalid_dreamer_runner(reason))
}

pub(super) fn expect_u64(value: &Value, reason: &'static str) -> Result<u64> {
    value.as_u64().ok_or(invalid_dreamer_runner(reason))
}

pub(super) fn pinned_key_index(key: &str, keys: &[&str]) -> Option<usize> {
    keys.iter().position(|known| *known == key)
}

pub(super) fn budget_key(budget_id: &str) -> Result<Vec<u8>> {
    validate_budget_id(budget_id)?;
    let mut out = Vec::with_capacity(DREAMER_PRIVATE_BUDGET_PREFIX.len() + budget_id.len());
    out.extend_from_slice(DREAMER_PRIVATE_BUDGET_PREFIX);
    out.extend_from_slice(budget_id.as_bytes());
    Ok(out)
}

pub(super) fn budget_reservation_key(budget_id: &str, attempt_id: AttemptId) -> Result<Vec<u8>> {
    validate_budget_id(budget_id)?;
    let budget_id_len = u16::try_from(budget_id.len())
        .map_err(|_| invalid_dreamer_runner("dreamer budget_id exceeds 128 bytes"))?;
    let mut out = Vec::with_capacity(
        DREAMER_PRIVATE_BUDGET_RESERVATION_PREFIX.len() + 2 + budget_id.len() + 16,
    );
    out.extend_from_slice(DREAMER_PRIVATE_BUDGET_RESERVATION_PREFIX);
    out.extend_from_slice(&budget_id_len.to_be_bytes());
    out.extend_from_slice(budget_id.as_bytes());
    out.extend_from_slice(attempt_id.as_bytes());
    Ok(out)
}

pub(super) fn run_tree_key(attempt_id: AttemptId) -> Vec<u8> {
    let mut out = Vec::with_capacity(DREAMER_PRIVATE_RUN_TREE_PREFIX.len() + 16);
    out.extend_from_slice(DREAMER_PRIVATE_RUN_TREE_PREFIX);
    out.extend_from_slice(attempt_id.as_bytes());
    out
}

pub(super) fn parked_key(attempt_id: AttemptId) -> Vec<u8> {
    let mut out = Vec::with_capacity(DREAMER_PRIVATE_PARKED_PREFIX.len() + 16);
    out.extend_from_slice(DREAMER_PRIVATE_PARKED_PREFIX);
    out.extend_from_slice(attempt_id.as_bytes());
    out
}

pub(super) fn validate_attempt_type(attempt_type: &str) -> Result<()> {
    if attempt_type.is_empty() {
        return Err(invalid_dreamer_runner("dreamer job_type must not be empty"));
    }
    if attempt_type.len() > MAX_DREAMER_ATTEMPT_TYPE_LEN {
        return Err(invalid_dreamer_runner("dreamer job_type exceeds 128 bytes"));
    }
    Ok(())
}

pub(super) fn validate_budget_id(budget_id: &str) -> Result<()> {
    if budget_id.is_empty() {
        return Err(invalid_dreamer_runner(
            "dreamer budget_id must not be empty",
        ));
    }
    if budget_id.len() > MAX_DREAMER_BUDGET_ID_LEN {
        return Err(invalid_dreamer_runner(
            "dreamer budget_id exceeds 128 bytes",
        ));
    }
    Ok(())
}

pub(super) fn validate_park_reason(reason: &str) -> Result<()> {
    if reason.is_empty() {
        return Err(invalid_dreamer_runner(
            "dreamer parked reason must not be empty",
        ));
    }
    if reason.len() > MAX_DREAMER_PARK_REASON_LEN {
        return Err(invalid_dreamer_runner(
            "dreamer parked reason exceeds 512 bytes",
        ));
    }
    Ok(())
}

pub(super) fn validate_park_owner(park_owner: &str) -> Result<()> {
    if park_owner.is_empty() {
        return Err(invalid_dreamer_runner(
            "dreamer parked park_owner must not be empty",
        ));
    }
    if park_owner.len() > MAX_DREAMER_PARK_OWNER_LEN {
        return Err(invalid_dreamer_runner(
            "dreamer parked park_owner exceeds 128 bytes",
        ));
    }
    Ok(())
}

pub(super) fn validate_budget_record(record: &DreamerBudgetRecord) -> Result<()> {
    validate_budget_id(&record.budget_id)?;
    if record.remaining_units > record.total_units || record.reserved_units > record.total_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget counters exceed total",
        ));
    }
    let used = record
        .remaining_units
        .checked_add(record.reserved_units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget counters"))?;
    if used > record.total_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget counters exceed total",
        ));
    }
    Ok(())
}

pub(super) fn validate_budget_reservation(record: &DreamerBudgetReservation) -> Result<()> {
    validate_budget_id(&record.budget_id)?;
    if record.reserved_units == 0 {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation must reserve > 0 units",
        ));
    }
    if record.updated_at < record.created_at {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation updated_at precedes created_at",
        ));
    }
    Ok(())
}

pub(super) fn validate_home_node_designation(record: &DreamerHomeNodeDesignation) -> Result<()> {
    if record.node_id == 0 {
        return Err(invalid_dreamer_runner(
            "dreamer home node_id must be nonzero",
        ));
    }
    Ok(())
}

pub(super) const fn invalid_dreamer_runner(reason: &'static str) -> Error {
    Error::InvalidAttemptQueueRecord(reason)
}
