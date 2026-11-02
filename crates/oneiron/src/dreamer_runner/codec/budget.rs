//! MessagePack codecs and validators for the private wake-budget rows: the
//! counter, with its overdraft and owed calls, and the per-child reservation,
//! with its owed units (FIX 8702, 8728, 9015).

use rmpv::Value;

use crate::error::{Error, Result};
use crate::side_table::{CodecError, RawValue};

use super::super::constants::{
    DREAMER_BUDGET_KEYS, DREAMER_BUDGET_RESERVATION_KEYS,
    DREAMER_BUDGET_RESERVATION_SCHEMA_VERSION, DREAMER_BUDGET_SCHEMA_VERSION, KEY_ATTEMPT_ID,
    KEY_BUDGET_ID, KEY_CREATED_AT, KEY_OVERDRAFT_UNITS, KEY_OWED_CALLS, KEY_OWED_UNITS,
    KEY_REMAINING_UNITS, KEY_RESERVED_UNITS, KEY_SCHEMA_VERSION, KEY_TOTAL_UNITS, KEY_UPDATED_AT,
};
use super::super::types::{DreamerBudgetRecord, DreamerBudgetReservation};
use super::{
    decode_attempt_id, decode_value, encode_attempt_id, encode_value, expect_key, expect_map,
    expect_string, expect_u64, invalid_dreamer_runner, pinned_key_index, validate_budget_id,
};

fn encode_budget_record(record: &DreamerBudgetRecord) -> Result<Vec<u8>> {
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
        (
            Value::from(KEY_OVERDRAFT_UNITS),
            Value::from(record.overdraft_units),
        ),
        (Value::from(KEY_OWED_CALLS), Value::from(record.owed_calls)),
        (Value::from(KEY_UPDATED_AT), Value::from(record.updated_at)),
    ]);
    encode_value(&value, "dreamer budget MessagePack encode failed")
}

fn decode_budget_record(bytes: &[u8]) -> Result<DreamerBudgetRecord> {
    let value = decode_value(bytes)?;
    let entries = expect_map(&value, "dreamer budget must be a MessagePack map")?;
    let mut schema_version = None;
    let mut budget_id = None;
    let mut total_units = None;
    let mut remaining_units = None;
    let mut reserved_units = None;
    let mut overdraft_units = None;
    let mut owed_calls = None;
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
            KEY_OVERDRAFT_UNITS => {
                overdraft_units = Some(expect_u64(
                    value,
                    "dreamer overdraft_units must be an integer",
                )?);
            }
            KEY_OWED_CALLS => {
                owed_calls = Some(expect_u64(value, "dreamer owed_calls must be an integer")?);
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
        overdraft_units: overdraft_units
            .ok_or(invalid_dreamer_runner("missing dreamer overdraft_units"))?,
        owed_calls: owed_calls.ok_or(invalid_dreamer_runner("missing dreamer owed_calls"))?,
        updated_at: updated_at.ok_or(invalid_dreamer_runner("missing dreamer updated_at"))?,
    };
    validate_budget_record(&record)?;
    Ok(record)
}

impl RawValue for DreamerBudgetRecord {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_budget_record(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_budget_record(bytes)?)
    }
}

fn encode_budget_reservation(record: &DreamerBudgetReservation) -> Result<Vec<u8>> {
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
        (Value::from(KEY_OWED_UNITS), Value::from(record.owed_units)),
        (Value::from(KEY_CREATED_AT), Value::from(record.created_at)),
        (Value::from(KEY_UPDATED_AT), Value::from(record.updated_at)),
    ]);
    encode_value(
        &value,
        "dreamer budget reservation MessagePack encode failed",
    )
}

fn decode_budget_reservation(bytes: &[u8]) -> Result<DreamerBudgetReservation> {
    let value = decode_value(bytes)?;
    let entries = expect_map(
        &value,
        "dreamer budget reservation must be a MessagePack map",
    )?;
    let mut schema_version = None;
    let mut budget_id = None;
    let mut attempt_id = None;
    let mut reserved_units = None;
    let mut owed_units = None;
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
            KEY_OWED_UNITS => {
                owed_units = Some(expect_u64(value, "dreamer owed_units must be an integer")?);
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
        owed_units: owed_units.ok_or(invalid_dreamer_runner("missing dreamer owed_units"))?,
        created_at: created_at.ok_or(invalid_dreamer_runner("missing dreamer created_at"))?,
        updated_at: updated_at.ok_or(invalid_dreamer_runner("missing dreamer updated_at"))?,
    };
    validate_budget_reservation(&record)?;
    Ok(record)
}

impl RawValue for DreamerBudgetReservation {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_budget_reservation(self)?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_budget_reservation(bytes)?)
    }
}

/// A counter's remaining and reserved units fit its total, and an overdraft
/// is carried only once nothing remains (FIX 8702).
pub(in crate::dreamer_runner) fn validate_budget_record(
    record: &DreamerBudgetRecord,
) -> Result<()> {
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
    if record.overdraft_units > 0 && record.remaining_units > 0 {
        return Err(invalid_dreamer_runner(
            "dreamer budget overdraft beside remaining units",
        ));
    }
    Ok(())
}

pub(in crate::dreamer_runner) fn validate_budget_reservation(
    record: &DreamerBudgetReservation,
) -> Result<()> {
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
