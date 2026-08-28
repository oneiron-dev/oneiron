//! Strict versioned MessagePack codec for the opaque
//! `CommitmentRecord.schedule` slot.
//!
//! CMT-1 stores those bytes without looking at them, so this codec is the only
//! thing standing between a typed schedule and a blob. It is therefore STRICT
//! in both directions: fixed key order on encode; unknown keys, duplicate keys,
//! missing keys, and wrong-typed values all rejected on decode. `Nil` is legal
//! on exactly the three optional wrapper fields and nowhere else.
//!
//! Two shapes only — SERIES (`series_ref` and `occurrence` both absent) and
//! INSTANCE (both present). A half-linked payload is a decode failure, not a
//! series with a stray field.
//!
//! No `chrono` type and no [`crate::edge::EdgeKind`] appears anywhere in these
//! bytes: the payload is scalar UTC seconds, and series linkage is an id field,
//! not an edge.

use rmpv::Value;

use super::{
    COMMITMENT_SCHEDULE_PAYLOAD_SCHEMA_VERSION, COMMITMENT_SCHEDULE_STRING_MAX_BYTES,
    CommitmentOccurrence, CommitmentSchedulePayload, QuotaWindow, Schedule, ScheduleError,
    ScheduleResult, validate_quota_count,
};
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;

/// Pinned wrapper key order.
pub(super) const PAYLOAD_KEYS: [&str; 5] = [
    "schema_version",
    "schedule",
    "lead_seconds",
    "series_ref",
    "occurrence",
];

const KEY_SCHEMA_VERSION: &str = PAYLOAD_KEYS[0];
const KEY_SCHEDULE: &str = PAYLOAD_KEYS[1];
const KEY_LEAD_SECONDS: &str = PAYLOAD_KEYS[2];
const KEY_SERIES_REF: &str = PAYLOAD_KEYS[3];
const KEY_OCCURRENCE: &str = PAYLOAD_KEYS[4];

const KEY_KIND: &str = "kind";

const KIND_ONCE: &str = "once";
const KIND_INTERVAL: &str = "interval";
const KIND_QUOTA: &str = "quota";
const KIND_RRULE: &str = "rrule";
const KIND_ISO_WEEK: &str = "iso_week";

const ONCE_KEYS: [&str; 2] = [KEY_KIND, "due"];
const INTERVAL_KEYS: [&str; 3] = [KEY_KIND, "period", "anchor"];
const QUOTA_KEYS: [&str; 3] = [KEY_KIND, "count", "window"];
const RRULE_KEYS: [&str; 3] = [KEY_KIND, "rrule_string", "tz"];
const ISO_WEEK_KEYS: [&str; 2] = [KEY_KIND, "tz"];
const OCCURRENCE_KEYS: [&str; 4] = ["due_at", "window_start", "window_end", "ordinal"];

pub(super) fn encode_schedule_payload(
    payload: &CommitmentSchedulePayload,
) -> ScheduleResult<Value> {
    validate_schedule(&payload.schedule)?;
    match (payload.series_ref, payload.occurrence) {
        (None, None) => {}
        (Some(_), Some(occurrence)) => occurrence.validate()?,
        _ => {
            return Err(ScheduleError::Invalid(
                "commitment schedule payload must carry both or neither of series_ref/occurrence",
            ));
        }
    }
    Ok(Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COMMITMENT_SCHEDULE_PAYLOAD_SCHEMA_VERSION),
        ),
        (Value::from(KEY_SCHEDULE), encode_schedule(&payload.schedule)),
        (
            Value::from(KEY_LEAD_SECONDS),
            payload.lead_seconds.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_SERIES_REF),
            payload
                .series_ref
                .map_or(Value::Nil, |id| Value::from(id.to_hex())),
        ),
        (
            Value::from(KEY_OCCURRENCE),
            payload.occurrence.map_or(Value::Nil, encode_occurrence),
        ),
    ]))
}

pub(super) fn decode_schedule_payload(value: &Value) -> ScheduleResult<CommitmentSchedulePayload> {
    let entries = map_entries(value)?;
    check_keys(entries, &PAYLOAD_KEYS)?;
    if required(entries, KEY_SCHEMA_VERSION)?.as_u64()
        != Some(COMMITMENT_SCHEDULE_PAYLOAD_SCHEMA_VERSION)
    {
        return Err(ScheduleError::InvalidPayload);
    }
    let schedule = decode_schedule(required(entries, KEY_SCHEDULE)?)?;
    let lead_seconds = optional(entries, KEY_LEAD_SECONDS)?
        .map(|value| value.as_u64().ok_or(ScheduleError::InvalidPayload))
        .transpose()?;
    let series_ref = optional(entries, KEY_SERIES_REF)?
        .map(decode_entity_ref)
        .transpose()?;
    let occurrence = optional(entries, KEY_OCCURRENCE)?
        .map(decode_occurrence)
        .transpose()?;
    if series_ref.is_some() != occurrence.is_some() {
        return Err(ScheduleError::InvalidPayload);
    }
    if let Some(occurrence) = occurrence {
        occurrence.validate().map_err(|_| ScheduleError::InvalidPayload)?;
    }
    Ok(CommitmentSchedulePayload {
        schedule,
        lead_seconds,
        series_ref,
        occurrence,
    })
}

/// Structural bounds a schedule must satisfy before it is written. Kept out of
/// the enum itself: the contract crate owns the wire shape, this crate owns
/// what the evaluator can actually honour.
pub(super) fn validate_schedule(schedule: &Schedule) -> ScheduleResult<()> {
    match schedule {
        Schedule::Once { .. } => Ok(()),
        Schedule::Interval { period, .. } => {
            if *period == 0 {
                return Err(ScheduleError::Invalid(
                    "interval schedule period must be positive",
                ));
            }
            Ok(())
        }
        Schedule::Quota { count, window } => {
            validate_quota_count(*count)?;
            let QuotaWindow::IsoWeek { tz } = window;
            bounded_string(tz, "quota window tz must be non-empty and bounded")
        }
        Schedule::Rrule { rrule_string, tz } => {
            bounded_string(rrule_string, "rrule text must be non-empty and bounded")?;
            bounded_string(tz, "rrule tz must be non-empty and bounded")
        }
    }
}

fn bounded_string(value: &str, reason: &'static str) -> ScheduleResult<()> {
    if value.is_empty() || value.len() > COMMITMENT_SCHEDULE_STRING_MAX_BYTES {
        return Err(ScheduleError::Invalid(reason));
    }
    Ok(())
}

fn encode_schedule(schedule: &Schedule) -> Value {
    match schedule {
        Schedule::Once { due } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(KIND_ONCE)),
            (Value::from(ONCE_KEYS[1]), Value::from(*due)),
        ]),
        Schedule::Interval { period, anchor } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(KIND_INTERVAL)),
            (Value::from(INTERVAL_KEYS[1]), Value::from(*period)),
            (Value::from(INTERVAL_KEYS[2]), Value::from(*anchor)),
        ]),
        Schedule::Quota { count, window } => {
            let QuotaWindow::IsoWeek { tz } = window;
            Value::Map(vec![
                (Value::from(KEY_KIND), Value::from(KIND_QUOTA)),
                (Value::from(QUOTA_KEYS[1]), Value::from(*count)),
                (
                    Value::from(QUOTA_KEYS[2]),
                    Value::Map(vec![
                        (Value::from(KEY_KIND), Value::from(KIND_ISO_WEEK)),
                        (Value::from(ISO_WEEK_KEYS[1]), Value::from(tz.as_str())),
                    ]),
                ),
            ])
        }
        Schedule::Rrule { rrule_string, tz } => Value::Map(vec![
            (Value::from(KEY_KIND), Value::from(KIND_RRULE)),
            (
                Value::from(RRULE_KEYS[1]),
                Value::from(rrule_string.as_str()),
            ),
            (Value::from(RRULE_KEYS[2]), Value::from(tz.as_str())),
        ]),
    }
}

fn decode_schedule(value: &Value) -> ScheduleResult<Schedule> {
    let entries = map_entries(value)?;
    let kind = required(entries, KEY_KIND)?
        .as_str()
        .ok_or(ScheduleError::InvalidPayload)?
        .to_owned();
    let schedule = match kind.as_str() {
        KIND_ONCE => {
            check_keys(entries, &ONCE_KEYS)?;
            Schedule::Once {
                due: u64_at(entries, ONCE_KEYS[1])?,
            }
        }
        KIND_INTERVAL => {
            check_keys(entries, &INTERVAL_KEYS)?;
            Schedule::Interval {
                period: u64_at(entries, INTERVAL_KEYS[1])?,
                anchor: u64_at(entries, INTERVAL_KEYS[2])?,
            }
        }
        KIND_QUOTA => {
            check_keys(entries, &QUOTA_KEYS)?;
            let count = u32::try_from(u64_at(entries, QUOTA_KEYS[1])?)
                .map_err(|_| ScheduleError::Invalid("quota count exceeds maximum"))?;
            Schedule::Quota {
                count,
                window: decode_quota_window(required(entries, QUOTA_KEYS[2])?)?,
            }
        }
        KIND_RRULE => {
            check_keys(entries, &RRULE_KEYS)?;
            // Decodes, never evaluates: the rule text is carried verbatim and
            // handed to the calendar layer. No parser is vendored here.
            Schedule::Rrule {
                rrule_string: string_at(entries, RRULE_KEYS[1])?,
                tz: string_at(entries, RRULE_KEYS[2])?,
            }
        }
        _ => return Err(ScheduleError::InvalidPayload),
    };
    validate_schedule(&schedule)?;
    Ok(schedule)
}

fn decode_quota_window(value: &Value) -> ScheduleResult<QuotaWindow> {
    let entries = map_entries(value)?;
    check_keys(entries, &ISO_WEEK_KEYS)?;
    if required(entries, KEY_KIND)?.as_str() != Some(KIND_ISO_WEEK) {
        return Err(ScheduleError::InvalidPayload);
    }
    Ok(QuotaWindow::IsoWeek {
        tz: string_at(entries, ISO_WEEK_KEYS[1])?,
    })
}

fn encode_occurrence(occurrence: CommitmentOccurrence) -> Value {
    Value::Map(vec![
        (
            Value::from(OCCURRENCE_KEYS[0]),
            Value::from(occurrence.due_at),
        ),
        (
            Value::from(OCCURRENCE_KEYS[1]),
            Value::from(occurrence.window.start),
        ),
        (
            Value::from(OCCURRENCE_KEYS[2]),
            Value::from(occurrence.window.end),
        ),
        (
            Value::from(OCCURRENCE_KEYS[3]),
            Value::from(occurrence.ordinal),
        ),
    ])
}

fn decode_occurrence(value: &Value) -> ScheduleResult<CommitmentOccurrence> {
    let entries = map_entries(value)?;
    check_keys(entries, &OCCURRENCE_KEYS)?;
    Ok(CommitmentOccurrence {
        due_at: u64_at(entries, OCCURRENCE_KEYS[0])?,
        window: TimeRange {
            start: u64_at(entries, OCCURRENCE_KEYS[1])?,
            end: u64_at(entries, OCCURRENCE_KEYS[2])?,
        },
        ordinal: u32::try_from(u64_at(entries, OCCURRENCE_KEYS[3])?)
            .map_err(|_| ScheduleError::InvalidPayload)?,
    })
}

fn decode_entity_ref(value: &Value) -> ScheduleResult<EntityId> {
    let hex = value.as_str().ok_or(ScheduleError::InvalidPayload)?;
    if hex.chars().any(|c| c.is_ascii_uppercase()) {
        // Lower-case hex is the pinned spelling. Accepting both would let one
        // id have two encodings and two hashes.
        return Err(ScheduleError::InvalidPayload);
    }
    EntityId::from_hex(hex).map_err(|_| ScheduleError::InvalidPayload)
}

fn map_entries(value: &Value) -> ScheduleResult<&[(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(ScheduleError::InvalidPayload),
    }
}

/// Exact key-set equality: no unknown key, no missing key, no duplicate.
fn check_keys(entries: &[(Value, Value)], expected: &[&str]) -> ScheduleResult<()> {
    if entries.len() != expected.len() {
        return Err(ScheduleError::InvalidPayload);
    }
    for (index, (key, _)) in entries.iter().enumerate() {
        let key = key.as_str().ok_or(ScheduleError::InvalidPayload)?;
        if !expected.contains(&key) {
            return Err(ScheduleError::InvalidPayload);
        }
        if entries[..index]
            .iter()
            .any(|(seen, _)| seen.as_str() == Some(key))
        {
            return Err(ScheduleError::InvalidPayload);
        }
    }
    Ok(())
}

fn required<'a>(entries: &'a [(Value, Value)], key: &str) -> ScheduleResult<&'a Value> {
    let value = entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or(ScheduleError::InvalidPayload)?;
    if matches!(value, Value::Nil) {
        return Err(ScheduleError::InvalidPayload);
    }
    Ok(value)
}

/// The three optional wrapper fields: present-and-`Nil` means absent, and this
/// is the ONLY place `Nil` is tolerated.
fn optional<'a>(entries: &'a [(Value, Value)], key: &str) -> ScheduleResult<Option<&'a Value>> {
    let value = entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or(ScheduleError::InvalidPayload)?;
    Ok((!matches!(value, Value::Nil)).then_some(value))
}

fn u64_at(entries: &[(Value, Value)], key: &str) -> ScheduleResult<u64> {
    required(entries, key)?
        .as_u64()
        .ok_or(ScheduleError::InvalidPayload)
}

fn string_at(entries: &[(Value, Value)], key: &str) -> ScheduleResult<String> {
    Ok(required(entries, key)?
        .as_str()
        .ok_or(ScheduleError::InvalidPayload)?
        .to_owned())
}
