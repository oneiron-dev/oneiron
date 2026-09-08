//! Calendar claim validation dispatch plus MessagePack encode/decode and field helpers.

use rmpv::Value;

use super::predicates::{
    CONTENT_HASH_LEN, MAX_RRULE_BYTES, MAX_TEXT_BYTES, PREDICATE_CALENDAR_ATTENDEE,
    PREDICATE_CALENDAR_MEETING_LINK, PREDICATE_CALENDAR_ORIGIN, PREDICATE_CALENDAR_PASSPORT,
    PREDICATE_CALENDAR_RRULE, PREDICATE_CALENDAR_SERIES_EXCEPTION,
    PREDICATE_CALENDAR_SERIES_MASTER, PREDICATE_CALENDAR_STATUS, PREDICATE_CALENDAR_SUCCESSOR,
    PREDICATE_CALENDAR_TIME_KIND, PREDICATE_CALENDAR_TZ, PREDICATE_CALENDAR_WALL_TIME,
    is_calendar_claim_predicate,
};
use super::values::{
    CalendarAttendeeValue, CalendarBusyTransparency, CalendarOrigin, CalendarPassportDirection,
    CalendarPassportPresence, CalendarPassportValue, CalendarSeriesExceptionValue,
    CalendarSeriesMasterValue, CalendarStatus, CalendarStatusBasis, CalendarStatusValue,
    CalendarSuccessorValue, CalendarTimeKind, CalendarTimeKindValue, CalendarWallTimeValue,
};
use crate::Vault;
use crate::calendar::outcome::{
    EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue, PREDICATE_CALENDAR_EVENT_OUTCOME,
};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_EVENT;

pub(super) const KEY_KIND: &str = "kind";

pub(super) const KEY_BUSY_TRANSPARENCY: &str = "busy_transparency";

pub(super) const KEY_YEAR: &str = "y";

pub(super) const KEY_MONTH: &str = "mo";

pub(super) const KEY_DAY: &str = "d";

pub(super) const KEY_HOUR: &str = "h";

pub(super) const KEY_MINUTE: &str = "mi";

pub(super) const KEY_SECOND: &str = "s";

pub(super) const KEY_RRULE: &str = "rrule";

pub(super) const KEY_DTSTART_UTC: &str = "dtstart_utc";

pub(super) const KEY_TZ: &str = "tz";

pub(super) const KEY_MASTER_REF: &str = "master_ref";

pub(super) const KEY_UID: &str = "uid";

pub(super) const KEY_ORIGINAL_START_UTC: &str = "original_start_utc";

pub(super) const KEY_PREDECESSOR_REF: &str = "predecessor_ref";

pub(super) const KEY_WHO: &str = "who";

pub(super) const KEY_ROLE: &str = "role";

pub(super) const KEY_PARTSTAT: &str = "partstat";

pub(super) const KEY_SYSTEM: &str = "system";

pub(super) const KEY_LAST_SEQUENCE: &str = "last_sequence";

pub(super) const KEY_CONTENT_HASH: &str = "content_hash";

pub(super) const KEY_DIRECTION: &str = "direction";

pub(super) const KEY_LAST_SEEN_AT: &str = "last_seen_at";

pub(super) const KEY_PRESENCE: &str = "presence";

pub(super) const KEY_STATUS: &str = "status";

pub(super) const KEY_BASIS: &str = "basis";

pub(super) const KEY_RECORDED_AT: &str = "recorded_at";

pub(super) const KEY_OUTCOME: &str = "outcome";

/// Asserts that a calendar claim's subject is an existing EVENT row.
///
/// The byte-level validator chain cannot reach storage, so this is the
/// store-aware half of the EVENT-subject law, mirroring the `comm.rs`
/// PERSON-subject precedent. Calendar writers call it before staging a write;
/// generic subject-existence enforcement at the write doors stays unchanged.
///
/// Public because the writers that call it land in later CAL layers: CAL-02's
/// feed diff, CAL-04's invite path, and CAL-07's outcome path each assert the
/// subject here rather than re-deriving the EVENT rule.
#[must_use = "the EVENT-subject assertion must be propagated, not discarded"]
pub fn require_event_subject(vault: &Vault, subject: &EntityId) -> Result<()> {
    if vault.get_entity_type(subject)? != Some(ENTITY_TYPE_EVENT) {
        return Err(Error::EntityNotFound);
    }
    Ok(())
}

/// Validates one `calendar.*` claim subject and value shape.
///
/// Structural only: IANA zones are not resolved and RRULEs are not parsed at
/// this layer. Every value is an exact key set with no extras, except the two
/// documented back-compat defaults (`busy_transparency` and `presence`).
pub(crate) fn validate_calendar_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(invalid_claim("calendar claim subject must be an entity"));
    }
    if !is_calendar_claim_predicate(&body.predicate) {
        return Err(invalid_claim("unknown calendar claim predicate"));
    }
    match body.predicate.as_str() {
        PREDICATE_CALENDAR_TIME_KIND => decode_time_kind_value(&body.value).map(|_| ()),
        PREDICATE_CALENDAR_WALL_TIME => decode_wall_time_value(&body.value).map(|_| ()),
        PREDICATE_CALENDAR_TZ => {
            validate_bounded_text(as_str(&body.value, "calendar.tz must be a string")?, "tz")
        }
        PREDICATE_CALENDAR_RRULE => {
            let rrule = as_str(&body.value, "calendar.rrule must be a string")?;
            validate_rrule_text(rrule)
        }
        PREDICATE_CALENDAR_SERIES_MASTER => decode_series_master_value(&body.value).map(|_| ()),
        PREDICATE_CALENDAR_SERIES_EXCEPTION => {
            decode_series_exception_value(&body.value).map(|_| ())
        }
        PREDICATE_CALENDAR_SUCCESSOR => decode_successor_value(&body.value).map(|_| ()),
        PREDICATE_CALENDAR_ATTENDEE => decode_attendee_value(&body.value).map(|_| ()),
        PREDICATE_CALENDAR_MEETING_LINK => {
            let link = as_str(&body.value, "calendar.meeting_link must be a string")?;
            validate_meeting_link(link)
        }
        PREDICATE_CALENDAR_PASSPORT => decode_passport_value(&body.value).map(|_| ()),
        PREDICATE_CALENDAR_ORIGIN => {
            let origin = as_str(&body.value, "calendar.origin must be a string")?;
            CalendarOrigin::parse(origin)
                .map(|_| ())
                .ok_or_else(|| invalid_claim("calendar.origin is invalid"))
        }
        PREDICATE_CALENDAR_STATUS => decode_status_value(&body.value).map(|_| ()),
        PREDICATE_CALENDAR_EVENT_OUTCOME => decode_event_outcome_value(&body.value).map(|_| ()),
        _ => unreachable!("predicate membership checked above"),
    }
}

/// Decodes a `calendar.time_kind` value.
///
/// A missing `busy_transparency` key decodes as [`CalendarBusyTransparency::Busy`]
/// for back-compat; new writes include it.
pub(crate) fn decode_time_kind_value(value: &Value) -> Result<CalendarTimeKindValue> {
    let entries = value_map(value)?;
    validate_keys(entries, &[KEY_KIND, KEY_BUSY_TRANSPARENCY], &[KEY_KIND])?;
    let kind = CalendarTimeKind::parse(required_string(entries, KEY_KIND)?)
        .ok_or_else(|| invalid_claim("calendar time_kind kind is invalid"))?;
    let busy_transparency = match optional_string(entries, KEY_BUSY_TRANSPARENCY)? {
        Some(token) => CalendarBusyTransparency::parse(token)
            .ok_or_else(|| invalid_claim("calendar busy_transparency is invalid"))?,
        None => CalendarBusyTransparency::default(),
    };
    Ok(CalendarTimeKindValue {
        kind,
        busy_transparency,
    })
}

/// Decodes a `calendar.wall_time` value.
///
/// Field ranges are checked structurally; this is storage, not a calendar
/// computation, so day-of-month is not validated against the month.
pub(crate) fn decode_wall_time_value(value: &Value) -> Result<CalendarWallTimeValue> {
    let entries = value_map(value)?;
    let keys = [
        KEY_YEAR, KEY_MONTH, KEY_DAY, KEY_HOUR, KEY_MINUTE, KEY_SECOND,
    ];
    validate_keys(entries, &keys, &keys)?;
    Ok(CalendarWallTimeValue {
        y: required_i32(entries, KEY_YEAR)?,
        mo: required_u8_in_range(entries, KEY_MONTH, 1, 12)?,
        d: required_u8_in_range(entries, KEY_DAY, 1, 31)?,
        h: required_u8_in_range(entries, KEY_HOUR, 0, 23)?,
        mi: required_u8_in_range(entries, KEY_MINUTE, 0, 59)?,
        s: required_u8_in_range(entries, KEY_SECOND, 0, 60)?,
    })
}

/// Decodes a `calendar.series_master` value.
pub(crate) fn decode_series_master_value(value: &Value) -> Result<CalendarSeriesMasterValue> {
    let entries = value_map(value)?;
    let keys = [KEY_RRULE, KEY_DTSTART_UTC, KEY_TZ];
    validate_keys(entries, &keys, &keys)?;
    let rrule = required_string(entries, KEY_RRULE)?;
    validate_rrule_text(rrule)?;
    let tz = required_string(entries, KEY_TZ)?;
    validate_bounded_text(tz, "tz")?;
    Ok(CalendarSeriesMasterValue {
        rrule: rrule.to_owned(),
        dtstart_utc: required_u64(entries, KEY_DTSTART_UTC)?,
        tz: tz.to_owned(),
    })
}

/// Decodes a `calendar.series_exception` value.
pub(crate) fn decode_series_exception_value(value: &Value) -> Result<CalendarSeriesExceptionValue> {
    let entries = value_map(value)?;
    let keys = [KEY_MASTER_REF, KEY_UID, KEY_ORIGINAL_START_UTC];
    validate_keys(entries, &keys, &keys)?;
    let uid = required_string(entries, KEY_UID)?;
    validate_bounded_text(uid, "uid")?;
    Ok(CalendarSeriesExceptionValue {
        master_ref: required_entity_ref(entries, KEY_MASTER_REF)?,
        uid: uid.to_owned(),
        original_start_utc: required_u64(entries, KEY_ORIGINAL_START_UTC)?,
    })
}

/// Decodes a `calendar.successor` value.
pub(crate) fn decode_successor_value(value: &Value) -> Result<CalendarSuccessorValue> {
    let entries = value_map(value)?;
    validate_keys(entries, &[KEY_PREDECESSOR_REF], &[KEY_PREDECESSOR_REF])?;
    Ok(CalendarSuccessorValue {
        predecessor_ref: required_entity_ref(entries, KEY_PREDECESSOR_REF)?,
    })
}

/// Decodes a `calendar.attendee` value, preserving vendor role/partstat text.
pub(crate) fn decode_attendee_value(value: &Value) -> Result<CalendarAttendeeValue> {
    let entries = value_map(value)?;
    let keys = [KEY_WHO, KEY_ROLE, KEY_PARTSTAT];
    validate_keys(entries, &keys, &keys)?;
    let who = required_string(entries, KEY_WHO)?;
    let role = required_string(entries, KEY_ROLE)?;
    let partstat = required_string(entries, KEY_PARTSTAT)?;
    validate_bounded_text(who, "who")?;
    validate_bounded_text(role, "role")?;
    validate_bounded_text(partstat, "partstat")?;
    Ok(CalendarAttendeeValue {
        who: who.to_owned(),
        role: role.to_owned(),
        partstat: partstat.to_owned(),
    })
}

/// Decodes a `calendar.passport` value.
///
/// A missing `presence` key decodes as [`CalendarPassportPresence::Live`] for
/// back-compat; new writes include it. The content hash is MessagePack binary
/// of exactly 32 bytes.
pub(crate) fn decode_passport_value(value: &Value) -> Result<CalendarPassportValue> {
    let entries = value_map(value)?;
    let required = [
        KEY_SYSTEM,
        KEY_UID,
        KEY_LAST_SEQUENCE,
        KEY_CONTENT_HASH,
        KEY_DIRECTION,
        KEY_LAST_SEEN_AT,
    ];
    let mut allowed = required.to_vec();
    allowed.push(KEY_PRESENCE);
    validate_keys(entries, &allowed, &required)?;
    let system = required_string(entries, KEY_SYSTEM)?;
    let uid = required_string(entries, KEY_UID)?;
    validate_bounded_text(system, "system")?;
    validate_bounded_text(uid, "uid")?;
    let direction = CalendarPassportDirection::parse(required_string(entries, KEY_DIRECTION)?)
        .ok_or_else(|| invalid_claim("calendar passport direction is invalid"))?;
    let presence = match optional_string(entries, KEY_PRESENCE)? {
        Some(token) => CalendarPassportPresence::parse(token)
            .ok_or_else(|| invalid_claim("calendar passport presence is invalid"))?,
        None => CalendarPassportPresence::default(),
    };
    Ok(CalendarPassportValue {
        system: system.to_owned(),
        uid: uid.to_owned(),
        last_sequence: required_u32(entries, KEY_LAST_SEQUENCE)?,
        content_hash: required_binary_32(entries, KEY_CONTENT_HASH)?,
        direction,
        last_seen_at: required_u64(entries, KEY_LAST_SEEN_AT)?,
        presence,
    })
}

/// Decodes a `calendar.status` value.
pub(crate) fn decode_status_value(value: &Value) -> Result<CalendarStatusValue> {
    let entries = value_map(value)?;
    let keys = [KEY_STATUS, KEY_BASIS, KEY_RECORDED_AT];
    validate_keys(entries, &keys, &keys)?;
    let status = CalendarStatus::parse(required_string(entries, KEY_STATUS)?)
        .ok_or_else(|| invalid_claim("calendar status is invalid"))?;
    let basis = CalendarStatusBasis::parse(required_string(entries, KEY_BASIS)?)
        .ok_or_else(|| invalid_claim("calendar status basis is invalid"))?;
    Ok(CalendarStatusValue {
        status,
        basis,
        recorded_at: required_u64(entries, KEY_RECORDED_AT)?,
    })
}

/// Encodes a [`EventOutcomeClaimValue`] into the exact wire map
/// [`decode_event_outcome_value`] accepts.
///
/// The write half of the CAL-07 codec, and the only way an outcome writer builds
/// the value: without it, every writer would re-spell this module's key literals
/// and the closed token sets, which is exactly how a family's wire shape drifts.
#[must_use]
pub(crate) fn encode_event_outcome_value(value: &EventOutcomeClaimValue) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_OUTCOME),
            Value::from(value.outcome.as_str()),
        ),
        (Value::from(KEY_BASIS), Value::from(value.basis.as_str())),
        (Value::from(KEY_RECORDED_AT), Value::from(value.recorded_at)),
    ])
}

/// Decodes a `calendar.event_outcome` value.
///
/// Exact key set, closed token sets, and a `u64` `recorded_at`: an outcome token
/// this layer does not know must never decode as one it does.
pub(crate) fn decode_event_outcome_value(value: &Value) -> Result<EventOutcomeClaimValue> {
    let entries = value_map(value)?;
    let keys = [KEY_OUTCOME, KEY_BASIS, KEY_RECORDED_AT];
    validate_keys(entries, &keys, &keys)?;
    Ok(EventOutcomeClaimValue {
        outcome: EventOutcome::parse(required_string(entries, KEY_OUTCOME)?)
            .ok_or_else(|| invalid_claim("calendar event_outcome outcome is invalid"))?,
        basis: EventOutcomeBasis::parse(required_string(entries, KEY_BASIS)?)
            .ok_or_else(|| invalid_claim("calendar event_outcome basis is invalid"))?,
        recorded_at: required_u64(entries, KEY_RECORDED_AT)?,
    })
}

fn value_map(value: &Value) -> Result<&[(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid_claim("calendar claim value must be a map")),
    }
}

fn as_str<'a>(value: &'a Value, reason: &'static str) -> Result<&'a str> {
    value.as_str().ok_or_else(|| invalid_claim(reason))
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    let mut matches = entries
        .iter()
        .filter_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value));
    let value = matches
        .next()
        .ok_or_else(|| invalid_claim("calendar value missing required key"))?;
    if matches.next().is_some() {
        return Err(invalid_claim("calendar value contains duplicate key"));
    }
    Ok(value)
}

fn optional_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a Value>> {
    if entries
        .iter()
        .any(|(candidate, _)| candidate.as_str() == Some(key))
    {
        return required_value(entries, key).map(Some);
    }
    Ok(None)
}

fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    as_str(
        required_value(entries, key)?,
        "calendar value string invalid",
    )
}

fn optional_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a str>> {
    optional_value(entries, key)?
        .map(|value| as_str(value, "calendar value string invalid"))
        .transpose()
}

fn required_u64(entries: &[(Value, Value)], key: &str) -> Result<u64> {
    required_value(entries, key)?
        .as_u64()
        .ok_or_else(|| invalid_claim("calendar value integer invalid"))
}

fn required_u32(entries: &[(Value, Value)], key: &str) -> Result<u32> {
    u32::try_from(required_u64(entries, key)?)
        .map_err(|_| invalid_claim("calendar value integer out of range"))
}

fn required_i32(entries: &[(Value, Value)], key: &str) -> Result<i32> {
    required_value(entries, key)?
        .as_i64()
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| invalid_claim("calendar value integer out of range"))
}

fn required_u8_in_range(entries: &[(Value, Value)], key: &str, min: u8, max: u8) -> Result<u8> {
    let value = u8::try_from(required_u64(entries, key)?)
        .map_err(|_| invalid_claim("calendar wall_time field out of range"))?;
    if value < min || value > max {
        return Err(invalid_claim("calendar wall_time field out of range"));
    }
    Ok(value)
}

fn required_binary_32(entries: &[(Value, Value)], key: &str) -> Result<[u8; CONTENT_HASH_LEN]> {
    let Value::Binary(bytes) = required_value(entries, key)? else {
        return Err(invalid_claim("calendar content_hash must be binary"));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_claim("calendar content_hash must be 32 bytes"))
}

fn required_entity_ref(entries: &[(Value, Value)], key: &str) -> Result<EntityId> {
    let hex = required_string(entries, key)?;
    let id =
        EntityId::from_hex(hex).map_err(|_| invalid_claim("calendar entity reference invalid"))?;
    if id.to_hex() != hex {
        return Err(invalid_claim("calendar entity reference invalid"));
    }
    Ok(id)
}

/// Rejects extra keys, missing required keys, and non-string keys.
///
/// `allowed` is the full key set; `required` is the subset that must be present.
/// The two differ only where a documented back-compat default exists.
fn validate_keys(entries: &[(Value, Value)], allowed: &[&str], required: &[&str]) -> Result<()> {
    if entries.len() > allowed.len() {
        return Err(invalid_claim("calendar value key set invalid"));
    }
    if entries
        .iter()
        .any(|(key, _)| key.as_str().is_none_or(|key| !allowed.contains(&key)))
    {
        return Err(invalid_claim("calendar value key set invalid"));
    }
    for key in required {
        required_value(entries, key)?;
    }
    Ok(())
}

/// Bounded, non-empty, control-character-free text.
fn validate_bounded_text(value: &str, _field: &'static str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(invalid_claim("calendar text field length invalid"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_claim("calendar text field has control characters"));
    }
    Ok(())
}

/// Verbatim RFC 5545 text: bounded and non-empty, never parsed at this layer.
fn validate_rrule_text(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_RRULE_BYTES {
        return Err(invalid_claim("calendar rrule length invalid"));
    }
    if value
        .chars()
        .any(|c| c.is_control() && c != '\r' && c != '\n')
    {
        return Err(invalid_claim("calendar rrule has control characters"));
    }
    Ok(())
}

/// Structural URL validation. Tolerant extraction stays an adapter concern.
fn validate_meeting_link(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(invalid_claim("calendar meeting_link length invalid"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_claim(
            "calendar meeting_link has control characters",
        ));
    }
    Ok(())
}

fn invalid_claim(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}
