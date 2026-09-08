//! Counterparty contact MessagePack codecs, claim validators, and normalize helpers.

use super::types::{
    COUNTERPARTY_CONTACT_BODY_KEYS, COUNTERPARTY_CONTACT_CLAIM_PREDICATES,
    COUNTERPARTY_CONTACT_SCHEMA_VERSION, CounterpartyContactRecord, CounterpartyContactStatus,
    CounterpartyFirstTouch, CounterpartyOptOut, CounterpartyOptOutReason, KEY_COUNTERPARTY,
    KEY_CREATED_AT, KEY_FIRST_TOUCH, KEY_IDENTITY_REF, KEY_NOTES, KEY_OPT_OUT, KEY_OPT_OUT_REASON,
    KEY_OPT_OUT_RECEIPT_REASON, KEY_OPT_OUT_RECORDED_AT, KEY_PROMO_CONSENT, KEY_REVOKED_AT,
    KEY_SCHEMA_VERSION, KEY_STATUS, KEY_UPDATED_AT, MAX_COUNTERPARTY_BYTES, MAX_NOTE_BYTES,
    MAX_NOTES, OPT_OUT_KEYS, PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY,
    PREDICATE_COUNTERPARTY_CONTACT_CREATED_AT, PREDICATE_COUNTERPARTY_CONTACT_FIRST_TOUCH,
    PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF, PREDICATE_COUNTERPARTY_CONTACT_NOTES,
    PREDICATE_COUNTERPARTY_CONTACT_OPT_OUT, PREDICATE_COUNTERPARTY_CONTACT_PROMO_CONSENT,
    PREDICATE_COUNTERPARTY_CONTACT_REVOKED_AT, PREDICATE_COUNTERPARTY_CONTACT_STATUS,
    PREDICATE_COUNTERPARTY_CONTACT_UPDATED_AT,
};
use crate::claim::{ClaimBody, ClaimSubject, MAX_PREDICATE_BYTES};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use rmpv::Value;
use std::io::Cursor;

/// Encodes a CounterpartyContactRecord body in canonical MessagePack field order.
pub fn encode_counterparty_contact_body(record: &CounterpartyContactRecord) -> Result<Vec<u8>> {
    record.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COUNTERPARTY_CONTACT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_IDENTITY_REF),
            Value::from(record.identity_ref.to_hex()),
        ),
        (
            Value::from(KEY_COUNTERPARTY),
            Value::from(record.counterparty.as_str()),
        ),
        (
            Value::from(KEY_FIRST_TOUCH),
            Value::from(record.first_touch.as_str()),
        ),
        (Value::from(KEY_STATUS), Value::from(record.status.as_str())),
        (Value::from(KEY_CREATED_AT), Value::from(record.created_at)),
        (Value::from(KEY_UPDATED_AT), Value::from(record.updated_at)),
        (
            Value::from(KEY_REVOKED_AT),
            record.revoked_at.map_or(Value::Nil, Value::from),
        ),
        (Value::from(KEY_OPT_OUT), encode_opt_out(record.opt_out)),
        (
            Value::from(KEY_PROMO_CONSENT),
            Value::Boolean(record.promo_consent),
        ),
        (Value::from(KEY_NOTES), encode_notes(&record.notes)),
    ]);

    encode_msgpack_value(
        &value,
        "counterparty contact body MessagePack encode failed",
    )
}

/// Decodes and validates a CounterpartyContactRecord body.
pub fn decode_counterparty_contact_body(bytes: &[u8]) -> Result<CounterpartyContactRecord> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_contact())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_contact());
    }

    decode_counterparty_contact_value(&value)
}

pub(super) fn decode_counterparty_contact_value(
    value: &Value,
) -> Result<CounterpartyContactRecord> {
    let Value::Map(entries) = value else {
        return Err(invalid_contact());
    };
    validate_keys(entries, &COUNTERPARTY_CONTACT_BODY_KEYS)?;

    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64()
        != Some(COUNTERPARTY_CONTACT_SCHEMA_VERSION)
    {
        return Err(invalid_contact());
    }

    let identity_ref = decode_entity_ref(required_value(entries, KEY_IDENTITY_REF)?)?;
    let counterparty = required_string(entries, KEY_COUNTERPARTY)?.to_owned();
    let first_touch = CounterpartyFirstTouch::parse(required_string(entries, KEY_FIRST_TOUCH)?)
        .ok_or_else(invalid_contact)?;
    let status = CounterpartyContactStatus::parse(required_string(entries, KEY_STATUS)?)
        .ok_or_else(invalid_contact)?;
    let created_at = required_value(entries, KEY_CREATED_AT)?
        .as_u64()
        .ok_or_else(invalid_contact)?;
    let updated_at = required_value(entries, KEY_UPDATED_AT)?
        .as_u64()
        .ok_or_else(invalid_contact)?;
    let revoked_value = required_value(entries, KEY_REVOKED_AT)?;
    let revoked_at = if matches!(revoked_value, Value::Nil) {
        None
    } else {
        Some(revoked_value.as_u64().ok_or_else(invalid_contact)?)
    };
    let opt_out = decode_opt_out(required_value(entries, KEY_OPT_OUT)?)?;
    let promo_consent = match required_value(entries, KEY_PROMO_CONSENT)? {
        Value::Boolean(value) => *value,
        _ => return Err(invalid_contact()),
    };
    let notes = decode_notes(required_value(entries, KEY_NOTES)?)?;

    let record = CounterpartyContactRecord {
        identity_ref,
        counterparty,
        first_touch,
        status,
        created_at,
        updated_at,
        revoked_at,
        opt_out,
        promo_consent,
        notes,
    };
    record.validate()?;
    Ok(record)
}

/// Returns whether `predicate` belongs to the CounterpartyContact claim family.
#[must_use]
pub fn is_counterparty_contact_claim_predicate(predicate: &str) -> bool {
    COUNTERPARTY_CONTACT_CLAIM_PREDICATES.contains(&predicate)
}

/// Validates one `counterparty_contact.*` claim body.
pub(crate) fn validate_counterparty_contact_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "counterparty_contact claim subject must be an entity",
        ));
    }
    if !is_counterparty_contact_claim_predicate(&body.predicate) {
        return Err(Error::InvalidClaimBody(
            "unknown counterparty_contact claim predicate",
        ));
    }
    if body.predicate.len() > MAX_PREDICATE_BYTES {
        return Err(Error::InvalidClaimBody(
            "counterparty_contact predicate exceeds max predicate bytes",
        ));
    }

    match body.predicate.as_str() {
        PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF => decode_entity_ref(&body.value)
            .map(|_| ())
            .map_err(|_| Error::InvalidClaimBody("counterparty_contact identity_ref invalid")),
        PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY => validate_claim_string(
            &body.value,
            MAX_COUNTERPARTY_BYTES,
            "counterparty_contact.counterparty value must be non-empty string",
        ),
        PREDICATE_COUNTERPARTY_CONTACT_FIRST_TOUCH => body
            .value
            .as_str()
            .and_then(CounterpartyFirstTouch::parse)
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "counterparty_contact.first_touch value must be pinned",
            )),
        PREDICATE_COUNTERPARTY_CONTACT_STATUS => body
            .value
            .as_str()
            .and_then(CounterpartyContactStatus::parse)
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "counterparty_contact.status value must be active|revoked",
            )),
        PREDICATE_COUNTERPARTY_CONTACT_CREATED_AT | PREDICATE_COUNTERPARTY_CONTACT_UPDATED_AT => {
            body.value
                .as_u64()
                .map(|_| ())
                .ok_or(Error::InvalidClaimBody(
                    "counterparty_contact timestamp value must be u64",
                ))
        }
        PREDICATE_COUNTERPARTY_CONTACT_REVOKED_AT => {
            if matches!(body.value, Value::Nil) || body.value.as_u64().is_some() {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "counterparty_contact.revoked_at value must be nil or u64",
                ))
            }
        }
        PREDICATE_COUNTERPARTY_CONTACT_OPT_OUT => decode_opt_out(&body.value)
            .map(|_| ())
            .map_err(|_| Error::InvalidClaimBody("counterparty_contact.opt_out invalid")),
        PREDICATE_COUNTERPARTY_CONTACT_PROMO_CONSENT => {
            if matches!(body.value, Value::Boolean(_)) {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "counterparty_contact.promo_consent value must be boolean",
                ))
            }
        }
        PREDICATE_COUNTERPARTY_CONTACT_NOTES => validate_notes_value(&body.value),
        _ => unreachable!("predicate membership checked above"),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_counterparty_contact_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_counterparty_contact_body(bytes).map(|_| ())
}

/// The body field one `counterparty_contact.*` predicate projects.
pub(super) fn counterparty_contact_body_key(predicate: &str) -> &'static str {
    match predicate {
        PREDICATE_COUNTERPARTY_CONTACT_IDENTITY_REF => KEY_IDENTITY_REF,
        PREDICATE_COUNTERPARTY_CONTACT_COUNTERPARTY => KEY_COUNTERPARTY,
        PREDICATE_COUNTERPARTY_CONTACT_FIRST_TOUCH => KEY_FIRST_TOUCH,
        PREDICATE_COUNTERPARTY_CONTACT_STATUS => KEY_STATUS,
        PREDICATE_COUNTERPARTY_CONTACT_CREATED_AT => KEY_CREATED_AT,
        PREDICATE_COUNTERPARTY_CONTACT_UPDATED_AT => KEY_UPDATED_AT,
        PREDICATE_COUNTERPARTY_CONTACT_REVOKED_AT => KEY_REVOKED_AT,
        PREDICATE_COUNTERPARTY_CONTACT_OPT_OUT => KEY_OPT_OUT,
        PREDICATE_COUNTERPARTY_CONTACT_PROMO_CONSENT => KEY_PROMO_CONSENT,
        PREDICATE_COUNTERPARTY_CONTACT_NOTES => KEY_NOTES,
        _ => unreachable!("predicate drawn from the counterparty contact family"),
    }
}

pub(super) fn encode_opt_out(opt_out: Option<CounterpartyOptOut>) -> Value {
    opt_out.map_or(Value::Nil, |opt_out| {
        Value::Map(vec![
            (
                Value::from(KEY_OPT_OUT_REASON),
                Value::from(opt_out.reason.as_str()),
            ),
            (
                Value::from(KEY_OPT_OUT_RECORDED_AT),
                Value::from(opt_out.recorded_at),
            ),
            (
                Value::from(KEY_OPT_OUT_RECEIPT_REASON),
                Value::from(opt_out.receipt_reason()),
            ),
        ])
    })
}

fn decode_opt_out(value: &Value) -> Result<Option<CounterpartyOptOut>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    let Value::Map(entries) = value else {
        return Err(invalid_contact());
    };
    validate_keys(entries, &OPT_OUT_KEYS)?;
    let reason = required_value(entries, KEY_OPT_OUT_REASON)?
        .as_str()
        .and_then(CounterpartyOptOutReason::parse)
        .ok_or_else(invalid_contact)?;
    let recorded_at = required_value(entries, KEY_OPT_OUT_RECORDED_AT)?
        .as_u64()
        .ok_or_else(invalid_contact)?;
    if required_value(entries, KEY_OPT_OUT_RECEIPT_REASON)?.as_str()
        != Some(reason.receipt_reason())
    {
        return Err(invalid_contact());
    }
    Ok(Some(CounterpartyOptOut {
        reason,
        recorded_at,
    }))
}

pub(super) fn encode_notes(notes: &[String]) -> Value {
    Value::Array(
        notes
            .iter()
            .map(|note| Value::from(note.as_str()))
            .collect(),
    )
}

fn decode_notes(value: &Value) -> Result<Vec<String>> {
    let Value::Array(values) = value else {
        return Err(invalid_contact());
    };
    let notes = values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(invalid_contact)
        })
        .collect::<Result<Vec<_>>>()?;
    validate_notes(&notes)?;
    Ok(notes)
}

fn validate_notes_value(value: &Value) -> Result<()> {
    decode_notes(value)
        .map(|_| ())
        .map_err(|_| Error::InvalidClaimBody("counterparty_contact.notes invalid"))
}

pub(super) fn validate_notes(notes: &[String]) -> Result<()> {
    if notes.len() > MAX_NOTES {
        return Err(invalid_contact());
    }
    for note in notes {
        validate_note(note)?;
    }
    Ok(())
}

pub(super) fn normalize_counterparty(value: String) -> Result<String> {
    let trimmed = value.trim().to_owned();
    validate_counterparty(&trimmed)?;
    Ok(trimmed)
}

pub(super) fn validate_counterparty(value: &str) -> Result<()> {
    validate_non_empty_bounded(
        value,
        MAX_COUNTERPARTY_BYTES,
        "counterparty must be non-empty and at most 512 bytes",
    )
}

pub(super) fn normalize_note(value: String) -> Result<String> {
    let trimmed = value.trim().to_owned();
    validate_note(&trimmed)?;
    Ok(trimmed)
}

fn validate_note(value: &str) -> Result<()> {
    validate_non_empty_bounded(
        value,
        MAX_NOTE_BYTES,
        "note must be non-empty and at most 2048 bytes",
    )
}

fn validate_claim_string(value: &Value, max_bytes: usize, reason: &'static str) -> Result<()> {
    let Some(value) = value.as_str() else {
        return Err(Error::InvalidClaimBody(reason));
    };
    if value.trim().is_empty() || value.trim() != value || value.len() > max_bytes {
        Err(Error::InvalidClaimBody(reason))
    } else {
        Ok(())
    }
}

fn validate_non_empty_bounded(value: &str, max: usize, reason: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.trim() != value || value.len() > max {
        Err(Error::InvalidCounterpartyContactBody(reason))
    } else {
        Ok(())
    }
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_contact)?;
    EntityId::from_hex(hex).map_err(|_| invalid_contact())
}

fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    required_value(entries, key)?
        .as_str()
        .ok_or_else(invalid_contact)
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_contact)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_contact());
        };
        if seen[index] {
            return Err(invalid_contact());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_contact())
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_contact)
}

fn encode_msgpack_value(value: &Value, reason: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(reason))?;
    Ok(out)
}

pub(super) fn invalid_contact() -> Error {
    Error::InvalidCounterpartyContactBody("body failed validation")
}
