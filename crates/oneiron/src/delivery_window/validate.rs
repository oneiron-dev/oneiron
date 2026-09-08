//! Claim-body structural validation and map-extraction helpers.

use rmpv::Value;

use crate::claim::{ClaimBody, ClaimSubject};
use crate::error::{Error, Result};

use super::evaluate::normalize_channel_key;
use super::types::{
    DELIVERY_WINDOW_CLAIM_PREDICATES, DELIVERY_WINDOW_SCHEMA_VERSION, DeliveryWindowAppliesTo,
    DeliveryWindowContextCondition, KEY_APPLIES_TO, KEY_CHANNEL, KEY_REASON, KEY_SCHEMA_VERSION,
    KEY_TZ, KEY_WHEN, KEY_WINDOW, MAX_CHANNEL_BYTES, MAX_REASON_BYTES,
    PREDICATE_DELIVERY_WINDOW_CHANNEL, PREDICATE_DELIVERY_WINDOW_CONTEXT,
    PREDICATE_DELIVERY_WINDOW_QUIET,
};
use super::window::decode_time_window;

#[must_use]
pub fn is_delivery_window_claim_predicate(predicate: &str) -> bool {
    DELIVERY_WINDOW_CLAIM_PREDICATES.contains(&predicate)
}

pub(crate) fn validate_delivery_window_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(invalid_claim(
            "delivery_window claim subject must be an entity",
        ));
    }
    if !is_delivery_window_claim_predicate(&body.predicate) {
        return Err(invalid_claim("unknown delivery_window claim predicate"));
    }
    let entries = value_map(&body.value)?;
    require_schema_version(entries)?;
    let applies_to = required_str(entries, KEY_APPLIES_TO)?;
    if DeliveryWindowAppliesTo::parse(applies_to) != Some(DeliveryWindowAppliesTo::Interrupt) {
        return Err(invalid_claim(
            "delivery_window applies_to must be interrupt",
        ));
    }
    if let Some(reason) = optional_str(entries, KEY_REASON)?
        && (reason.is_empty() || reason.len() > MAX_REASON_BYTES)
    {
        return Err(invalid_claim("delivery_window reason is invalid"));
    }

    match body.predicate.as_str() {
        PREDICATE_DELIVERY_WINDOW_QUIET => {
            validate_keys_for_predicate(
                entries,
                &[
                    KEY_SCHEMA_VERSION,
                    KEY_APPLIES_TO,
                    KEY_WINDOW,
                    KEY_TZ,
                    KEY_REASON,
                ],
            )?;
            let window = required_value(entries, KEY_WINDOW)?;
            decode_time_window(window)?;
            if let Some(tz) = optional_str(entries, KEY_TZ)?
                && tz != "user-local"
            {
                return Err(invalid_claim("delivery_window tz is invalid"));
            }
            Ok(())
        }
        PREDICATE_DELIVERY_WINDOW_CONTEXT => {
            validate_keys_for_predicate(
                entries,
                &[KEY_SCHEMA_VERSION, KEY_APPLIES_TO, KEY_WHEN, KEY_REASON],
            )?;
            let when = required_str(entries, KEY_WHEN)?;
            DeliveryWindowContextCondition::parse(when)
                .map(|_| ())
                .ok_or_else(|| invalid_claim("delivery_window when value is unknown"))
        }
        PREDICATE_DELIVERY_WINDOW_CHANNEL => {
            validate_keys_for_predicate(
                entries,
                &[
                    KEY_SCHEMA_VERSION,
                    KEY_APPLIES_TO,
                    KEY_CHANNEL,
                    KEY_WINDOW,
                    KEY_REASON,
                ],
            )?;
            let channel = required_str(entries, KEY_CHANNEL)?;
            let normalized_channel = normalize_channel_key(channel);
            if normalized_channel.is_empty() || normalized_channel.len() > MAX_CHANNEL_BYTES {
                return Err(invalid_claim("delivery_window channel is invalid"));
            }
            if let Some(window) = optional_value(entries, KEY_WINDOW)? {
                decode_time_window(window)?;
            }
            Ok(())
        }
        _ => unreachable!("predicate membership checked above"),
    }
}

pub(super) fn value_map(value: &Value) -> Result<&[(Value, Value)]> {
    match value {
        Value::Map(entries) => {
            for (key, _) in entries {
                if key.as_str().is_none() {
                    return Err(invalid_claim("delivery_window value keys must be strings"));
                }
            }
            Ok(entries)
        }
        _ => Err(invalid_claim("delivery_window value must be a map")),
    }
}

fn validate_keys_for_predicate(entries: &[(Value, Value)], allowed: &[&str]) -> Result<()> {
    for (key, _) in entries {
        let key = key
            .as_str()
            .expect("delivery_window value_map validates string keys");
        if !allowed.contains(&key) {
            return Err(invalid_claim(
                "delivery_window value has key outside predicate variant",
            ));
        }
    }
    Ok(())
}

fn require_schema_version(entries: &[(Value, Value)]) -> Result<()> {
    match required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() {
        Some(DELIVERY_WINDOW_SCHEMA_VERSION) => Ok(()),
        _ => Err(invalid_claim(
            "delivery_window schema_version is unsupported",
        )),
    }
}

pub(super) fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    optional_value(entries, key)?.ok_or_else(|| invalid_claim("delivery_window value missing key"))
}

pub(super) fn optional_value<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
) -> Result<Option<&'a Value>> {
    let mut found = None;
    for (entry_key, value) in entries {
        if entry_key.as_str() == Some(key) {
            if found.is_some() {
                return Err(invalid_claim("delivery_window value has duplicate key"));
            }
            found = Some(value);
        }
    }
    Ok(found)
}

pub(super) fn required_str<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    optional_str(entries, key)?
        .ok_or_else(|| invalid_claim("delivery_window value missing string key"))
}

pub(super) fn optional_str<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
) -> Result<Option<&'a str>> {
    optional_value(entries, key)?
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid_claim("delivery_window value key must be string"))
        })
        .transpose()
}

pub(super) fn required_u16(entries: &[(Value, Value)], key: &str) -> Result<u16> {
    required_value(entries, key)?
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| invalid_claim("delivery_window minute value is invalid"))
}

pub(super) fn invalid_claim(message: &'static str) -> Error {
    Error::InvalidClaimBody(message)
}
