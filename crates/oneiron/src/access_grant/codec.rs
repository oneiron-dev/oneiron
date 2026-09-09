//! Pinned AccessGrant body/scope key sets and fail-closed MessagePack codec.

use std::io::Cursor;

use rmpv::Value;

use crate::booking::DisclosureRung;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::record::{AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus};

/// Current AccessGrant body schema version.
pub const ACCESS_GRANT_SCHEMA_VERSION: u64 = 2;

/// Pinned on-disk MessagePack key set for AccessGrant bodies.
pub const ACCESS_GRANT_BODY_KEYS: [&str; 7] = [
    "schema_version",
    "principal_ref",
    "scope",
    "capability",
    "status",
    "created_at",
    "revoked_at",
];

pub(crate) const ACCESS_GRANT_FIELDS_MINIMAL: &[&str] = &["scope", "capability", "status"];

pub(crate) const ACCESS_GRANT_FIELDS_STANDARD: &[&str] =
    &["principal_ref", "scope", "capability", "status"];

pub(crate) const ACCESS_GRANT_FIELDS_FULL: &[&str] = &ACCESS_GRANT_BODY_KEYS;

pub(super) const KEY_SCHEMA_VERSION: &str = ACCESS_GRANT_BODY_KEYS[0];

pub(super) const KEY_PRINCIPAL_REF: &str = ACCESS_GRANT_BODY_KEYS[1];

pub(super) const KEY_SCOPE: &str = ACCESS_GRANT_BODY_KEYS[2];

pub(super) const KEY_CAPABILITY: &str = ACCESS_GRANT_BODY_KEYS[3];

pub(super) const KEY_STATUS: &str = ACCESS_GRANT_BODY_KEYS[4];

pub(super) const KEY_CREATED_AT: &str = ACCESS_GRANT_BODY_KEYS[5];

pub(super) const KEY_REVOKED_AT: &str = ACCESS_GRANT_BODY_KEYS[6];

pub(super) const SCOPE_KEY_KIND: &str = "kind";

pub(super) const SCOPE_KEYS_COMPANION_PROFILE: [&str; 3] =
    [SCOPE_KEY_KIND, "person_ref", "persona_ref"];

pub(super) const SCOPE_KEYS_CALENDAR: [&str; 3] = [SCOPE_KEY_KIND, "calendar_ref", "rung"];

pub(super) const SCOPE_KIND_COMPANION_PROFILE: &str = "companion_profile";

pub(super) const SCOPE_KIND_CALENDAR: &str = "calendar";

/// Encodes an AccessGrant body in canonical MessagePack field order.
pub fn encode_access_grant_body(grant: &AccessGrant) -> Result<Vec<u8>> {
    grant.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(ACCESS_GRANT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PRINCIPAL_REF),
            Value::from(grant.principal_ref.to_hex()),
        ),
        (Value::from(KEY_SCOPE), encode_scope(&grant.scope)),
        (
            Value::from(KEY_CAPABILITY),
            Value::from(grant.capability.as_str()),
        ),
        (Value::from(KEY_STATUS), Value::from(grant.status.as_str())),
        (Value::from(KEY_CREATED_AT), Value::from(grant.created_at)),
        (
            Value::from(KEY_REVOKED_AT),
            grant.revoked_at.map_or(Value::Nil, Value::from),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("access grant body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and validates an AccessGrant body.
pub fn decode_access_grant_body(bytes: &[u8]) -> Result<AccessGrant> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_grant())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_grant());
    }

    decode_access_grant_value(&value)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_access_grant_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_access_grant_body(bytes).map(|_| ())
}

fn decode_access_grant_value(value: &Value) -> Result<AccessGrant> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };
    validate_keys(entries, &ACCESS_GRANT_BODY_KEYS)?;

    let version = required_value(entries, KEY_SCHEMA_VERSION)?.as_u64();
    if version != Some(ACCESS_GRANT_SCHEMA_VERSION) {
        return Err(invalid_grant());
    }

    let principal_ref = decode_entity_ref(required_value(entries, KEY_PRINCIPAL_REF)?)?;
    let scope = decode_scope(required_value(entries, KEY_SCOPE)?)?;
    let capability = required_value(entries, KEY_CAPABILITY)?
        .as_str()
        .and_then(AccessGrantCapability::parse)
        .ok_or_else(invalid_grant)?;
    let status = required_value(entries, KEY_STATUS)?
        .as_str()
        .and_then(AccessGrantStatus::parse)
        .ok_or_else(invalid_grant)?;
    let created_at = required_value(entries, KEY_CREATED_AT)?
        .as_u64()
        .ok_or_else(invalid_grant)?;
    let revoked_value = required_value(entries, KEY_REVOKED_AT)?;
    let revoked_at = if matches!(revoked_value, Value::Nil) {
        None
    } else {
        Some(revoked_value.as_u64().ok_or_else(invalid_grant)?)
    };

    let grant = AccessGrant {
        principal_ref,
        scope,
        capability,
        status,
        created_at,
        revoked_at,
    };
    grant.validate()?;
    Ok(grant)
}

pub(super) fn encode_scope(scope: &AccessGrantScope) -> Value {
    match scope {
        AccessGrantScope::SharedBrief { .. } => crate::share::encode_shared_brief_scope(scope),
        AccessGrantScope::ChannelIdentity {
            identity_ref,
            envelope_ref,
        } => Value::Map(vec![
            (Value::from("kind"), Value::from("channel_identity")),
            (
                Value::from("identity_ref"),
                Value::from(identity_ref.to_hex()),
            ),
            (
                Value::from("envelope_ref"),
                Value::from(envelope_ref.to_hex()),
            ),
        ]),
        AccessGrantScope::CompanionProfile {
            person_ref,
            persona_ref,
        } => Value::Map(vec![
            (
                Value::from(SCOPE_KEYS_COMPANION_PROFILE[0]),
                Value::from(SCOPE_KIND_COMPANION_PROFILE),
            ),
            (
                Value::from(SCOPE_KEYS_COMPANION_PROFILE[1]),
                Value::from(person_ref.to_hex()),
            ),
            (
                Value::from(SCOPE_KEYS_COMPANION_PROFILE[2]),
                Value::from(persona_ref.to_hex()),
            ),
        ]),
        AccessGrantScope::Calendar { calendar_ref, rung } => Value::Map(vec![
            (
                Value::from(SCOPE_KEYS_CALENDAR[0]),
                Value::from(SCOPE_KIND_CALENDAR),
            ),
            (
                Value::from(SCOPE_KEYS_CALENDAR[1]),
                Value::from(calendar_ref.to_hex()),
            ),
            (
                Value::from(SCOPE_KEYS_CALENDAR[2]),
                Value::from(rung.as_str()),
            ),
        ]),
    }
}

fn decode_scope(value: &Value) -> Result<AccessGrantScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };

    // The kind selects the key set, so each scope shape validates against its
    // own pinned keys and no shape can borrow another's.
    let kind = required_value(entries, SCOPE_KEY_KIND)?
        .as_str()
        .ok_or_else(invalid_grant)?;

    match kind {
        "shared_brief" => crate::share::decode_shared_brief_scope(entries),
        "channel_identity" => {
            validate_keys(entries, &["kind", "identity_ref", "envelope_ref"])?;
            Ok(AccessGrantScope::ChannelIdentity {
                identity_ref: decode_entity_ref(required_value(entries, "identity_ref")?)?,
                envelope_ref: decode_entity_ref(required_value(entries, "envelope_ref")?)?,
            })
        }
        SCOPE_KIND_COMPANION_PROFILE => {
            validate_keys(entries, &SCOPE_KEYS_COMPANION_PROFILE)?;
            Ok(AccessGrantScope::CompanionProfile {
                person_ref: decode_entity_ref(required_value(
                    entries,
                    SCOPE_KEYS_COMPANION_PROFILE[1],
                )?)?,
                persona_ref: decode_entity_ref(required_value(
                    entries,
                    SCOPE_KEYS_COMPANION_PROFILE[2],
                )?)?,
            })
        }
        SCOPE_KIND_CALENDAR => {
            validate_keys(entries, &SCOPE_KEYS_CALENDAR)?;
            Ok(AccessGrantScope::Calendar {
                calendar_ref: decode_entity_ref(required_value(entries, SCOPE_KEYS_CALENDAR[1])?)?,
                rung: required_value(entries, SCOPE_KEYS_CALENDAR[2])?
                    .as_str()
                    .and_then(DisclosureRung::parse)
                    .ok_or_else(invalid_grant)?,
            })
        }
        _ => Err(invalid_grant()),
    }
}

pub(crate) fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_grant)?;
    EntityId::from_hex(hex).map_err(|_| invalid_grant())
}

pub(crate) fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_grant)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_grant());
        };
        if seen[index] {
            return Err(invalid_grant());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_grant())
    }
}

pub(crate) fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_grant)
}

pub(crate) fn invalid_grant() -> Error {
    Error::InvalidAccessGrantBody("body failed validation")
}
