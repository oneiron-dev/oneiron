//! Pinned AccessGrant body/scope key sets and fail-closed MessagePack codec.

use std::io::Cursor;

use rmpv::Value;

use crate::booking::DisclosureRung;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::record::{AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus};
use crate::error::RecordError;

/// Current AccessGrant body schema version.
pub const ACCESS_GRANT_SCHEMA_VERSION: u64 = 4;

/// Pinned on-disk MessagePack key set for AccessGrant bodies.
pub const ACCESS_GRANT_BODY_KEYS: [&str; 10] = [
    "schema_version",
    "principal_ref",
    "scope",
    "capability",
    "status",
    "created_at",
    "revoked_at",
    "expires_at",
    "authority_scope",
    "companion_bounds",
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

const KEY_COMPANION_BOUNDS: &str = ACCESS_GRANT_BODY_KEYS[9];

const BOUNDS_KEYS: [&str; 2] = ["issuer_slip", "ceiling"];

pub(super) const SCOPE_KEY_KIND: &str = "kind";

pub(super) const SCOPE_KEYS_COMPANION_PROFILE: [&str; 3] =
    [SCOPE_KEY_KIND, "person_ref", "facet_ref"];

pub(super) const SCOPE_KEYS_CALENDAR: [&str; 3] = [SCOPE_KEY_KIND, "calendar_ref", "rung"];

pub(super) const SCOPE_KIND_COMPANION_PROFILE: &str = "companion_profile";

pub(super) const SCOPE_KIND_CALENDAR: &str = "calendar";

/// The principal a brief share's inert history names once its recipient was
/// erased (FIX 4231): no one. No live decoder reads it as an id.
const ERASED_PRINCIPAL: &str = crate::receipt::ERASED_CALL_IDENTITY;

/// Encodes an AccessGrant body in canonical MessagePack field order.
pub fn encode_access_grant_body(grant: &AccessGrant) -> Result<Vec<u8>> {
    encode_body(grant, Value::from(grant.principal_ref.to_hex()))
}

/// `grant`'s body as a brief share's inert history once its recipient was
/// erased (FIX 4231): its live body, its principal naming no one.
pub(crate) fn encode_erased_share_body(grant: &AccessGrant) -> Result<Vec<u8>> {
    if !matches!(grant.scope, AccessGrantScope::SharedBrief { .. }) {
        return Err(invalid_grant());
    }
    encode_body(grant, Value::from(ERASED_PRINCIPAL))
}

fn encode_body(grant: &AccessGrant, principal: Value) -> Result<Vec<u8>> {
    grant.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(ACCESS_GRANT_SCHEMA_VERSION),
        ),
        (Value::from(KEY_PRINCIPAL_REF), principal),
        (Value::from(KEY_SCOPE), encode_scope(&grant.scope)),
        (
            "authority_scope".into(),
            crate::federation::scope_codec::encode_scope_value(&grant.authority_scope)?,
        ),
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
        (
            Value::from("expires_at"),
            grant.expires_at.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_COMPANION_BOUNDS),
            encode_companion_bounds(grant.companion_bounds.as_ref())?,
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("access grant body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and validates an AccessGrant body.
pub fn decode_access_grant_body(bytes: &[u8]) -> Result<AccessGrant> {
    let value = read_body(bytes)?;
    let (principal, terms) = decode_body(&value)?;
    let grant = terms.granted_to(decode_entity_ref(principal)?);
    grant.validate()?;
    Ok(grant)
}

/// [`decode_access_grant_body`] for a walk over every stored grant: a brief
/// share's inert history (FIX 4231) grants nothing, so it reads as none.
pub(crate) fn decode_live_access_grant_body(bytes: &[u8]) -> Result<Option<AccessGrant>> {
    match decode_access_grant_body(bytes) {
        Ok(grant) => Ok(Some(grant)),
        Err(_) if decode_erased_share_body(bytes).is_ok() => Ok(None),
        Err(error) => Err(error),
    }
}

/// A brief share's inert history body (FIX 4231): the terms its live body
/// held, its principal naming no one.
pub(crate) fn decode_erased_share_body(bytes: &[u8]) -> Result<GrantTerms> {
    let value = read_body(bytes)?;
    let (principal, terms) = decode_body(&value)?;
    if principal.as_str() != Some(ERASED_PRINCIPAL)
        || !matches!(terms.scope, AccessGrantScope::SharedBrief { .. })
        || terms.capability != terms.scope.required_capability()
    {
        return Err(invalid_grant());
    }
    Ok(terms)
}

/// A live body, or a brief share's inert history (FIX 4231).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_access_grant_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_live_access_grant_body(bytes).map(|_| ())
}

/// An AccessGrant body's terms but its principal.
pub(crate) struct GrantTerms {
    pub(crate) authority_scope: crate::federation::Scope,
    pub(crate) scope: AccessGrantScope,
    pub(crate) capability: AccessGrantCapability,
    pub(crate) status: AccessGrantStatus,
    pub(crate) created_at: u64,
    pub(crate) revoked_at: Option<u64>,
    pub(crate) expires_at: Option<u64>,
    pub(crate) companion_bounds: Option<super::CompanionGrantBounds>,
}

impl GrantTerms {
    fn granted_to(self, principal_ref: EntityId) -> AccessGrant {
        AccessGrant {
            authority_scope: self.authority_scope,
            principal_ref,
            scope: self.scope,
            capability: self.capability,
            status: self.status,
            created_at: self.created_at,
            revoked_at: self.revoked_at,
            expires_at: self.expires_at,
            companion_bounds: self.companion_bounds,
        }
    }
}

fn read_body(bytes: &[u8]) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_grant())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_grant());
    }
    Ok(value)
}

/// A body's principal as stored, beside its other terms.
fn decode_body(value: &Value) -> Result<(&Value, GrantTerms)> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };
    // One body format: the current schema's every key, nothing older.
    validate_keys(entries, &ACCESS_GRANT_BODY_KEYS)?;
    if required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() != Some(ACCESS_GRANT_SCHEMA_VERSION) {
        return Err(invalid_grant());
    }

    let principal = required_value(entries, KEY_PRINCIPAL_REF)?;
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

    let expires_at = match required_value(entries, "expires_at")? {
        Value::Nil => None,
        value => Some(value.as_u64().ok_or_else(invalid_grant)?),
    };
    let companion_bounds = decode_companion_bounds(required_value(entries, KEY_COMPANION_BOUNDS)?)?;
    let terms = GrantTerms {
        authority_scope: crate::federation::scope_codec::decode_scope_value(required_value(
            entries,
            "authority_scope",
        )?)
        .map_err(|_| invalid_grant())?,
        scope,
        capability,
        status,
        created_at,
        revoked_at,
        expires_at,
        companion_bounds,
    };
    Ok((principal, terms))
}

/// A companion grant's issuer bounds (FIX 8140): the issuing slip's id and
/// its record ceiling, or nil.
fn encode_companion_bounds(bounds: Option<&super::CompanionGrantBounds>) -> Result<Value> {
    let Some(bounds) = bounds else {
        return Ok(Value::Nil);
    };
    Ok(Value::Map(vec![
        (
            Value::from(BOUNDS_KEYS[0]),
            Value::from(bounds.issuer_slip.as_str()),
        ),
        (
            Value::from(BOUNDS_KEYS[1]),
            crate::federation::scope_codec::encode_scope_value(&bounds.ceiling)?,
        ),
    ]))
}

fn decode_companion_bounds(value: &Value) -> Result<Option<super::CompanionGrantBounds>> {
    let Value::Map(entries) = value else {
        return match value {
            Value::Nil => Ok(None),
            _ => Err(invalid_grant()),
        };
    };
    validate_keys(entries, &BOUNDS_KEYS)?;
    Ok(Some(super::CompanionGrantBounds {
        issuer_slip: required_value(entries, BOUNDS_KEYS[0])?
            .as_str()
            .ok_or_else(invalid_grant)?
            .to_owned(),
        ceiling: crate::federation::scope_codec::decode_scope_value(required_value(
            entries,
            BOUNDS_KEYS[1],
        )?)
        .map_err(|_| invalid_grant())?,
    }))
}

pub(super) fn encode_scope(scope: &AccessGrantScope) -> Value {
    match scope {
        AccessGrantScope::Messages { space_ref }
        | AccessGrantScope::Summaries { space_ref }
        | AccessGrantScope::RelationshipClaims { space_ref } => Value::Map(vec![
            (
                Value::from("kind"),
                Value::from(match scope {
                    AccessGrantScope::Messages { .. } => "messages",
                    AccessGrantScope::Summaries { .. } => "summaries",
                    _ => "relationshipClaims",
                }),
            ),
            (Value::from("space_ref"), Value::from(space_ref.to_hex())),
        ]),
        AccessGrantScope::ConversationMessages { conversation_ref } => Value::Map(vec![
            (Value::from("kind"), Value::from("conversation_messages")),
            (
                Value::from("conversation_ref"),
                Value::from(conversation_ref.to_hex()),
            ),
        ]),
        AccessGrantScope::DiaryCoreference {
            left_ref,
            right_ref,
        } => Value::Map(vec![
            (Value::from("kind"), Value::from("diary_coreference")),
            (Value::from("left_ref"), Value::from(left_ref.to_hex())),
            (Value::from("right_ref"), Value::from(right_ref.to_hex())),
        ]),
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
            facet_ref,
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
                facet_ref.map_or(Value::Nil, |facet_ref| Value::from(facet_ref.to_hex())),
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
        "messages" | "summaries" | "relationshipClaims" => {
            validate_keys(entries, &["kind", "space_ref"])?;
            let space_ref = decode_entity_ref(required_value(entries, "space_ref")?)?;
            Ok(match kind {
                "messages" => AccessGrantScope::Messages { space_ref },
                "summaries" => AccessGrantScope::Summaries { space_ref },
                _ => AccessGrantScope::RelationshipClaims { space_ref },
            })
        }
        "conversation_messages" => {
            validate_keys(entries, &["kind", "conversation_ref"])?;
            Ok(AccessGrantScope::ConversationMessages {
                conversation_ref: decode_entity_ref(required_value(entries, "conversation_ref")?)?,
            })
        }
        "diary_coreference" => {
            validate_keys(entries, &["kind", "left_ref", "right_ref"])?;
            Ok(AccessGrantScope::DiaryCoreference {
                left_ref: decode_entity_ref(required_value(entries, "left_ref")?)?,
                right_ref: decode_entity_ref(required_value(entries, "right_ref")?)?,
            })
        }
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
                facet_ref: match required_value(entries, SCOPE_KEYS_COMPANION_PROFILE[2])? {
                    Value::Nil => None,
                    facet_ref => Some(decode_entity_ref(facet_ref)?),
                },
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
    Error::Record(RecordError::InvalidAccessGrantBody(
        "body failed validation",
    ))
}
