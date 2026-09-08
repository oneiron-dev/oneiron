//! Canonical MessagePack body and claim-structure codec for ChannelIdentity.

use std::io::Cursor;

use rmpv::Value;

use crate::claim::{ClaimBody, ClaimSubject, MAX_PREDICATE_BYTES};

use crate::entity_id::EntityId;

use crate::error::{Error, Result};

use super::binding::{ChannelIdentityBinding, ChannelIdentityFulfillment};

use super::custody::{DelegatedGrant, DelegatedGrantScope};

use super::keys::{
    CHANNEL_IDENTITY_BODY_KEYS, CHANNEL_IDENTITY_CLAIM_PREDICATES,
    CHANNEL_IDENTITY_DELEGATED_BODY_KEYS, CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION,
    CHANNEL_IDENTITY_SCHEMA_VERSION, KEY_ADDRESS_OR_HANDLE, KEY_BINDING_FACET_REF,
    KEY_BINDING_SCOPE, KEY_BINDING_TARGET, KEY_CHANNEL, KEY_DELEGATED_GRANT_REF, KEY_GRANT_SCOPES,
    KEY_MANIFEST_REF, KEY_PENDING_FULFILLMENT, KEY_QUARANTINE_UNTIL, KEY_REPUTATION_REF,
    KEY_SCHEMA_VERSION, KEY_SHAPE, KEY_STATE, KEY_STATE_CHANGED_AT, MAX_ADDRESS_OR_HANDLE_BYTES,
    MAX_CHANNEL_BYTES, PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE,
    PREDICATE_CHANNEL_IDENTITY_BINDING_FACET_REF, PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE,
    PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET, PREDICATE_CHANNEL_IDENTITY_CHANNEL,
    PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF, PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT,
    PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL, PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF,
    PREDICATE_CHANNEL_IDENTITY_SHAPE, PREDICATE_CHANNEL_IDENTITY_STATE,
    PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT,
};

use super::lifecycle::ChannelIdentityState;

use super::record::ChannelIdentity;

use super::shape::ChannelIdentityShape;

/// Encodes a ChannelIdentity body in canonical MessagePack field order.
///
/// A self-held row encodes the thirteen pinned keys at
/// [`CHANNEL_IDENTITY_SCHEMA_VERSION`]. Only a `delegated_grant` row appends
/// the two custody keys and stamps
/// [`CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION`].
pub fn encode_channel_identity_body(identity: &ChannelIdentity) -> Result<Vec<u8>> {
    identity.validate()?;
    let mut entries = vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(body_schema_version(identity)),
        ),
        (
            Value::from(KEY_CHANNEL),
            Value::from(identity.channel.as_str()),
        ),
        (
            Value::from(KEY_ADDRESS_OR_HANDLE),
            Value::from(identity.address_or_handle.as_str()),
        ),
        (Value::from(KEY_SHAPE), Value::from(identity.shape.as_str())),
        (
            Value::from(KEY_BINDING_SCOPE),
            Value::from(identity.binding.scope_str()),
        ),
        (
            Value::from(KEY_BINDING_TARGET),
            encode_binding_target(identity.binding),
        ),
        (Value::from(KEY_STATE), Value::from(identity.state.as_str())),
        (
            Value::from(KEY_PENDING_FULFILLMENT),
            identity
                .pending_fulfillment
                .map_or(Value::Nil, |fulfillment| Value::from(fulfillment.as_str())),
        ),
        (
            Value::from(KEY_STATE_CHANGED_AT),
            Value::from(identity.state_changed_at),
        ),
        (
            Value::from(KEY_QUARANTINE_UNTIL),
            identity.quarantine_until.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_REPUTATION_REF),
            encode_optional_entity_ref(identity.reputation_ref),
        ),
        (
            Value::from(KEY_MANIFEST_REF),
            encode_optional_entity_ref(identity.manifest_ref),
        ),
        (
            Value::from(KEY_BINDING_FACET_REF),
            encode_optional_entity_ref(identity.binding.facet_ref()),
        ),
    ];

    if let Some(grant) = &identity.grant {
        entries.push((
            Value::from(KEY_DELEGATED_GRANT_REF),
            Value::from(grant.custody_record_ref.as_str()),
        ));
        entries.push((
            Value::from(KEY_GRANT_SCOPES),
            Value::Array(
                grant
                    .scopes
                    .iter()
                    .map(|scope| Value::from(scope.as_str()))
                    .collect(),
            ),
        ));
    }

    encode_msgpack_value(
        &Value::Map(entries),
        "channel identity body MessagePack encode failed",
    )
}

pub(super) const fn body_schema_version(identity: &ChannelIdentity) -> u64 {
    if identity.grant.is_some() {
        CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION
    } else {
        CHANNEL_IDENTITY_SCHEMA_VERSION
    }
}

/// Decodes and validates a ChannelIdentity body.
pub fn decode_channel_identity_body(bytes: &[u8]) -> Result<ChannelIdentity> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_identity())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_identity());
    }
    decode_channel_identity_value(&value)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_channel_identity_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_channel_identity_body(bytes).map(|_| ())
}

/// Returns whether `predicate` belongs to the ChannelIdentity claim family.
#[must_use]
pub fn is_channel_identity_claim_predicate(predicate: &str) -> bool {
    CHANNEL_IDENTITY_CLAIM_PREDICATES.contains(&predicate)
}

/// Validates one `channel_identity.*` claim body.
pub(crate) fn validate_channel_identity_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(Error::InvalidClaimBody(
            "channel_identity claim subject must be an entity",
        ));
    }
    if !is_channel_identity_claim_predicate(&body.predicate) {
        return Err(Error::InvalidClaimBody(
            "unknown channel_identity claim predicate",
        ));
    }
    if body.predicate.len() > MAX_PREDICATE_BYTES {
        return Err(Error::InvalidClaimBody(
            "channel_identity predicate exceeds max predicate bytes",
        ));
    }

    match body.predicate.as_str() {
        PREDICATE_CHANNEL_IDENTITY_CHANNEL => validate_claim_string(
            &body.value,
            MAX_CHANNEL_BYTES,
            "channel_identity.channel value must be non-empty string",
        ),
        PREDICATE_CHANNEL_IDENTITY_ADDRESS_OR_HANDLE => validate_claim_string(
            &body.value,
            MAX_ADDRESS_OR_HANDLE_BYTES,
            "channel_identity.address_or_handle value must be non-empty string",
        ),
        PREDICATE_CHANNEL_IDENTITY_SHAPE => body
            .value
            .as_str()
            .and_then(ChannelIdentityShape::parse)
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "channel_identity.shape value must be a pinned shape",
            )),
        PREDICATE_CHANNEL_IDENTITY_BINDING_SCOPE => match body.value.as_str() {
            Some("actor" | "vault") => Ok(()),
            _ => Err(Error::InvalidClaimBody(
                "channel_identity.binding_scope value must be actor|vault",
            )),
        },
        PREDICATE_CHANNEL_IDENTITY_BINDING_TARGET => validate_claim_binding_target(&body.value),
        PREDICATE_CHANNEL_IDENTITY_STATE => body
            .value
            .as_str()
            .and_then(ChannelIdentityState::parse)
            .map(|_| ())
            .ok_or(Error::InvalidClaimBody(
                "channel_identity.state value must be a pinned state",
            )),
        PREDICATE_CHANNEL_IDENTITY_PENDING_FULFILLMENT => {
            if matches!(body.value, Value::Nil)
                || body
                    .value
                    .as_str()
                    .and_then(ChannelIdentityFulfillment::parse)
                    .is_some()
            {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "channel_identity.pending_fulfillment value must be nil|api|manual|review",
                ))
            }
        }
        PREDICATE_CHANNEL_IDENTITY_STATE_CHANGED_AT => {
            body.value
                .as_u64()
                .map(|_| ())
                .ok_or(Error::InvalidClaimBody(
                    "channel_identity.state_changed_at value must be u64",
                ))
        }
        PREDICATE_CHANNEL_IDENTITY_QUARANTINE_UNTIL => {
            if matches!(body.value, Value::Nil) || body.value.as_u64().is_some() {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "channel_identity.quarantine_until value must be nil or u64",
                ))
            }
        }
        PREDICATE_CHANNEL_IDENTITY_REPUTATION_REF
        | PREDICATE_CHANNEL_IDENTITY_MANIFEST_REF
        | PREDICATE_CHANNEL_IDENTITY_BINDING_FACET_REF => {
            if matches!(body.value, Value::Nil) || decode_entity_ref(&body.value).is_ok() {
                Ok(())
            } else {
                Err(Error::InvalidClaimBody(
                    "channel_identity ref claim value must be nil or entity hex",
                ))
            }
        }
        _ => unreachable!("predicate membership checked above"),
    }
}

pub(super) fn decode_channel_identity_value(value: &Value) -> Result<ChannelIdentity> {
    let Value::Map(entries) = value else {
        return Err(invalid_identity());
    };
    // The version selects the pinned key set, so no two key sets can ever be
    // mixed: an unknown version, a self-held body carrying custody keys, and a
    // delegated body missing them all fail closed before any field is read.
    let delegated_grant = match required_value(entries, KEY_SCHEMA_VERSION)?.as_u64() {
        Some(CHANNEL_IDENTITY_SCHEMA_VERSION) => {
            validate_keys(entries, &CHANNEL_IDENTITY_BODY_KEYS)?;
            None
        }
        Some(CHANNEL_IDENTITY_DELEGATED_SCHEMA_VERSION) => {
            validate_keys(entries, &CHANNEL_IDENTITY_DELEGATED_BODY_KEYS)?;
            Some(decode_delegated_grant(entries)?)
        }
        _ => {
            return Err(Error::InvalidChannelIdentityBody(
                "unsupported channel identity schema version",
            ));
        }
    };

    let channel = required_string(entries, KEY_CHANNEL)?.to_owned();
    let address_or_handle = required_string(entries, KEY_ADDRESS_OR_HANDLE)?.to_owned();
    let shape = ChannelIdentityShape::parse(required_string(entries, KEY_SHAPE)?)
        .ok_or_else(invalid_identity)?;
    let binding_scope = required_string(entries, KEY_BINDING_SCOPE)?;
    let facet_ref = decode_optional_entity_ref(required_value(entries, KEY_BINDING_FACET_REF)?)?;
    let binding = decode_binding(
        binding_scope,
        required_value(entries, KEY_BINDING_TARGET)?,
        facet_ref,
    )?;
    let state = ChannelIdentityState::parse(required_string(entries, KEY_STATE)?)
        .ok_or_else(invalid_identity)?;
    let pending_fulfillment_value = required_value(entries, KEY_PENDING_FULFILLMENT)?;
    let pending_fulfillment = if matches!(pending_fulfillment_value, Value::Nil) {
        None
    } else {
        Some(
            pending_fulfillment_value
                .as_str()
                .and_then(ChannelIdentityFulfillment::parse)
                .ok_or_else(invalid_identity)?,
        )
    };
    let state_changed_at = required_value(entries, KEY_STATE_CHANGED_AT)?
        .as_u64()
        .ok_or_else(invalid_identity)?;
    let quarantine_until_value = required_value(entries, KEY_QUARANTINE_UNTIL)?;
    let quarantine_until = if matches!(quarantine_until_value, Value::Nil) {
        None
    } else {
        Some(
            quarantine_until_value
                .as_u64()
                .ok_or_else(invalid_identity)?,
        )
    };
    let reputation_ref = decode_optional_entity_ref(required_value(entries, KEY_REPUTATION_REF)?)?;
    let manifest_ref = decode_optional_entity_ref(required_value(entries, KEY_MANIFEST_REF)?)?;

    let identity = ChannelIdentity {
        channel,
        address_or_handle,
        shape,
        binding,
        state,
        pending_fulfillment,
        state_changed_at,
        quarantine_until,
        reputation_ref,
        manifest_ref,
        grant: delegated_grant,
    };
    identity.validate()?;
    Ok(identity)
}

pub(super) fn decode_delegated_grant(entries: &[(Value, Value)]) -> Result<DelegatedGrant> {
    let custody_record_ref = required_string(entries, KEY_DELEGATED_GRANT_REF)?.to_owned();
    let Value::Array(scopes) = required_value(entries, KEY_GRANT_SCOPES)? else {
        return Err(invalid_identity());
    };
    let scopes = scopes
        .iter()
        .map(|scope| {
            scope
                .as_str()
                .and_then(DelegatedGrantScope::parse)
                .ok_or_else(invalid_identity)
        })
        .collect::<Result<Vec<_>>>()?;
    let grant = DelegatedGrant {
        custody_record_ref,
        scopes,
    };
    grant.validate()?;
    Ok(grant)
}

pub(super) fn encode_binding_target(binding: ChannelIdentityBinding) -> Value {
    match binding {
        ChannelIdentityBinding::Actor { actor_ref, .. } => Value::from(actor_ref.to_hex()),
        ChannelIdentityBinding::Vault { vault_id } => Value::from(vault_id),
    }
}

/// Decodes a canonical actor or vault binding.
///
/// A `vault` row carrying a facet is refused rather than silently dropping the mask.
pub(super) fn decode_binding(
    scope: &str,
    target: &Value,
    facet_ref: Option<EntityId>,
) -> Result<ChannelIdentityBinding> {
    match scope {
        "actor" => Ok(ChannelIdentityBinding::Actor {
            actor_ref: decode_entity_ref(target)?,
            facet_ref,
        }),
        "vault" if facet_ref.is_none() => target
            .as_u64()
            .map(ChannelIdentityBinding::vault)
            .ok_or_else(invalid_identity),
        _ => Err(invalid_identity()),
    }
}

pub(super) fn validate_claim_binding_target(value: &Value) -> Result<()> {
    if decode_entity_ref(value).is_ok() {
        return Ok(());
    }
    match value.as_u64() {
        Some(0) => Err(Error::InvalidClaimBody(
            "channel_identity.binding_target vault id must be non-zero",
        )),
        Some(_) => Ok(()),
        None => Err(Error::InvalidClaimBody(
            "channel_identity.binding_target value must be entity hex or non-zero vault id",
        )),
    }
}

pub(super) fn encode_optional_entity_ref(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::from(id.to_hex()))
}

pub(super) fn decode_optional_entity_ref(value: &Value) -> Result<Option<EntityId>> {
    if matches!(value, Value::Nil) {
        Ok(None)
    } else {
        decode_entity_ref(value).map(Some)
    }
}

pub(super) fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value.as_str().ok_or_else(invalid_identity)?;
    EntityId::from_hex(hex).map_err(|_| invalid_identity())
}

pub(super) fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    required_value(entries, key)?
        .as_str()
        .ok_or_else(invalid_identity)
}

pub(super) fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_identity)?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(invalid_identity());
        };
        if seen[index] {
            return Err(invalid_identity());
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_identity())
    }
}

pub(super) fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_identity)
}

pub(super) fn validate_non_empty_bounded(
    value: &str,
    max: usize,
    reason: &'static str,
) -> Result<()> {
    if value.trim().is_empty() || value.len() > max {
        Err(Error::InvalidChannelIdentityBody(reason))
    } else {
        Ok(())
    }
}

pub(super) fn validate_claim_string(value: &Value, max: usize, reason: &'static str) -> Result<()> {
    let Some(value) = value.as_str() else {
        return Err(Error::InvalidClaimBody(reason));
    };
    if value.trim().is_empty() || value.len() > max {
        Err(Error::InvalidClaimBody(reason))
    } else {
        Ok(())
    }
}

pub(super) fn encode_msgpack_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(out)
}

pub(super) fn invalid_identity() -> Error {
    Error::InvalidChannelIdentityBody("body failed validation")
}
