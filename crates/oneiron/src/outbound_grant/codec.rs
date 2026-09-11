//! MessagePack body codec plus private key and decode helpers.

use std::io::Cursor;

use rmpv::Value;

use super::grant::{StandingOutboundGrant, StandingOutboundGrantStatus};
use super::scope::{
    SCOPE_KEYS, SCOPE_KIND_BOOKING_PAGE_INVITES, SCOPE_KIND_BRIEF_VERB_CLASS, SCOPE_KIND_CHANNEL,
    SCOPE_KIND_CONTACT, SCOPE_KIND_SCOPED_MCP, SCOPE_KIND_VERB_CLASS, SEND_VERB_CLASS,
    StandingOutboundGrantScope,
};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::outbound_consent::DataClass;

/// Current StandingOutboundGrant body schema version.
pub const OUTBOUND_GRANT_SCHEMA_VERSION: u64 = 2;

/// Pinned recursive MessagePack key vocabulary for StandingOutboundGrant
/// bodies. Existing top-level positions remain stable; scoped-tool keys are
/// appended and encoded inside the `scope` map.
pub const OUTBOUND_GRANT_BODY_KEYS: [&str; 16] = [
    "schema_version",
    "principal_ref",
    "origin_component_id",
    "origin_action_id",
    "origin_receipt_ref",
    "scope",
    "status",
    "created_at",
    "revoked_at",
    "last_used_at",
    "binding_diff_handle",
    "read_frontier_hash",
    "server",
    "tool",
    "data_class_ceiling",
    "endpoint_allowlist",
];

const OUTBOUND_GRANT_TOP_LEVEL_KEYS: [&str; 12] = [
    OUTBOUND_GRANT_BODY_KEYS[0],
    OUTBOUND_GRANT_BODY_KEYS[1],
    OUTBOUND_GRANT_BODY_KEYS[2],
    OUTBOUND_GRANT_BODY_KEYS[3],
    OUTBOUND_GRANT_BODY_KEYS[4],
    OUTBOUND_GRANT_BODY_KEYS[5],
    OUTBOUND_GRANT_BODY_KEYS[6],
    OUTBOUND_GRANT_BODY_KEYS[7],
    OUTBOUND_GRANT_BODY_KEYS[8],
    OUTBOUND_GRANT_BODY_KEYS[9],
    OUTBOUND_GRANT_BODY_KEYS[10],
    OUTBOUND_GRANT_BODY_KEYS[11],
];

pub(crate) const OUTBOUND_GRANT_FIELDS_MINIMAL: &[&str] = &["scope", "status", "last_used_at"];

pub(crate) const OUTBOUND_GRANT_FIELDS_STANDARD: &[&str] = &[
    "principal_ref",
    "origin_component_id",
    "origin_action_id",
    "scope",
    "status",
    "last_used_at",
];

pub(crate) const OUTBOUND_GRANT_FIELDS_FULL: &[&str] = &OUTBOUND_GRANT_TOP_LEVEL_KEYS;

pub(super) const KEY_SCHEMA_VERSION: &str = OUTBOUND_GRANT_BODY_KEYS[0];

pub(super) const KEY_PRINCIPAL_REF: &str = OUTBOUND_GRANT_BODY_KEYS[1];

pub(super) const KEY_ORIGIN_COMPONENT_ID: &str = OUTBOUND_GRANT_BODY_KEYS[2];

pub(super) const KEY_ORIGIN_ACTION_ID: &str = OUTBOUND_GRANT_BODY_KEYS[3];

pub(super) const KEY_ORIGIN_RECEIPT_REF: &str = OUTBOUND_GRANT_BODY_KEYS[4];

pub(super) const KEY_SCOPE: &str = OUTBOUND_GRANT_BODY_KEYS[5];

pub(super) const KEY_STATUS: &str = OUTBOUND_GRANT_BODY_KEYS[6];

pub(super) const KEY_CREATED_AT: &str = OUTBOUND_GRANT_BODY_KEYS[7];

pub(super) const KEY_REVOKED_AT: &str = OUTBOUND_GRANT_BODY_KEYS[8];

pub(super) const KEY_LAST_USED_AT: &str = OUTBOUND_GRANT_BODY_KEYS[9];

pub(super) const KEY_BINDING_DIFF_HANDLE: &str = OUTBOUND_GRANT_BODY_KEYS[10];

pub(super) const KEY_READ_FRONTIER_HASH: &str = OUTBOUND_GRANT_BODY_KEYS[11];

/// Encodes a StandingOutboundGrant body in canonical MessagePack field order.
pub fn encode_standing_outbound_grant_body(grant: &StandingOutboundGrant) -> Result<Vec<u8>> {
    grant.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(OUTBOUND_GRANT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PRINCIPAL_REF),
            Value::from(grant.principal_ref.clone()),
        ),
        (
            Value::from(KEY_ORIGIN_COMPONENT_ID),
            Value::from(grant.origin_component_id.clone()),
        ),
        (
            Value::from(KEY_ORIGIN_ACTION_ID),
            Value::from(grant.origin_action_id.clone()),
        ),
        (
            Value::from(KEY_ORIGIN_RECEIPT_REF),
            option_string_value(grant.origin_receipt_ref.as_deref()),
        ),
        (Value::from(KEY_SCOPE), encode_scope(&grant.scope)),
        (Value::from(KEY_STATUS), Value::from(grant.status.as_str())),
        (Value::from(KEY_CREATED_AT), Value::from(grant.created_at)),
        (
            Value::from(KEY_REVOKED_AT),
            grant.revoked_at.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_LAST_USED_AT),
            grant.last_used_at.map_or(Value::Nil, Value::from),
        ),
        (
            Value::from(KEY_BINDING_DIFF_HANDLE),
            Value::Binary(grant.binding_diff_handle.clone()),
        ),
        (
            Value::from(KEY_READ_FRONTIER_HASH),
            Value::Binary(grant.read_frontier_hash.to_vec()),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).map_err(|_| {
        Error::InvariantViolation("standing outbound grant body MessagePack encode failed")
    })?;
    Ok(out)
}

/// Decodes a StandingOutboundGrant body after fail-closed structural validation.
pub fn decode_standing_outbound_grant_body(bytes: &[u8]) -> Result<StandingOutboundGrant> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid_grant())?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_grant());
    }
    decode_standing_outbound_grant_value(&value)
}

pub(crate) fn validate_standing_outbound_grant_body_bytes(bytes: &[u8]) -> Result<()> {
    decode_standing_outbound_grant_body(bytes).map(|_| ())
}

fn decode_standing_outbound_grant_value(value: &Value) -> Result<StandingOutboundGrant> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };
    validate_keys(entries, &OUTBOUND_GRANT_TOP_LEVEL_KEYS)?;

    let version = required_value(entries, KEY_SCHEMA_VERSION)?.as_u64();
    if version != Some(OUTBOUND_GRANT_SCHEMA_VERSION) {
        return Err(invalid_grant());
    }

    let revoked_at = decode_optional_u64(required_value(entries, KEY_REVOKED_AT)?)?;
    let last_used_at = decode_optional_u64(required_value(entries, KEY_LAST_USED_AT)?)?;
    let grant = StandingOutboundGrant {
        principal_ref: decode_non_empty_string(required_value(entries, KEY_PRINCIPAL_REF)?)?,
        origin_component_id: decode_non_empty_string(required_value(
            entries,
            KEY_ORIGIN_COMPONENT_ID,
        )?)?,
        origin_action_id: decode_non_empty_string(required_value(entries, KEY_ORIGIN_ACTION_ID)?)?,
        origin_receipt_ref: decode_optional_string(required_value(
            entries,
            KEY_ORIGIN_RECEIPT_REF,
        )?)?,
        scope: decode_scope(required_value(entries, KEY_SCOPE)?)?,
        status: required_value(entries, KEY_STATUS)?
            .as_str()
            .and_then(StandingOutboundGrantStatus::parse)
            .ok_or_else(invalid_grant)?,
        created_at: required_value(entries, KEY_CREATED_AT)?
            .as_u64()
            .ok_or_else(invalid_grant)?,
        revoked_at,
        last_used_at,
        binding_diff_handle: decode_non_empty_binary(required_value(
            entries,
            KEY_BINDING_DIFF_HANDLE,
        )?)?,
        read_frontier_hash: decode_hash32(required_value(entries, KEY_READ_FRONTIER_HASH)?)?,
    };
    grant.validate()?;
    Ok(grant)
}

fn encode_scope(scope: &StandingOutboundGrantScope) -> Value {
    let mut contact_ref = Value::Nil;
    let mut verb_class = Value::Nil;
    let mut channel = Value::Nil;
    let mut brief_ref = Value::Nil;
    let mut server = Value::Nil;
    let mut tool = Value::Nil;
    let mut data_class_ceiling = Value::Nil;
    let mut endpoint_allowlist = Value::Nil;
    let kind = match scope {
        StandingOutboundGrantScope::Contact {
            contact_ref: grant_contact_ref,
        } => {
            contact_ref = Value::from(grant_contact_ref.clone());
            SCOPE_KIND_CONTACT
        }
        StandingOutboundGrantScope::VerbClass {
            verb_class: grant_verb_class,
        } => {
            verb_class = Value::from(grant_verb_class.clone());
            SCOPE_KIND_VERB_CLASS
        }
        StandingOutboundGrantScope::Channel {
            channel: grant_channel,
        } => {
            channel = Value::from(grant_channel.clone());
            SCOPE_KIND_CHANNEL
        }
        StandingOutboundGrantScope::BriefVerbClass {
            brief_ref: grant_brief_ref,
            verb_class: grant_verb_class,
        } => {
            brief_ref = Value::from(grant_brief_ref.clone());
            verb_class = Value::from(grant_verb_class.clone());
            SCOPE_KIND_BRIEF_VERB_CLASS
        }
        StandingOutboundGrantScope::ScopedMcp {
            server: grant_server,
            tool: grant_tool,
            data_class_ceiling: grant_ceiling,
            endpoint_allowlist: grant_endpoints,
        } => {
            server = Value::from(grant_server.clone());
            tool = Value::from(grant_tool.clone());
            data_class_ceiling = Value::from(grant_ceiling.as_str());
            endpoint_allowlist =
                Value::Array(grant_endpoints.iter().cloned().map(Value::from).collect());
            SCOPE_KIND_SCOPED_MCP
        }
        StandingOutboundGrantScope::BookingPageInvites { .. } => SCOPE_KIND_BOOKING_PAGE_INVITES,
        StandingOutboundGrantScope::ChannelIdentityEnvelope {
            identity_ref,
            envelope_ref,
            verb_class,
        } => {
            return Value::Map(vec![
                (
                    Value::from("kind"),
                    Value::from("channel_identity_envelope"),
                ),
                (
                    Value::from("identity_ref"),
                    Value::from(identity_ref.to_hex()),
                ),
                (
                    Value::from("envelope_ref"),
                    Value::from(envelope_ref.to_hex()),
                ),
                (Value::from("verb_class"), Value::from(verb_class.clone())),
            ]);
        }
    };

    let mut entries = vec![
        (Value::from(SCOPE_KEYS[0]), Value::from(kind)),
        (Value::from(SCOPE_KEYS[1]), contact_ref),
        (Value::from(SCOPE_KEYS[2]), verb_class),
        (Value::from(SCOPE_KEYS[3]), channel),
        (Value::from(SCOPE_KEYS[4]), brief_ref),
        (Value::from(SCOPE_KEYS[5]), server),
        (Value::from(SCOPE_KEYS[6]), tool),
        (Value::from(SCOPE_KEYS[7]), data_class_ceiling),
        (Value::from(SCOPE_KEYS[8]), endpoint_allowlist),
    ];
    // The tenth pair is pushed ONLY by the scope that owns it. Emitting a Nil
    // `page_ref` for every other kind would move their encoded bytes, and this
    // codec is append-only.
    if let StandingOutboundGrantScope::BookingPageInvites { page_ref } = scope {
        entries.push((Value::from(SCOPE_KEYS[9]), Value::from(page_ref.to_hex())));
    }
    Value::Map(entries)
}

pub(super) fn decode_scope(value: &Value) -> Result<StandingOutboundGrantScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_grant());
    };
    if required_value(entries, "kind")?.as_str() == Some("channel_identity_envelope") {
        validate_keys(
            entries,
            &["kind", "identity_ref", "envelope_ref", "verb_class"],
        )?;
        return Ok(StandingOutboundGrantScope::ChannelIdentityEnvelope {
            identity_ref: decode_entity_ref(required_value(entries, "identity_ref")?)?,
            envelope_ref: decode_entity_ref(required_value(entries, "envelope_ref")?)?,
            verb_class: decode_canonical_non_empty_string(required_value(entries, "verb_class")?)?,
        });
    }
    validate_keys_with_optional(entries, &SCOPE_KEYS[..5], &SCOPE_KEYS[5..])?;

    let kind = required_value(entries, SCOPE_KEYS[0])?
        .as_str()
        .ok_or_else(invalid_grant)?;
    // Each kind names exactly the keys it does NOT own. A blind kind's
    // non-applicable set now reaches `page_ref` too: blind rows never carried
    // it, so every pre-existing row still decodes identically.
    let non_applicable: Vec<&str> = if kind == SCOPE_KIND_BOOKING_PAGE_INVITES {
        SCOPE_KEYS[1..9].to_vec()
    } else if kind == SCOPE_KIND_SCOPED_MCP {
        let mut keys = SCOPE_KEYS[1..5].to_vec();
        keys.extend_from_slice(&SCOPE_KEYS[9..]);
        keys
    } else {
        SCOPE_KEYS[5..].to_vec()
    };
    let has_non_applicable_field = non_applicable.iter().any(|scope_key| {
        entries
            .iter()
            .any(|(key, value)| key.as_str() == Some(*scope_key) && !matches!(value, Value::Nil))
    });
    if has_non_applicable_field {
        return Err(invalid_grant());
    }
    match kind {
        SCOPE_KIND_CONTACT => Ok(StandingOutboundGrantScope::Contact {
            contact_ref: decode_non_empty_string(required_value(entries, SCOPE_KEYS[1])?)?,
        }),
        SCOPE_KIND_VERB_CLASS => Ok(StandingOutboundGrantScope::VerbClass {
            verb_class: decode_non_empty_string(required_value(entries, SCOPE_KEYS[2])?)?,
        }),
        SCOPE_KIND_CHANNEL => Ok(StandingOutboundGrantScope::Channel {
            channel: decode_non_empty_string(required_value(entries, SCOPE_KEYS[3])?)?,
        }),
        SCOPE_KIND_BRIEF_VERB_CLASS => Ok(StandingOutboundGrantScope::BriefVerbClass {
            brief_ref: decode_non_empty_string(required_value(entries, SCOPE_KEYS[4])?)?,
            verb_class: decode_non_empty_string(required_value(entries, SCOPE_KEYS[2])?)?,
        }),
        SCOPE_KIND_SCOPED_MCP => {
            let data_class_ceiling = DataClass::parse(
                required_value(entries, SCOPE_KEYS[7])?
                    .as_str()
                    .ok_or_else(invalid_grant)?,
            );
            if !data_class_ceiling.is_grantable() {
                return Err(invalid_grant());
            }
            Ok(StandingOutboundGrantScope::ScopedMcp {
                server: decode_canonical_scoped_server(required_value(entries, SCOPE_KEYS[5])?)?,
                tool: decode_canonical_non_empty_string(required_value(entries, SCOPE_KEYS[6])?)?,
                data_class_ceiling,
                endpoint_allowlist: decode_canonical_non_empty_string_array(required_value(
                    entries,
                    SCOPE_KEYS[8],
                )?)?,
            })
        }
        SCOPE_KIND_BOOKING_PAGE_INVITES => Ok(StandingOutboundGrantScope::BookingPageInvites {
            // Required for this kind: a row that claims the booking-page scope
            // without naming its page authorizes nothing and fails closed.
            page_ref: decode_entity_ref(required_value(entries, SCOPE_KEYS[9])?)?,
        }),
        _ => Err(invalid_grant()),
    }
}

fn validate_keys(entries: &[(Value, Value)], keys: &[&str]) -> Result<()> {
    validate_keys_with_optional(entries, keys, &[])
}

fn validate_keys_with_optional(
    entries: &[(Value, Value)],
    required_keys: &[&str],
    optional_keys: &[&str],
) -> Result<()> {
    let mut required_seen = vec![false; required_keys.len()];
    let mut optional_seen = vec![false; optional_keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or_else(invalid_grant)?;
        if let Some(index) = required_keys.iter().position(|known| *known == key) {
            if required_seen[index] {
                return Err(invalid_grant());
            }
            required_seen[index] = true;
        } else if let Some(index) = optional_keys.iter().position(|known| *known == key) {
            if optional_seen[index] {
                return Err(invalid_grant());
            }
            optional_seen[index] = true;
        } else {
            return Err(invalid_grant());
        }
    }
    if required_seen.into_iter().all(|value| value) {
        Ok(())
    } else {
        Err(invalid_grant())
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or_else(invalid_grant)
}

fn decode_non_empty_string(value: &Value) -> Result<String> {
    let value = value.as_str().ok_or_else(invalid_grant)?;
    non_empty_string(value)
}

fn decode_canonical_non_empty_string(value: &Value) -> Result<String> {
    let value = value.as_str().ok_or_else(invalid_grant)?;
    canonical_non_empty_str(value)?;
    Ok(value.to_owned())
}

fn decode_entity_ref(value: &Value) -> Result<EntityId> {
    let value = value.as_str().ok_or_else(invalid_grant)?;
    EntityId::from_hex(value).map_err(|_| invalid_grant())
}

fn decode_optional_string(value: &Value) -> Result<Option<String>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_non_empty_string(value).map(Some)
}

fn decode_optional_u64(value: &Value) -> Result<Option<u64>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    value.as_u64().ok_or_else(invalid_grant).map(Some)
}

fn decode_non_empty_binary(value: &Value) -> Result<Vec<u8>> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_grant());
    };
    if bytes.is_empty() {
        return Err(invalid_grant());
    }
    Ok(bytes.clone())
}

fn decode_canonical_non_empty_string_array(value: &Value) -> Result<Vec<String>> {
    let Value::Array(values) = value else {
        return Err(invalid_grant());
    };
    if values.is_empty() {
        return Err(invalid_grant());
    }
    values
        .iter()
        .map(decode_canonical_non_empty_string)
        .collect()
}

fn decode_hash32(value: &Value) -> Result<[u8; 32]> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_grant());
    };
    bytes.as_slice().try_into().map_err(|_| invalid_grant())
}

pub(super) fn option_string_value(value: Option<&str>) -> Value {
    value.map_or(Value::Nil, Value::from)
}

pub(super) fn non_empty_optional(value: Option<&str>) -> Result<Option<String>> {
    value.map(non_empty_string).transpose()
}

pub(super) fn non_empty_string(value: &str) -> Result<String> {
    non_empty_str(value)?;
    Ok(value.trim().to_owned())
}

pub(super) fn non_empty_str(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid_grant());
    }
    Ok(())
}

pub(super) fn canonical_non_empty_str(value: &str) -> Result<()> {
    non_empty_str(value)?;
    if value != value.trim() {
        return Err(invalid_grant());
    }
    Ok(())
}

/// Validates and preserves the ONE exact canonical scoped-server segment,
/// shared with the capability-key producer, scoped-call admission, and charter
/// compiler (ONE-1885). No scoped seam trims, case-folds, or aliases identity
/// punctuation.
pub(super) fn canonical_scoped_server(server: &str) -> Result<String> {
    crate::connector_key::canonical_scoped_server_segment(server).ok_or_else(invalid_grant)
}

fn decode_canonical_scoped_server(value: &Value) -> Result<String> {
    let value = value.as_str().ok_or_else(invalid_grant)?;
    if canonical_scoped_server(value)? != value {
        return Err(invalid_grant());
    }
    Ok(value.to_owned())
}

pub(super) fn refs_match(candidate: &str, target: &str) -> bool {
    candidate.trim() == target.trim()
}

pub(super) fn is_send_class_verb(verb: &str) -> bool {
    verb.trim() == SEND_VERB_CLASS
}

pub(super) fn is_mcp_channel(channel: &str) -> bool {
    channel
        .trim()
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("mcp:"))
}

pub(super) fn invalid_grant() -> Error {
    Error::Record(RecordError::InvalidOutboundGrantBody(
        "body failed validation",
    ))
}
