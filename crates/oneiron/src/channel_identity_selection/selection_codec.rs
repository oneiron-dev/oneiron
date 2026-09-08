//! Strict canonical MessagePack codec for the stored selection rule set.

use std::io::Cursor;

use rmpv::Value;

use crate::entity_id::EntityId;

use super::selection_resolution::{
    ChannelIdentitySelectionError, ChannelIdentitySelectionResult, SelectionRuleScope,
};
use super::selection_rules::{
    ChannelIdentitySelectionRule, ChannelIdentitySelectionRuleSet, RULE_KEYS, RULE_SET_KEYS,
};
use super::selection_vocabulary::{
    ChannelIdentityFace, RelationshipContext, SelectionRuleWriterKind,
};

// ---------------------------------------------------------------------------
// Strict MessagePack codec
// ---------------------------------------------------------------------------

/// Encodes the stored overlay in canonical field order.
pub(super) fn encode_rule_set(
    set: &ChannelIdentitySelectionRuleSet,
) -> ChannelIdentitySelectionResult<Vec<u8>> {
    set.validate_stored()?;
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rule_set_value(set)).map_err(|_| {
        ChannelIdentitySelectionError::MalformedRuleSet("rule set could not be encoded")
    })?;
    Ok(bytes)
}

pub(super) fn rule_set_value(set: &ChannelIdentitySelectionRuleSet) -> Value {
    Value::Map(vec![
        (
            Value::from(RULE_SET_KEYS[0]),
            Value::from(u64::from(set.schema_version)),
        ),
        (Value::from(RULE_SET_KEYS[1]), Value::from(set.revision)),
        (
            Value::from(RULE_SET_KEYS[2]),
            Value::Array(set.rows.iter().map(rule_value).collect()),
        ),
    ])
}

fn rule_value(rule: &ChannelIdentitySelectionRule) -> Value {
    Value::Map(vec![
        (
            Value::from(RULE_KEYS[0]),
            Value::from(rule.rule_id.as_str()),
        ),
        (
            Value::from(RULE_KEYS[1]),
            Value::from(rule.relationship.as_str()),
        ),
        (Value::from(RULE_KEYS[2]), scope_value(&rule.scope)),
        (Value::from(RULE_KEYS[3]), Value::from(rule.face.as_str())),
        (
            Value::from(RULE_KEYS[4]),
            optional_entity_value(rule.pinned_identity_ref),
        ),
        (Value::from(RULE_KEYS[5]), Value::from(rule.priority)),
        (Value::from(RULE_KEYS[6]), Value::from(rule.enabled)),
        (Value::from(RULE_KEYS[7]), Value::from(rule.agent_amendable)),
        (Value::from(RULE_KEYS[8]), Value::from(rule.updated_at)),
        (
            Value::from(RULE_KEYS[9]),
            optional_entity_value(rule.updated_by),
        ),
        (
            Value::from(RULE_KEYS[10]),
            Value::from(rule.writer_kind.as_str()),
        ),
    ])
}

fn scope_value(scope: &SelectionRuleScope) -> Value {
    let mut entries = vec![(Value::from("kind"), Value::from(scope.kind_str()))];
    match scope {
        SelectionRuleScope::VaultDefault => {}
        SelectionRuleScope::World { world_ref } => {
            entries.push((Value::from("world_ref"), entity_value(*world_ref)));
        }
        SelectionRuleScope::Relationship { relationship_ref } => {
            entries.push((
                Value::from("relationship_ref"),
                entity_value(*relationship_ref),
            ));
        }
        SelectionRuleScope::Brief { brief_ref } => {
            entries.push((Value::from("brief_ref"), Value::from(brief_ref.as_str())));
        }
        SelectionRuleScope::Space { space_ref } => {
            entries.push((Value::from("space_ref"), Value::from(space_ref.as_str())));
        }
    }
    Value::Map(entries)
}

fn entity_value(id: EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn optional_entity_value(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, entity_value)
}

/// Decodes a stored overlay, rejecting every shape two decoders could read
/// differently: invalid MessagePack, trailing bytes, a non-map root, non-string
/// keys, unknown or missing or reordered or duplicated keys, bad enum tokens,
/// malformed scopes, and invalid entity references.
pub(super) fn decode_rule_set(
    raw: &[u8],
) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionRuleSet> {
    let mut cursor = Cursor::new(raw);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| ChannelIdentitySelectionError::MalformedRuleSet("not valid MessagePack"))?;
    if cursor.position() != raw.len() as u64 {
        return Err(ChannelIdentitySelectionError::MalformedRuleSet(
            "trailing bytes after rule set map",
        ));
    }
    let fields = strict_fields(&value, &RULE_SET_KEYS, "rule set map")?;
    let schema_version = fields[0]
        .as_u64()
        .and_then(|raw| u16::try_from(raw).ok())
        .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(
            "schema_version must be a u16",
        ))?;
    let revision = fields[1]
        .as_u64()
        .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(
            "revision must be a u64",
        ))?;
    let Value::Array(raw_rows) = fields[2] else {
        return Err(ChannelIdentitySelectionError::MalformedRuleSet(
            "rows must be an array",
        ));
    };
    let mut rows = Vec::with_capacity(raw_rows.len());
    for raw_row in raw_rows {
        rows.push(rule_from_value(raw_row)?);
    }
    let set = ChannelIdentitySelectionRuleSet {
        schema_version,
        revision,
        rows,
    };
    set.validate_stored()?;
    Ok(set)
}

fn rule_from_value(value: &Value) -> ChannelIdentitySelectionResult<ChannelIdentitySelectionRule> {
    let fields = strict_fields(value, &RULE_KEYS, "rule map")?;
    let rule =
        ChannelIdentitySelectionRule {
            rule_id: token(fields[0], "rule_id must be a string")?.to_owned(),
            relationship: RelationshipContext::parse(token(
                fields[1],
                "relationship must be a string",
            )?)
            .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(
                "unknown relationship context token",
            ))?,
            scope: scope_from_value(fields[2])?,
            face: ChannelIdentityFace::parse(token(fields[3], "face must be a string")?).ok_or(
                ChannelIdentitySelectionError::MalformedRuleSet("unknown face token"),
            )?,
            pinned_identity_ref: optional_entity_from_value(fields[4])?,
            priority: fields[5]
                .as_i64()
                .and_then(|raw| i32::try_from(raw).ok())
                .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(
                    "priority must be an i32",
                ))?,
            enabled: boolean(fields[6], "enabled must be a boolean")?,
            agent_amendable: boolean(fields[7], "agent_amendable must be a boolean")?,
            updated_at: fields[8].as_u64().ok_or(
                ChannelIdentitySelectionError::MalformedRuleSet("updated_at must be a u64"),
            )?,
            updated_by: optional_entity_from_value(fields[9])?,
            writer_kind: SelectionRuleWriterKind::parse(token(
                fields[10],
                "writer_kind must be a string",
            )?)
            .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(
                "unknown writer kind token",
            ))?,
        };
    rule.validate()?;
    Ok(rule)
}

fn scope_from_value(value: &Value) -> ChannelIdentitySelectionResult<SelectionRuleScope> {
    let Value::Map(entries) = value else {
        return Err(ChannelIdentitySelectionError::MalformedScope);
    };
    let (kind_key, kind_value) = entries
        .first()
        .ok_or(ChannelIdentitySelectionError::MalformedScope)?;
    if kind_key.as_str() != Some("kind") {
        return Err(ChannelIdentitySelectionError::MalformedScope);
    }
    let kind = kind_value
        .as_str()
        .ok_or(ChannelIdentitySelectionError::MalformedScope)?;
    if kind == "vault_default" {
        return match entries.len() {
            1 => Ok(SelectionRuleScope::VaultDefault),
            _ => Err(ChannelIdentitySelectionError::MalformedScope),
        };
    }
    if entries.len() != 2 {
        return Err(ChannelIdentitySelectionError::MalformedScope);
    }
    let (payload_key, payload) = &entries[1];
    let scope = match (kind, payload_key.as_str()) {
        ("world", Some("world_ref")) => SelectionRuleScope::World {
            world_ref: entity_from_value(payload)?,
        },
        ("relationship", Some("relationship_ref")) => SelectionRuleScope::Relationship {
            relationship_ref: entity_from_value(payload)?,
        },
        ("brief", Some("brief_ref")) => SelectionRuleScope::Brief {
            brief_ref: scope_text(payload)?,
        },
        ("space", Some("space_ref")) => SelectionRuleScope::Space {
            space_ref: scope_text(payload)?,
        },
        _ => return Err(ChannelIdentitySelectionError::MalformedScope),
    };
    scope.validate()?;
    Ok(scope)
}

fn scope_text(value: &Value) -> ChannelIdentitySelectionResult<String> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or(ChannelIdentitySelectionError::MalformedScope)
}

/// An entity reference is 16 raw bytes and nothing else — a same-length string
/// is a different wire type and is refused rather than reinterpreted.
fn entity_from_value(value: &Value) -> ChannelIdentitySelectionResult<EntityId> {
    let Value::Binary(raw) = value else {
        return Err(ChannelIdentitySelectionError::InvalidEntityRef);
    };
    let bytes = <[u8; 16]>::try_from(raw.as_slice())
        .map_err(|_| ChannelIdentitySelectionError::InvalidEntityRef)?;
    EntityId::from_bytes(bytes).map_err(|_| ChannelIdentitySelectionError::InvalidEntityRef)
}

fn optional_entity_from_value(value: &Value) -> ChannelIdentitySelectionResult<Option<EntityId>> {
    match value {
        Value::Nil => Ok(None),
        other => entity_from_value(other).map(Some),
    }
}

fn token<'a>(value: &'a Value, what: &'static str) -> ChannelIdentitySelectionResult<&'a str> {
    value
        .as_str()
        .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(what))
}

fn boolean(value: &Value, what: &'static str) -> ChannelIdentitySelectionResult<bool> {
    value
        .as_bool()
        .ok_or(ChannelIdentitySelectionError::MalformedRuleSet(what))
}

/// Requires the map to carry exactly `keys`, in order, with string keys.
///
/// One check rejects unknown keys, missing keys, duplicates, and reordering,
/// which is what makes the encoding canonical rather than merely parseable.
fn strict_fields<'a>(
    value: &'a Value,
    keys: &[&str],
    what: &'static str,
) -> ChannelIdentitySelectionResult<Vec<&'a Value>> {
    let Value::Map(entries) = value else {
        return Err(ChannelIdentitySelectionError::MalformedRuleSet(what));
    };
    if entries.len() != keys.len() {
        return Err(ChannelIdentitySelectionError::MalformedRuleSet(what));
    }
    let mut fields = Vec::with_capacity(keys.len());
    for (index, (key, field)) in entries.iter().enumerate() {
        if key.as_str() != Some(keys[index]) {
            return Err(ChannelIdentitySelectionError::MalformedRuleSet(what));
        }
        fields.push(field);
    }
    Ok(fields)
}
