//! Scope/subject task payload codecs and JSON value conversion for persona input.

use super::keys::{RELATIONSHIP_REF_KEYS, SCOPE_KEYS, SUBJECT_KEYS};
use super::model::{CompanionScope, CompanionSubject};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use rmpv::Value;
use serde_json::Value as JsonValue;
use std::io::Cursor;

/// Converts JSON accepted by public APIs into the opaque MessagePack value
/// carried by a companion record.
pub fn companion_value_from_json(value: &JsonValue) -> Result<Value> {
    let encoded = rmp_serde::to_vec_named(value)
        .map_err(|_| invalid_companion("companion record value must be msgpack-encodable JSON"))?;
    let mut cursor = Cursor::new(encoded.as_slice());
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_companion("companion record value is not valid MessagePack"))?;
    if cursor.position() != encoded.len() as u64 {
        return Err(invalid_companion(
            "trailing bytes after companion record value",
        ));
    }
    Ok(value)
}

/// Converts the opaque companion MessagePack value back to JSON for typed API
/// envelopes. MessagePack binary/ext values are redacted because they are not
/// JSON-shaped public API values.
#[must_use]
pub fn companion_value_to_json(value: &Value) -> JsonValue {
    projected_json(companion_value_projection(value))
}

/// What [`companion_value_to_json`] keeps of a value, still as MessagePack:
/// binary, extension and non-finite floats as nil, a string that is no UTF-8
/// as the `invalid_utf8_string` marker, and a map's text keys once each (the
/// last value at the first key's place), as a JSON object keeps them. Each
/// number keeps the width that JSON drops, so a reader can read this value
/// exactly as the JSON it becomes.
pub(crate) fn companion_value_projection(value: &Value) -> Value {
    match value {
        Value::F32(number) if !number.is_finite() => Value::Nil,
        Value::F64(number) if !number.is_finite() => Value::Nil,
        Value::String(text) if text.as_str().is_none() => Value::Map(vec![(
            Value::from("redacted"),
            Value::from("invalid_utf8_string"),
        )]),
        Value::Binary(_) | Value::Ext(_, _) => Value::Nil,
        Value::Array(values) => {
            Value::Array(values.iter().map(companion_value_projection).collect())
        }
        Value::Map(entries) => {
            let mut kept: Vec<(Value, Value)> = Vec::with_capacity(entries.len());
            let mut at: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::with_capacity(entries.len());
            for (key, value) in entries {
                let Some(key) = key.as_str() else {
                    continue;
                };
                let value = companion_value_projection(value);
                match at.entry(key) {
                    std::collections::hash_map::Entry::Occupied(slot) => {
                        kept[*slot.get()].1 = value;
                    }
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(kept.len());
                        kept.push((Value::from(key), value));
                    }
                }
            }
            Value::Map(kept)
        }
        other => other.clone(),
    }
}

/// A [`companion_value_projection`] as JSON, which loses only number widths.
fn projected_json(value: Value) -> JsonValue {
    match value {
        Value::Boolean(value) => JsonValue::Bool(value),
        Value::Integer(value) => match (value.as_i64(), value.as_u64()) {
            (Some(signed), _) => JsonValue::from(signed),
            (None, Some(unsigned)) => JsonValue::from(unsigned),
            (None, None) => JsonValue::Null,
        },
        Value::F32(value) => serde_json::json!(value),
        Value::F64(value) => serde_json::json!(value),
        Value::String(value) => value.into_str().map_or(JsonValue::Null, JsonValue::String),
        Value::Array(values) => JsonValue::Array(values.into_iter().map(projected_json).collect()),
        Value::Map(entries) => JsonValue::Object(
            entries
                .into_iter()
                .filter_map(|(key, value)| match key {
                    Value::String(key) => Some((key.into_str()?, projected_json(value))),
                    _ => None,
                })
                .collect(),
        ),
        Value::Nil | Value::Binary(_) | Value::Ext(_, _) => JsonValue::Null,
    }
}

pub(super) fn encode_scope(scope: &CompanionScope) -> Value {
    let mut entries = vec![(Value::from(SCOPE_KEYS[0]), Value::from(scope.as_str()))];
    match scope {
        CompanionScope::Neutral => {}
        CompanionScope::Personal { person_ref } => {
            entries.push((Value::from(SCOPE_KEYS[1]), entity_value(person_ref)));
        }
        CompanionScope::SharedVault { vault_id } => {
            entries.push((Value::from(SCOPE_KEYS[2]), Value::from(*vault_id)));
        }
    }
    Value::Map(entries)
}

pub(super) fn decode_scope(value: &Value) -> Result<CompanionScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion("scope must be a map"));
    };

    let mut kind: Option<&str> = None;
    let mut person_ref: Option<EntityId> = None;
    let mut vault_id: Option<u64> = None;
    let mut seen = [false; SCOPE_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion("scope keys must be strings"));
        };
        let Some(index) = SCOPE_KEYS.iter().position(|known| *known == key) else {
            return Err(invalid_companion(
                "scope key is not kind|person_ref|vault_id",
            ));
        };
        if seen[index] {
            return Err(invalid_companion("duplicate scope key"));
        }
        seen[index] = true;

        match SCOPE_KEYS[index] {
            "kind" => {
                kind = Some(
                    value
                        .as_str()
                        .ok_or(invalid_companion("scope.kind must be a string"))?,
                );
            }
            "person_ref" => {
                person_ref = Some(entity_from_value(
                    value,
                    "scope.person_ref must be entity id",
                )?);
            }
            "vault_id" => {
                vault_id = Some(
                    value
                        .as_u64()
                        .ok_or(invalid_companion("scope.vault_id must be an integer"))?,
                );
            }
            _ => unreachable!("index resolved from SCOPE_KEYS"),
        }
    }

    let scope = match kind.ok_or(invalid_companion("scope missing kind"))? {
        "neutral" if person_ref.is_none() && vault_id.is_none() => CompanionScope::Neutral,
        "personal" if vault_id.is_none() => CompanionScope::Personal {
            person_ref: person_ref.ok_or(invalid_companion(
                "personal companion scope requires person_ref",
            ))?,
        },
        "shared_vault" if person_ref.is_none() => CompanionScope::SharedVault {
            vault_id: vault_id.ok_or(invalid_companion(
                "shared-vault companion scope requires vault_id",
            ))?,
        },
        _ => return Err(invalid_companion("scope shape does not match scope.kind")),
    };
    scope.validate()?;
    Ok(scope)
}

pub(super) fn encode_subject(subject: &CompanionSubject) -> Value {
    match subject {
        CompanionSubject::Persona { persona_ref } => Value::Map(vec![
            (Value::from(SUBJECT_KEYS[0]), Value::from("persona")),
            (Value::from(SUBJECT_KEYS[1]), entity_value(persona_ref)),
        ]),
        CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => Value::Map(vec![
            (Value::from(SUBJECT_KEYS[0]), Value::from("relationship")),
            (
                Value::from(SUBJECT_KEYS[2]),
                Value::Map(vec![
                    (
                        Value::from(RELATIONSHIP_REF_KEYS[0]),
                        entity_value(source_ref),
                    ),
                    (
                        Value::from(RELATIONSHIP_REF_KEYS[1]),
                        entity_value(target_ref),
                    ),
                ]),
            ),
        ]),
    }
}

pub(super) fn decode_subject(value: &Value) -> Result<CompanionSubject> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion("subject must be a map"));
    };

    let mut kind: Option<&str> = None;
    let mut persona_ref: Option<EntityId> = None;
    let mut relationship_ref: Option<(EntityId, EntityId)> = None;
    let mut seen = [false; SUBJECT_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion("subject keys must be strings"));
        };
        let Some(index) = SUBJECT_KEYS.iter().position(|known| *known == key) else {
            return Err(invalid_companion(
                "subject key is not kind|persona_ref|relationship_ref",
            ));
        };
        if seen[index] {
            return Err(invalid_companion("duplicate subject key"));
        }
        seen[index] = true;

        match SUBJECT_KEYS[index] {
            "kind" => {
                kind = Some(
                    value
                        .as_str()
                        .ok_or(invalid_companion("subject.kind must be a string"))?,
                );
            }
            "persona_ref" => {
                persona_ref = Some(entity_from_value(
                    value,
                    "subject.persona_ref must be entity id",
                )?);
            }
            "relationship_ref" => relationship_ref = Some(decode_relationship_ref(value)?),
            _ => unreachable!("index resolved from SUBJECT_KEYS"),
        }
    }

    match kind.ok_or(invalid_companion("subject missing kind"))? {
        "persona" if relationship_ref.is_none() => Ok(CompanionSubject::Persona {
            persona_ref: persona_ref
                .ok_or(invalid_companion("persona subject requires persona_ref"))?,
        }),
        "relationship" if persona_ref.is_none() => {
            let (source_ref, target_ref) = relationship_ref.ok_or(invalid_companion(
                "relationship subject requires relationship_ref",
            ))?;
            Ok(CompanionSubject::Relationship {
                source_ref,
                target_ref,
            })
        }
        _ => Err(invalid_companion(
            "subject shape does not match subject.kind",
        )),
    }
}

fn decode_relationship_ref(value: &Value) -> Result<(EntityId, EntityId)> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion("relationship_ref must be a map"));
    };

    let mut source_ref: Option<EntityId> = None;
    let mut target_ref: Option<EntityId> = None;
    let mut seen = [false; RELATIONSHIP_REF_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion("relationship_ref keys must be strings"));
        };
        let Some(index) = RELATIONSHIP_REF_KEYS.iter().position(|known| *known == key) else {
            return Err(invalid_companion(
                "relationship_ref key is not source_ref|target_ref",
            ));
        };
        if seen[index] {
            return Err(invalid_companion("duplicate relationship_ref key"));
        }
        seen[index] = true;

        match RELATIONSHIP_REF_KEYS[index] {
            "source_ref" => {
                source_ref = Some(entity_from_value(
                    value,
                    "relationship_ref.source_ref must be entity id",
                )?);
            }
            "target_ref" => {
                target_ref = Some(entity_from_value(
                    value,
                    "relationship_ref.target_ref must be entity id",
                )?);
            }
            _ => unreachable!("index resolved from RELATIONSHIP_REF_KEYS"),
        }
    }

    Ok((
        source_ref.ok_or(invalid_companion("relationship_ref missing source_ref"))?,
        target_ref.ok_or(invalid_companion("relationship_ref missing target_ref"))?,
    ))
}

fn entity_value(id: &EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn entity_from_value(value: &Value, context: &'static str) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_companion(context));
    };
    if bytes.len() != crate::entity_id::ENTITY_ID_LEN {
        return Err(invalid_companion(context));
    }
    let mut arr = [0_u8; crate::entity_id::ENTITY_ID_LEN];
    arr.copy_from_slice(bytes);
    EntityId::from_bytes(arr).map_err(|_| invalid_companion(context))
}

pub(super) fn invalid_companion(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

pub(super) fn invalid_companion_task(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(reason))
}
