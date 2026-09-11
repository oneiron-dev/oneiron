//! Canonical MessagePack codec for companion records, scope, subject, and provenance.

use super::keys::{
    COMPANION_RECORD_BODY_KEYS, COMPANION_RECORD_SCHEMA_VERSION,
    COMPANION_RECORD_SCHEMA_VERSION_V1, KEY_EXPORT, KEY_KIND, KEY_LIFECYCLE, KEY_LIFECYCLE_EVENTS,
    KEY_PROVENANCE, KEY_SCHEMA_VERSION, KEY_SCOPE, KEY_SUBJECT, KEY_VALUE, LIFECYCLE_EVENT_KEYS,
    PROVENANCE_KEYS, RELATIONSHIP_REF_KEYS, SCOPE_KEYS, SUBJECT_KEYS,
};
use super::model::{
    CompanionExportClassification, CompanionLifecycleEvent, CompanionLifecycleEventKind,
    CompanionProvenance, CompanionRecord, CompanionRecordKind, CompanionScope, CompanionSubject,
};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use rmpv::Value;
use serde_json::Value as JsonValue;
use std::io::Cursor;

/// Encodes a companion record body in canonical MessagePack field order.
pub fn encode_companion_record_body(record: &CompanionRecord) -> Result<Vec<u8>> {
    record.validate_current_schema_lifecycle_events()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COMPANION_RECORD_SCHEMA_VERSION),
        ),
        (Value::from(KEY_KIND), Value::from(record.kind().as_str())),
        (Value::from(KEY_SCOPE), encode_scope(&record.scope)),
        (Value::from(KEY_SUBJECT), encode_subject(&record.subject)),
        (Value::from(KEY_VALUE), record.value.clone()),
        (
            Value::from(KEY_PROVENANCE),
            encode_provenance(&record.provenance),
        ),
        (
            Value::from(KEY_LIFECYCLE),
            Value::from(record.lifecycle.as_str()),
        ),
        (
            Value::from(KEY_EXPORT),
            Value::from(record.export_classification.as_str()),
        ),
        (
            Value::from(KEY_LIFECYCLE_EVENTS),
            encode_lifecycle_events(&record.lifecycle_events),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("companion record MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and validates a companion record body.
pub fn decode_companion_record_body(bytes: &[u8]) -> Result<CompanionRecord> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_companion("body is not valid MessagePack"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_companion("trailing bytes after body map"));
    }

    decode_companion_record_value(&value)
}

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
    match value {
        Value::Nil => JsonValue::Null,
        Value::Boolean(value) => JsonValue::Bool(*value),
        Value::Integer(value) => {
            if let Some(value) = value.as_i64() {
                serde_json::json!(value)
            } else if let Some(value) = value.as_u64() {
                serde_json::json!(value)
            } else {
                JsonValue::Null
            }
        }
        Value::F32(value) => serde_json::json!(value),
        Value::F64(value) => serde_json::json!(value),
        Value::String(value) => match value.as_str() {
            Some(value) => JsonValue::String(value.to_owned()),
            None => serde_json::json!({ "redacted": "invalid_utf8_string" }),
        },
        Value::Binary(_) | Value::Ext(_, _) => JsonValue::Null,
        Value::Array(values) => {
            JsonValue::Array(values.iter().map(companion_value_to_json).collect())
        }
        Value::Map(entries) => {
            let mut object = serde_json::Map::new();
            for (key, value) in entries {
                let Some(key) = key.as_str() else {
                    continue;
                };
                object.insert(key.to_owned(), companion_value_to_json(value));
            }
            JsonValue::Object(object)
        }
    }
}

fn decode_companion_record_value(value: &Value) -> Result<CompanionRecord> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion("body must be a MessagePack map"));
    };

    let mut schema_version: Option<u64> = None;
    let mut kind: Option<CompanionRecordKind> = None;
    let mut scope: Option<CompanionScope> = None;
    let mut subject: Option<CompanionSubject> = None;
    let mut record_value: Option<Value> = None;
    let mut provenance: Option<CompanionProvenance> = None;
    let mut lifecycle: Option<ClaimLifecycleStatus> = None;
    let mut export_classification: Option<CompanionExportClassification> = None;
    let mut lifecycle_events: Option<Vec<CompanionLifecycleEvent>> = None;
    let mut seen = [false; COMPANION_RECORD_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion("body keys must be strings"));
        };
        let Some(index) = COMPANION_RECORD_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(invalid_companion(
                "body key is not in the pinned COMPANION_RECORD_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(invalid_companion("duplicate body key"));
        }
        seen[index] = true;

        match COMPANION_RECORD_BODY_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(
                    value
                        .as_u64()
                        .ok_or(invalid_companion("schema_version must be an integer"))?,
                );
            }
            KEY_KIND => {
                let parsed = value
                    .as_str()
                    .and_then(CompanionRecordKind::parse)
                    .ok_or(invalid_companion("kind must be persona|relationship"))?;
                kind = Some(parsed);
            }
            KEY_SCOPE => scope = Some(decode_scope(value)?),
            KEY_SUBJECT => subject = Some(decode_subject(value)?),
            KEY_VALUE => record_value = Some(value.clone()),
            KEY_PROVENANCE => provenance = Some(decode_provenance(value)?),
            KEY_LIFECYCLE => {
                let parsed = value.as_str().and_then(ClaimLifecycleStatus::parse).ok_or(
                    invalid_companion("lifecycle must be active|superseded|retracted"),
                )?;
                lifecycle = Some(parsed);
            }
            KEY_EXPORT => {
                let parsed = value
                    .as_str()
                    .and_then(CompanionExportClassification::parse)
                    .ok_or(invalid_companion(
                        "export must be local_only|portable|shared_vault",
                    ))?;
                export_classification = Some(parsed);
            }
            KEY_LIFECYCLE_EVENTS => {
                lifecycle_events = Some(decode_lifecycle_events(value)?);
            }
            _ => unreachable!("index resolved from COMPANION_RECORD_BODY_KEYS"),
        }
    }

    let schema_version =
        schema_version.ok_or(invalid_companion("missing required field schema_version"))?;
    if !matches!(
        Some(schema_version),
        Some(COMPANION_RECORD_SCHEMA_VERSION_V1 | COMPANION_RECORD_SCHEMA_VERSION)
    ) {
        return Err(invalid_companion(
            "unsupported companion record schema_version",
        ));
    }

    let record = CompanionRecord::new(
        scope.ok_or(invalid_companion("missing required field scope"))?,
        subject.ok_or(invalid_companion("missing required field subject"))?,
        record_value.ok_or(invalid_companion("missing required field value"))?,
        provenance.ok_or(invalid_companion("missing required field provenance"))?,
        lifecycle.ok_or(invalid_companion("missing required field lifecycle"))?,
        export_classification.ok_or(invalid_companion("missing required field export"))?,
    );
    let mut record = record;
    record.lifecycle_events = match (schema_version, lifecycle_events) {
        (COMPANION_RECORD_SCHEMA_VERSION, Some(events)) => events,
        (COMPANION_RECORD_SCHEMA_VERSION, None) => {
            return Err(invalid_companion("missing required field lifecycle_events"));
        }
        (_, events) => events.unwrap_or_default(),
    };
    let expected_kind = kind.ok_or(invalid_companion("missing required field kind"))?;
    if record.kind() != expected_kind {
        return Err(invalid_companion("kind does not match subject shape"));
    }
    record.validate()?;
    if schema_version == COMPANION_RECORD_SCHEMA_VERSION {
        record.validate_current_schema_lifecycle_events()?;
    }
    Ok(record)
}

pub(super) fn encode_lifecycle_events(events: &[CompanionLifecycleEvent]) -> Value {
    Value::Array(events.iter().map(encode_lifecycle_event).collect())
}

fn encode_lifecycle_event(event: &CompanionLifecycleEvent) -> Value {
    Value::Map(vec![
        (
            Value::from(LIFECYCLE_EVENT_KEYS[0]),
            Value::from(event.kind.as_str()),
        ),
        (Value::from(LIFECYCLE_EVENT_KEYS[1]), Value::from(event.at)),
    ])
}

fn decode_lifecycle_events(value: &Value) -> Result<Vec<CompanionLifecycleEvent>> {
    let Value::Array(events) = value else {
        return Err(invalid_companion("lifecycle_events must be an array"));
    };
    events.iter().map(decode_lifecycle_event).collect()
}

fn decode_lifecycle_event(value: &Value) -> Result<CompanionLifecycleEvent> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion("lifecycle event must be a map"));
    };

    let mut kind: Option<CompanionLifecycleEventKind> = None;
    let mut at: Option<u64> = None;
    let mut seen = [false; LIFECYCLE_EVENT_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion("lifecycle event keys must be strings"));
        };
        let Some(index) = LIFECYCLE_EVENT_KEYS.iter().position(|known| *known == key) else {
            return Err(invalid_companion("lifecycle event key is not kind|at"));
        };
        if seen[index] {
            return Err(invalid_companion("duplicate lifecycle event key"));
        }
        seen[index] = true;

        match LIFECYCLE_EVENT_KEYS[index] {
            "kind" => {
                kind = Some(
                    value
                        .as_str()
                        .and_then(CompanionLifecycleEventKind::parse)
                        .ok_or(invalid_companion(
                            "lifecycle event kind must be created|superseded|retired|revived",
                        ))?,
                );
            }
            "at" => {
                at = Some(
                    value
                        .as_u64()
                        .ok_or(invalid_companion("lifecycle event at must be an integer"))?,
                );
            }
            _ => unreachable!("index resolved from LIFECYCLE_EVENT_KEYS"),
        }
    }

    Ok(CompanionLifecycleEvent {
        kind: kind.ok_or(invalid_companion("lifecycle event missing kind"))?,
        at: at.ok_or(invalid_companion("lifecycle event missing at"))?,
    })
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

pub(super) fn encode_provenance(provenance: &CompanionProvenance) -> Value {
    Value::Map(vec![
        (
            Value::from(PROVENANCE_KEYS[0]),
            entity_value(&provenance.actor_ref),
        ),
        (
            Value::from(PROVENANCE_KEYS[1]),
            Value::from(provenance.actor_class as u8),
        ),
        (
            Value::from(PROVENANCE_KEYS[2]),
            Value::from(provenance.source.as_str()),
        ),
        (
            Value::from(PROVENANCE_KEYS[3]),
            Value::from(provenance.approval.as_str()),
        ),
        (Value::from(PROVENANCE_KEYS[4]), provenance.value.clone()),
    ])
}

fn decode_provenance(value: &Value) -> Result<CompanionProvenance> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion("provenance must be a map"));
    };

    let mut actor_ref: Option<EntityId> = None;
    let mut actor_class: Option<EdgeActorClass> = None;
    let mut source: Option<ClaimSource> = None;
    let mut approval: Option<ClaimApprovalStatus> = None;
    let mut provenance_value: Option<Value> = None;
    let mut seen = [false; PROVENANCE_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion("provenance keys must be strings"));
        };
        let Some(index) = PROVENANCE_KEYS.iter().position(|known| *known == key) else {
            return Err(invalid_companion(
                "provenance key is not actor_ref|actor_class|source|approval|value",
            ));
        };
        if seen[index] {
            return Err(invalid_companion("duplicate provenance key"));
        }
        seen[index] = true;

        match PROVENANCE_KEYS[index] {
            "actor_ref" => {
                actor_ref = Some(entity_from_value(
                    value,
                    "provenance.actor_ref must be entity id",
                )?);
            }
            "actor_class" => {
                let raw = value
                    .as_u64()
                    .and_then(|raw| u8::try_from(raw).ok())
                    .ok_or(invalid_companion("provenance.actor_class must be a u8"))?;
                actor_class = Some(EdgeActorClass::try_from_u8(raw).ok_or(invalid_companion(
                    "provenance.actor_class must be human|agent|system",
                ))?);
            }
            "source" => {
                source = Some(
                    value
                        .as_str()
                        .and_then(ClaimSource::parse)
                        .ok_or(invalid_companion("provenance.source is not recognized"))?,
                );
            }
            "approval" => {
                approval = Some(
                    value
                        .as_str()
                        .and_then(ClaimApprovalStatus::parse)
                        .ok_or(invalid_companion("provenance.approval is not recognized"))?,
                );
            }
            "value" => provenance_value = Some(value.clone()),
            _ => unreachable!("index resolved from PROVENANCE_KEYS"),
        }
    }

    let provenance = CompanionProvenance::new(
        actor_ref.ok_or(invalid_companion("provenance missing actor_ref"))?,
        actor_class.ok_or(invalid_companion("provenance missing actor_class"))?,
        source.ok_or(invalid_companion("provenance missing source"))?,
        approval.ok_or(invalid_companion("provenance missing approval"))?,
        provenance_value.ok_or(invalid_companion("provenance missing value"))?,
    );
    provenance.validate()?;
    Ok(provenance)
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
