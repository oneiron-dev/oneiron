use std::fmt;

use oneiron::types::{
    CompanionScope, CompanionSubject, ENTITY_TYPE_CLAIM, ENTITY_TYPE_COMPANION_REGISTER,
    ENTITY_TYPE_EVENT, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_SKILL,
    ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TASK, ENTITY_TYPE_TASK_LIST, ENTITY_TYPE_TURN,
    companion::CompanionLifecycleEvent, decode_companion_record_body, entity_type_registry_entry,
};
use oneiron::{EdgeInfo, EntityId, FieldProfile, SKILL_RECORD_BODY_KEYS, Vault};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value, json};

#[cfg(test)]
const ENTITY_SUMMARY_FIELDS: &[&str] = &["id", "kind", "label", "updatedAt"];
#[cfg(test)]
const ENTITY_FULL_META_FIELDS: &[&str] = &["id", "kind", "type", "label", "updatedAt"];

/// Read projection requested by homogeneous CRUD read endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, utoipa::ToSchema)]
#[schema(rename_all = "lowercase")]
pub enum View {
    /// Compact read projection for list/search results.
    Summary,
    /// Default entity read projection; raw bytes for `/api/entity/{id}`.
    Standard,
    /// Full JSON projection with decoded body fields and metadata.
    Full,
}

impl View {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Summary => "summary",
            Self::Standard => "standard",
            Self::Full => "full",
        }
    }

    pub const fn field_profile(self) -> FieldProfile {
        match self {
            Self::Summary => FieldProfile::Minimal,
            Self::Standard => FieldProfile::Standard,
            Self::Full => FieldProfile::Full,
        }
    }

    pub fn parse(value: &str) -> Result<Self, InvalidView> {
        match value {
            "summary" => Ok(Self::Summary),
            "standard" => Ok(Self::Standard),
            "full" => Ok(Self::Full),
            _ => Err(InvalidView),
        }
    }
}

impl<'de> Deserialize<'de> for View {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ViewVisitor;

        impl Visitor<'_> for ViewVisitor {
            type Value = View;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("summary, standard, or full")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                View::parse(value).map_err(|_| E::custom("invalid_view"))
            }
        }

        deserializer.deserialize_str(ViewVisitor)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InvalidView;

pub fn project_entity(vault: &Vault, id: &EntityId, view: View) -> oneiron::Result<Option<Value>> {
    let Some(body) = vault.get(id)? else {
        return Ok(None);
    };
    let Some(entity_type) = vault.get_entity_type(id)? else {
        return Ok(None);
    };
    let updated_at = vault.get_learned_at(id)?;

    Ok(Some(project_entity_parts(
        id,
        entity_type,
        updated_at,
        &body,
        view,
    )))
}

pub fn project_entity_parts(
    id: &EntityId,
    entity_type: u8,
    updated_at: u64,
    body: &[u8],
    view: View,
) -> Value {
    let id_hex = id.to_hex();
    let fields = decode_body_fields(entity_type, body);
    let label = label_from_fields(&fields).unwrap_or_else(|| id_hex.clone());

    match view {
        View::Summary => summary_object(id_hex, entity_type, label, updated_at),
        View::Standard => Value::Object(select_profile_fields(entity_type, view, &fields)),
        View::Full => {
            let mut object = fields;
            insert_entity_metadata(&mut object, id_hex, entity_type, label, updated_at);
            Value::Object(object)
        }
    }
}

pub fn project_search_result(
    vault: &Vault,
    result: oneiron::ScoredEntity,
    view: View,
) -> oneiron::Result<Option<Value>> {
    let id_hex = result.id.to_hex();
    match view {
        View::Standard => Ok(Some(json!({
            "id": id_hex,
            "score": result.score,
        }))),
        View::Summary => project_entity(vault, &result.id, View::Summary),
        View::Full => {
            let Some(mut value) = project_entity(vault, &result.id, View::Full)? else {
                return Ok(None);
            };
            if let Value::Object(object) = &mut value {
                object.insert("score".to_owned(), json!(result.score));
            }
            Ok(Some(value))
        }
    }
}

pub fn project_edge(edge: &EdgeInfo, view: View) -> Value {
    match view {
        View::Summary => json!({
            "kind": edge.kind as u8,
            "target": edge.target.to_hex(),
        }),
        View::Standard => json!({
            "kind": edge.kind as u8,
            "target": edge.target.to_hex(),
            "weight": edge.weight,
            "created_at": edge.created_at,
        }),
        View::Full => {
            let mut object = Map::from_iter([
                ("kind".to_owned(), json!(edge.kind as u8)),
                ("target".to_owned(), json!(edge.target.to_hex())),
                ("weight".to_owned(), json!(edge.weight)),
                ("created_at".to_owned(), json!(edge.created_at)),
            ]);
            if let Some(vad) = edge.vad {
                object.insert(
                    "vad".to_owned(),
                    json!({
                        "valence": vad.valence,
                        "arousal": vad.arousal,
                        "dominance": vad.dominance,
                    }),
                );
            }
            if let Some(provenance) = edge.provenance {
                object.insert(
                    "provenance".to_owned(),
                    json!({
                        "confirmation_status": provenance.confirmation_status as u8,
                        "actor_class": provenance.actor_class as u8,
                    }),
                );
            }
            Value::Object(object)
        }
    }
}

#[cfg(test)]
pub(crate) fn entity_projection_keys(entity_type: u8, view: View) -> Vec<&'static str> {
    match view {
        View::Summary => ENTITY_SUMMARY_FIELDS.to_vec(),
        View::Standard => profile_fields(entity_type, view.field_profile()).to_vec(),
        View::Full => {
            let mut keys = ENTITY_FULL_META_FIELDS.to_vec();
            keys.extend(profile_fields(entity_type, view.field_profile()));
            keys
        }
    }
}

fn summary_object(id_hex: String, entity_type: u8, label: String, updated_at: u64) -> Value {
    json!({
        "id": id_hex,
        "kind": entity_kind(entity_type),
        "label": label,
        "updatedAt": updated_at,
    })
}

fn insert_entity_metadata(
    object: &mut Map<String, Value>,
    id_hex: String,
    entity_type: u8,
    label: String,
    updated_at: u64,
) {
    object.insert("id".to_owned(), Value::String(id_hex));
    object.insert("kind".to_owned(), Value::String(entity_kind(entity_type)));
    object.insert("type".to_owned(), json!(entity_type));
    object.insert("label".to_owned(), Value::String(label));
    object.insert("updatedAt".to_owned(), json!(updated_at));
}

fn entity_kind(entity_type: u8) -> String {
    entity_type_registry_entry(entity_type).map_or_else(
        || format!("TYPE_{entity_type}"),
        |entry| entry.kind.to_owned(),
    )
}

fn decode_body_fields(entity_type: u8, body: &[u8]) -> Map<String, Value> {
    if entity_type == ENTITY_TYPE_COMPANION_REGISTER {
        return decode_companion_register_fields(body).unwrap_or_else(|| {
            Map::from_iter([(
                "redacted".to_owned(),
                Value::String("invalid_companion_register_body".to_owned()),
            )])
        });
    }

    match rmp_serde::from_slice::<Value>(body) {
        Ok(Value::Object(fields)) => fields,
        Ok(value) => Map::from_iter([("body".to_owned(), value)]),
        Err(_) => Map::from_iter([(
            "bodyBytes".to_owned(),
            Value::Array(body.iter().map(|byte| json!(byte)).collect()),
        )]),
    }
}

fn decode_companion_register_fields(body: &[u8]) -> Option<Map<String, Value>> {
    let record = decode_companion_record_body(body).ok()?;
    let mut fields = Map::new();
    fields.insert(
        "record_kind".to_owned(),
        Value::String(record.kind().as_str().to_owned()),
    );
    fields.insert("scope".to_owned(), companion_scope_to_json(&record.scope));
    fields.insert(
        "subject".to_owned(),
        companion_subject_to_json(&record.subject),
    );
    fields.insert(
        "lifecycle".to_owned(),
        Value::String(record.lifecycle.as_str().to_owned()),
    );
    fields.insert(
        "export".to_owned(),
        Value::String(record.export_classification.as_str().to_owned()),
    );
    fields.insert(
        "provenance".to_owned(),
        json!({
            "actor_ref": record.provenance.actor_ref.to_hex(),
            "actor_class": record.provenance.actor_class as u8,
            "source": record.provenance.source.as_str(),
            "approval": record.provenance.approval.as_str(),
        }),
    );
    fields.insert(
        "lifecycle_events".to_owned(),
        companion_lifecycle_events_to_json(&record.lifecycle_events),
    );
    Some(fields)
}

fn companion_lifecycle_events_to_json(events: &[CompanionLifecycleEvent]) -> Value {
    Value::Array(
        events
            .iter()
            .map(|event| {
                json!({
                    "kind": event.kind.as_str(),
                    "at": event.at,
                })
            })
            .collect(),
    )
}

fn companion_scope_to_json(scope: &CompanionScope) -> Value {
    match scope {
        CompanionScope::Neutral => json!({ "kind": "neutral" }),
        CompanionScope::Personal { person_ref } => {
            json!({ "kind": "personal", "person_ref": person_ref.to_hex() })
        }
        CompanionScope::SharedVault { vault_id } => {
            json!({ "kind": "shared_vault", "vault_id": vault_id })
        }
        _ => json!({ "kind": "unknown" }),
    }
}

fn companion_subject_to_json(subject: &CompanionSubject) -> Value {
    match subject {
        CompanionSubject::Persona { persona_ref } => {
            json!({ "kind": "persona", "persona_ref": persona_ref.to_hex() })
        }
        CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => json!({
            "kind": "relationship",
            "relationship_ref": {
                "source_ref": source_ref.to_hex(),
                "target_ref": target_ref.to_hex(),
            },
        }),
        _ => json!({ "kind": "unknown" }),
    }
}

fn select_profile_fields(
    entity_type: u8,
    view: View,
    fields: &Map<String, Value>,
) -> Map<String, Value> {
    let allow = profile_fields(entity_type, view.field_profile());
    if allow.is_empty() {
        return fields
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
    }

    allow
        .iter()
        .filter_map(|key| {
            fields
                .get_key_value(*key)
                .map(|(key, value)| (key.clone(), value.clone()))
        })
        .collect()
}

fn label_from_fields(fields: &Map<String, Value>) -> Option<String> {
    for key in ["label", "title", "name", "skillId", "pred", "txt"] {
        if let Some(label) = fields.get(key).and_then(value_to_label) {
            return Some(label);
        }
    }
    None
}

fn value_to_label(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn profile_fields(entity_type: u8, profile: FieldProfile) -> &'static [&'static str] {
    match (entity_type, profile) {
        (ENTITY_TYPE_CLAIM, FieldProfile::Minimal) => &["pred", "val"],
        (ENTITY_TYPE_CLAIM, FieldProfile::Standard) => &["pred", "val", "conf", "sal", "evid"],
        (ENTITY_TYPE_CLAIM, FieldProfile::Full) => &[
            "pred", "val", "conf", "sal", "evid", "from", "to", "src", "world", "subj", "scope",
        ],

        (ENTITY_TYPE_TURN, FieldProfile::Minimal) => &["txt"],
        (ENTITY_TYPE_TURN, FieldProfile::Standard) => &[
            "txt",
            "spkr",
            "at",
            "message_type",
            "voice",
            "attribution",
            "announcement_status",
            "show_original",
        ],
        (ENTITY_TYPE_TURN, FieldProfile::Full) => &[
            "txt",
            "spkr",
            "speaker",
            "at",
            "sess",
            "message_type",
            "voice",
            "attribution",
            "render_voice",
            "platform_voice",
            "is_eiri",
            "announcement_status",
            "retracted",
            "corrected",
            "localized",
            "locale",
            "original_txt",
            "show_original",
        ],

        (ENTITY_TYPE_SUMMARY, FieldProfile::Minimal) => &["txt"],
        (ENTITY_TYPE_SUMMARY, FieldProfile::Standard) => &["txt", "lvl", "at"],
        (ENTITY_TYPE_SUMMARY, FieldProfile::Full) => &["txt", "lvl", "at", "src"],

        (ENTITY_TYPE_EVENT, FieldProfile::Minimal) => &["name"],
        (ENTITY_TYPE_EVENT, FieldProfile::Standard) => &["name", "at", "ppl"],
        (ENTITY_TYPE_EVENT, FieldProfile::Full) => &["name", "at", "ppl", "place", "desc"],

        (ENTITY_TYPE_PERSON, FieldProfile::Minimal) => &["name"],
        (ENTITY_TYPE_PERSON, FieldProfile::Standard) => &["name"],
        (ENTITY_TYPE_PERSON, FieldProfile::Full) => &["name", "role", "rel"],

        (ENTITY_TYPE_SKILL, FieldProfile::Minimal) => &["skillId"],
        (ENTITY_TYPE_SKILL, FieldProfile::Standard) => &["skillId", "desc", "approvalStatus"],
        (ENTITY_TYPE_SKILL, FieldProfile::Full) => &SKILL_RECORD_BODY_KEYS,

        (ENTITY_TYPE_TASK_LIST, FieldProfile::Minimal) => &["name"],
        (ENTITY_TYPE_TASK_LIST, FieldProfile::Standard) => &["name", "goal", "status"],
        (ENTITY_TYPE_TASK_LIST, FieldProfile::Full) => {
            &["name", "goal", "status", "icon", "color", "repoUrl"]
        }

        (ENTITY_TYPE_TASK, FieldProfile::Minimal) => &["title", "role"],
        (ENTITY_TYPE_TASK, FieldProfile::Standard) => {
            &["title", "role", "status", "priority", "dueDate"]
        }
        (ENTITY_TYPE_TASK, FieldProfile::Full) => &[
            "title",
            "role",
            "status",
            "priority",
            "dueDate",
            "frequency",
            "frequencyDetail",
            "currentStreak",
            "longestStreak",
            "parentId",
            "listId",
            "position",
        ],

        (ENTITY_TYPE_MACHINE, _) => &[],

        _ => &[],
    }
}

#[cfg(test)]
mod tests;
