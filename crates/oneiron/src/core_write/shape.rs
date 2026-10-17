//! The shape every core entity write shares: its id, its interval, its
//! announcement-normalized body and its text index. The REST create routes
//! and the `vault.conversations.*` and `vault.batch` rows stage through
//! these, so one rule set holds for both callers.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::memory::{MemoryError, MemoryResult};
use crate::registry::{ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN};
use crate::{BatchBuilder, EntityId, TimeRange};

/// The most entities one atomic batch puts.
pub const CORE_MAX_BATCH_ENTITIES: usize = 256;

pub const PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE: &str = "platform_announcement";

pub const PLATFORM_ANNOUNCEMENT_VOICE: &str = "platform";

pub const ANNOUNCEMENT_STATUS_ACTIVE: &str = "active";

pub const ANNOUNCEMENT_STATUS_CORRECTED: &str = "corrected";

pub const ANNOUNCEMENT_STATUS_RETRACTED: &str = "retracted";

/// One text-index field written with an entity body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreWriteTextField {
    pub field: String,
    pub value: String,
}

/// Why a core write's shape is refused. Each names the field it faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreWriteRefusal {
    /// The interval starts after it ends.
    Interval,
    /// The body does not encode as MessagePack.
    Body,
    /// A scope summary's body, which only the Dreamer writes (ARCH-0006a).
    ScopeSummary,
}

impl CoreWriteRefusal {
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::Interval => "occurred_start must be less than or equal to occurred_end",
            Self::Body => "body must be msgpack-encodable JSON",
            Self::ScopeSummary => {
                "a scope summary's body is written by the Dreamer; declare the scope at POST /v1/core/conversations/{conversation_id}/summaries"
            }
        }
    }

    #[must_use]
    pub fn field(self) -> &'static str {
        match self {
            Self::Interval => "occurred_start",
            Self::Body => "body",
            Self::ScopeSummary => "entity_type",
        }
    }
}

impl From<CoreWriteRefusal> for MemoryError {
    fn from(refusal: CoreWriteRefusal) -> Self {
        Self::bad_request(refusal.message())
    }
}

/// A write's occurrence interval and learned time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreWriteTimes {
    pub occurred: TimeRange,
    pub learned_at: u64,
}

/// The interval a write names: learned defaults to now, the start to the
/// learned time, the end to the start.
/// # Errors
/// [`CoreWriteRefusal::Interval`] when the start is after the end.
pub fn core_write_times(
    occurred_start: Option<u64>,
    occurred_end: Option<u64>,
    learned_at: Option<u64>,
) -> Result<CoreWriteTimes, CoreWriteRefusal> {
    let learned_at = learned_at.unwrap_or_else(crate::unix_seconds_now);
    let start = occurred_start.unwrap_or(learned_at);
    let end = occurred_end.unwrap_or(start);
    if start > end {
        return Err(CoreWriteRefusal::Interval);
    }
    Ok(CoreWriteTimes {
        occurred: TimeRange { start, end },
        learned_at,
    })
}

/// The body as stored: a TURN's platform announcement is normalized.
#[must_use]
pub fn core_body_for_write(entity_type: u8, body: &Value) -> Cow<'_, Value> {
    if entity_type != ENTITY_TYPE_TURN {
        return Cow::Borrowed(body);
    }
    normalize_platform_announcement_body(body)
}

/// # Errors
/// [`CoreWriteRefusal::Body`] when the body does not encode.
pub fn encode_core_body(body: &Value) -> Result<Vec<u8>, CoreWriteRefusal> {
    rmp_serde::to_vec_named(body).map_err(|_| CoreWriteRefusal::Body)
}

#[must_use]
pub fn normalize_platform_announcement_body(body: &Value) -> Cow<'_, Value> {
    let Value::Object(object) = body else {
        return Cow::Borrowed(body);
    };
    if !is_platform_announcement_body(object) {
        return Cow::Borrowed(body);
    }

    let mut normalized = object.clone();
    normalized.remove("messageType");
    normalized.remove("originalText");
    normalized.remove("showOriginal");
    normalized.insert(
        "message_type".to_owned(),
        Value::String(PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE.to_owned()),
    );
    for key in [
        "spkr",
        "speaker",
        "voice",
        "attribution",
        "render_voice",
    ] {
        normalized.insert(
            key.to_owned(),
            Value::String(PLATFORM_ANNOUNCEMENT_VOICE.to_owned()),
        );
    }
    normalized.insert("platform_voice".to_owned(), Value::Bool(true));
    normalized.insert("is_companion".to_owned(), Value::Bool(false));

    let status = announcement_status(object);
    normalized.insert(
        "announcement_status".to_owned(),
        Value::String(status.to_owned()),
    );
    normalized.insert(
        "retracted".to_owned(),
        Value::Bool(status == ANNOUNCEMENT_STATUS_RETRACTED),
    );
    normalized.insert(
        "corrected".to_owned(),
        Value::Bool(status == ANNOUNCEMENT_STATUS_CORRECTED),
    );

    let original = announcement_original_text(object);
    if let Some(original) = original {
        normalized.insert(
            "original_txt".to_owned(),
            Value::String(original.to_owned()),
        );
    }
    let localized = object_bool_field(object, &["localized"]).unwrap_or(false)
        || object_string_field(object, &["locale", "localized_locale", "localizedLocale"])
            .is_some()
        || original.is_some();
    if localized {
        normalized.insert("localized".to_owned(), Value::Bool(true));
    }
    if let Some(show_original) = object_bool_field(object, &["show_original", "showOriginal"]) {
        normalized.insert("show_original".to_owned(), Value::Bool(show_original));
    } else if original.is_some() {
        normalized.insert("show_original".to_owned(), Value::Bool(true));
    }

    Cow::Owned(Value::Object(normalized))
}

#[must_use]
pub fn is_platform_announcement_body(object: &serde_json::Map<String, Value>) -> bool {
    object_string_field(object, &["message_type", "messageType"]).is_some_and(|message_type| {
        message_type.eq_ignore_ascii_case(PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE)
    })
}

#[must_use]
pub fn announcement_status(object: &serde_json::Map<String, Value>) -> &'static str {
    match object_string_field(object, &["announcement_status", "announcementStatus"]) {
        Some(status) if status.eq_ignore_ascii_case(ANNOUNCEMENT_STATUS_RETRACTED) => {
            ANNOUNCEMENT_STATUS_RETRACTED
        }
        Some(status) if status.eq_ignore_ascii_case(ANNOUNCEMENT_STATUS_CORRECTED) => {
            ANNOUNCEMENT_STATUS_CORRECTED
        }
        Some(status) if status.eq_ignore_ascii_case(ANNOUNCEMENT_STATUS_ACTIVE) => {
            ANNOUNCEMENT_STATUS_ACTIVE
        }
        _ if object_bool_field(object, &["retracted"]).unwrap_or(false) => {
            ANNOUNCEMENT_STATUS_RETRACTED
        }
        _ if object_bool_field(object, &["corrected"]).unwrap_or(false) => {
            ANNOUNCEMENT_STATUS_CORRECTED
        }
        _ => ANNOUNCEMENT_STATUS_ACTIVE,
    }
}

#[must_use]
pub fn announcement_original_text(object: &serde_json::Map<String, Value>) -> Option<&str> {
    object_string_field(object, &["original_txt", "originalText", "original_text"]).or_else(|| {
        let original = object.get("original")?.as_object()?;
        object_string_field(original, &["txt", "text", "body"])
    })
}

fn object_string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
}

fn object_bool_field(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_bool))
}

/// The text a write indexes: the explicit fields, each nonempty pair of
/// them; with none named, the body's nonempty top-level strings. An empty
/// explicit list indexes nothing.
pub fn core_text_pairs<'t>(
    text: Option<impl IntoIterator<Item = (&'t str, &'t str)>>,
    body: &Value,
) -> Vec<(String, String)> {
    if let Some(text) = text {
        return text
            .into_iter()
            .filter(|(field, value)| !field.is_empty() && !value.is_empty())
            .map(|(field, value)| (field.to_owned(), value.to_owned()))
            .collect();
    }

    let Value::Object(object) = body else {
        return Vec::new();
    };
    object
        .iter()
        .filter_map(|(key, value)| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(|value| (key.clone(), value.to_owned()))
        })
        .collect()
}

/// A row's text fields as the pairs [`core_text_pairs`] reads.
pub(crate) fn text_pairs(
    text: &[CoreWriteTextField],
) -> impl Iterator<Item = (&str, &str)> {
    text.iter()
        .map(|entry| (entry.field.as_str(), entry.value.as_str()))
}

/// Stages one entity put, and its text index, on `batch`.
/// # Errors
/// A body that does not encode, or a scope summary's body.
pub fn stage_core_put<'a, 't>(
    batch: BatchBuilder<'a>,
    id: &EntityId,
    entity_type: u8,
    times: CoreWriteTimes,
    body: &Value,
    text: Option<impl IntoIterator<Item = (&'t str, &'t str)>>,
) -> Result<BatchBuilder<'a>, CoreWriteRefusal> {
    let body = core_body_for_write(entity_type, body);
    let data = encode_core_body(&body)?;
    // ARCH-0006a: only the Dreamer writes a scope summary's body. A caller
    // declares the scope; it never puts the body through a generic write.
    if entity_type == ENTITY_TYPE_SUMMARY
        && crate::scope_summary::decode_scope_summary_body(&data).is_ok()
    {
        return Err(CoreWriteRefusal::ScopeSummary);
    }
    let mut batch = batch.put(id, entity_type, times.occurred, times.learned_at, &data);
    let text_fields = core_text_pairs(text, &body);
    if !text_fields.is_empty() {
        let refs: Vec<(&str, &str)> = text_fields
            .iter()
            .map(|(field, value)| (field.as_str(), value.as_str()))
            .collect();
        batch = batch.text(id, &refs);
    }
    Ok(batch)
}

/// The entity `field` names.
pub(crate) fn entity_id(value: &str, field: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(value)
        .map_err(|_| MemoryError::bad_request(format!("{field} must be a 32-hex entity id")))
}

/// The entity `field` names, if any.
pub(crate) fn optional_entity_id(value: Option<&str>, field: &str) -> MemoryResult<Option<EntityId>> {
    value.map(|value| entity_id(value, field)).transpose()
}

/// The id a write names, or a fresh one.
pub(crate) fn write_id(value: Option<&str>) -> MemoryResult<EntityId> {
    Ok(optional_entity_id(value, "id")?.unwrap_or_else(EntityId::now))
}
