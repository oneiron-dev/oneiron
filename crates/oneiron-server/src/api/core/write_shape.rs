//! Create-entity DTOs, announcement normalization, and body field helpers.

use super::super::unix_seconds_now;
use super::batch::CoreTextField;
use super::batch::core_body_for_write;
use super::batch::encode_core_body;
use crate::error::ApiError;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::borrow::Cow;
use utoipa::ToSchema;

pub(crate) const CORE_MAX_BATCH_ENTITIES: usize = 256;

pub(crate) const CORE_MAX_LIST_LIMIT: usize = 1000;

pub(crate) const PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE: &str = "platform_announcement";

pub(crate) const PLATFORM_ANNOUNCEMENT_VOICE: &str = "platform";

pub(crate) const ANNOUNCEMENT_STATUS_ACTIVE: &str = "active";

pub(crate) const ANNOUNCEMENT_STATUS_CORRECTED: &str = "corrected";

pub(crate) const ANNOUNCEMENT_STATUS_RETRACTED: &str = "retracted";

/// Generic core entity create request.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "body": { "name": "Dream session" },
    "text": [{ "field": "name", "value": "Dream session" }]
}))]
pub(crate) struct CoreCreateEntityRequest {
    /// Optional hex entity id. When omitted, the server generates an id.
    #[serde(default)]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pub(crate) id: Option<String>,
    /// Occurrence start timestamp in Unix seconds. Defaults to `learned_at` or current server time.
    #[serde(default, rename = "occurred_start", alias = "occurredStart")]
    #[schema(example = 1782357600_u64)]
    pub(crate) occurred_start: Option<u64>,
    /// Occurrence end timestamp in Unix seconds. Defaults to `occurred_start`.
    #[serde(default, rename = "occurred_end", alias = "occurredEnd")]
    #[schema(example = 1782357600_u64)]
    pub(crate) occurred_end: Option<u64>,
    /// Learned-at timestamp in Unix seconds. Defaults to current server time.
    #[serde(default, rename = "learned_at", alias = "learnedAt")]
    #[schema(example = 1782357635_u64)]
    pub(crate) learned_at: Option<u64>,
    /// JSON body encoded into the vault's msgpack entity payload.
    #[schema(value_type = Object, example = json!({"name": "Dream session"}))]
    pub(crate) body: Value,
    /// Optional explicit text index fields. When omitted, top-level string body fields are indexed.
    #[serde(default)]
    pub(crate) text: Option<Vec<CoreTextField>>,
}

/// Response from core conversation/turn create routes.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreEntityWriteResponse {
    /// Hex entity id written by the route.
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    pub(crate) id: String,
    /// Numeric entity type byte.
    #[schema(example = 1)]
    pub(crate) entity_type: u8,
    /// Projected entity body after write.
    #[schema(value_type = Object)]
    pub(crate) item: Value,
}

#[derive(Clone, Copy)]
pub(crate) struct CoreEntityTimestamps {
    pub(crate) occurred: oneiron::TimeRange,
    pub(crate) learned_at: u64,
}

pub(crate) fn core_entity_timestamps(
    occurred_start: Option<u64>,
    occurred_end: Option<u64>,
    learned_at: Option<u64>,
) -> Result<CoreEntityTimestamps, ApiError> {
    let learned_at = learned_at.unwrap_or_else(unix_seconds_now);
    let start = occurred_start.unwrap_or(learned_at);
    let end = occurred_end.unwrap_or(start);
    if start > end {
        return Err(ApiError::bad_request(
            "occurred_start must be less than or equal to occurred_end",
            Some("occurred_start"),
        ));
    }
    Ok(CoreEntityTimestamps {
        occurred: oneiron::TimeRange { start, end },
        learned_at,
    })
}

pub(crate) fn normalize_platform_announcement_body(body: &Value) -> Cow<'_, Value> {
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
    normalized.insert(
        "spkr".to_owned(),
        Value::String(PLATFORM_ANNOUNCEMENT_VOICE.to_owned()),
    );
    normalized.insert(
        "speaker".to_owned(),
        Value::String(PLATFORM_ANNOUNCEMENT_VOICE.to_owned()),
    );
    normalized.insert(
        "voice".to_owned(),
        Value::String(PLATFORM_ANNOUNCEMENT_VOICE.to_owned()),
    );
    normalized.insert(
        "attribution".to_owned(),
        Value::String(PLATFORM_ANNOUNCEMENT_VOICE.to_owned()),
    );
    normalized.insert(
        "render_voice".to_owned(),
        Value::String(PLATFORM_ANNOUNCEMENT_VOICE.to_owned()),
    );
    normalized.insert("platform_voice".to_owned(), Value::Bool(true));
    normalized.insert("is_eiri".to_owned(), Value::Bool(false));

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

pub(crate) fn is_platform_announcement_body(object: &serde_json::Map<String, Value>) -> bool {
    object_string_field(object, &["message_type", "messageType"]).is_some_and(|message_type| {
        message_type.eq_ignore_ascii_case(PLATFORM_ANNOUNCEMENT_MESSAGE_TYPE)
    })
}

pub(crate) fn announcement_status(object: &serde_json::Map<String, Value>) -> &'static str {
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

pub(crate) fn announcement_original_text(object: &serde_json::Map<String, Value>) -> Option<&str> {
    object_string_field(object, &["original_txt", "originalText", "original_text"]).or_else(|| {
        let original = object.get("original")?.as_object()?;
        object_string_field(original, &["txt", "text", "body"])
    })
}

pub(crate) fn object_string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
}

pub(crate) fn object_bool_field(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<bool> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_bool))
}

pub(crate) fn stage_core_entity_put<'a>(
    batch: oneiron::BatchBuilder<'a>,
    id: &oneiron::EntityId,
    entity_type: u8,
    timestamps: CoreEntityTimestamps,
    body: &Value,
    text: Option<&[CoreTextField]>,
) -> Result<oneiron::BatchBuilder<'a>, ApiError> {
    let body = core_body_for_write(entity_type, body);
    let data = encode_core_body(&body)?;
    let mut batch = batch.put(
        id,
        entity_type,
        timestamps.occurred,
        timestamps.learned_at,
        &data,
    );
    let text_fields = core_text_fields(text, &body);
    if !text_fields.is_empty() {
        let refs: Vec<(&str, &str)> = text_fields
            .iter()
            .map(|(field, value)| (field.as_str(), value.as_str()))
            .collect();
        batch = batch.text(id, &refs);
    }
    Ok(batch)
}

pub(crate) fn core_text_fields(
    text: Option<&[CoreTextField]>,
    body: &Value,
) -> Vec<(String, String)> {
    if let Some(text) = text {
        return text
            .iter()
            .filter(|entry| !entry.field.is_empty() && !entry.value.is_empty())
            .map(|entry| (entry.field.clone(), entry.value.clone()))
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
