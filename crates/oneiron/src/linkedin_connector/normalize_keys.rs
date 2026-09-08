//! Key builders, thread/message id normalization, and bounded validators.

use serde_json::Value;

use crate::error::{Error, Result};

use super::{
    LINKEDIN_INBOX_SYNC_DEDUPE_PREFIX, LINKEDIN_INBOX_SYNC_PROVENANCE_PREFIX,
    LINKEDIN_INBOX_SYNC_SEEN_PREFIX, LinkedInConversationMessage, LinkedInInboxSyncConfig,
    MAX_LINKEDIN_MESSAGE_ID_BYTES, MAX_LINKEDIN_SESSION_REF_BYTES, MAX_LINKEDIN_THREAD_ID_BYTES,
};

pub(super) fn linkedin_inbox_seen_key(
    config: &LinkedInInboxSyncConfig,
    message: &LinkedInConversationMessage,
) -> String {
    format!(
        "{LINKEDIN_INBOX_SYNC_SEEN_PREFIX}{}",
        linkedin_inbox_message_key_hash(config, message)
    )
}

pub(super) fn linkedin_inbox_provenance_key(
    config: &LinkedInInboxSyncConfig,
    message: &LinkedInConversationMessage,
) -> String {
    format!(
        "{LINKEDIN_INBOX_SYNC_PROVENANCE_PREFIX}{}",
        linkedin_inbox_message_key_hash(config, message)
    )
}

fn linkedin_inbox_message_key_hash(
    config: &LinkedInInboxSyncConfig,
    message: &LinkedInConversationMessage,
) -> String {
    let (session_kind, session_ref) = match config.session_ref.as_deref() {
        Some(session_ref) => ("session", session_ref),
        None => ("no-session", ""),
    };
    event_hash(
        [
            config.receiving_address_or_handle.as_str(),
            session_kind,
            session_ref,
            message.thread_id.as_str(),
            message.message_id.as_str(),
        ]
        .as_slice(),
    )
}

pub(super) fn linkedin_inbox_sync_dedupe_key(config: &LinkedInInboxSyncConfig) -> String {
    let session_ref = config.session_ref.as_deref().unwrap_or("no-session");
    format!(
        "{LINKEDIN_INBOX_SYNC_DEDUPE_PREFIX}{}:{}",
        event_hash([&config.receiving_address_or_handle, session_ref].as_slice()),
        config.backfill_window_secs
    )
}

pub(super) fn optional_section_text<'a>(
    payload: &'a Value,
    section: &str,
) -> Result<Option<&'a str>> {
    let Some(sections) = payload.get("sections") else {
        return Ok(None);
    };
    let Some(sections) = sections.as_object() else {
        return Err(Error::InvalidConfig(
            "LinkedIn MCP sections must be an object".to_owned(),
        ));
    };
    let Some(section_value) = sections.get(section) else {
        return Ok(None);
    };
    section_value.as_str().map(Some).ok_or_else(|| {
        Error::InvalidConfig(format!("LinkedIn MCP sections.{section} must be a string"))
    })
}

pub(super) fn section_references<'a>(payload: &'a Value, section: &str) -> Vec<&'a Value> {
    payload
        .get("references")
        .and_then(|references| references.get(section))
        .and_then(Value::as_array)
        .map(|references| references.iter().collect())
        .unwrap_or_default()
}

pub(super) fn reference_kind_is(reference: &Value, kind: &str) -> bool {
    reference.get("kind").and_then(Value::as_str) == Some(kind)
}

pub(super) fn first_conversation_thread_id(references: &[&Value]) -> Result<Option<String>> {
    for reference in references {
        if !reference_kind_is(reference, "conversation") {
            continue;
        }
        if let Some(thread_id) = thread_id_from_reference(reference)? {
            return Ok(Some(thread_id));
        }
    }
    Ok(None)
}

pub(super) fn thread_id_from_reference(reference: &Value) -> Result<Option<String>> {
    if let Some(thread_id) = reference.get("thread_id").and_then(Value::as_str) {
        return normalize_thread_id(thread_id).map(Some);
    }
    if let Some(url) = reference.get("url").and_then(Value::as_str) {
        return thread_id_from_url(url);
    }
    Ok(None)
}

pub(super) fn thread_id_from_payload_url(payload: &Value) -> Result<Option<String>> {
    if let Some(url) = payload.get("url").and_then(Value::as_str) {
        return thread_id_from_url(url);
    }
    Ok(None)
}

fn thread_id_from_url(url: &str) -> Result<Option<String>> {
    let marker = "/messaging/thread/";
    let Some((_, rest)) = url.split_once(marker) else {
        return Ok(None);
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    normalize_thread_id(&rest[..end]).map(Some)
}

pub(super) fn normalize_thread_id(thread_id: &str) -> Result<String> {
    let thread_id = thread_id.trim();
    if thread_id.is_empty() {
        return Err(Error::InvalidConfig(
            "LinkedIn thread id must be non-empty".to_owned(),
        ));
    }
    if thread_id.len() > MAX_LINKEDIN_THREAD_ID_BYTES {
        return Err(Error::InvalidConfig(
            "LinkedIn thread id exceeds maximum length".to_owned(),
        ));
    }
    if thread_id
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'?' | b'#' | b':'))
    {
        return Err(Error::InvalidConfig(
            "LinkedIn thread id contains a reserved delimiter".to_owned(),
        ));
    }
    Ok(thread_id.to_owned())
}

pub(super) fn normalize_message_id(message_id: &str) -> Result<String> {
    let message_id = message_id.trim();
    if message_id.is_empty() {
        return Err(Error::InvalidConfig(
            "LinkedIn message id must be non-empty".to_owned(),
        ));
    }
    if message_id.len() > MAX_LINKEDIN_MESSAGE_ID_BYTES {
        return Err(Error::InvalidConfig(
            "LinkedIn message id exceeds maximum length".to_owned(),
        ));
    }
    Ok(message_id.to_owned())
}

pub(super) fn counterparty_key(thread_id: &str) -> String {
    format!("linkedin:thread:{thread_id}")
}

pub(super) fn bounded_identifier(
    value: String,
    max_bytes: usize,
    too_long_message: &'static str,
) -> Result<String> {
    if value.len() > max_bytes {
        return Err(Error::InvalidConfig(too_long_message.to_owned()));
    }
    Ok(value)
}

pub(super) fn bounded_ref(
    value: String,
    blank_message: &'static str,
    too_long_message: &'static str,
) -> Result<String> {
    normalize_non_blank(
        value,
        MAX_LINKEDIN_SESSION_REF_BYTES,
        blank_message,
        too_long_message,
    )
}

pub(super) fn vault_scoped_secret_ref(value: String) -> Result<String> {
    let value = bounded_ref(
        value,
        "LinkedIn session cookie secret ref must be non-empty",
        "LinkedIn session cookie secret ref exceeds maximum length",
    )?;
    if !value.starts_with("vault-secret:") {
        return Err(Error::InvalidConfig(
            "LinkedIn session cookie secret ref must be vault-scoped".to_owned(),
        ));
    }
    Ok(value)
}

pub(super) fn event_hash(parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(&[0]);
    }
    let hex = hasher.finalize().to_hex().to_string();
    hex[..16].to_owned()
}

pub(super) fn normalize_non_blank(
    value: String,
    max_bytes: usize,
    blank_message: &'static str,
    too_long_message: &'static str,
) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::InvalidConfig(blank_message.to_owned()));
    }
    if value.len() > max_bytes {
        return Err(Error::InvalidConfig(too_long_message.to_owned()));
    }
    Ok(value.to_owned())
}

pub(super) fn normalize_verb_key(verb: &str) -> String {
    verb.trim().to_ascii_lowercase().replace(['-', '.'], "_")
}
