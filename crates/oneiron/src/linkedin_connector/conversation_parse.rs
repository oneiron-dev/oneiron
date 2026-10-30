//! Message parsers for `get_conversation` output: explicit message objects,
//! the plain-text conversation fallback, and their timestamp and time-label
//! readers.

use std::collections::HashSet;

use serde_json::Value;

use crate::error::{Error, Result};

use super::LinkedInConversationMessage;
use super::normalize_keys::normalize_message_id;
use super::verified_send::normalize_whitespace;

pub(super) fn explicit_conversation_messages(
    thread_id: &str,
    message_values: &[Value],
) -> Result<Vec<LinkedInConversationMessage>> {
    let mut messages = Vec::new();
    let mut seen_message_ids = HashSet::new();
    for value in message_values {
        let Some(object) = value.as_object() else {
            return Err(Error::InvalidConfig(
                "LinkedIn conversation messages must be objects".to_owned(),
            ));
        };
        let Some(message_id) = first_string_field(
            object,
            &["id", "message_id", "messageId", "urn", "entity_urn"],
        ) else {
            continue;
        };
        let message_id = normalize_message_id(message_id)?;
        if !seen_message_ids.insert(message_id.clone()) {
            continue;
        }
        let text = first_string_field(object, &["text", "body", "content", "message"])
            .map(normalize_whitespace)
            .filter(|text| !text.is_empty());
        let occurred_at = first_timestamp_field(
            object,
            &["occurred_at", "timestamp", "created_at", "sent_at"],
        )?;
        messages.push(LinkedInConversationMessage {
            thread_id: thread_id.to_owned(),
            message_id,
            occurred_at,
            text,
        });
    }
    Ok(messages)
}

pub(super) fn fallback_conversation_messages(
    thread_id: &str,
    conversation_text: &str,
) -> Result<Vec<LinkedInConversationMessage>> {
    let lines = conversation_text
        .lines()
        .map(normalize_whitespace)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        return Ok(Vec::new());
    }

    let mut start = 0;
    if lines.len() >= 3 && lines[0] == lines[1] && looks_like_linkedin_time(&lines[2]) {
        start = 1;
    }

    let mut messages = Vec::new();
    let mut index = start;
    while index < lines.len() {
        if index + 2 < lines.len() && looks_like_linkedin_time(&lines[index + 1]) {
            let timestamp = &lines[index + 1];
            index += 2;
            let body_start = index;
            while index < lines.len() {
                if index + 1 < lines.len() && looks_like_linkedin_time(&lines[index + 1]) {
                    break;
                }
                index += 1;
            }
            let body = lines[body_start..index].join(" ");
            if !body.is_empty() {
                messages.push(fallback_message(
                    thread_id,
                    [timestamp.as_str(), body.as_str()].as_slice(),
                    Some(body.clone()),
                )?);
            }
            continue;
        }

        let body = lines[index].clone();
        messages.push(fallback_message(
            thread_id,
            [body.as_str()].as_slice(),
            Some(body.clone()),
        )?);
        index += 1;
    }
    Ok(messages)
}

fn fallback_message(
    thread_id: &str,
    hash_parts: &[&str],
    text: Option<String>,
) -> Result<LinkedInConversationMessage> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(thread_id.as_bytes());
    for part in hash_parts {
        hasher.update(&[0]);
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize().to_hex().to_string();
    Ok(LinkedInConversationMessage {
        thread_id: thread_id.to_owned(),
        message_id: normalize_message_id(&format!("fallback-{}", &digest[..16]))?,
        occurred_at: None,
        text,
    })
}

fn first_string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn first_u64_field(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_u64))
}

fn first_timestamp_field(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Result<Option<u64>> {
    first_u64_field(object, keys)
        .map(normalize_epoch_timestamp_secs)
        .transpose()
}

fn normalize_epoch_timestamp_secs(value: u64) -> Result<u64> {
    if value >= 1_000_000_000_000_000 {
        return Err(Error::InvalidConfig(
            "LinkedIn timestamp unit exceeds supported epoch milliseconds".to_owned(),
        ));
    }
    if value >= 10_000_000_000 {
        return Ok(value / 1_000);
    }
    Ok(value)
}

pub(super) fn looks_like_linkedin_time(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    if lower.contains(':') && (lower.ends_with("am") || lower.ends_with("pm")) {
        return true;
    }
    lower == "today"
        || lower == "yesterday"
        || lower.contains(" ago")
        || looks_like_linkedin_date_label(&lower)
}

fn looks_like_linkedin_date_label(lower: &str) -> bool {
    let mut parts = lower.split_whitespace();
    let Some(month) = parts.next() else {
        return false;
    };
    if !matches!(
        month.trim_end_matches('.'),
        "jan"
            | "january"
            | "feb"
            | "february"
            | "mar"
            | "march"
            | "apr"
            | "april"
            | "may"
            | "jun"
            | "june"
            | "jul"
            | "july"
            | "aug"
            | "august"
            | "sep"
            | "sept"
            | "september"
            | "oct"
            | "october"
            | "nov"
            | "november"
            | "dec"
            | "december"
    ) {
        return false;
    }
    let Some(day) = parts.next() else {
        return false;
    };
    let day = day.trim_end_matches(',');
    if !matches!(day.parse::<u8>(), Ok(1..=31)) {
        return false;
    }
    match parts.next() {
        None => true,
        Some(year) if year.len() == 4 && year.parse::<u16>().is_ok() => parts.next().is_none(),
        Some(_) => false,
    }
}
