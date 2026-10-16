//! Cursor agent transcripts, as its hooks hand them over (`transcript_path`),
//! seen at `~/.cursor/projects/<folder>/agent-transcripts/<id>/<id>.jsonl`.
//!
//! Cursor publishes no schema for this file. The reader decodes only what a
//! dated public sample shows (forum.cursor.com/t/166592/7, 2026-07-27): one
//! line per message, `{role, message: {content: [blocks]}}`, with `text` and
//! `tool_use` blocks and no ids or times, and, in older sessions, a
//! `{type: "turn_ended"}` line. Other fields are ignored; a line of any other
//! shape is counted unreadable. A user block wraps the person's words in
//! `<user_query>`, after a `<timestamp>` the host added; only the words are
//! kept. With no ids to go by, each message's id chains from the one before it,
//! as Codex's id-less messages do, so a log that grows keeps its earlier ids.

use serde_json::Value;

use super::codex::chained_id;
use super::text::{join_texts, json_record, str_field};
use super::{HistoryConversation, HistoryFile, HistoryMessage, HistoryRole, HistoryThreadKind};

/// Whether a record is a Cursor transcript line: a message, or the end of a
/// turn.
pub(super) fn is_record(value: &Value) -> bool {
    message_role(value).is_some() || turn_ended(value)
}

fn message_role(value: &Value) -> Option<HistoryRole> {
    if !value.get("message").is_some_and(Value::is_object) {
        return None;
    }
    match str_field(value, "role")? {
        "user" => Some(HistoryRole::User),
        "assistant" => Some(HistoryRole::Assistant),
        _ => None,
    }
}

fn turn_ended(value: &Value) -> bool {
    str_field(value, "type") == Some("turn_ended") && value.get("role").is_none()
}

pub(super) fn decode(text: &str, file: &HistoryFile) -> Vec<HistoryConversation> {
    let id = format!("cursor:{}", file.stem);
    let mut conversation = HistoryConversation::new(id.clone(), HistoryThreadKind::Main, None);
    // The id the next message chains from: the conversation's, then each kept
    // message's in turn. Tool-only lines do not move it.
    let mut previous = id;
    let mut pending_tools: Vec<String> = Vec::new();

    for raw in text.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let Some(value) = json_record(raw) else {
            conversation.skipped.unreadable += 1;
            continue;
        };
        if turn_ended(&value) {
            conversation.skipped.other += 1;
            continue;
        }
        let (Some(role), Some(blocks)) = (
            message_role(&value),
            value
                .get("message")
                .and_then(|message| message.get("content"))
                .and_then(Value::as_array),
        ) else {
            conversation.skipped.unreadable += 1;
            continue;
        };
        let mut texts: Vec<&str> = Vec::new();
        let mut tools: Vec<String> = Vec::new();
        for block in blocks {
            match str_field(block, "type") {
                Some("text") => {
                    if let Some(text) = block.get("text").and_then(Value::as_str) {
                        texts.push(match role {
                            HistoryRole::User => user_words(text),
                            HistoryRole::Assistant => text,
                        });
                    }
                }
                Some("tool_use") => {
                    conversation.skipped.tool_calls += 1;
                    if let Some(name) = str_field(block, "name") {
                        tools.push(name.to_owned());
                    }
                }
                _ => conversation.skipped.other += 1,
            }
        }
        let text = join_texts(&texts);
        if text.is_empty() {
            if tools.is_empty() {
                conversation.skipped.empty += 1;
            } else {
                // Tool calls label the assistant message they follow, or else
                // the next.
                match conversation.messages.last_mut() {
                    Some(last) if last.role == HistoryRole::Assistant => last.tools.extend(tools),
                    _ => pending_tools.extend(tools),
                }
            }
            continue;
        }
        let native_id = format!("cursor:{}", chained_id(role, &previous));
        let parent_id = conversation
            .messages
            .last()
            .map(|last| last.native_id.clone());
        let tools = match role {
            HistoryRole::Assistant => {
                let mut all = std::mem::take(&mut pending_tools);
                all.extend(tools);
                all
            }
            HistoryRole::User => {
                pending_tools.clear();
                Vec::new()
            }
        };
        previous.clone_from(&native_id);
        conversation.messages.push(HistoryMessage {
            native_id,
            parent_id,
            role,
            text,
            at_ms: None,
            said_by: None,
            tools,
            alias: None,
        });
    }
    vec![conversation]
}

/// The person's words in a user text block: inside `<user_query>` when the
/// block wraps them, else the block less a leading `<timestamp>`.
fn user_words(text: &str) -> &str {
    if let Some((_, rest)) = text.split_once("<user_query>") {
        return rest
            .split_once("</user_query>")
            .map_or(rest, |(words, _)| words);
    }
    let trimmed = text.trim_start();
    if let Some(rest) = trimmed.strip_prefix("<timestamp>")
        && let Some((_, words)) = rest.split_once("</timestamp>")
    {
        return words;
    }
    text
}
