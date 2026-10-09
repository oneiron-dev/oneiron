//! Claude.ai export: `conversations.json`, a list of conversations with their
//! `chat_messages` in order. When a message names its parent the conversation
//! branched: each edit or retry becomes its own thread, with what followed it.

use serde_json::Value;

use super::text::{export_conversations, join_texts, str_field, time_field};
use super::tree::{TreeNode, threads};
use super::{HistoryConversation, HistoryMessage, HistoryRole, HistorySkips, HistoryThreadKind};
use crate::ingest::{IngestError, IngestResult};

const SOURCE_ID: &str = "claude";

/// The parent a root message names.
const ROOT_PARENT: &str = "00000000-0000-4000-8000-000000000000";

pub(super) fn decode(text: &str) -> IngestResult<Vec<HistoryConversation>> {
    let mut out = Vec::new();
    export_conversations(SOURCE_ID, text, &mut |conversation| {
        out.extend(decode_conversation(&conversation)?);
        Ok(())
    })?;
    Ok(out)
}

fn bad(path: &str) -> IngestError {
    IngestError::InvalidDocumentField {
        source_id: SOURCE_ID,
        path: path.to_owned(),
    }
}

fn decode_conversation(conversation: &Value) -> IngestResult<Vec<HistoryConversation>> {
    let id = str_field(conversation, "uuid")
        .or_else(|| str_field(conversation, "id"))
        .ok_or_else(|| bad("uuid"))?;
    let messages = conversation
        .get("chat_messages")
        .and_then(Value::as_array)
        .ok_or_else(|| bad("chat_messages"))?;
    let title = str_field(conversation, "name").map(str::to_owned);
    let started_at_ms = time_field(conversation, "created_at");

    let ids: Vec<String> = messages
        .iter()
        .enumerate()
        .map(|(position, message)| {
            str_field(message, "uuid").map_or_else(|| format!("{id}#{position}"), str::to_owned)
        })
        .collect();
    let parents: Vec<Option<&str>> = messages
        .iter()
        .map(|message| str_field(message, "parent_message_uuid").filter(|p| *p != ROOT_PARENT))
        .collect();
    // Without parents the export is one thread in its own order.
    let members = if parents.iter().any(Option::is_some) {
        let nodes: Vec<TreeNode<'_>> = ids
            .iter()
            .zip(&parents)
            .enumerate()
            .map(|(position, (id, parent))| TreeNode {
                id,
                parent: *parent,
                order: (
                    time_field(&messages[position], "created_at").unwrap_or(0),
                    position,
                ),
            })
            .collect();
        threads(&nodes)
    } else {
        vec![(0..messages.len()).collect()]
    };

    let mut out: Vec<HistoryConversation> = Vec::new();
    for (number, members) in members.into_iter().enumerate() {
        let mut thread = if number == 0 {
            HistoryConversation::new(id.to_owned(), HistoryThreadKind::Main, None)
        } else {
            let first = members.first().map_or("", |&node| ids[node].as_str());
            HistoryConversation::new(
                format!("{id}/branch/{first}"),
                HistoryThreadKind::Branch,
                Some(id.to_owned()),
            )
        };
        thread.title.clone_from(&title);
        thread.started_at_ms = started_at_ms;
        for position in members {
            let message = &messages[position];
            if let Some(kept) = decode_message(message, &mut thread.skipped) {
                thread.messages.push(HistoryMessage {
                    native_id: ids[position].clone(),
                    parent_id: parents[position].map(str::to_owned),
                    ..kept
                });
            }
        }
        if number > 0 && thread.messages.is_empty() {
            if let Some(main) = out.first_mut() {
                main.skipped.add(&thread.skipped);
            }
            continue;
        }
        out.push(thread);
    }
    Ok(out)
}

/// One chat message, or `None` with its kind counted. The returned message's
/// id and parent are the caller's to fill.
fn decode_message(message: &Value, skipped: &mut HistorySkips) -> Option<HistoryMessage> {
    if !message.is_object() {
        skipped.unreadable += 1;
        return None;
    }
    let role = match str_field(message, "sender") {
        Some("human" | "user") => HistoryRole::User,
        Some("assistant") => HistoryRole::Assistant,
        _ => {
            skipped.other += 1;
            return None;
        }
    };
    for key in ["attachments", "files"] {
        let count = message
            .get(key)
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        skipped.attachments += u32::try_from(count).unwrap_or(u32::MAX);
    }
    let mut tools = Vec::new();
    let blocks = message
        .get("content")
        .and_then(Value::as_array)
        .filter(|blocks| !blocks.is_empty());
    let text = match blocks {
        Some(blocks) => {
            let mut texts = Vec::new();
            for block in blocks {
                match str_field(block, "type") {
                    Some("text") => texts.extend(str_field(block, "text")),
                    Some("tool_use") => {
                        skipped.tool_calls += 1;
                        tools.extend(str_field(block, "name").map(str::to_owned));
                    }
                    Some("tool_result") => skipped.tool_results += 1,
                    Some("thinking" | "redacted_thinking") => skipped.thinking += 1,
                    Some("image" | "document") => skipped.attachments += 1,
                    _ => skipped.other += 1,
                }
            }
            join_texts(&texts)
        }
        None => str_field(message, "text")
            .unwrap_or_default()
            .trim()
            .to_owned(),
    };
    if text.is_empty() {
        skipped.empty += 1;
        return None;
    }
    Some(HistoryMessage {
        native_id: String::new(),
        parent_id: None,
        role,
        text,
        at_ms: time_field(message, "created_at"),
        said_by: None,
        tools,
        alias: None,
    })
}
