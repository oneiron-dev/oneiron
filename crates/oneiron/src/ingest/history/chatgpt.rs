//! ChatGPT export: `conversations.json`, a list of conversations whose
//! `mapping` is a message tree. Each edit or regeneration becomes its own
//! thread, with what was said after it. `current_node` (the branch the app
//! shows) is not read: the person can switch it, and an imported message stays
//! in the thread it landed in.

use std::collections::HashMap;

use serde_json::Value;

use super::text::{export_conversations, join_texts, str_field, time_field};
use super::tree::{TreeNode, threads};
use super::{HistoryConversation, HistoryMessage, HistoryRole, HistorySkips, HistoryThreadKind};
use crate::ingest::{IngestError, IngestResult};

const SOURCE_ID: &str = "chatgpt";

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

/// What one mapping node holds.
enum Node {
    /// A message and how many of its parts were images or files.
    Kept(HistoryMessage, u32),
    ToolCall(String),
    Skipped(fn(&mut HistorySkips)),
    /// The tree's root and other message-less nodes.
    Structural,
}

fn decode_conversation(conversation: &Value) -> IngestResult<Vec<HistoryConversation>> {
    let id = str_field(conversation, "conversation_id")
        .or_else(|| str_field(conversation, "id"))
        .ok_or_else(|| bad("conversation_id"))?;
    let mapping = conversation
        .get("mapping")
        .and_then(Value::as_object)
        .ok_or_else(|| bad("mapping"))?;
    let entries: Vec<(&str, &Value)> = mapping
        .iter()
        .map(|(key, node)| (key.as_str(), node))
        .collect();
    // A node's place in its parent's `children`, which the app only appends
    // to: an edit or regeneration made later never sorts before the child
    // an earlier export already had first, dated or not.
    let mut rank: HashMap<&str, u64> = HashMap::new();
    for (_, node) in &entries {
        let children = node.get("children").and_then(Value::as_array);
        for (place, child) in children.into_iter().flatten().enumerate() {
            if let Some(child) = child.as_str() {
                rank.entry(child)
                    .or_insert(u64::try_from(place).unwrap_or(u64::MAX));
            }
        }
    }
    let nodes: Vec<TreeNode<'_>> = entries
        .iter()
        .enumerate()
        .map(|(position, (key, node))| TreeNode {
            id: key,
            parent: str_field(node, "parent"),
            order: (rank.get(key).copied().unwrap_or(u64::MAX), position),
        })
        .collect();
    let decoded: Vec<Node> = entries
        .iter()
        .map(|(key, node)| decode_node(key, node))
        .collect();
    let title = str_field(conversation, "title").map(str::to_owned);
    let started_at_ms = time_field(conversation, "create_time");

    let mut out: Vec<HistoryConversation> = Vec::new();
    for (number, members) in threads(&nodes).into_iter().enumerate() {
        let mut thread = if number == 0 {
            HistoryConversation::new(id.to_owned(), HistoryThreadKind::Main, None)
        } else {
            let first = members.first().map_or("", |&node| nodes[node].id);
            HistoryConversation::new(
                format!("{id}/branch/{first}"),
                HistoryThreadKind::Branch,
                Some(id.to_owned()),
            )
        };
        thread.title.clone_from(&title);
        thread.started_at_ms = started_at_ms;
        let mut pending_tools = Vec::new();
        for node in members {
            match &decoded[node] {
                Node::Kept(message, attachments) => {
                    thread.skipped.attachments += attachments;
                    let mut message = message.clone();
                    if message.role == HistoryRole::Assistant {
                        message.tools.append(&mut pending_tools);
                    } else {
                        pending_tools.clear();
                    }
                    thread.messages.push(message);
                }
                Node::ToolCall(name) => {
                    thread.skipped.tool_calls += 1;
                    match thread.messages.last_mut() {
                        Some(last) if last.role == HistoryRole::Assistant => {
                            last.tools.push(name.clone());
                        }
                        _ => pending_tools.push(name.clone()),
                    }
                }
                Node::Skipped(count) => count(&mut thread.skipped),
                Node::Structural => {}
            }
        }
        // A branch that kept nothing (a regenerated tool call, say) still
        // counts what it held, on the main thread.
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

fn decode_node(key: &str, node: &Value) -> Node {
    let Some(message) = node.get("message").filter(|message| !message.is_null()) else {
        return Node::Structural;
    };
    if !message.is_object() {
        return Node::Skipped(|skips| skips.unreadable += 1);
    }
    let role = message
        .pointer("/author/role")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let content = message.get("content").unwrap_or(&Value::Null);
    let content_type = str_field(content, "content_type").unwrap_or("text");
    let hidden = message
        .pointer("/metadata/is_visually_hidden_from_conversation")
        .and_then(Value::as_bool)
        == Some(true);
    let recipient = str_field(message, "recipient").unwrap_or("all");
    let role = match role {
        "user" => HistoryRole::User,
        "assistant" => HistoryRole::Assistant,
        "system" => return Node::Skipped(|skips| skips.system += 1),
        "tool" => return Node::Skipped(|skips| skips.tool_results += 1),
        _ => return Node::Skipped(|skips| skips.other += 1),
    };
    if role == HistoryRole::Assistant && recipient != "all" {
        return Node::ToolCall(recipient.to_owned());
    }
    match content_type {
        "text" | "multimodal_text" => {}
        "thoughts" | "reasoning_recap" => return Node::Skipped(|skips| skips.thinking += 1),
        "user_editable_context" | "model_editable_context" => {
            return Node::Skipped(|skips| skips.system += 1);
        }
        "code" | "execution_output" => return Node::ToolCall(content_type.to_owned()),
        _ => return Node::Skipped(|skips| skips.other += 1),
    }
    if hidden {
        return Node::Skipped(|skips| skips.system += 1);
    }
    let parts = content
        .get("parts")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let texts: Vec<&str> = parts
        .iter()
        .filter_map(|part| {
            part.as_str()
                .or_else(|| part.get("text").and_then(Value::as_str))
        })
        .collect();
    let text = join_texts(&texts);
    let attachments = parts
        .iter()
        .filter(|part| part.is_object() && part.get("text").is_none())
        .count();
    if text.is_empty() {
        return if attachments > 0 {
            Node::Skipped(|skips| skips.attachments += 1)
        } else {
            Node::Skipped(|skips| skips.empty += 1)
        };
    }
    let message = HistoryMessage {
        native_id: str_field(message, "id").unwrap_or(key).to_owned(),
        parent_id: str_field(node, "parent").map(str::to_owned),
        role,
        text,
        at_ms: time_field(message, "create_time"),
        said_by: None,
        tools: Vec::new(),
        alias: None,
    };
    Node::Kept(message, u32::try_from(attachments).unwrap_or(u32::MAX))
}
