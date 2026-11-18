//! The MESSAGE and CONVERSATION bodies an import writes: each message's
//! text under its provenance, and the conversation's source fields.

use rmpv::Value as Msgpack;
use serde_json::{Map, Value};

use super::{IMPORT_CWD_KEY, label, witness_author};
use crate::entity_id::EntityId;
use crate::ingest::history::ledger::LedgerRow;
use crate::ingest::history::{HistoryConversation, HistoryMessage, HistoryRole, HistorySource};
use crate::memory::{IMPORTED_SOURCE_KEY, MemoryError, MemoryResult, WitnessMessage};

/// Tool names one message's metadata lists; the rest are counted.
const MAX_TOOL_LABELS: usize = 64;

/// The MESSAGE an imported message lands as. The dry run builds the same one
/// to scan exactly the bytes the write door would.
pub(in crate::ingest::history) fn imported_message(
    source: HistorySource,
    conversation: &HistoryConversation,
    message: &HistoryMessage,
    previous: Option<&LedgerRow>,
    id: Option<EntityId>,
    order: u32,
) -> WitnessMessage {
    WitnessMessage {
        id: id.map(|id| id.to_hex()),
        author: witness_author(message),
        message_type: format!("import.{}", source.source_id()),
        content: message.text.clone(),
        parts: None,
        metadata: Some(provenance(source, conversation, message, previous)),
        is_visible: true,
        order,
        quote: None,
    }
}

/// The imported CONVERSATION's body: its source, the source's id for it and,
/// for a branch or subagent thread, the conversation it belongs to.
pub(in crate::ingest::history) fn conversation_body(
    source: HistorySource,
    conversation: &HistoryConversation,
) -> MemoryResult<Vec<u8>> {
    let mut fields = vec![
        (
            Msgpack::from(IMPORTED_SOURCE_KEY),
            Msgpack::from(source.source_id()),
        ),
        (
            Msgpack::from("import_conversation"),
            Msgpack::from(label(&conversation.native_id)),
        ),
        (
            Msgpack::from("import_kind"),
            Msgpack::from(conversation.kind.as_str()),
        ),
    ];
    if let Some(parent) = &conversation.parent {
        fields.push((Msgpack::from("import_parent"), Msgpack::from(label(parent))));
    }
    if let Some(title) = &conversation.title {
        fields.push((Msgpack::from("title"), Msgpack::from(label(title))));
    }
    if let Some(cwd) = &conversation.cwd {
        fields.push((Msgpack::from(IMPORT_CWD_KEY), Msgpack::from(label(cwd))));
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Msgpack::Map(fields))
        .map_err(|_| MemoryError::bad_request("imported conversation body is not encodable"))?;
    Ok(out)
}

/// A message's provenance, as its MESSAGE metadata: who said it in the
/// source, where it sat, when, and what it went on to call.
fn provenance(
    source: HistorySource,
    conversation: &HistoryConversation,
    message: &HistoryMessage,
    revises: Option<&LedgerRow>,
) -> Value {
    let mut fields = Map::new();
    fields.insert("source".into(), Value::from(source.source_id()));
    fields.insert(
        "conversation".into(),
        Value::from(label(&conversation.native_id)),
    );
    fields.insert("id".into(), Value::from(label(&message.native_id)));
    let role = match message.role {
        HistoryRole::User => "user",
        HistoryRole::Assistant => "assistant",
    };
    fields.insert("role".into(), Value::from(role));
    if let Some(parent) = &message.parent_id {
        fields.insert("parent".into(), Value::from(label(parent)));
    }
    if let Some(at) = message.at_ms {
        fields.insert("at_ms".into(), Value::from(at));
    }
    if let Some(said_by) = &message.said_by {
        fields.insert("said_by".into(), Value::from(said_by.as_str()));
    }
    if !message.tools.is_empty() {
        let tools: Vec<Value> = message
            .tools
            .iter()
            .take(MAX_TOOL_LABELS)
            .map(|tool| Value::from(label(tool)))
            .collect();
        fields.insert("tools".into(), Value::from(tools));
        if message.tools.len() > MAX_TOOL_LABELS {
            fields.insert(
                "tools_more".into(),
                Value::from(message.tools.len() - MAX_TOOL_LABELS),
            );
        }
    }
    if let Some(previous) = revises {
        fields.insert("revision".into(), Value::from(previous.next_revision()));
        // The latest text still in the vault; an erased one is never named.
        if let Some(latest) = previous.messages.last() {
            fields.insert("revises".into(), Value::from(latest.to_hex()));
        }
    }
    let mut metadata = Map::new();
    metadata.insert("import".into(), Value::Object(fields));
    Value::Object(metadata)
}
