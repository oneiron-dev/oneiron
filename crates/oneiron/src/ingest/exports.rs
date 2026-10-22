//! Native export layouts with catalog-supplied platform identity (ARCH-0027).
//! Parsing never admits a claim; all outputs retain the registry's Imported ceiling.
use super::parsed::{ParsedImport, ParsedMessage};
use super::{
    IngestError, IngestResult, IngestSource, NormalizedIngestBatch, NormalizedIngestClaim,
};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy)]
pub enum ExportLayout {
    ConversationTree,
    ConversationMessages,
    ActivityTakeout,
    CharacterLog,
    MemoryDirectory,
    Markdown,
    Knowledge,
    AgentArchive,
    SessionArchive,
    MemoryArchive,
}

/// Each registry entry is an independent IngestSource; identity is catalog data.
pub struct ExportSource {
    pub source_id: &'static str,
    pub layout: ExportLayout,
}

impl IngestSource for ExportSource {
    fn normalize(&self, input: &str) -> IngestResult<NormalizedIngestBatch> {
        Ok(self.parse_import(input, 0)?.normalized)
    }
    fn parse_import(&self, input: &str, recorded_at: u64) -> IngestResult<ParsedImport> {
        let mut out = ParsedImport {
            messages: Vec::new(),
            resource_uris: Vec::new(),
            normalized: NormalizedIngestBatch {
                source_id: self.source_id,
                records: Vec::new(),
                claims: Vec::new(),
                entities: Vec::new(),
                note_fallback: None,
            },
        };
        match self.layout {
            ExportLayout::Markdown => self.parse_markdown_layout(&mut out, recorded_at, input)?,
            ExportLayout::CharacterLog => {
                self.parse_character_log_layout(&mut out, recorded_at, input)?
            }
            ExportLayout::MemoryDirectory => {
                self.parse_memory_directory_layout(&mut out, recorded_at, input)?
            }
            layout => {
                let doc = self.json(input)?;
                match layout {
                    ExportLayout::ConversationTree => {
                        self.parse_conversation_tree_layout(&mut out, recorded_at, &doc)?
                    }
                    ExportLayout::ConversationMessages => {
                        self.parse_conversation_messages_layout(&mut out, recorded_at, &doc)?
                    }
                    ExportLayout::ActivityTakeout => {
                        self.parse_activity_takeout_layout(&mut out, recorded_at, &doc)?
                    }
                    ExportLayout::Knowledge => {
                        self.parse_knowledge_layout(&mut out, recorded_at, &doc)?
                    }
                    ExportLayout::AgentArchive => {
                        self.parse_agent_archive_layout(&mut out, recorded_at, &doc)?
                    }
                    ExportLayout::SessionArchive => {
                        self.parse_session_archive_layout(&mut out, recorded_at, &doc)?
                    }
                    ExportLayout::MemoryArchive => {
                        self.parse_memory_archive_layout(&mut out, recorded_at, &doc)?
                    }
                    _ => unreachable!("handled above"),
                }
            }
        }
        let mut ids = BTreeSet::new();
        for message in &out.messages {
            if !ids.insert((&message.conversation_id, &message.message_id)) {
                return Err(IngestError::DuplicateId {
                    source_id: self.source_id,
                    kind: "message",
                    id: message.message_id.clone(),
                });
            }
        }
        out.normalized.records = out.messages.iter().map(ParsedMessage::record).collect();
        Ok(out)
    }
}

impl ExportSource {
    fn parse_markdown_layout(
        &self,
        out: &mut ParsedImport,
        recorded_at: u64,
        input: &str,
    ) -> IngestResult<()> {
        self.push(
            out,
            &serde_json::json!({"text": input}),
            "document",
            recorded_at,
        )?;
        Ok(())
    }

    fn parse_character_log_layout(
        &self,
        out: &mut ParsedImport,
        recorded_at: u64,
        input: &str,
    ) -> IngestResult<()> {
        if let Ok(card) = serde_json::from_str::<Value>(input) {
            if card.get("spec").and_then(Value::as_str) == Some("chara_card_v2") {
                self.card(&card, out, recorded_at)?;
            } else {
                self.log(input, out, recorded_at)?;
            }
        } else {
            self.log(input, out, recorded_at)?;
        }
        Ok(())
    }

    fn parse_memory_directory_layout(
        &self,
        out: &mut ParsedImport,
        recorded_at: u64,
        input: &str,
    ) -> IngestResult<()> {
        let doc = self.json(input)?;
        let files = doc
            .get("files")
            .and_then(Value::as_array)
            .ok_or_else(|| self.bad("files"))?;
        for file in files {
            let path = file
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| self.bad("files.path"))?;
            if path.is_empty()
                || path.starts_with('/')
                || path.split(['/', '\\']).any(|p| p == "..")
            {
                return Err(self.bad("files.path"));
            }
            let text = file
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| self.bad("files.content"))?;
            // The host supplies a file snapshot; the parser never traverses a filesystem.
            if path.ends_with(".jsonl") {
                for line in text.lines().filter(|line| !line.trim().is_empty()) {
                    let value = self.json(line)?;
                    let message = value
                        .get("message")
                        .or_else(|| value.get("payload"))
                        .unwrap_or(&value);
                    if message.get("content").is_some() || message.get("text").is_some() {
                        self.push(out, message, path, recorded_at)?;
                    }
                }
            } else {
                self.push(
                    out,
                    &serde_json::json!({"id":path,"text":text}),
                    path,
                    recorded_at,
                )?;
            }
        }
        Ok(())
    }

    fn parse_conversation_tree_layout(
        &self,
        out: &mut ParsedImport,
        recorded_at: u64,
        doc: &Value,
    ) -> IngestResult<()> {
        for conversation in self.array(doc, "conversations")? {
            let thread = self
                .id(conversation, "id")
                .or_else(|| self.id(conversation, "conversation_id"))
                .unwrap_or("conversation");
            let mapping = conversation
                .get("mapping")
                .and_then(Value::as_object)
                .ok_or_else(|| self.bad("mapping"))?;
            // Include every stored branch, not just the currently selected leaf.
            for (node_id, node) in mapping {
                if let Some(message) = node.get("message").filter(|m| !m.is_null()) {
                    let mut message = message.clone();
                    if message.get("id").is_none() {
                        message["id"] = Value::from(node_id.as_str());
                    }
                    self.push(out, &message, thread, recorded_at)?;
                }
            }
        }
        Ok(())
    }

    fn parse_conversation_messages_layout(
        &self,
        out: &mut ParsedImport,
        recorded_at: u64,
        doc: &Value,
    ) -> IngestResult<()> {
        for conversation in self.array(doc, "conversations")? {
            let thread = self
                .id(conversation, "uuid")
                .or_else(|| self.id(conversation, "id"))
                .unwrap_or("conversation");
            let messages = conversation
                .get("chat_messages")
                .and_then(Value::as_array)
                .ok_or_else(|| self.bad("chat_messages"))?;
            for message in messages {
                self.push(out, message, thread, recorded_at)?;
            }
        }
        Ok(())
    }

    fn parse_activity_takeout_layout(
        &self,
        out: &mut ParsedImport,
        recorded_at: u64,
        doc: &Value,
    ) -> IngestResult<()> {
        for activity in self.array(doc, "activities")? {
            self.push(out, activity, "takeout", recorded_at)?;
        }
        Ok(())
    }

    fn parse_knowledge_layout(
        &self,
        out: &mut ParsedImport,
        _recorded_at: u64,
        doc: &Value,
    ) -> IngestResult<()> {
        let concepts = doc
            .get("concepts")
            .and_then(Value::as_array)
            .ok_or_else(|| self.bad("concepts"))?;
        for concept in concepts {
            let id = self
                .id(concept, "id")
                .ok_or_else(|| self.bad("concept.id"))?;
            let predicate = self.id(concept, "predicate").unwrap_or("import.concept");
            // No confidence, provenance, source, or approval can be imported as authority.
            let value = concept
                .get("value")
                .or_else(|| concept.get("label"))
                .ok_or_else(|| self.bad("concept.value"))?;
            out.normalized.claims.push(NormalizedIngestClaim {
                source_record_id: id.into(),
                predicate: predicate.into(),
                value: value.clone(),
            });
        }
        if let Some(resources) = doc.get("resources") {
            for resource in resources.as_array().ok_or_else(|| self.bad("resources"))? {
                let uri = resource
                    .as_str()
                    .or_else(|| resource.get("uri").and_then(Value::as_str))
                    .ok_or_else(|| self.bad("resource.uri"))?;
                if !uri.contains(':') {
                    return Err(self.bad("resource.uri"));
                }
                out.resource_uris.push(uri.into());
            }
        }
        Ok(())
    }

    fn parse_agent_archive_layout(
        &self,
        out: &mut ParsedImport,
        recorded_at: u64,
        doc: &Value,
    ) -> IngestResult<()> {
        let agents = doc.get("agents").and_then(Value::as_array);
        if let Some(agents) = agents {
            for agent in agents {
                self.messages(
                    agent,
                    "messages",
                    self.id(agent, "id").unwrap_or("agent"),
                    out,
                    recorded_at,
                )?;
            }
        } else {
            self.messages(doc, "messages", "agent", out, recorded_at)?;
        }
        Ok(())
    }

    fn parse_session_archive_layout(
        &self,
        out: &mut ParsedImport,
        recorded_at: u64,
        doc: &Value,
    ) -> IngestResult<()> {
        if let Some(sessions) = doc.get("sessions").and_then(Value::as_array) {
            for session in sessions {
                self.messages(
                    session,
                    "messages",
                    self.id(session, "session_id").unwrap_or("session"),
                    out,
                    recorded_at,
                )?;
            }
        } else {
            self.messages(
                doc,
                "messages",
                self.id(doc, "session_id").unwrap_or("session"),
                out,
                recorded_at,
            )?;
        }
        Ok(())
    }

    fn parse_memory_archive_layout(
        &self,
        out: &mut ParsedImport,
        recorded_at: u64,
        doc: &Value,
    ) -> IngestResult<()> {
        for memory in self.array(
            doc,
            if doc.get("results").is_some() {
                "results"
            } else {
                "memories"
            },
        )? {
            self.push(
                out,
                memory,
                self.id(memory, "id").unwrap_or("memory"),
                recorded_at,
            )?;
            if let Some(history) = memory.get("history").and_then(Value::as_array) {
                for revision in history {
                    if let Some(old) = revision.get("old_memory").and_then(Value::as_str)
                        && !old.trim().is_empty()
                        && Some(old) != revision.get("new_memory").and_then(Value::as_str)
                    {
                        let mut previous = revision.clone();
                        let fields = previous
                            .as_object_mut()
                            .ok_or_else(|| self.bad("history"))?;
                        fields.insert("text".into(), Value::from(old));
                        let revision_id = self.id(revision, "id").map_or_else(
                            || {
                                blake3::hash(&serde_json::to_vec(revision).expect("JSON encodes"))
                                    .to_hex()
                                    .to_string()
                            },
                            str::to_owned,
                        );
                        fields.insert("id".into(), Value::from(format!("{revision_id}:before")));
                        self.push(
                            out,
                            &previous,
                            self.id(memory, "id").unwrap_or("memory"),
                            recorded_at,
                        )?;
                    }
                    self.push(
                        out,
                        revision,
                        self.id(memory, "id").unwrap_or("memory"),
                        recorded_at,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn bad(&self, path: &str) -> IngestError {
        IngestError::InvalidDocumentField {
            source_id: self.source_id,
            path: path.into(),
        }
    }
    fn json(&self, input: &str) -> IngestResult<Value> {
        serde_json::from_str(input).map_err(|e| IngestError::InvalidDocument {
            source_id: self.source_id,
            message: e.to_string(),
        })
    }
    fn id<'a>(&self, value: &'a Value, key: &str) -> Option<&'a str> {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    }
    fn array<'a>(&self, value: &'a Value, key: &str) -> IngestResult<&'a Vec<Value>> {
        value
            .as_array()
            .or_else(|| value.get(key).and_then(Value::as_array))
            .ok_or_else(|| self.bad(key))
    }
    fn messages(
        &self,
        doc: &Value,
        key: &str,
        thread: &str,
        out: &mut ParsedImport,
        at: u64,
    ) -> IngestResult<()> {
        for message in self.array(doc, key)? {
            self.push(out, message, thread, at)?;
        }
        Ok(())
    }
    fn log(&self, input: &str, out: &mut ParsedImport, at: u64) -> IngestResult<()> {
        for line in input.lines().filter(|line| !line.trim().is_empty()) {
            let message = self.json(line)?;
            if message.get("chat_metadata").is_some() || message.get("user_name").is_some() {
                continue;
            }
            self.push(out, &message, "chat", at)?;
        }
        Ok(())
    }
    fn card(&self, card: &Value, out: &mut ParsedImport, at: u64) -> IngestResult<()> {
        let data = card
            .get("data")
            .filter(|d| d.is_object())
            .ok_or_else(|| self.bad("card.data"))?;
        let name = self.id(data, "name").ok_or_else(|| self.bad("card.name"))?;
        let description = self
            .id(data, "description")
            .ok_or_else(|| self.bad("card.description"))?;
        // A persona candidate, never an ordinary-world fact or an edited live persona.
        out.normalized.claims.push(NormalizedIngestClaim {
            source_record_id: name.into(),
            predicate: "companion.persona".into(),
            value: data.clone(),
        });
        self.push(
            out,
            &serde_json::json!({"id":name,"text":description,"role":"system"}),
            name,
            at,
        )?;
        out.messages.last_mut().expect("just pushed").character_card = Some(card.clone());
        Ok(())
    }
    fn push(
        &self,
        out: &mut ParsedImport,
        value: &Value,
        thread: &str,
        at: u64,
    ) -> IngestResult<()> {
        if !value.is_object() {
            return Err(self.bad("message"));
        }
        let content = ["text", "content", "mes", "memory", "new_memory", "title"]
            .iter()
            .find_map(|key| value.get(*key))
            .ok_or_else(|| self.bad("content"))?;
        let text = content_text(content).ok_or_else(|| self.bad("content"))?;
        if text.trim().is_empty() {
            return Err(self.bad("content"));
        }
        let raw_role = self
            .id(value, "role")
            .or_else(|| self.id(value, "sender"))
            .or_else(|| value.pointer("/author/role").and_then(Value::as_str))
            .unwrap_or(
                if value.get("is_user").and_then(Value::as_bool) == Some(true) {
                    "user"
                } else {
                    "system"
                },
            );
        let role = match raw_role {
            "human" | "user" => "user",
            "assistant" | "ai" | "model" => "assistant",
            "system" => "system",
            _ => return Err(self.bad("role")),
        };
        let timestamp = [
            "create_time",
            "created_at",
            "timestamp",
            "time",
            "send_date",
        ]
        .iter()
        .find_map(|key| value.get(*key))
        .filter(|v| !v.is_null());
        let occurred_at = timestamp
            .map(|v| timestamp_seconds(v).ok_or_else(|| self.bad("timestamp")))
            .transpose()?;
        let id = ["id", "uuid", "message_id"]
            .iter()
            .find_map(|key| self.id(value, key))
            .map_or_else(
                || {
                    let identity = serde_json::to_vec(&(thread, out.messages.len(), value))
                        .expect("JSON encodes");
                    blake3::hash(&identity).to_hex().to_string()
                },
                str::to_owned,
            );
        out.messages.push(ParsedMessage {
            message_id: id,
            conversation_id: thread.into(),
            platform_source: self.source_id.into(),
            role: role.into(),
            content: text,
            speaker_id: self.id(value, "name").map(str::to_owned),
            occurred_at,
            recorded_at: at,
            character_card: None,
            is_group_chat: value
                .get("is_group")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
        Ok(())
    }
}

fn content_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Array(parts) => parts
            .iter()
            .map(content_text)
            .collect::<Option<Vec<_>>>()
            .map(|parts| parts.join("\n")),
        Value::Object(object) => object
            .get("parts")
            .or_else(|| object.get("text"))
            .and_then(content_text),
        _ => None,
    }
}
fn timestamp_seconds(value: &Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    if let Some(n) = value
        .as_f64()
        .filter(|n| n.is_finite() && *n >= 0.0 && *n < u64::MAX as f64)
    {
        return Some(n as u64);
    }
    chrono::DateTime::parse_from_rfc3339(value.as_str()?)
        .ok()
        .and_then(|time| u64::try_from(time.timestamp()).ok())
}
