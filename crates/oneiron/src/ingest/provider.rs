//! Provider conversation decoders. All provider roles remain Imported/Proposed data.
use super::{
    IngestError, IngestResult, IngestSource, NormalizedIngestBatch, NormalizedIngestRecord,
};
use serde_json::Value;
#[derive(Clone, Copy)]
pub(super) enum ProviderWire {
    Openai,
    Anthropic,
    Gemini,
}
pub(super) struct ProviderSource(pub(super) ProviderWire);
impl ProviderSource {
    fn id(&self) -> &'static str {
        match self.0 {
            ProviderWire::Openai => "openai-compat",
            ProviderWire::Anthropic => "anthropic-messages",
            ProviderWire::Gemini => "gemini",
        }
    }
    fn invalid(&self, path: &str) -> IngestError {
        IngestError::InvalidDocumentField {
            source_id: self.id(),
            path: path.into(),
        }
    }
}
impl IngestSource for ProviderSource {
    fn normalize(&self, input: &str) -> IngestResult<NormalizedIngestBatch> {
        let root: Value =
            serde_json::from_str(input).map_err(|e| IngestError::InvalidDocument {
                source_id: self.id(),
                message: e.to_string(),
            })?;
        let field = if matches!(self.0, ProviderWire::Gemini) {
            "contents"
        } else {
            "messages"
        };
        let messages = root
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| self.invalid(field))?;
        let mut records = Vec::new();
        if matches!(self.0, ProviderWire::Anthropic)
            && let Some(system) = root.get("system")
        {
            let text = blocks_text(system, self.0).ok_or_else(|| self.invalid("system"))?;
            if text.trim().is_empty() {
                return Err(IngestError::EmptyText {
                    source_id: self.id(),
                    line: 0,
                });
            }
            records.push(NormalizedIngestRecord {
                source_record_id: "system".into(),
                thread_id: None,
                speaker: Some("system".into()),
                occurred_at: None,
                text,
            });
        }
        for (index, message) in messages.iter().enumerate() {
            let role = message
                .get("role")
                .and_then(Value::as_str)
                .ok_or_else(|| self.invalid("role"))?;
            let valid_role = match self.0 {
                ProviderWire::Openai => matches!(
                    role,
                    "system" | "developer" | "user" | "assistant" | "tool" | "function"
                ),
                ProviderWire::Anthropic => matches!(role, "user" | "assistant"),
                ProviderWire::Gemini => matches!(role, "user" | "model"),
            };
            if !valid_role {
                return Err(self.invalid("role"));
            }
            let body = if matches!(self.0, ProviderWire::Gemini) {
                "parts"
            } else {
                "content"
            };
            let mut text = match message.get(body).filter(|v| !v.is_null()) {
                Some(value) => blocks_text(value, self.0).ok_or_else(|| self.invalid(body))?,
                None => String::new(),
            };
            for key in ["reasoning_content", "tool_calls"] {
                if let Some(value) = message.get(key) {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(&value.to_string());
                }
            }
            if text.trim().is_empty() {
                return Err(IngestError::EmptyText {
                    source_id: self.id(),
                    line: index + 1,
                });
            }
            records.push(NormalizedIngestRecord {
                source_record_id: message
                    .get("id")
                    .and_then(Value::as_str)
                    .map_or_else(|| format!("{}:{index}", self.id()), str::to_owned),
                thread_id: root.get("id").and_then(Value::as_str).map(str::to_owned),
                speaker: Some(if role == "model" { "assistant" } else { role }.into()),
                occurred_at: None,
                text,
            });
        }
        Ok(NormalizedIngestBatch {
            source_id: self.id(),
            records,
            claims: vec![],
            entities: vec![],
            note_fallback: None,
        })
    }
}
fn blocks_text(value: &Value, wire: ProviderWire) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(text.into());
    }
    let blocks = value.as_array()?;
    let mut text = Vec::new();
    for block in blocks {
        if !block.is_object() {
            return None;
        }
        let kind = match block.get("type") {
            None => None,
            Some(value) => Some(value.as_str()?),
        };
        let value = if kind == Some("text")
            || (kind.is_none()
                && matches!(wire, ProviderWire::Gemini)
                && block.get("text").is_some())
        {
            block.get("text")?.as_str()?.to_owned()
        } else if kind == Some("thinking") {
            block.get("thinking")?.as_str()?.to_owned()
        } else if kind == Some("tool_use") {
            block.get("id")?.as_str()?;
            block.get("name")?.as_str()?;
            block.get("input")?.as_object()?;
            block.to_string()
        } else if kind == Some("tool_result") {
            block.get("tool_use_id")?.as_str()?;
            blocks_text(block.get("content")?, wire)?;
            block.to_string()
        } else if kind.is_none()
            && let Some(call) = block.get("functionCall")
        {
            call.get("name")?.as_str()?;
            call.get("args")?.as_object()?;
            block.to_string()
        } else if kind.is_none()
            && let Some(result) = block.get("functionResponse")
        {
            result.get("name")?.as_str()?;
            result.get("response")?.as_object()?;
            block.to_string()
        } else {
            return None;
        };
        text.push(value);
    }
    Some(text.join("\n"))
}
