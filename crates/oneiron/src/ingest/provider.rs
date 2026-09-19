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
                let Some(value) = message.get(key) else {
                    continue;
                };
                if !matches!(self.0, ProviderWire::Openai) || role != "assistant" {
                    return Err(self.invalid(key));
                }
                // Nullable optional fields do not supply otherwise-missing content.
                if value.is_null() {
                    continue;
                }
                let auxiliary = if key == "reasoning_content" {
                    value.as_str().ok_or_else(|| self.invalid(key))?.to_owned()
                } else {
                    let calls = value.as_array().ok_or_else(|| self.invalid(key))?;
                    if !calls.iter().all(valid_openai_tool_call) {
                        return Err(self.invalid(key));
                    }
                    if calls.is_empty() {
                        String::new()
                    } else {
                        value.to_string()
                    }
                };
                if !auxiliary.is_empty() {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(&auxiliary);
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
        return (!matches!(wire, ProviderWire::Gemini)).then(|| text.into());
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
        let value = if (kind == Some("text") && !matches!(wire, ProviderWire::Gemini))
            || (kind.is_none()
                && matches!(wire, ProviderWire::Gemini)
                && block.get("text").is_some())
        {
            block.get("text")?.as_str()?.to_owned()
        } else if kind == Some("thinking") && matches!(wire, ProviderWire::Anthropic) {
            block.get("thinking")?.as_str()?.to_owned()
        } else if kind == Some("tool_use") && matches!(wire, ProviderWire::Anthropic) {
            block.get("id")?.as_str().filter(|s| !s.trim().is_empty())?;
            block
                .get("name")?
                .as_str()
                .filter(|s| !s.trim().is_empty())?;
            block.get("input")?.as_object()?;
            block.to_string()
        } else if kind == Some("tool_result") && matches!(wire, ProviderWire::Anthropic) {
            block
                .get("tool_use_id")?
                .as_str()
                .filter(|s| !s.trim().is_empty())?;
            blocks_text(block.get("content")?, wire)?;
            block.to_string()
        } else if matches!(wire, ProviderWire::Gemini)
            && kind.is_none()
            && let Some(call) = block.get("functionCall")
        {
            call.get("name")?
                .as_str()
                .filter(|s| !s.trim().is_empty())?;
            call.get("args")?.as_object()?;
            block.to_string()
        } else if matches!(wire, ProviderWire::Gemini)
            && kind.is_none()
            && let Some(result) = block.get("functionResponse")
        {
            result
                .get("name")?
                .as_str()
                .filter(|s| !s.trim().is_empty())?;
            result.get("response")?.as_object()?;
            block.to_string()
        } else {
            return None;
        };
        text.push(value);
    }
    Some(text.join("\n"))
}

fn valid_openai_tool_call(value: &Value) -> bool {
    let nonempty = |value: Option<&Value>| {
        value
            .and_then(Value::as_str)
            .is_some_and(|s| !s.trim().is_empty())
    };
    value.get("type").and_then(Value::as_str) == Some("function")
        && nonempty(value.get("id"))
        && nonempty(value.pointer("/function/name"))
        && value
            .pointer("/function/arguments")
            .and_then(Value::as_str)
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
            .is_some_and(|args| args.is_object())
}
