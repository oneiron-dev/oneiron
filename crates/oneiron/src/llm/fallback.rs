//! Named deterministic non-LLM fallback runners. No backend or write capability crosses this seam.
use super::{
    ContentPart, DeterministicFallback, FatalLlmError, FinishReason, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, LlmUsage,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FallbackError {
    #[error("unknown deterministic fallback: {0}")]
    Unknown(String),
    #[error("duplicate deterministic fallback: {0}")]
    Duplicate(String),
    #[error("deterministic fallback {name} failed: {reason}")]
    Failed { name: String, reason: String },
    #[error("deterministic fallback returned empty content: {0}")]
    Empty(String),
}

pub trait DeterministicRunner: Send + Sync {
    fn run(
        &self,
        request: &LlmRequest,
        config: Option<&serde_json::Value>,
        failure: &FatalLlmError,
    ) -> Result<LlmMessage, String>;
}

#[derive(Default)]
pub struct FallbackRegistry {
    runners: BTreeMap<String, Box<dyn DeterministicRunner>>,
}
impl FallbackRegistry {
    pub fn register(
        &mut self,
        name: String,
        runner: Box<dyn DeterministicRunner>,
    ) -> Result<(), FallbackError> {
        if name.trim().is_empty() || self.runners.contains_key(&name) {
            return Err(FallbackError::Duplicate(name));
        }
        self.runners.insert(name, runner);
        Ok(())
    }
    /// Engine defaults fail closed. Generic rule rows are supplied as call config.
    pub fn standard() -> Self {
        let mut registry = Self::default();
        registry
            .runners
            .insert("json_rules_v1".into(), Box::new(JsonRules));
        registry
            .runners
            .insert("fail_closed_to_proposed".into(), Box::new(FailClosed));
        registry
    }
    pub fn run(
        &self,
        declared: &DeterministicFallback,
        request: &LlmRequest,
        failure: &FatalLlmError,
    ) -> Result<LlmResponse, FallbackError> {
        let runner = self
            .runners
            .get(&declared.name)
            .ok_or_else(|| FallbackError::Unknown(declared.name.clone()))?;
        let message = runner
            .run(request, declared.config.as_ref(), failure)
            .map_err(|reason| FallbackError::Failed {
                name: declared.name.clone(),
                reason,
            })?;
        if message.content.is_empty()
            || message
                .content
                .iter()
                .all(|p| matches!(p, ContentPart::Text { text } if text.trim().is_empty()))
        {
            return Err(FallbackError::Empty(declared.name.clone()));
        }
        Ok(LlmResponse {
            message,
            usage: LlmUsage::zero(),
            finish_reason: FinishReason::Other {
                name: format!("fallback:{}:{failure:?}", declared.name),
            },
        })
    }
}
struct FailClosed;
impl DeterministicRunner for FailClosed {
    fn run(
        &self,
        _: &LlmRequest,
        _: Option<&serde_json::Value>,
        _: &FatalLlmError,
    ) -> Result<LlmMessage, String> {
        Ok(json_message(
            serde_json::json!({"verdict":"hold", "reasons":["model_unavailable"]}),
        ))
    }
}
struct JsonRules;
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Rules {
    version: u8,
    rows: Vec<Rule>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    failure: String,
    value: serde_json::Value,
}
impl DeterministicRunner for JsonRules {
    fn run(
        &self,
        _: &LlmRequest,
        config: Option<&serde_json::Value>,
        failure: &FatalLlmError,
    ) -> Result<LlmMessage, String> {
        let rules: Rules = serde_json::from_value(config.cloned().ok_or("missing rules")?)
            .map_err(|e| e.to_string())?;
        if rules.version != 1 {
            return Err("unsupported rule version".into());
        }
        let class = match failure {
            FatalLlmError::Auth => "auth",
            FatalLlmError::InvalidRequest => "invalid_request",
            FatalLlmError::ContentFiltered => "content_filtered",
            FatalLlmError::EmptyResponse => "empty_response",
            FatalLlmError::Unsupported(_) => "unsupported",
        };
        let row = rules
            .rows
            .iter()
            .find(|row| row.failure == class)
            .or_else(|| rules.rows.iter().find(|row| row.failure == "fatal"))
            .ok_or("no matching fatal rule")?;
        Ok(json_message(row.value.clone()))
    }
}
fn json_message(value: serde_json::Value) -> LlmMessage {
    LlmMessage {
        role: LlmMessageRole::Assistant,
        content: vec![ContentPart::Text {
            text: value.to_string(),
        }],
    }
}
