//! One-shot structured-output policy. No shim is applied to agent-loop calls.
use super::super::{
    BudgetGuard, BudgetLease, ContentPart, LlmBackend, LlmCapability, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, LlmUsage, ResponseFormat,
};
use super::{DurableStepError, DurableStepResult};

/// The shared validator also serves hosts implementing self.json.validate.
pub fn validate_json_schema(
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<(), String> {
    let validator = jsonschema::validator_for(schema).map_err(|error| error.to_string())?;
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub(super) fn validate_fallback(
    request: &LlmRequest,
    response: &LlmResponse,
) -> DurableStepResult<()> {
    let ResponseFormat::Json { schema } = &request.envelope.response_format else {
        return Ok(());
    };
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    serde_json::from_str::<serde_json::Value>(&text)
        .map_err(|e| e.to_string())
        .and_then(|value| validate_json_schema(schema, &value))
        .map_err(|error| DurableStepError::SchemaValidation {
            attempts: 1,
            errors: vec![error],
        })
}

pub(super) async fn generate(
    backend: &dyn LlmBackend,
    request: &LlmRequest,
    lease: &BudgetLease,
    guard: &BudgetGuard,
) -> DurableStepResult<LlmResponse> {
    let ResponseFormat::Json { schema } = &request.envelope.response_format else {
        return Ok(super::execute::generate_with_retry(backend, request, lease).await?);
    };
    if backend.supports(&request.model, LlmCapability::JsonResponse) {
        return Ok(super::execute::generate_with_retry(backend, request, lease).await?);
    }
    // Validate the schema itself before contacting the backend. Remote refs are disabled.
    let validator =
        jsonschema::validator_for(schema).map_err(|error| DurableStepError::SchemaValidation {
            attempts: 0,
            errors: vec![error.to_string()],
        })?;
    let mut wire = request.clone();
    wire.envelope.response_format = ResponseFormat::Text;
    // Machine-readable schema data, not a hard-coded persona or prompt policy.
    wire.messages.insert(
        0,
        LlmMessage {
            role: LlmMessageRole::System,
            content: vec![ContentPart::Text {
                text: serde_json::json!({"response_format":{"type":"json_schema","schema":schema}})
                    .to_string(),
            }],
        },
    );
    let mut spend = SchemaSpend {
        guard,
        lease,
        usage: LlmUsage::zero(),
        armed: true,
    };
    for attempt in 1..=3 {
        let mut response = match super::execute::generate_with_retry(backend, &wire, lease).await {
            Ok(response) => response,
            Err(source) => {
                spend.armed = false;
                return Err(DurableStepError::SpentLlm {
                    source,
                    usage: Box::new(spend.usage.clone()),
                });
            }
        };
        add_usage(&mut spend.usage, &response.usage);
        let text: String = response
            .message
            .content
            .iter()
            .filter_map(|part| match part {
                ContentPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        let errors = match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(value) => validator
                .iter_errors(&value)
                .map(|e| e.to_string())
                .collect::<Vec<_>>(),
            Err(error) => vec![error.to_string()],
        };
        if errors.is_empty() {
            response.usage = spend.usage.clone();
            spend.armed = false;
            return Ok(response);
        }
        if attempt == 3 {
            return Err(DurableStepError::SchemaValidation {
                attempts: 3,
                errors,
            });
        }
        wire.messages.push(response.message);
        wire.messages.push(LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text:
                    serde_json::json!({"schema_validation_errors":errors,"required_schema":schema})
                        .to_string(),
            }],
        });
    }
    unreachable!("bounded attempts return")
}

struct SchemaSpend<'a> {
    guard: &'a BudgetGuard,
    lease: &'a BudgetLease,
    usage: LlmUsage,
    armed: bool,
}
impl Drop for SchemaSpend<'_> {
    fn drop(&mut self) {
        if self.armed && (self.usage.input.total > 0 || self.usage.output.total > 0) {
            let _ = self.guard.settle_per_call(self.lease, &self.usage);
        }
    }
}
fn add_usage(total: &mut LlmUsage, usage: &LlmUsage) {
    total.input.total = total.input.total.saturating_add(usage.input.total);
    total.input.cache_read = total
        .input
        .cache_read
        .saturating_add(usage.input.cache_read);
    total.input.cache_write = total
        .input
        .cache_write
        .saturating_add(usage.input.cache_write);
    total.output.total = total.output.total.saturating_add(usage.output.total);
    total.output.text = total.output.text.saturating_add(usage.output.text);
    total.output.reasoning = total
        .output
        .reasoning
        .saturating_add(usage.output.reasoning);
    total.raw_provider = usage.raw_provider.clone();
}
