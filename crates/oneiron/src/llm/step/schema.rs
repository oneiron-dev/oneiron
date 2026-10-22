//! One-shot structured-output policy. No shim is applied to agent-loop calls.
use super::super::{
    BudgetGuard, BudgetLease, ContentPart, LlmBackend, LlmCapability, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, LlmUsage, ResponseFormat,
};
use super::schema_runtime::{self, SchemaValidationOutcome, SchemaValidationRequest};
use super::types::ReplyCheck;
use super::{DurableStepError, DurableStepResult};
use crate::dreamer_wake::{StepCalls, WakePassDeadline};

/// The shared validator also serves hosts implementing self.json.validate.
pub fn validate_json_schema(
    schema: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<(), String> {
    match schema_runtime::validate(SchemaValidationRequest::Validate { schema, value }) {
        Ok(SchemaValidationOutcome::Valid) => Ok(()),
        Ok(
            SchemaValidationOutcome::InvalidSchema(errors)
            | SchemaValidationOutcome::InvalidValue(errors),
        ) => Err(errors.join("; ")),
        Ok(SchemaValidationOutcome::LimitExceeded) => Err("schema validator resource limit".into()),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn validate_fallback(
    request: &LlmRequest,
    response: &LlmResponse,
    check: Option<&ReplyCheck>,
) -> DurableStepResult<()> {
    let ResponseFormat::Json { schema } = &request.envelope.response_format else {
        return check.map_or(Ok(()), |check| {
            check(response).map_err(|error| DurableStepError::SchemaValidation {
                attempts: 1,
                errors: vec![error],
            })
        });
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
    calls: StepCalls<'_>,
    check: Option<&ReplyCheck>,
    max_retries: usize,
) -> DurableStepResult<LlmResponse> {
    let ResponseFormat::Json { schema } = &request.envelope.response_format else {
        let response =
            super::retry::generate_with_retry(backend, request, lease, max_retries).await?;
        let Some(Err(error)) = check.map(|check| check(&response)) else {
            return Ok(response);
        };
        // One answer, paid and refused, as a native schema miss is.
        guard
            .settle_per_call(lease, &response.usage)
            .map_err(super::super::LlmError::from)?;
        return Err(DurableStepError::SpentSchemaValidation {
            attempts: 1,
            errors: vec![error],
            usage: Box::new(response.usage),
        });
    };
    // Compile in the same bounded compartment before contacting the backend.
    match schema_runtime::validate(SchemaValidationRequest::CheckSchema(schema)) {
        Ok(SchemaValidationOutcome::Valid) => {}
        Ok(
            SchemaValidationOutcome::InvalidSchema(errors)
            | SchemaValidationOutcome::InvalidValue(errors),
        ) => {
            return Err(DurableStepError::SchemaValidation {
                attempts: 0,
                errors,
            });
        }
        Ok(SchemaValidationOutcome::LimitExceeded) => {
            return Err(DurableStepError::SchemaValidation {
                attempts: 0,
                errors: vec!["schema validator resource limit".into()],
            });
        }
        Err(error) => {
            return Err(DurableStepError::SchemaValidation {
                attempts: 0,
                errors: vec![error.into()],
            });
        }
    }
    let mut wire = request.clone();
    let native = backend.supports(&request.model, LlmCapability::JsonResponse);
    if !native {
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
    }
    let max_attempts = if native { 1 } else { 3 };
    let mut usage = LlmUsage::zero();
    for attempt in 1..=max_attempts {
        // Declared first, a correction's observation closes after its lease.
        let _correction_call;
        let correction;
        let active_lease = if attempt == 1 {
            lease
        } else {
            // A correction is a new paid call with a new lease, not a retry
            // under the admitted call's lease. The prior response is settled.
            if calls
                .deadline
                .is_some_and(WakePassDeadline::in_finalize_window)
            {
                return Err(DurableStepError::SpentFinalizeRefused {
                    usage: Box::new(usage),
                });
            }
            correction = CorrectionLease {
                guard,
                lease: guard
                    .admit_for_request(&wire)
                    .map_err(|source| DurableStepError::SpentLlm {
                        source: source.into(),
                        usage: Box::new(usage.clone()),
                    })?
                    .lease,
            };
            // Its own call under the same logical step, bound as the step's
            // first call is (DOOR-144); transport retries reuse it.
            _correction_call = calls.admitted(guard, &correction.lease, u32::from(attempt - 1));
            &correction.lease
        };
        let mut response =
            match super::retry::generate_with_retry(backend, &wire, active_lease, max_retries)
                .await
            {
                Ok(response) => response,
                // The first call failed: nothing was answered, nothing spent.
                Err(source) if attempt == 1 => return Err(DurableStepError::Llm(source)),
                Err(source) => {
                    return Err(DurableStepError::SpentLlm {
                        source,
                        usage: Box::new(usage.clone()),
                    });
                }
            };
        // The completed call is paid before another corrective call can reserve.
        guard
            .settle_per_call(active_lease, &response.usage)
            .map_err(super::super::LlmError::from)?;
        add_usage(&mut usage, &response.usage);
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
            Ok(value) => match schema_runtime::validate(SchemaValidationRequest::Validate {
                schema,
                value: &value,
            }) {
                Ok(SchemaValidationOutcome::Valid) => Vec::new(),
                Ok(
                    SchemaValidationOutcome::InvalidSchema(errors)
                    | SchemaValidationOutcome::InvalidValue(errors),
                ) => errors,
                Ok(SchemaValidationOutcome::LimitExceeded) => {
                    return Err(DurableStepError::SpentSchemaValidation {
                        attempts: attempt,
                        errors: vec!["schema validator resource limit".into()],
                        usage: Box::new(usage),
                    });
                }
                Err(error) => {
                    return Err(DurableStepError::SpentSchemaValidation {
                        attempts: attempt,
                        errors: vec![error.into()],
                        usage: Box::new(usage),
                    });
                }
            },
            Err(error) => vec![error.to_string()],
        };
        if errors.is_empty() {
            response.usage = usage.clone();
            // A reply the schema admits still answers to the step's check
            // (FIX 7321): refused, it is paid and never memoized.
            if let Some(Err(error)) = check.map(|check| check(&response)) {
                return Err(DurableStepError::SpentSchemaValidation {
                    attempts: attempt,
                    errors: vec![error],
                    usage: Box::new(usage),
                });
            }
            return Ok(response);
        }
        if attempt == max_attempts {
            return Err(DurableStepError::SpentSchemaValidation {
                attempts: attempt,
                errors,
                usage: Box::new(usage),
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

// The outer step owns the first admission. Each later correction owns and
// releases its own reservation on error or cancellation. Settled leases are
// already closed, so aborting them on drop changes no accounting.
struct CorrectionLease<'a> {
    guard: &'a BudgetGuard,
    lease: BudgetLease,
}
impl Drop for CorrectionLease<'_> {
    fn drop(&mut self) {
        let _ = self.guard.abort(&self.lease);
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
