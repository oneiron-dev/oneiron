//! One-shot structured-output policy. No shim is applied to agent-loop calls.
use super::super::{
    BudgetGuard, BudgetLease, ContentPart, LlmBackend, LlmCapability, LlmError, LlmMessage,
    LlmMessageRole, LlmRequest, LlmResponse, LlmUsage, ResponseFormat, RetryableLlmError,
};
use super::schema_runtime::{self, SchemaValidationOutcome, SchemaValidationRequest};
use super::types::ReplyCheck;
use super::{DurableStepError, DurableStepResult};
use crate::dreamer_wake::{StepCalls, WakePassDeadline};
use crate::store::model_step_submission::CorrectionPoint;

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
            ContentPart::Text { text, .. } => Some(text.as_str()),
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

/// `request` through the backend, its schema met natively or by corrective
/// calls. `capture` keeps each corrective call's wire under its own call index
/// before it is sent (FIX 6145), best effort, as the step's own call is kept.
/// Where the step keeps its corrections, each one's point is kept with its
/// sends, a correction its offer's rest holds past the step's wait parks the
/// step as its first call does, and the pass that resumes it continues that
/// correction (STEP-CORRECTION-HEALTH-PARK).
#[expect(
    clippy::too_many_arguments,
    reason = "the step's call, its budget, observation and capture join the reply check"
)]
pub(super) async fn generate(
    backend: &dyn LlmBackend,
    request: &LlmRequest,
    lease: &BudgetLease,
    guard: &BudgetGuard,
    calls: StepCalls<'_>,
    capture: &(dyn Fn(&LlmRequest, u32) + Sync),
    check: Option<&ReplyCheck>,
    retries: &super::retry::TransportRetries<'_>,
) -> DurableStepResult<LlmResponse> {
    let ResponseFormat::Json { schema } = &request.envelope.response_format else {
        let response = super::retry::generate_with_retry(backend, request, lease, retries).await?;
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
                    signature: None,
            }],
            },
        );
        // Each message boundary the request marks still names the block it
        // named before the schema message went first (FIX 5035).
        crate::code_run::shift_cache_boundaries(&mut wire);
    }
    let max_attempts = if native { 1 } else { 3 };
    // The step's own messages: a correction's point keeps the ones after.
    let asked = wire.messages.len();
    let mut usage = LlmUsage::zero();
    // The correction an earlier pass parked in resumes where it stood, with
    // what the calls before it spent: no paid call is asked twice. A point
    // the step's wire no longer fits starts the step over.
    let resumed = retries
        .resume_point()
        .filter(|point| (2..=max_attempts).contains(&point.attempt));
    let first = match resumed {
        Some(point) => {
            wire.messages.extend(point.tail.iter().cloned());
            usage = point.usage.clone();
            point.attempt
        }
        None => 1,
    };
    for attempt in first..=max_attempts {
        // Declared first, a correction's observation closes after its lease.
        let _correction_call;
        let correction;
        let active_lease = if attempt == first {
            // The step's admission lease, bound as its call by the caller
            // (DOOR-144): the first call's, or the correction's a resume
            // continues, whose wire is kept under its own call.
            if attempt > 1 {
                capture(&wire, u32::from(attempt - 1));
            }
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
            // first call is (DOOR-144); transport retries reuse it. Its wire
            // is kept under that call before it goes (FIX 6145).
            let call = u32::from(attempt - 1);
            _correction_call = calls.admitted(guard, &correction.lease, call);
            capture(&wire, call);
            &correction.lease
        };
        // Each correction is its own call with its own retries, its sends
        // kept with its point where the step keeps corrections.
        let point = (attempt > 1).then(|| CorrectionPoint {
            attempt,
            tail: wire.messages[asked..].to_vec(),
            usage: usage.clone(),
            sends: resumed
                .filter(|_| attempt == first)
                .map_or(0, |point| point.sends),
        });
        let keep_point = |sends: usize| {
            point.as_ref().is_none_or(|point| {
                retries.keep_correction(&CorrectionPoint {
                    sends: u8::try_from(sends).unwrap_or(u8::MAX),
                    ..point.clone()
                })
            })
        };
        let correction_retries;
        let call_retries = match &point {
            None => retries,
            Some(point) => {
                correction_retries = retries
                    .for_another_call(usize::from(point.sends))
                    .keeping(&keep_point);
                &correction_retries
            }
        };
        let mut response =
            match super::retry::generate_with_retry(backend, &wire, active_lease, call_retries)
                .await
            {
                Ok(response) => response,
                // The first call failed: nothing was answered, nothing spent.
                Err(source) if attempt == 1 => return Err(DurableStepError::Llm(source)),
                // Its offer rests past the step's wait, and its point is
                // kept: the step parks unfailed, as its first call does.
                Err(source @ LlmError::Retryable(RetryableLlmError::HealthRest { .. }))
                    if retries.keeps_corrections() =>
                {
                    return Err(DurableStepError::Llm(source));
                }
                Err(source) => {
                    // A resumed correction that failed unanswered closes the
                    // step's admission lease at nothing: the spend it carries
                    // is its earlier passes', each settled in its own pass.
                    if attempt == first {
                        let _closed = guard.settle_per_call(lease, &LlmUsage::zero());
                    }
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
                ContentPart::Text { text, .. } => Some(text.as_str()),
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
                signature: None,
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
    total.merge_provider_metadata(usage);
}
