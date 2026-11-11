//! Owned response and stream-event JSON in model output records.

use oneiron::llm::{ContentPart, LlmResponse, model_stream::ModelStreamTerminal};

use super::{Lift, OneironError, WireJson, lift_record};

pub(crate) fn lift_model_stream_terminal(
    verb: &str,
    mut terminal: ModelStreamTerminal,
) -> Result<crate::ModelStreamTerminal, OneironError> {
    let response = terminal
        .response
        .as_mut()
        .map(ResponseJson::take)
        .transpose()?;
    let mut output: crate::ModelStreamTerminal = lift_record(verb, &terminal)?;
    if let Some((output, response)) = output.response.as_mut().zip(response) {
        response.put(output);
    }
    Ok(output)
}

pub(crate) fn lift_settled_step(
    verb: &str,
    mut step: Option<oneiron::llm::model_step::SettledStepView>,
) -> Result<Option<crate::SettledStepView>, OneironError> {
    let response = step
        .as_mut()
        .map(|step| ResponseJson::take(&mut step.response))
        .transpose()?;
    let mut output: Option<crate::SettledStepView> = lift_record(verb, &step)?;
    if let Some((output, response)) = output.as_mut().zip(response) {
        response.put(&mut output.response);
    }
    Ok(output)
}

pub(crate) fn lift_settled_program_step(
    verb: &str,
    mut step: Option<oneiron::dreamer_runner::SettledProgramStepView>,
) -> Result<Option<crate::SettledProgramStepView>, OneironError> {
    let response = step
        .as_mut()
        .and_then(|step| step.model_step.as_mut())
        .map(|step| ResponseJson::take(&mut step.response))
        .transpose()?;
    let mut output: Option<crate::SettledProgramStepView> = lift_record(verb, &step)?;
    if let Some((output, response)) = output
        .as_mut()
        .and_then(|step| step.model_step.as_mut())
        .zip(response)
    {
        response.put(&mut output.response);
    }
    Ok(output)
}

pub(crate) fn lift_model_role_invocation(
    verb: &str,
    mut invocation: oneiron::llm::manifest::doors::ModelRoleInvocation,
) -> Result<crate::ModelRoleInvocation, OneironError> {
    let response = match &mut invocation.output {
        oneiron::llm::manifest::doors::ModelRoleOutput::Generated { response } => {
            Some(ResponseJson::take(response))
        }
        _ => None,
    }
    .transpose()?;
    let mut output: crate::ModelRoleInvocation = lift_record(verb, &invocation)?;
    if let (crate::ModelRoleOutput::Generated { response: target }, Some(response)) =
        (&mut output.output, response)
    {
        response.put(target);
    }
    Ok(output)
}

pub(crate) fn lift_model_step_receipt(
    verb: &str,
    mut receipt: oneiron::llm::model_step::ModelStepReceipt,
) -> Result<crate::ModelStepReceipt, OneironError> {
    let result = receipt
        .result
        .as_mut()
        .map(StepResultJson::take)
        .transpose()?
        .flatten();
    let mut output: crate::ModelStepReceipt = lift_record(verb, &receipt)?;
    if let Some((output, result)) = output.result.as_mut().zip(result) {
        result.put(output);
    }
    Ok(output)
}

pub(crate) fn lift_model_stream_events(
    verb: &str,
    mut events: oneiron::llm::model_stream::ModelStreamEvents,
) -> Result<crate::ModelStreamEvents, OneironError> {
    let values: Vec<_> = events
        .events
        .iter_mut()
        .map(|event| match event {
            oneiron::llm::LlmStreamEvent::ToolCallEnd { input, .. } => {
                WireJson::lift(std::mem::take(input))
                    .map(|value| Some(StreamEventJson::Tool(value)))
            }
            oneiron::llm::LlmStreamEvent::ToolResultEnd { output, .. } => {
                WireJson::lift(std::mem::take(output))
                    .map(|value| Some(StreamEventJson::Tool(value)))
            }
            oneiron::llm::LlmStreamEvent::Done { message, usage, .. } => {
                MessageUsageJson::take(message, usage)
                    .map(|value| Some(StreamEventJson::Done(value)))
            }
            _ => Ok(None),
        })
        .collect();
    // Consume every event's leaves, even if an earlier event failed.
    let values = values.into_iter().collect::<Result<Vec<_>, _>>()?;
    let mut output: crate::ModelStreamEvents = lift_record(verb, &events)?;
    for (event, value) in output.events.iter_mut().zip(values) {
        match (event, value) {
            (
                crate::LlmStreamEvent::ToolCallEnd { input, .. },
                Some(StreamEventJson::Tool(value)),
            ) => {
                *input = value;
            }
            (
                crate::LlmStreamEvent::ToolResultEnd { output, .. },
                Some(StreamEventJson::Tool(value)),
            ) => {
                *output = value;
            }
            (
                crate::LlmStreamEvent::Done { message, usage, .. },
                Some(StreamEventJson::Done(value)),
            ) => {
                value.put(message, usage);
            }
            _ => {}
        }
    }
    Ok(output)
}

enum StreamEventJson {
    Tool(WireJson),
    Done(MessageUsageJson),
}

enum StepResultJson {
    Finished {
        response: ResponseJson,
        json: Option<WireJson>,
    },
    Failed(WireJson),
}

impl StepResultJson {
    fn take(
        result: &mut oneiron::llm::model_step::ModelStepResult,
    ) -> Result<Option<Self>, OneironError> {
        match result {
            oneiron::llm::model_step::ModelStepResult::Finished { response, json, .. } => {
                let response = ResponseJson::take(response);
                let json = json
                    .take()
                    .filter(|value| !value.is_null())
                    .map(WireJson::lift)
                    .transpose();
                // The parsed JSON is consumed even if response conversion failed.
                Ok(Some(Self::Finished {
                    response: response?,
                    json: json?,
                }))
            }
            oneiron::llm::model_step::ModelStepResult::Failed { failure } => failure
                .spent_usage
                .as_mut()
                .map(|usage| WireJson::lift(std::mem::take(&mut usage.raw_provider)))
                .transpose()
                .map(|value| value.map(Self::Failed)),
            _ => Ok(None),
        }
    }

    fn put(self, result: &mut crate::ModelStepResult) {
        match (result, self) {
            (
                crate::ModelStepResult::Finished {
                    response: target,
                    json: target_json,
                    ..
                },
                Self::Finished { response, json },
            ) => {
                response.put(target);
                *target_json = json;
            }
            (crate::ModelStepResult::Failed { failure }, Self::Failed(value)) => {
                if let Some(usage) = &mut failure.spent_usage {
                    usage.raw_provider = value;
                }
            }
            _ => {}
        }
    }
}

struct ResponseJson {
    message_usage: MessageUsageJson,
    token_scores: Option<WireJson>,
}

impl ResponseJson {
    fn take(response: &mut LlmResponse) -> Result<Self, OneironError> {
        let message_usage = MessageUsageJson::take(&mut response.message, &mut response.usage);
        let token_scores = response
            .token_scores
            .take()
            .filter(|value| !value.is_null())
            .map(WireJson::lift)
            .transpose();
        // Token scores are consumed even if another response leaf failed.
        Ok(Self {
            message_usage: message_usage?,
            token_scores: token_scores?,
        })
    }

    fn put(self, response: &mut crate::LlmResponse) {
        self.message_usage
            .put(&mut response.message, &mut response.usage);
        response.token_scores = self.token_scores;
    }
}

struct MessageUsageJson {
    content: Vec<WireJson>,
    raw_provider: WireJson,
}

impl MessageUsageJson {
    fn take(
        message: &mut oneiron::llm::LlmMessage,
        usage: &mut oneiron::llm::LlmUsage,
    ) -> Result<Self, OneironError> {
        let content: Vec<_> = message
            .content
            .iter_mut()
            .filter_map(|part| match part {
                ContentPart::ToolCall { input, .. } => Some(WireJson::lift(std::mem::take(input))),
                ContentPart::ToolResult { output, .. } => {
                    Some(WireJson::lift(std::mem::take(output)))
                }
                _ => None,
            })
            .collect();
        let raw_provider = WireJson::lift(std::mem::take(&mut usage.raw_provider));
        // Drain every message and usage leaf before any error can return.
        Ok(Self {
            content: content.into_iter().collect::<Result<_, _>>()?,
            raw_provider: raw_provider?,
        })
    }

    fn put(self, message: &mut crate::LlmMessage, usage: &mut crate::LlmUsage) {
        let content = message.content.iter_mut().filter_map(|part| match part {
            crate::ContentPart::ToolCall { input, .. } => Some(input),
            crate::ContentPart::ToolResult { output, .. } => Some(output),
            _ => None,
        });
        for (target, value) in content.zip(self.content) {
            *target = value;
        }
        usage.raw_provider = self.raw_provider;
    }
}
