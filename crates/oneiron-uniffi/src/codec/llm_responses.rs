//! Owned response JSON in model-stream terminal and settled-run outputs.

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

struct ResponseJson {
    content: Vec<WireJson>,
    raw_provider: WireJson,
    token_scores: Option<WireJson>,
}

impl ResponseJson {
    fn take(response: &mut LlmResponse) -> Result<Self, OneironError> {
        let content: Vec<_> = response
            .message
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
        let raw_provider = WireJson::lift(std::mem::take(&mut response.usage.raw_provider));
        let token_scores = response
            .token_scores
            .take()
            .filter(|value| !value.is_null())
            .map(WireJson::lift)
            .transpose();
        // Drain every response leaf before any conversion error can return.
        Ok(Self {
            content: content.into_iter().collect::<Result<_, _>>()?,
            raw_provider: raw_provider?,
            token_scores: token_scores?,
        })
    }

    fn put(self, response: &mut crate::LlmResponse) {
        let content = response
            .message
            .content
            .iter_mut()
            .filter_map(|part| match part {
                crate::ContentPart::ToolCall { input, .. } => Some(input),
                crate::ContentPart::ToolResult { output, .. } => Some(output),
                _ => None,
            });
        for (target, value) in content.zip(self.content) {
            *target = value;
        }
        response.usage.raw_provider = self.raw_provider;
        response.token_scores = self.token_scores;
    }
}
