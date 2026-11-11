//! One native System One request over a shared state and ordered typed questions.

use super::{MAX_RESPONSE_BYTES, Response, SystemOneSeat, build_question, parse_prediction};
use oneiron::llm::decision::{
    DecisionAnswer, DecisionAudio, DecisionImage, DecisionQuestion, SeatPhase, SeatRequest,
};
use oneiron::{
    BudgetLease, FatalLlmError, HostingPrivacyPosture, LlmResult, LlmUsage, RetryableLlmError,
};
use serde_json::{Value, json};
use std::time::Duration;

pub struct SystemOnePackQuestion {
    pub question: DecisionQuestion,
    pub score_levels: Vec<String>,
}

/// All questions read this same caller-prepared state and media.
pub struct SystemOnePackRequest {
    pub questions: Vec<SystemOnePackQuestion>,
    pub state: Value,
    pub images: Vec<DecisionImage>,
    pub audio: Vec<DecisionAudio>,
    pub posture: HostingPrivacyPosture,
    pub remote_opt_in: bool,
    pub phase: SeatPhase,
}

/// A logical answer has no separately measured share of the pack's token use.
pub struct SystemOnePackPrediction {
    pub answer: DecisionAnswer,
    pub probability: f64,
}

pub struct SystemOnePackAnswer {
    /// In request order. A malformed or missing row does not discard other answers.
    pub answers: Vec<LlmResult<SystemOnePackPrediction>>,
    /// The provider's single measurement for the whole physical request.
    pub usage: LlmUsage,
}

fn validate_pack_context(request: &SeatRequest) -> LlmResult<()> {
    if !oneiron::llm::decision::unit_text_may_leave_host(request.posture, request.remote_opt_in)
        || request.phase == SeatPhase::Light
        || !request.state.is_object()
    {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    serde_json::to_vec(&request.state).map_err(|_| FatalLlmError::InvalidRequest)?;
    DecisionImage::check_call(&request.images, &request.state, false)?;
    DecisionAudio::check_call(&request.audio, &request.images, &request.state)
}

impl SystemOnePackRequest {
    /// Checks the shared context before admission. Invalid question rows remain
    /// local abstentions; false means no physical request is needed.
    pub fn has_valid_questions(&self) -> LlmResult<bool> {
        let Some(first) = self.questions.first() else {
            return Ok(false);
        };
        let mut template = SeatRequest {
            question: first.question.clone(),
            state: self.state.clone(),
            images: self.images.clone(),
            audio: self.audio.clone(),
            score_levels: first.score_levels.clone(),
            posture: self.posture,
            remote_opt_in: self.remote_opt_in,
            phase: self.phase,
        };
        validate_pack_context(&template)?;
        Ok(self.questions.iter().any(|row| {
            template.question = row.question.clone();
            template.score_levels = row.score_levels.clone();
            template.validate_remote().is_ok()
        }))
    }

    fn into_parts(self) -> LlmResult<(SeatRequest, Vec<SystemOnePackQuestion>)> {
        let first = self
            .questions
            .first()
            .ok_or(FatalLlmError::InvalidRequest)?;
        let template = SeatRequest {
            question: first.question.clone(),
            state: self.state,
            images: self.images,
            audio: self.audio,
            score_levels: first.score_levels.clone(),
            posture: self.posture,
            remote_opt_in: self.remote_opt_in,
            phase: self.phase,
        };
        Ok((template, self.questions))
    }
}

impl SystemOneSeat {
    /// Sends every question in one request, with one aggregate token measurement.
    pub async fn ask_pack(
        &self,
        request: SystemOnePackRequest,
        lease: &BudgetLease,
        time_left: Duration,
    ) -> LlmResult<SystemOnePackAnswer> {
        let (mut template, questions) = request.into_parts()?;
        validate_pack_context(&template)?;
        let mut wire_questions = serde_json::Map::new();
        let questions = questions
            .into_iter()
            .enumerate()
            .map(|(index, row)| {
                template.question = row.question.clone();
                template.score_levels = row.score_levels.clone();
                if template.validate_remote().is_err() {
                    return None;
                }
                wire_questions.insert(format!("q{index}"), build_question(&template));
                Some(row)
            })
            .collect::<Vec<_>>();
        if wire_questions.is_empty() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let sent = self
            .build_questions(&template, Value::Object(wire_questions), time_left)
            .await?;
        let model = sent.model.clone();
        let response = self.transport.send(sent, lease).await?;
        if !(200..300).contains(&response.status) {
            return Err(if response.status >= 500 || response.status == 429 {
                RetryableLlmError::ServerError.into()
            } else {
                FatalLlmError::InvalidRequest.into()
            });
        }
        if response.body.len() > MAX_RESPONSE_BYTES {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let wire: Response =
            serde_json::from_slice(&response.body).map_err(|_| FatalLlmError::InvalidRequest)?;
        if wire.model != model {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let answers = questions
            .into_iter()
            .enumerate()
            .map(|(index, row)| {
                let row = row.ok_or(FatalLlmError::InvalidRequest)?;
                template.question = row.question;
                template.score_levels = row.score_levels;
                let value = wire
                    .answers
                    .get(&format!("q{index}"))
                    .ok_or(FatalLlmError::InvalidRequest)?;
                let (answer, probability) = parse_prediction(value, &template)?;
                Ok(SystemOnePackPrediction {
                    answer,
                    probability,
                })
            })
            .collect();
        let mut usage = LlmUsage::zero();
        usage.input.total = wire.usage.input_tokens;
        usage.output.total = wire.usage.output_tokens;
        usage.raw_provider = json!({
            "input_tokens": wire.usage.input_tokens,
            "output_tokens": wire.usage.output_tokens,
        });
        Ok(SystemOnePackAnswer { answers, usage })
    }
}
