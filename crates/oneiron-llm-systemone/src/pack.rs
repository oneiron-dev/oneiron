//! One native System One request over a shared state and ordered typed questions.

use super::{
    MAX_RESPONSE_BYTES, Response, SystemOneHttpRequest, SystemOneSeat, build_question,
    native_seat_read_digests, parse_prediction,
};
use oneiron::code_run::model_call::NativeReadDigests;
use oneiron::llm::DispatchRelease;
use oneiron::llm::decision::{
    DecisionAnswer, DecisionAudio, DecisionImage, DecisionQuestion, DecisionSystemOneResponse,
    SeatPhase, SeatRequest,
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

pub struct SystemOnePackRead {
    pub request: Option<NativeReadDigests>,
    pub result: LlmResult<SystemOnePackAnswer>,
}

pub struct PreparedSystemOnePackRead<'seat> {
    seat: &'seat SystemOneSeat,
    template: SeatRequest,
    questions: Vec<Option<SystemOnePackQuestion>>,
    sent: SystemOneHttpRequest,
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

impl<'seat> PreparedSystemOnePackRead<'seat> {
    /// The exact body and non-credential transport metadata, before admission.
    pub fn request(&self) -> &SystemOneHttpRequest {
        &self.sent
    }

    pub async fn ask_recorded<'call>(
        self,
        lease: &'call BudgetLease,
        time_left: Duration,
        release: Option<DispatchRelease<'call>>,
    ) -> SystemOnePackRead
    where
        'seat: 'call,
    {
        self.ask_observed(lease, time_left, release).await.0
    }

    /// Returns raw source beside the unchanged pack result, never per-row shares.
    pub async fn ask_observed<'call>(
        mut self,
        lease: &'call BudgetLease,
        time_left: Duration,
        release: Option<DispatchRelease<'call>>,
    ) -> (SystemOnePackRead, Option<DecisionSystemOneResponse>)
    where
        'seat: 'call,
    {
        self.sent.time_left = time_left;
        let seat = self.seat;
        seat.send_prepared_pack(self, lease, release).await
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
        self.ask_pack_recorded(request, lease, time_left, None)
            .await
            .result
    }

    /// Validates every question by the existing single-seat contract and builds
    /// one shared set of transformed assets. No lease, credential or I/O.
    pub async fn prepare_pack_read(
        &self,
        request: SystemOnePackRequest,
        time_left: Duration,
    ) -> LlmResult<PreparedSystemOnePackRead<'_>> {
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
        Ok(PreparedSystemOnePackRead {
            seat: self,
            template,
            questions,
            sent,
        })
    }

    /// Sends one pack; the original transport owns its physical release check.
    pub async fn ask_pack_recorded<'a>(
        &'a self,
        request: SystemOnePackRequest,
        lease: &'a BudgetLease,
        time_left: Duration,
        release: Option<DispatchRelease<'a>>,
    ) -> SystemOnePackRead {
        match self.prepare_pack_read(request, time_left).await {
            Ok(prepared) => prepared.ask_recorded(lease, time_left, release).await,
            Err(error) => SystemOnePackRead {
                request: None,
                result: Err(error),
            },
        }
    }

    async fn send_prepared_pack(
        &self,
        prepared: PreparedSystemOnePackRead<'_>,
        lease: &BudgetLease,
        release: Option<DispatchRelease<'_>>,
    ) -> (SystemOnePackRead, Option<DecisionSystemOneResponse>) {
        let PreparedSystemOnePackRead {
            mut template,
            questions,
            sent,
            ..
        } = prepared;
        let digests = serde_json::from_slice::<Value>(&sent.body)
            .ok()
            .and_then(|body| native_seat_read_digests(&body).ok());
        let mut observation = None;
        let result = async {
            let model = sent.model.clone();
            let response = match release {
                Some(release) => self.transport.send_released(sent, lease, release).await?,
                None => self.transport.send(sent, lease).await?,
            };
            observation = Some(response.observation(&model));
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
            let wire: Response = serde_json::from_slice(&response.body)
                .map_err(|_| FatalLlmError::InvalidRequest)?;
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
        .await;
        (
            SystemOnePackRead {
                request: digests,
                result,
            },
            observation,
        )
    }
}
