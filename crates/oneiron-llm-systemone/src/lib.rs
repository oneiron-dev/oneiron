//! The remote System One protocol adapter; policy and receipts live in `oneiron::llm::decision`.

use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionRung, DecisionSeat, ProviderPin, SeatAnswer,
    SeatFuture, SeatRequest,
};
use oneiron::{BudgetLease, FatalLlmError, RetryableLlmError};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const MAX_RESPONSE_BYTES: usize = 65_536;

/// Authenticated, exact-revision HTTP adapter. The host chooses the endpoint,
/// credentials, and version; no model or question text is compiled into policy.
pub struct SystemOneSeat {
    client: reqwest::Client,
    endpoint: String,
    bearer: String,
    pin: ProviderPin,
}

impl SystemOneSeat {
    pub fn new(
        endpoint: String,
        bearer: String,
        model: String,
        version: String,
    ) -> oneiron::LlmResult<Self> {
        let url = reqwest::Url::parse(&endpoint).map_err(|_| FatalLlmError::InvalidRequest)?;
        if (url.scheme() != "https"
            && !(url.scheme() == "http"
                && url.host_str().is_some_and(|host| {
                    host == "localhost"
                        || host
                            .parse::<std::net::IpAddr>()
                            .is_ok_and(|ip| ip.is_loopback())
                })))
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.path().ends_with("/v1/systemone")
            || bearer.trim().is_empty()
            || model.trim().is_empty()
            || version.trim().is_empty()
            || !bearer.is_ascii()
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .connect_timeout(std::time::Duration::from_secs(3))
            .build()
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        Ok(Self {
            client,
            endpoint,
            bearer,
            pin: ProviderPin {
                rung: DecisionRung::SystemOne,
                model,
                version,
            },
        })
    }
}

impl DecisionSeat for SystemOneSeat {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    fn ask<'a>(&'a self, request: SeatRequest, _lease: &'a BudgetLease) -> SeatFuture<'a> {
        Box::pin(async move {
            request.validate_remote()?;
            let model = format!("{}-{}", self.pin.model, self.pin.version);
            let (kind, criteria) = match &request.question.contract {
                AnswerContract::Noul => ("noul", None),
                AnswerContract::Choice { options } => {
                    let map: BTreeMap<&str, Value> =
                        options.iter().map(|s| (s.as_str(), Value::Null)).collect();
                    ("choice", Some(json!(map)))
                }
                AnswerContract::Score { .. } => ("score", Some(json!(request.score_levels))),
            };
            let mut question = json!({"type":kind,"instructions":request.question.text});
            if let Some(criteria) = criteria {
                question["criteria"] = criteria;
            }
            let body =
                json!({"model":model,"state":request.state,"questions":{"decision":question}});
            let response = self
                .client
                .post(&self.endpoint)
                .bearer_auth(&self.bearer)
                .json(&body)
                .send()
                .await
                .map_err(transport_error)?;
            let status = response.status();
            if !status.is_success() {
                return Err(if status.is_server_error() || status.as_u16() == 429 {
                    RetryableLlmError::ServerError.into()
                } else {
                    FatalLlmError::InvalidRequest.into()
                });
            }
            if response
                .content_length()
                .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
            {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
                if chunk.len() > MAX_RESPONSE_BYTES - bytes.len() {
                    return Err(FatalLlmError::InvalidRequest.into());
                }
                bytes.extend_from_slice(&chunk);
            }
            let wire: Response =
                serde_json::from_slice(&bytes).map_err(|_| FatalLlmError::InvalidRequest)?;
            if wire.model != model || wire.answers.len() != 1 {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            let answer = wire
                .answers
                .get("decision")
                .ok_or(FatalLlmError::InvalidRequest)?;
            parse_answer(answer, &request)
        })
    }
}

#[derive(Deserialize)]
struct Response {
    model: String,
    answers: BTreeMap<String, Value>,
}

fn parse_answer(value: &Value, request: &SeatRequest) -> oneiron::LlmResult<SeatAnswer> {
    let invalid = || oneiron::LlmError::from(FatalLlmError::InvalidRequest);
    let kind = value
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let (answer, probability) = match (&request.question.contract, kind) {
        (AnswerContract::Noul, "noul") => {
            let p = value
                .get("noul")
                .and_then(Value::as_f64)
                .ok_or_else(invalid)?;
            (DecisionAnswer::Noul(p >= 0.5), p)
        }
        (AnswerContract::Choice { options }, "choice") => {
            let choice = value
                .get("choice")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            if !options.iter().any(|s| s == choice) {
                return Err(invalid());
            }
            let probs = value
                .get("probabilities")
                .and_then(Value::as_object)
                .ok_or_else(invalid)?;
            if probs.len() != options.len()
                || options.iter().any(|o| !probs.contains_key(o))
                || !valid_probabilities(probs.values())
            {
                return Err(invalid());
            }
            let p = value
                .get("confidence")
                .and_then(Value::as_f64)
                .ok_or_else(invalid)?;
            (DecisionAnswer::Choice(choice.to_owned()), p)
        }
        (AnswerContract::Score { min, max }, "score") => {
            let score = value
                .get("score")
                .and_then(Value::as_f64)
                .ok_or_else(invalid)?;
            let ceiling = (request.score_levels.len() - 1) as f64;
            if !score.is_finite() || !(0.0..=ceiling).contains(&score) {
                return Err(invalid());
            }
            let probs = value
                .get("probabilities")
                .and_then(Value::as_object)
                .ok_or_else(invalid)?;
            if probs.len() != request.score_levels.len()
                || (0..request.score_levels.len()).any(|i| !probs.contains_key(&i.to_string()))
                || !valid_probabilities(probs.values())
            {
                return Err(invalid());
            }
            let legend = value
                .get("legend")
                .and_then(Value::as_object)
                .ok_or_else(invalid)?;
            if legend.len() != request.score_levels.len()
                || request.score_levels.iter().enumerate().any(|(i, label)| {
                    legend.get(&i.to_string()).and_then(Value::as_str) != Some(label)
                })
            {
                return Err(invalid());
            }
            let mapped = min + score / ceiling * (max - min);
            if !mapped.is_finite() || !(min..=max).contains(&mapped) {
                return Err(invalid());
            }
            let p = value
                .get("confidence")
                .and_then(Value::as_f64)
                .ok_or_else(invalid)?;
            (DecisionAnswer::Score(mapped), p)
        }
        _ => return Err(invalid()),
    };
    if !probability.is_finite() || !(0.0..=1.0).contains(&probability) {
        return Err(invalid());
    }
    Ok(SeatAnswer {
        answer,
        probability,
    })
}

fn valid_probabilities<'a>(probabilities: impl Iterator<Item = &'a Value>) -> bool {
    probabilities.into_iter().all(|v| {
        v.as_f64()
            .is_some_and(|p| p.is_finite() && (0.0..=1.0).contains(&p))
    })
}

fn transport_error(error: reqwest::Error) -> oneiron::LlmError {
    if error.is_timeout() {
        RetryableLlmError::Timeout.into()
    } else {
        RetryableLlmError::ServerError.into()
    }
}

#[cfg(test)]
mod tests;
