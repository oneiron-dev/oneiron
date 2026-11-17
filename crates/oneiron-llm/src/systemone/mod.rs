//! The remote System One protocol adapter; policy and receipts live in `oneiron::llm::decision`.
//!
//! The seat builds each request and reads each reply here; a
//! [`SystemOneTransport`] carries the exact bytes between: this module's own
//! HTTPS client with a bearer key, or a host's (the credential broker, which
//! adds the key from the vault for one call at a time).

use oneiron::code_run::model_call::native_seat_read_digests;
use oneiron::llm::LabelReadFailure;
use oneiron::llm::decision::questions::QuestionCriteria;
use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionImage, DecisionRung, ImageBox, ProviderPin,
    RemoteDecisionSeat, SeatAnswer, SeatFuture, SeatRead, SeatReadFuture, SeatRequest,
};
use oneiron::{BudgetLease, FatalLlmError, LlmResult, LlmUsage, RetryableLlmError};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

mod pack;
pub use pack::{
    SystemOnePackAnswer, SystemOnePackPrediction, SystemOnePackQuestion, SystemOnePackRequest,
};

/// The largest reply body the seat reads.
pub const MAX_RESPONSE_BYTES: usize = 65_536;
/// The wire's largest image side; a longer image is sent downscaled.
pub const MAX_IMAGE_EDGE: u32 = 1_568;
/// The wire's opt-in for images and Box questions, sent with every request that has one.
const IMAGES_HEADER: &str = "TypeSafe-Danger-Zone-Images";
/// The body key that carries the call's time left to a server that takes a
/// native budget: whole milliseconds, rounded down (Engine ruling L9-19-WIRE).
pub const NATIVE_BUDGET_KEY: &str = "budget_ms";
/// The top-level `stop` a server's reply names when its read stopped at its
/// token cap before an answer (Engine ruling L9-19-WIRE).
pub const TOKEN_CAP_STOP: &str = "token_cap";

/// One request as the seat built it, for a transport to send: the transport
/// adds only the credential, and seals the request ([`Self::seal`]) at the
/// moment it sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemOneHttpRequest {
    /// The seat's endpoint, ending `/v1/systemone`.
    pub endpoint: String,
    /// The headers beside the credential, names lowercase: the content type,
    /// and the images opt-in on a request that has one.
    pub headers: Vec<(String, String)>,
    /// The model the body names (`<model>-<version>`), which the reply names too.
    pub model: String,
    /// The body as built, its images fitted: one JSON object, without the
    /// time left, which [`Self::seal`] reads.
    body: Value,
    /// The call's deadline, counted from when the seat took the call.
    deadline: SeatDeadline,
    /// The seat's server takes a native budget: the sealed body carries the
    /// time left as [`NATIVE_BUDGET_KEY`].
    native_budget: bool,
}

/// A request's exact bytes and wait, read at the moment its transport sends
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSystemOneRequest {
    /// The exact body, one JSON object.
    pub body: Vec<u8>,
    /// How long the answer may take: the call's time left at the seal.
    pub time_left: Duration,
}

impl SystemOneHttpRequest {
    /// The call's time left now.
    ///
    /// # Errors
    /// [`RetryableLlmError::Timeout`] once it is gone.
    pub fn time_left(&self) -> LlmResult<Duration> {
        self.deadline
            .time_left()
            .ok_or_else(|| RetryableLlmError::Timeout.into())
    }

    /// The exact body and wait to send now, from one reading of the call's
    /// time left: a server that takes a native budget gets it as
    /// [`NATIVE_BUDGET_KEY`], whole milliseconds rounded down, so it never
    /// gets more time than the call has left, and the transport waits that
    /// time for the answer. A transport seals once its credential is in
    /// hand, right before the bytes go out, so the time it spent first (a
    /// broker reached, a key read at its custody door) is spent from the call.
    ///
    /// # Errors
    /// [`RetryableLlmError::Timeout`] once the call's time is gone: the call
    /// is then not sent.
    pub fn seal(&mut self) -> LlmResult<SealedSystemOneRequest> {
        let time_left = self.time_left()?;
        if self.native_budget {
            self.body[NATIVE_BUDGET_KEY] =
                json!(u64::try_from(time_left.as_millis()).unwrap_or(u64::MAX));
        }
        Ok(SealedSystemOneRequest {
            body: serde_json::to_vec(&self.body).map_err(|_| FatalLlmError::InvalidRequest)?,
            time_left,
        })
    }
}

/// A reply as it came: its status, and its body for a success, at most
/// [`MAX_RESPONSE_BYTES`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemOneHttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub type SystemOneTransportFuture<'a> =
    Pin<Box<dyn Future<Output = LlmResult<SystemOneHttpResponse>> + Send + 'a>>;

/// What carries one request to the seat and its reply back.
pub trait SystemOneTransport: Send + Sync {
    /// Sends `request` once, under the measurement's `lease`, sealed
    /// ([`SystemOneHttpRequest::seal`]) once the credential is in hand and
    /// right before the bytes go out; a call out of time by then is answered
    /// as timed out, unsent.
    fn send<'a>(
        &'a self,
        request: SystemOneHttpRequest,
        lease: &'a BudgetLease,
    ) -> SystemOneTransportFuture<'a>;

    /// Every check the transport makes before it sends, with no I/O (a
    /// broker it cannot reach, a key its custody door would refuse); `Ok`,
    /// the default, for a transport that checks nothing first.
    fn preflight(&self) -> LlmResult<()> {
        Ok(())
    }
}

/// One seat call's deadline: the work time left when the seat took the call,
/// counted down from that moment, so time spent before the request goes out
/// (fitting images, a transport's wait for its credential) is spent from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SeatDeadline {
    started: Instant,
    time_left: Duration,
}

impl SeatDeadline {
    /// A deadline that starts now, with `time_left` of work time.
    fn start(time_left: Duration) -> Self {
        Self {
            started: Instant::now(),
            time_left,
        }
    }

    /// The time left now, or `None` once it is gone: the call is then answered
    /// as timed out, and nothing is sent.
    fn time_left(self) -> Option<Duration> {
        Some(self.time_left.saturating_sub(self.started.elapsed())).filter(|left| !left.is_zero())
    }
}

/// Authenticated, exact-revision adapter. The host chooses the endpoint,
/// credentials, and version; no model or question text is compiled into policy.
pub struct SystemOneSeat {
    transport: Box<dyn SystemOneTransport>,
    endpoint: String,
    pin: ProviderPin,
    /// The seat's server takes a native budget: each body carries the call's
    /// time left as [`NATIVE_BUDGET_KEY`].
    native_budget: bool,
}

impl SystemOneSeat {
    /// The seat at `endpoint`, sent to over this module's HTTPS client with
    /// `bearer`.
    pub fn new(
        endpoint: String,
        bearer: String,
        model: String,
        version: String,
    ) -> oneiron::LlmResult<Self> {
        if bearer.trim().is_empty() || !bearer.is_ascii() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        // The request's own wait is the decision's time left, set per call.
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        Self::with_transport(
            endpoint,
            model,
            version,
            Box::new(BearerTransport { client, bearer }),
        )
    }

    /// The seat at `endpoint`, its requests carried by `transport`, which
    /// adds the credential.
    pub fn with_transport(
        endpoint: String,
        model: String,
        version: String,
        transport: Box<dyn SystemOneTransport>,
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
            || model.trim().is_empty()
            || version.trim().is_empty()
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(Self {
            transport,
            endpoint,
            pin: ProviderPin {
                rung: DecisionRung::SystemOne,
                model,
                version,
            },
            native_budget: false,
        })
    }

    /// Whether the seat's server takes a native budget: the binding's
    /// `native_budget` row, the codec row ARCH-0036 #system-one-codec names.
    /// A server that takes one gets each call's time left as
    /// [`NATIVE_BUDGET_KEY`]; any other gets the body as before, never a key
    /// it may refuse.
    #[must_use]
    pub fn with_native_budget(mut self, native_budget: bool) -> Self {
        self.native_budget = native_budget;
        self
    }

    /// The transport's own checks before a measurement starts, with no I/O.
    pub fn preflight(&self) -> LlmResult<()> {
        self.transport.preflight()
    }

    /// The exact request `request` is sent as. Each image is decoded and resized on a
    /// blocking thread, off the caller's runtime.
    async fn build(
        &self,
        request: &SeatRequest,
        deadline: SeatDeadline,
    ) -> LlmResult<SystemOneHttpRequest> {
        self.build_questions(
            request,
            json!({"decision": build_question(request)}),
            deadline,
        )
        .await
    }

    /// The request for `questions`, for its transport to seal as it sends;
    /// a call out of time once its images are fitted is answered as timed
    /// out, unsent.
    async fn build_questions(
        &self,
        request: &SeatRequest,
        questions: Value,
        deadline: SeatDeadline,
    ) -> LlmResult<SystemOneHttpRequest> {
        let model = format!("{}-{}", self.pin.model, self.pin.version);
        // Each image is an asset; its state field holds the asset's reference, which
        // the question names in backticks.
        let mut state = request.state.clone();
        let mut assets = serde_json::Map::new();
        for (index, image) in request.images.iter().enumerate() {
            let fitted = image.fitted_async(MAX_IMAGE_EDGE).await?;
            let reference = format!("oneiron-image-{index}-{}", image.name);
            state[image.name.as_str()] = json!(reference);
            assets.insert(
                reference,
                json!({
                    "type": "image",
                    "format": image.format(),
                    "data_base64": DecisionImage::base64(&fitted),
                }),
            );
        }
        let images = !assets.is_empty()
            || questions.as_object().is_some_and(|questions| {
                questions.values().any(|question| question["type"] == "box")
            });
        let mut body = json!({"model":model,"state":state,"questions":questions});
        if !assets.is_empty() {
            body["assets"] = Value::Object(assets);
        }
        let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
        if images {
            headers.push((IMAGES_HEADER.to_ascii_lowercase(), "true".to_owned()));
        }
        let request = SystemOneHttpRequest {
            endpoint: self.endpoint.clone(),
            headers,
            model,
            body,
            deadline,
            native_budget: self.native_budget,
        };
        // A call the image fitting left out of time goes to no transport.
        request.time_left()?;
        Ok(request)
    }

    async fn ask_inner(
        &self,
        request: SeatRequest,
        lease: &BudgetLease,
        time_left: Duration,
        capture: bool,
    ) -> SeatRead {
        let deadline = SeatDeadline::start(time_left);
        let mut digests = None;
        let result = async {
            request.validate_remote()?;
            let sent = self.build(&request, deadline).await?;
            if capture {
                // Fingerprint the built JSON tree, not the pre-transform request
                // or its wire encoding, nor the time left the transport seals
                // into it: one read hashes the same whenever it is sent. The
                // host warns/skips missing evidence.
                digests = native_seat_read_digests(&sent.body).ok();
            }
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
            if stopped_at_token_cap(&response.body) {
                return Err(token_cap());
            }
            let wire: Response = serde_json::from_slice(&response.body)
                .map_err(|_| FatalLlmError::InvalidRequest)?;
            if wire.model != model || wire.answers.len() != 1 {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            let answer = wire
                .answers
                .get("decision")
                .ok_or(FatalLlmError::InvalidRequest)?;
            let mut parsed = parse_answer(answer, &request)?;
            parsed.usage.input.total = wire.usage.input_tokens;
            parsed.usage.output.total = wire.usage.output_tokens;
            parsed.usage.raw_provider = json!({
                "input_tokens": wire.usage.input_tokens,
                "output_tokens": wire.usage.output_tokens,
            });
            Ok(parsed)
        }
        .await;
        SeatRead {
            request: digests,
            result,
        }
    }
}

impl RemoteDecisionSeat for SystemOneSeat {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    fn image_edge(&self) -> Option<u32> {
        Some(MAX_IMAGE_EDGE)
    }

    fn ask<'a>(
        &'a self,
        request: SeatRequest,
        lease: &'a BudgetLease,
        time_left: std::time::Duration,
    ) -> SeatFuture<'a> {
        Box::pin(async move {
            self.ask_inner(request, lease, time_left, false)
                .await
                .result
        })
    }

    fn ask_recorded<'a>(
        &'a self,
        request: SeatRequest,
        lease: &'a BudgetLease,
        time_left: Duration,
    ) -> SeatReadFuture<'a> {
        Box::pin(self.ask_inner(request, lease, time_left, true))
    }
}

/// This module's own transport: one HTTPS request with the bearer key, no
/// redirect, its reply read up to [`MAX_RESPONSE_BYTES`].
struct BearerTransport {
    client: reqwest::Client,
    bearer: String,
}

impl SystemOneTransport for BearerTransport {
    fn send<'a>(
        &'a self,
        mut request: SystemOneHttpRequest,
        _lease: &'a BudgetLease,
    ) -> SystemOneTransportFuture<'a> {
        Box::pin(async move {
            // The bearer is in memory: nothing waits for it, so the request
            // is sealed here, as it goes out.
            let sealed = request.seal()?;
            let mut post = self
                .client
                .post(&request.endpoint)
                .timeout(sealed.time_left)
                .bearer_auth(&self.bearer);
            for (name, value) in &request.headers {
                post = post.header(name.as_str(), value.as_str());
            }
            let mut response = post
                .body(sealed.body)
                .send()
                .await
                .map_err(transport_error)?;
            let status = response.status().as_u16();
            if !response.status().is_success() {
                return Ok(SystemOneHttpResponse {
                    status,
                    body: Vec::new(),
                });
            }
            if response
                .content_length()
                .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
            {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
                if chunk.len() > MAX_RESPONSE_BYTES - bytes.len() {
                    return Err(FatalLlmError::InvalidRequest.into());
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(SystemOneHttpResponse {
                status,
                body: bytes,
            })
        })
    }
}

#[derive(Deserialize)]
struct Response {
    model: String,
    answers: BTreeMap<String, Value>,
    usage: WireUsage,
}

#[derive(Deserialize)]
struct WireUsage {
    input_tokens: u64,
    output_tokens: u64,
}

/// A reply's top-level stop, read from every server before its answers.
#[derive(Deserialize)]
struct ReplyStop {
    stop: Option<String>,
}

/// Whether the reply says its server stopped at its token cap before an
/// answer. Such a read is the cap, as the house read's is: the ladder steps
/// up past it (Engine ruling L2-31-ROUTE), never fails the call on it.
fn stopped_at_token_cap(body: &[u8]) -> bool {
    serde_json::from_slice::<ReplyStop>(body)
        .is_ok_and(|reply| reply.stop.as_deref() == Some(TOKEN_CAP_STOP))
}

/// The error a read its server stopped at its token cap answers: the house
/// read's own.
fn token_cap() -> oneiron::LlmError {
    FatalLlmError::LabelRead(LabelReadFailure::TokenCap).into()
}

fn build_question(request: &SeatRequest) -> Value {
    let (kind, criteria) = match &request.question.contract {
        // The question's criteria triple, as what a yes and a no mean.
        AnswerContract::Noul => (
            "noul",
            QuestionCriteria::from_state(&request.state).map(
                |criteria| json!({"true": criteria.yes_means(), "false": criteria.no_means()}),
            ),
        ),
        AnswerContract::Choice { options } => {
            let map: BTreeMap<&str, Value> =
                options.iter().map(|s| (s.as_str(), Value::Null)).collect();
            ("choice", Some(json!(map)))
        }
        AnswerContract::Score { .. } => ("score", Some(json!(request.score_levels))),
        // The wire has no point: a Point asks for a box, read as its centre.
        AnswerContract::Box | AnswerContract::Point => ("box", None),
    };
    // A question that is no yes/no reads its criteria as the rubric of its
    // own form after its instructions (FIX 2181).
    let rubric = QuestionCriteria::rubric_in(&request.state, &request.question.contract)
        .filter(|_| request.question.contract != AnswerContract::Noul);
    let instructions = match rubric {
        Some(rubric) => format!("{}\n\n{rubric}", request.question.text),
        None => request.question.text.clone(),
    };
    let mut question = json!({"type":kind,"instructions":instructions});
    if let Some(criteria) = criteria {
        question["criteria"] = criteria;
    }
    question
}

fn parse_answer(value: &Value, request: &SeatRequest) -> oneiron::LlmResult<SeatAnswer> {
    let (answer, probability) = parse_prediction(value, request)?;
    Ok(SeatAnswer {
        answer,
        probability,
        usage: LlmUsage::zero(),
    })
}

fn parse_prediction(
    value: &Value,
    request: &SeatRequest,
) -> oneiron::LlmResult<(DecisionAnswer, f64)> {
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
                || !valid_probabilities(probs)
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
                || !valid_probabilities(probs)
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
            // Exact endpoints stay exact. The weighted interior avoids overflow
            // in (max-min) for opposite-sign finite bounds.
            let mapped = if score == 0.0 {
                *min
            } else if score == ceiling {
                *max
            } else {
                let t = score / ceiling;
                ((1.0 - t) * min + t * max).clamp(*min, *max)
            };
            if !mapped.is_finite() {
                return Err(invalid());
            }
            let p = value
                .get("confidence")
                .and_then(Value::as_f64)
                .ok_or_else(invalid)?;
            (DecisionAnswer::Score(mapped), p)
        }
        (AnswerContract::Box | AnswerContract::Point, "box") => {
            // The wire always answers a box; a seat that reports the target absent
            // answers null.
            let found = match value.get("box").ok_or_else(invalid)? {
                Value::Null => None,
                edges => {
                    Some(serde_json::from_value::<ImageBox>(edges.clone()).map_err(|_| invalid())?)
                }
            };
            if found.is_some_and(|found| !found.is_valid()) {
                return Err(invalid());
            }
            let p = value
                .get("confidence")
                .and_then(Value::as_f64)
                .ok_or_else(invalid)?;
            let answer = match request.question.contract {
                AnswerContract::Point => DecisionAnswer::Point(found.map(ImageBox::point)),
                _ => DecisionAnswer::Box(found),
            };
            (answer, p)
        }
        _ => return Err(invalid()),
    };
    if !probability.is_finite() || !(0.0..=1.0).contains(&probability) {
        return Err(invalid());
    }
    Ok((answer, probability))
}

fn valid_probabilities(probabilities: &serde_json::Map<String, Value>) -> bool {
    probabilities.values().all(|v| {
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
