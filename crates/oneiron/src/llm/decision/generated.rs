//! The generated read: a typed pack answered by one generation on the caller's own backend,
//! for a caller already on an async path. The ladder is synchronous, so this entry awaits the
//! generation as the dial's first read under the call's clock, then routes each answer
//! exactly as [`DecisionLadder::run_pack`] does; a stronger rung is one of the ladder's own
//! slots. The generation goes out as the caller's own calls do: a durable step, the raw seam
//! on the caller's lease, or the raw seam under a per-call admission.

use serde_json::{Map, Value, json};

use super::ladder::{OpenPack, ProviderDecision, Read, asked, joined, take, validate_pin};
use super::types::invalid;
use super::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, DecisionLadder, DecisionPack,
    DecisionQuestion, DecisionRung, ProviderPin, Reversibility, TypedDecision,
};
use crate::llm::{
    BudgetDenied, BudgetGuard, BudgetLease, CallClass, ContentPart, DeterministicFallback,
    DurableStepContext, DurableStepResult, LlmBackend, LlmError, LlmMessage, LlmMessageRole,
    LlmRequest, LlmResponse, LlmUsage, ResponseFormat, StepOutcome, call_as_step,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Error, Result};

/// A noul's labels as the generation answers them, yes first.
const NOUL_LABELS: [&str; 2] = ["yes", "no"];

/// The rung whose read is one generation: its backend, how each request goes out, and the
/// request it goes out as.
pub struct GeneratedRung<'a> {
    /// The dial's first rung and the model the request names.
    pub pin: ProviderPin,
    pub backend: &'a dyn LlmBackend,
    pub step: GeneratedStep<'a>,
    /// The host's model, envelope, params, options and its own prompt. The read adds its
    /// turn after the host's messages, and sets its answer format and, on a durable call, an
    /// abstaining fallback.
    pub request: LlmRequest,
    /// The host's last word on the built request (its role authorization and reasoning
    /// binding), before the step hashes it.
    pub seal: &'a (dyn Fn(LlmRequest) -> Result<LlmRequest> + Sync),
}

/// How each of the read's requests goes out.
pub enum GeneratedStep<'a> {
    /// A durable step on the guard: memoized, replayed on resume, and a trap parks the
    /// caller's attempt.
    Durable {
        step: &'a DurableStepContext<'a>,
        guard: &'a BudgetGuard,
    },
    /// The raw seam on the lease the caller issued.
    Raw { lease: &'a BudgetLease },
    /// The raw seam, each request admitted on the guard and settled on what it spent.
    Admitted { guard: &'a BudgetGuard },
}

/// What a generated pack gave its caller.
pub enum GeneratedDecisions {
    /// Each question's decision in order, and each generation's request hash and usage.
    Decided {
        decisions: Vec<TypedDecision>,
        steps: Vec<([u8; 32], LlmUsage)>,
    },
    /// The durable step suspended the attempt; it parked, and replays on resume.
    Trapped,
    /// A raw request came back with no reply; nothing was decided.
    Unread(GeneratedMiss),
}

/// Why a raw read came back with no reply.
pub enum GeneratedMiss {
    /// The backend failed the request.
    Backend(LlmError),
    /// The guard admitted no request.
    Budget(BudgetDenied),
}

/// One request's outcome.
enum Reply {
    Answers(Result<Vec<ProviderDecision>>),
    Trapped,
    Unread(GeneratedMiss),
}

impl DecisionLadder<'_> {
    /// [`Self::run_pack`] with the generated read as the dial's first rung, in place of
    /// that slot's provider. Each request asks the questions (the person's last, when the
    /// dial reaches the person) over the call's state, and the reply gives a probability
    /// per label; a question it leaves out, or answers with no weight, abstains, and so does
    /// every question on the step's deterministic fallback. A step that traps, refuses or
    /// fails, and a raw request the backend fails or the guard does not admit, returns to the
    /// caller as its own outcome; it is not a decision.
    #[expect(
        clippy::too_many_arguments,
        reason = "the generated rung joins run_pack's inputs"
    )]
    pub async fn run_pack_generated(
        &self,
        rung: &GeneratedRung<'_>,
        questions: &[&DecisionQuestion],
        principal: EntityId,
        evidence: &[EntityId],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> DurableStepResult<GeneratedDecisions> {
        validate_pin(&rung.pin, dial.first)?;
        if !matches!(
            dial.first,
            DecisionRung::Local | DecisionRung::SystemOne | DecisionRung::Big
        ) || rung.pin.model != rung.request.model.as_str()
        {
            return Err(invalid("invalid generated rung").into());
        }
        if !questions.iter().all(|question| {
            matches!(
                question.contract,
                AnswerContract::Noul | AnswerContract::Choice { .. }
            )
        }) {
            return Err(invalid("a generated read takes noul and choice questions").into());
        }
        let pack = self.open(
            questions,
            principal,
            evidence,
            &[],
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )?;
        let mut readings = pack.readings();
        let mut first = Vec::with_capacity(questions.len());
        let mut steps = Vec::new();
        let per_call = policy.questions_per_call();
        for (chunk, readings) in questions
            .chunks(per_call)
            .zip(readings.chunks_mut(per_call))
        {
            let call = DecisionPack {
                questions: chunk,
                evidence,
                images: &[],
                state,
                deadline,
            };
            // A read the work time cannot start never goes out.
            if !deadline.decision_may_start() {
                first.extend(chunk.iter().map(|_| Some(Read::NotStarted)));
                continue;
            }
            let answers = match read(rung, &pack, &call, &mut steps).await? {
                Reply::Answers(answers) => answers,
                Reply::Trapped => return Ok(GeneratedDecisions::Trapped),
                Reply::Unread(miss) => return Ok(GeneratedDecisions::Unread(miss)),
            };
            first.extend(
                take(&rung.pin, &call, answers, readings)?
                    .into_iter()
                    .map(Some),
            );
        }
        let decisions = self.close(&pack, first, readings)?;
        Ok(GeneratedDecisions::Decided { decisions, steps })
    }
}

/// One generation for `call`'s questions.
async fn read(
    rung: &GeneratedRung<'_>,
    pack: &OpenPack<'_>,
    call: &DecisionPack<'_>,
    steps: &mut Vec<([u8; 32], LlmUsage)>,
) -> DurableStepResult<Reply> {
    let asked = asked(call, pack.person);
    let request = (rung.seal)(request(rung.request.clone(), &asked, call.state))?;
    let hash = request.canonical_hash()?;
    let response = match rung.step {
        GeneratedStep::Durable { step, guard } => {
            match call_as_step(step, rung.backend, guard, request).await? {
                StepOutcome::Finished { response, .. } => response,
                StepOutcome::Trapped { .. } => return Ok(Reply::Trapped),
            }
        }
        GeneratedStep::Raw { lease } => match rung.backend.generate(request, lease).await {
            Ok(response) => response,
            Err(error) => return Ok(Reply::Unread(GeneratedMiss::Backend(error))),
        },
        GeneratedStep::Admitted { guard } => match admitted(rung.backend, guard, request).await? {
            Ok(response) => response,
            Err(miss) => return Ok(Reply::Unread(miss)),
        },
    };
    steps.push((hash, response.usage.clone()));
    Ok(Reply::Answers(answers(&response, &asked).and_then(
        |answers| joined(answers, call.questions.len(), pack.person),
    )))
}

/// `request` on the raw seam under its own admission on `guard`, settled on what it spent.
async fn admitted(
    backend: &dyn LlmBackend,
    guard: &BudgetGuard,
    request: LlmRequest,
) -> Result<std::result::Result<LlmResponse, GeneratedMiss>> {
    let lease = match guard.admit_for_request(&request) {
        Ok(admission) => Reserved {
            guard,
            lease: admission.lease,
        },
        Err(denied) => return Ok(Err(GeneratedMiss::Budget(denied))),
    };
    let response = backend.generate(request, &lease.lease).await;
    match &response {
        Ok(reply) => guard.settle_per_call(&lease.lease, &reply.usage),
        Err(_) => guard.settle_reserved(&lease.lease),
    }
    .map_err(|_| Error::InvariantViolation("generated read budget settlement"))?;
    Ok(response.map_err(GeneratedMiss::Backend))
}

/// A started request's reservation: a request dropped before it returns spends its
/// estimate. Settling a settled lease again is a no-op.
struct Reserved<'a> {
    guard: &'a BudgetGuard,
    lease: BudgetLease,
}

impl Drop for Reserved<'_> {
    fn drop(&mut self) {
        let _ = self.guard.settle_reserved(&self.lease);
    }
}

/// `shell` asking `asked` over `state`: after the host's own messages, one user turn names
/// each question by id with its text and labels beside the state, and the answer format is
/// a weight per label for each question id.
fn request(mut shell: LlmRequest, asked: &[&DecisionQuestion], state: &Value) -> LlmRequest {
    let mut properties = Map::new();
    let questions: Vec<Value> = asked
        .iter()
        .map(|question| {
            let labels = labels_of(question);
            let weights: Map<String, Value> = labels
                .iter()
                .map(|label| {
                    (
                        (*label).to_owned(),
                        json!({"type": "number", "minimum": 0, "maximum": 1}),
                    )
                })
                .collect();
            properties.insert(
                question.id.to_hex(),
                json!({
                    "type": "object",
                    "properties": weights,
                    "required": labels,
                    "additionalProperties": false,
                }),
            );
            json!({"id": question.id.to_hex(), "question": question.text, "labels": labels})
        })
        .collect();
    shell.envelope.response_format = ResponseFormat::Json {
        schema: json!({
            "type": "object",
            "description": "For each question id, the probability of each of its labels.",
            "properties": properties,
            "additionalProperties": false,
        }),
    };
    if let CallClass::Durable { fallback } = &mut shell.envelope.class {
        // A read that cannot run answers nothing: every question abstains.
        *fallback = DeterministicFallback {
            name: "json_rules_v1".into(),
            config: Some(json!({"version": 1, "rows": [{"failure": "fatal", "value": {}}]})),
        };
    }
    shell.messages.push(LlmMessage {
        role: LlmMessageRole::User,
        content: vec![ContentPart::Text {
            text: json!({"questions": questions, "state": state}).to_string(),
        }],
    });
    shell
}

fn labels_of(question: &DecisionQuestion) -> Vec<&str> {
    match &question.contract {
        AnswerContract::Choice { options } => options.iter().map(String::as_str).collect(),
        _ => NOUL_LABELS.to_vec(),
    }
}

/// Each asked question's answer from `response`: the label with the most weight (the first
/// wins a tie, so a tied noul reads yes) at its share of the question's weight. A noul's
/// probability is P(yes), whichever way it reads.
fn answers(response: &LlmResponse, asked: &[&DecisionQuestion]) -> Result<Vec<ProviderDecision>> {
    let text: String = response
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let reply: Value = serde_json::from_str(text.trim())
        .map_err(|_| invalid("generated decision read is not JSON"))?;
    Ok(asked
        .iter()
        .map(|question| {
            let labels = labels_of(question);
            let weights: Option<Vec<f64>> = labels
                .iter()
                .map(|label| {
                    reply
                        .get(question.id.to_hex())
                        .and_then(|weights| weights.get(label))
                        .and_then(Value::as_f64)
                        .filter(|weight| weight.is_finite() && *weight >= 0.0)
                })
                .collect();
            let total = weights.as_ref().map_or(0.0, |weights| weights.iter().sum());
            let Some(weights) = weights.filter(|_| total > 0.0 && total.is_finite()) else {
                return ProviderDecision {
                    answer: DecisionAnswer::Abstain,
                    probability: None,
                    paired: None,
                    person: None,
                };
            };
            let mut top = 0;
            for (index, weight) in weights.iter().enumerate() {
                if *weight > weights[top] {
                    top = index;
                }
            }
            let (answer, weight) = match &question.contract {
                AnswerContract::Choice { options } => {
                    (DecisionAnswer::Choice(options[top].clone()), weights[top])
                }
                _ => (DecisionAnswer::Noul(top == 0), weights[0]),
            };
            ProviderDecision {
                answer,
                probability: Some((weight / total).clamp(0.0, 1.0)),
                paired: None,
                person: None,
            }
        })
        .collect())
}
