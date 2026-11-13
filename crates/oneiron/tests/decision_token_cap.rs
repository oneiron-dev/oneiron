//! ARCH-0076 #receipt: a typed decision's receipt names why the call stopped, "done,
//! deadline, token cap or provider failure" (ARCH-0036 #decision-deadline, step 8). A read
//! its provider stopped at the token cap is unfinished, and an unfinished reply is not an
//! answer: that rung answered nothing, so the question goes on to the next rung that can take
//! it, as past an abstaining rung (ruling L2-31-ROUTE). A call that ends on such a read
//! abstains, and its receipt's stop cause is the token cap.
//!
//! Two readers stop at a token cap here: the house read (`DecisionReadProvider`), whose
//! server reports a read that spent its generation-token budget as
//! `LabelReadFailure::TokenCap` (FIX 303), and the generated read, whose reply ends
//! `FinishReason::Length`.
//!
//! The file compiles on origin/main: it reads the stop cause by its serde name. On main each
//! capped call fails with an error instead of closing on a receipt.

use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionClass,
    DecisionDial, DecisionLadder, DecisionProvider, DecisionQuestion, DecisionReadProvider,
    DecisionRung, GeneratedDecisions, GeneratedRung, GeneratedStep, HumanAskReason,
    HumanDecisionQueue, HumanDecisionRequest, ProviderDecision, ProviderPin, Reversibility,
    TypedDecision,
};
use oneiron::llm::{
    CallClass, CallEnvelope, CallPurpose, LabelReadFailure, LabelReadModel, LabelReadRequest,
    LabelReadResponse, ModelTierRef, ResponseFormat, Scope, TierPrecedence,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, ContentPart, EntityId, FatalLlmError,
    FinishReason, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmInputUsage,
    LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmResult,
    LlmStreamResult, LlmUsage, ModelId, ModelLocality, Result, UnsupportedCapability,
};

/// The house reader's model and revision; its pin names exactly these.
const HOUSE_MODEL: &str = "house-reader";
const HOUSE_REVISION: &str = "r1";
/// The generated rung's model.
const GENERATED_MODEL: &str = "test/generated@r1";

/// A clock with ample work time: every read here answers at once.
fn deadline() -> RetrievalDeadline {
    RetrievalDeadline::hard(Instant::now(), Duration::from_secs(60))
}

fn question() -> DecisionQuestion {
    DecisionQuestion {
        id: EntityId::now(),
        version: 1,
        text: "Does this note answer the task?".into(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}

fn paired_question() -> DecisionQuestion {
    DecisionQuestion {
        id: EntityId::now(),
        version: 1,
        text: "Does this need more thinking?".into(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}

fn pin(rung: DecisionRung) -> ProviderPin {
    ProviderPin {
        rung,
        model: format!("fake-{rung:?}"),
        version: "1".into(),
    }
}

fn house_pin() -> ProviderPin {
    ProviderPin {
        rung: DecisionRung::Escalation,
        model: HOUSE_MODEL.into(),
        version: HOUSE_REVISION.into(),
    }
}

fn guard() -> BudgetGuard {
    BudgetGuard::with_reserve_units(
        "decision-token-cap",
        100_000,
        7,
        BudgetExhaustionPolicy::Suspend,
    )
}

/// The receipt's stop cause by its wire name.
fn stop(decision: &TypedDecision) -> String {
    let time = decision
        .receipt
        .time
        .expect("the receipt records the call's time");
    serde_json::to_value(time.stop)
        .expect("a stop cause serializes")
        .as_str()
        .expect("a stop cause is a name")
        .to_owned()
}

fn answered(decision: &TypedDecision) -> Option<DecisionRung> {
    decision
        .receipt
        .time
        .expect("the receipt records the call's time")
        .answered
}

fn rungs(decision: &TypedDecision) -> Vec<DecisionRung> {
    decision.receipt.providers.iter().map(|p| p.rung).collect()
}

/// The house model's reader: it stops at its token cap, or reads every question with
/// nearly all weight on the first label, its paired reading low.
struct HouseReader {
    capped: bool,
    reads: Mutex<usize>,
}

impl HouseReader {
    fn new(capped: bool) -> Self {
        Self {
            capped,
            reads: Mutex::new(0),
        }
    }

    fn reads(&self) -> usize {
        *self.reads.lock().expect("reads")
    }
}

impl LabelReadModel for HouseReader {
    fn model(&self) -> &str {
        HOUSE_MODEL
    }

    fn revision(&self) -> &str {
        HOUSE_REVISION
    }

    fn read(
        &self,
        request: &LabelReadRequest<'_>,
        _lease: &BudgetLease,
    ) -> LlmResult<LabelReadResponse> {
        *self.reads.lock().expect("reads") += 1;
        if self.capped {
            return Err(LlmError::Fatal(FatalLlmError::LabelRead(
                LabelReadFailure::TokenCap,
            )));
        }
        let readouts = request
            .questions
            .iter()
            .map(|readout| {
                let width = readout.width();
                let rest = 0.03 / (width - 1) as f64;
                let mut row = vec![rest; width];
                row[0] = 0.97;
                row
            })
            .collect();
        Ok(LabelReadResponse {
            readouts,
            usage: LlmUsage::zero(),
        })
    }
}

/// A rung that answers a clear yes.
struct Yes(DecisionRung);

impl DecisionProvider for Yes {
    fn pin(&self) -> ProviderPin {
        pin(self.0)
    }

    fn decide(&self, _call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        Ok(ProviderDecision {
            answer: DecisionAnswer::Noul(true),
            probability: Some(0.9),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        })
    }
}

#[derive(Default)]
struct Queue(Mutex<Vec<HumanDecisionRequest>>);

impl Queue {
    fn asks(&self) -> Vec<HumanDecisionRequest> {
        self.0.lock().expect("asks").clone()
    }
}

impl HumanDecisionQueue for Queue {
    fn queue(&self, request: HumanDecisionRequest) -> Result<()> {
        self.0.lock().expect("asks").push(request);
        Ok(())
    }
}

/// One reversible question decided from the house read (the escalation rung) up to
/// `ceiling`, with `big` in the Big slot when given.
fn decide_from_house(
    reader: &HouseReader,
    big: Option<&dyn DecisionProvider>,
    queue: &Queue,
    ceiling: DecisionRung,
) -> Result<TypedDecision> {
    let paired = paired_question();
    let guard = guard();
    let house = DecisionReadProvider::new(house_pin(), reader, &guard, &paired, None)?;
    DecisionLadder {
        rule: None,
        local: None,
        system_one: None,
        escalation: Some(&house),
        big,
        human: queue,
        human_pin: pin(DecisionRung::Human),
        ask_to: None,
        paired: Some(&paired),
        person: None,
        presence: None,
        correlation: None,
    }
    .run(
        &question(),
        EntityId::now(),
        &[],
        &serde_json::json!({}),
        DecisionDial {
            first: DecisionRung::Escalation,
            ceiling,
            band: DecisionBand::default(),
        },
        &DecisionBandPolicy::default(),
        Reversibility::ReversibleRead,
        &deadline(),
    )
}

/// The house read stops at its token cap, so the question goes on to the Big rung, which
/// answers: the call is done, and the receipt names both rungs.
#[test]
fn a_capped_house_read_passes_the_question_to_the_next_rung() {
    let reader = HouseReader::new(true);
    let big = Yes(DecisionRung::Big);
    let queue = Queue::default();
    let decision = decide_from_house(&reader, Some(&big), &queue, DecisionRung::Big)
        .expect("a capped read closes on a receipt, not an error");
    assert_eq!(reader.reads(), 1);
    assert_eq!(decision.answer, DecisionAnswer::Noul(true));
    assert_eq!(decision.probability, Some(0.9));
    assert_eq!(decision.human_ask, None);
    assert_eq!(stop(&decision), "done");
    assert_eq!(answered(&decision), Some(DecisionRung::Big));
    assert_eq!(
        rungs(&decision),
        vec![DecisionRung::Escalation, DecisionRung::Big]
    );
}

/// The house read stops at its token cap at the dial's ceiling: the call holds no answer,
/// so it abstains, and the receipt's stop cause is the token cap.
#[test]
fn a_capped_house_read_at_the_ceiling_abstains_on_a_token_cap_receipt() {
    let reader = HouseReader::new(true);
    let queue = Queue::default();
    let decision = decide_from_house(&reader, None, &queue, DecisionRung::Escalation)
        .expect("a capped read closes on a receipt, not an error");
    assert_eq!(decision.answer, DecisionAnswer::Abstain);
    assert_eq!(decision.probability, None);
    assert_eq!(
        decision.human_ask,
        Some(HumanAskReason::ProviderUnavailable)
    );
    assert_eq!(stop(&decision), "token_cap");
    assert_eq!(answered(&decision), None);
    assert_eq!(rungs(&decision), vec![DecisionRung::Escalation]);
    assert!(queue.asks().is_empty());
}

/// The dial reaches the person: after a capped house read the ask goes to the person, and
/// the receipt still says the call's last read stopped at its token cap.
#[test]
fn a_capped_house_read_asks_the_person_when_the_dial_reaches_one() {
    let reader = HouseReader::new(true);
    let queue = Queue::default();
    let decision = decide_from_house(&reader, None, &queue, DecisionRung::Human)
        .expect("a capped read closes on a receipt, not an error");
    assert_eq!(decision.answer, DecisionAnswer::Abstain);
    assert_eq!(
        decision.human_ask,
        Some(HumanAskReason::ProviderUnavailable)
    );
    assert_eq!(stop(&decision), "token_cap");
    let asks = queue.asks();
    assert_eq!(asks.len(), 1);
    assert_eq!(asks[0].reason, HumanAskReason::ProviderUnavailable);
    assert!(asks[0].prior.is_none());
    assert_eq!(
        rungs(&decision),
        vec![DecisionRung::Escalation, DecisionRung::Human]
    );
}

/// Control: a house read that finishes answers, and the call stops done.
#[test]
fn an_uncapped_house_read_still_stops_done() {
    let reader = HouseReader::new(false);
    let queue = Queue::default();
    let decision = decide_from_house(&reader, None, &queue, DecisionRung::Escalation)
        .expect("an answered read closes on a receipt");
    assert_ne!(decision.answer, DecisionAnswer::Abstain);
    assert_eq!(stop(&decision), "done");
    assert_eq!(answered(&decision), Some(DecisionRung::Escalation));
}

/// The generated read's backend: its provider stops the reply at the request's token cap,
/// midway through the JSON answer.
struct CappedBackend {
    calls: Mutex<usize>,
}

impl LlmBackend for CappedBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        *self.calls.lock().expect("calls") += 1;
        let reply = LlmResponse {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: vec![ContentPart::Text {
                    text: "{\"q\": {\"yes\": 0.9".into(),
                    signature: None,
                }],
            },
            usage: LlmUsage {
                input: LlmInputUsage {
                    total: 10,
                    cache_read: 0,
                    cache_write: 0,
                },
                output: LlmOutputUsage {
                    total: 16,
                    text: 16,
                    reasoning: 0,
                },
                raw_provider: serde_json::Value::Null,
                call_metadata: None,
            },
            finish_reason: FinishReason::Length,
            reply_assertions: Default::default(),
            token_scores: None,
        };
        Box::pin(async move { Ok(reply) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

fn generated_request() -> LlmRequest {
    LlmRequest {
        model: ModelId::new(GENERATED_MODEL).expect("model id"),
        envelope: CallEnvelope {
            scope: Scope::default(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
            seat_effort: None,
        },
        messages: Vec::new(),
        tools: Vec::new(),
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    }
}

/// Drives an async read on a current-thread runtime.
fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(future)
}

/// The generated read's reply ends at its token cap: the System One rung answered nothing,
/// and at the ceiling the call abstains on a token-cap receipt. The reply's spend stays
/// booked.
#[test]
fn a_generated_read_cut_at_its_token_cap_closes_on_a_token_cap_receipt() {
    let backend = CappedBackend {
        calls: Mutex::new(0),
    };
    let guard = guard();
    let lease = guard.admit().expect("the guard admits the read").lease;
    let seal = |request: LlmRequest| -> Result<LlmRequest> { Ok(request) };
    let rung = GeneratedRung {
        pin: ProviderPin {
            rung: DecisionRung::SystemOne,
            model: GENERATED_MODEL.into(),
            version: "1".into(),
        },
        backend: &backend,
        step: GeneratedStep::Raw { lease: &lease },
        request: generated_request(),
        seal: &seal,
    };
    let paired = paired_question();
    let question = question();
    let queue = Queue::default();
    let ladder = DecisionLadder {
        rule: None,
        local: None,
        system_one: None,
        escalation: None,
        big: None,
        human: &queue,
        human_pin: pin(DecisionRung::Human),
        ask_to: None,
        paired: Some(&paired),
        person: None,
        presence: None,
        correlation: None,
    };
    let outcome = block_on(ladder.run_pack_generated(
        &rung,
        &[&question],
        EntityId::now(),
        &[],
        &serde_json::json!({}),
        DecisionDial {
            first: DecisionRung::SystemOne,
            ceiling: DecisionRung::SystemOne,
            band: DecisionBand::default(),
        },
        &DecisionBandPolicy::default(),
        Reversibility::ReversibleRead,
        &deadline(),
    ));
    assert_eq!(*backend.calls.lock().expect("calls"), 1);
    let (decisions, steps) = match outcome {
        Ok(GeneratedDecisions::Decided { decisions, steps }) => (decisions, steps),
        Ok(GeneratedDecisions::Trapped) => panic!("a raw read never traps"),
        Ok(GeneratedDecisions::Unread(_)) => panic!("the backend replied"),
        Err(error) => panic!("a capped reply closes on a receipt, not an error: {error:?}"),
    };
    assert_eq!(decisions.len(), 1);
    let decision = &decisions[0];
    assert_eq!(decision.answer, DecisionAnswer::Abstain);
    assert_eq!(decision.probability, None);
    assert_eq!(
        decision.human_ask,
        Some(HumanAskReason::ProviderUnavailable)
    );
    assert_eq!(stop(decision), "token_cap");
    assert_eq!(answered(decision), None);
    assert_eq!(rungs(decision), vec![DecisionRung::SystemOne]);
    // The capped reply still spent: its usage is booked with the read.
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].1.output.total, 16);
}
