//! The precision band (`cross/models.md#oneiron-roles`, the band row): "the rung a unit in
//! the band (0.35 to 0.65) moves to. Answers units the hot-path head leaves in the band ...
//! Same wire and codec as the head". DECIDE-SWITCHOVER = A (2026-10-16): each decision role
//! is a backend inside decide().
//!
//! The ladder's Precision rung sits between the head (`SystemOne`) and the house read
//! (`Escalation`). Under an enforced band, the head's first in-band answer steps once to the
//! next rung with a provider (ARCH-0076 #escalation-slot-divergence): the precision band when
//! the host seats one, the escalation read when it does not. A remote seat on the System One
//! wire may be pinned at the Precision rung and answers there.
//!
//! On main the file does not compile: there is no `DecisionRung::Precision` and no
//! `precision` slot on `DecisionLadder`.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionClass,
    DecisionDial, DecisionLadder, DecisionProvider, DecisionQuestion, DecisionRung,
    HumanDecisionQueue, HumanDecisionRequest, ProviderDecision, ProviderPin, RemoteDecisionSeat,
    Reversibility, SeatAnswer, SeatFuture, SeatPhase, SeatRequest, TypedDecision,
    decide_at_remote_seat,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, EntityId, HostingPrivacyPosture, LlmUsage,
    Result,
};

/// The hot-path head's model and revision (`cross/models.md`, the head row).
const HEAD_MODEL: &str = "vllm-sr/d3-flash";
const HEAD_REVISION: &str = "521525e";
/// The precision band's model and revision (`cross/models.md`, the band row).
const BAND_MODEL: &str = "Cloudflare/clef";
const BAND_REVISION: &str = "2f3de3d";

/// A clock these reads never reach.
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

fn pin(rung: DecisionRung, model: &str, version: &str) -> ProviderPin {
    ProviderPin {
        rung,
        model: model.into(),
        version: version.into(),
    }
}

fn head_pin() -> ProviderPin {
    pin(DecisionRung::SystemOne, HEAD_MODEL, HEAD_REVISION)
}

fn band_pin() -> ProviderPin {
    pin(DecisionRung::Precision, BAND_MODEL, BAND_REVISION)
}

fn house_pin() -> ProviderPin {
    pin(DecisionRung::Escalation, "house-reader", "r1")
}

/// A yes with P(yes) = `probability`.
fn yes(probability: f64) -> ProviderDecision {
    ProviderDecision {
        answer: DecisionAnswer::Noul(true),
        probability: Some(probability),
        paired: None,
        person: None,
        served: None,
        cost_per_thousand: None,
    }
}

/// A rung that answers `reply` to every call and counts its calls.
struct Scripted {
    pin: ProviderPin,
    reply: ProviderDecision,
    calls: AtomicUsize,
}

impl Scripted {
    fn new(pin: ProviderPin, probability: f64) -> Self {
        Self {
            pin,
            reply: yes(probability),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl DecisionProvider for Scripted {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    fn decide(&self, _: &DecisionCall<'_>) -> Result<ProviderDecision> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.reply.clone())
    }
}

/// The person rung; these dials never reach it.
#[derive(Default)]
struct Queue(Mutex<Vec<HumanDecisionRequest>>);

impl HumanDecisionQueue for Queue {
    fn queue(&self, request: HumanDecisionRequest) -> Result<()> {
        self.0.lock().expect("queue").push(request);
        Ok(())
    }
}

/// The default band (0.35 to 0.65), learned and enforced for `question`.
fn enforced(question: &DecisionQuestion) -> DecisionBandPolicy {
    let mut policy = DecisionBandPolicy::default();
    policy
        .learn_shadow(
            question,
            Reversibility::ReversibleRead,
            DecisionBand::default(),
            1,
        )
        .expect("a learned band");
    policy
        .enforce(question, Reversibility::ReversibleRead)
        .expect("an enforced band");
    policy
}

/// One call from the head up to the Big rung, its band enforced.
fn decide(
    head: &Scripted,
    band: Option<&Scripted>,
    house: &Scripted,
    queue: &Queue,
) -> TypedDecision {
    let question = question();
    let policy = enforced(&question);
    DecisionLadder {
        rule: None,
        local: None,
        system_one: Some(head),
        precision: band.map(|band| band as &dyn DecisionProvider),
        escalation: Some(house),
        big: None,
        human: queue,
        human_pin: pin(DecisionRung::Human, "owner-asks", "1"),
        ask_to: None,
        paired: None,
        person: None,
        presence: None,
        correlation: None,
    }
    .run(
        &question,
        EntityId::now(),
        &[],
        &serde_json::json!({}),
        DecisionDial {
            first: DecisionRung::SystemOne,
            ceiling: DecisionRung::Big,
            band: DecisionBand::default(),
        },
        &policy,
        Reversibility::ReversibleRead,
        &deadline(),
    )
    .expect("the call closes on a receipt")
}

fn answered(decision: &TypedDecision) -> Option<DecisionRung> {
    decision.receipt.time.and_then(|time| time.answered)
}

#[test]
fn in_band_head_answer_moves_to_precision() {
    let head = Scripted::new(head_pin(), 0.5);
    let band = Scripted::new(band_pin(), 0.9);
    let house = Scripted::new(house_pin(), 0.95);
    let queue = Queue::default();

    let decision = decide(&head, Some(&band), &house, &queue);

    assert_eq!(decision.answer, DecisionAnswer::Noul(true));
    assert_eq!(decision.probability, Some(0.9));
    assert_eq!(decision.receipt.providers, vec![head_pin(), band_pin()]);
    assert_eq!(answered(&decision), Some(DecisionRung::Precision));
    assert_eq!(
        decision
            .receipt
            .providers
            .last()
            .map(|pin| pin.model.as_str()),
        Some(BAND_MODEL)
    );
    assert_eq!((head.calls(), band.calls(), house.calls()), (1, 1, 0));
    assert!(queue.0.lock().expect("queue").is_empty());
}

#[test]
fn confident_head_answer_stays_at_head() {
    let head = Scripted::new(head_pin(), 0.95);
    let band = Scripted::new(band_pin(), 0.9);
    let house = Scripted::new(house_pin(), 0.95);
    let queue = Queue::default();

    let decision = decide(&head, Some(&band), &house, &queue);

    assert_eq!(decision.probability, Some(0.95));
    assert_eq!(decision.receipt.providers, vec![head_pin()]);
    assert_eq!(answered(&decision), Some(DecisionRung::SystemOne));
    assert_eq!((head.calls(), band.calls(), house.calls()), (1, 0, 0));
}

#[test]
fn without_precision_in_band_steps_to_escalation() {
    let head = Scripted::new(head_pin(), 0.5);
    let house = Scripted::new(house_pin(), 0.95);
    let queue = Queue::default();

    let decision = decide(&head, None, &house, &queue);

    assert_eq!(decision.probability, Some(0.95));
    assert_eq!(decision.receipt.providers, vec![head_pin(), house_pin()]);
    assert_eq!(answered(&decision), Some(DecisionRung::Escalation));
    assert_eq!((head.calls(), house.calls()), (1, 1));
}

/// A remote seat on the System One wire pinned at `rung`, answering one confident yes.
struct WireSeat {
    rung: DecisionRung,
}

impl RemoteDecisionSeat for WireSeat {
    fn pin(&self) -> ProviderPin {
        pin(self.rung, BAND_MODEL, BAND_REVISION)
    }

    fn ask<'a>(&'a self, _: SeatRequest, _: &'a BudgetLease, _: Duration) -> SeatFuture<'a> {
        let mut usage = LlmUsage::zero();
        usage.input.total = 1;
        usage.output.total = 1;
        Box::pin(std::future::ready(Ok(SeatAnswer {
            answer: DecisionAnswer::Noul(true),
            probability: 0.9,
            usage,
        })))
    }
}

/// One accept-type yes/no at `seat` under `dial`, polled once: the fake replies at once.
fn at_seat(seat: &WireSeat, dial: DecisionDial) -> oneiron::LlmResult<TypedDecision> {
    let guard =
        BudgetGuard::with_reserve_units("precision-seat", 100, 7, BudgetExhaustionPolicy::Suspend);
    let deadline = deadline();
    let request = SeatRequest {
        question: DecisionQuestion {
            accept_type: true,
            ..question()
        },
        state: serde_json::json!({ "note": "bounded" }),
        images: Vec::new(),
        audio: Vec::new(),
        score_levels: Vec::new(),
        posture: HostingPrivacyPosture::Hosted,
        remote_opt_in: false,
        phase: SeatPhase::PreQuery,
    };
    let call = std::pin::pin!(decide_at_remote_seat(
        seat,
        request,
        EntityId::now(),
        Vec::new(),
        dial,
        &guard,
        Reversibility::ReversibleRead,
        &deadline,
    ));
    match call.poll(&mut std::task::Context::from_waker(std::task::Waker::noop())) {
        std::task::Poll::Ready(decision) => decision,
        std::task::Poll::Pending => panic!("the fake seat replies at once"),
    }
}

fn dial(first: DecisionRung, ceiling: DecisionRung) -> DecisionDial {
    DecisionDial {
        first,
        ceiling,
        band: DecisionBand::default(),
    }
}

#[test]
fn remote_seat_pinned_at_precision_answers_on_its_rung() {
    let seat = WireSeat {
        rung: DecisionRung::Precision,
    };

    let decision = at_seat(&seat, dial(DecisionRung::Rule, DecisionRung::Precision))
        .expect("a precision seat answers under a dial that spans it");

    assert_eq!(decision.answer, DecisionAnswer::Noul(true));
    assert_eq!(answered(&decision), Some(DecisionRung::Precision));
    assert_eq!(decision.receipt.providers, vec![band_pin()]);
    // A dial that stops at the head does not reach the band's seat.
    assert!(at_seat(&seat, dial(DecisionRung::Rule, DecisionRung::SystemOne)).is_err());
    // A seat on the System One wire is the head's or the band's, no other rung.
    let house_rung = WireSeat {
        rung: DecisionRung::Escalation,
    };
    assert!(at_seat(&house_rung, dial(DecisionRung::Rule, DecisionRung::Big)).is_err());
}
