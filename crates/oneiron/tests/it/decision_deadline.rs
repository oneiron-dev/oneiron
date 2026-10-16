//! DECISION-DEADLINE (owner, 2026-10-16): every typed decision runs under one clock. It reads an
//! answer first, starts a stronger rung or a second measurement only while work time is left, and
//! keeps the last quarter of the time for the answer. At the cut a reversible step takes the
//! answer it holds; an irreversible one abstains and asks. A product drives
//! `DecisionLadder::run` and `decide_at_remote_seat` with its own providers, as here: the fakes
//! spend the call's still clock, so each cut lands exactly where a case puts it.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use oneiron::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionClass, DecisionDial,
    DecisionLadder, DecisionProvider, DecisionQuestion, DecisionRung, DecisionTime, HumanAskReason,
    HumanDecisionQueue, HumanDecisionRequest, PairedAnswer, ProviderDecision, ProviderPin,
    Reasoning, ReasoningCause, RemoteDecisionSeat, Reversibility, SeatAnswer, SeatFuture,
    SeatPhase, SeatRequest, StopCause, TypedDecision, decide_at_remote_seat,
};
use oneiron::retrieval_depth::{RetrievalDeadline, still_deadline_clock_for_test};
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, EntityId, Error, HostingPrivacyPosture,
    LlmError, LlmResult, LlmUsage, Result, RetryableLlmError,
};

/// Each call's budget. Its work stops at [`WORK`]; the last quarter is the answer's.
const BUDGET: Duration = Duration::from_millis(1000);
const WORK: Duration = Duration::from_millis(750);
/// The units a seat measurement's lease reserves, and is charged when it fails unsettled.
const RESERVE: u64 = 7;

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

/// One call's clock, still: it moves only as the fakes spend it.
fn clock() -> RetrievalDeadline {
    let was = still_deadline_clock_for_test(true);
    let deadline = RetrievalDeadline::hard(Instant::now(), BUDGET);
    still_deadline_clock_for_test(was);
    deadline
}

/// The same budget given as a raw deadline.
fn raw_clock() -> RetrievalDeadline {
    let was = still_deadline_clock_for_test(true);
    let deadline = RetrievalDeadline::at(Instant::now() + BUDGET);
    still_deadline_clock_for_test(was);
    deadline
}

fn time(decision: &TypedDecision) -> DecisionTime {
    decision
        .receipt
        .time
        .expect("the receipt records the call's time")
}

fn pin(rung: DecisionRung) -> ProviderPin {
    ProviderPin {
        rung,
        model: format!("fake-{rung:?}"),
        version: "1".into(),
    }
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

/// A yes/no answer, with its paired "does this need more thinking?" reading when given.
fn answer(yes: bool, probability: f64, think: Option<f64>) -> ProviderDecision {
    ProviderDecision {
        answer: DecisionAnswer::Noul(yes),
        probability: Some(probability),
        paired: think.map(|probability| PairedAnswer {
            question: EntityId::now(),
            question_version: 1,
            probability,
        }),
        person: None,
    }
}

/// The surface's policy: its think row when given, and its band enforced when `enforce`.
fn policy(question: &DecisionQuestion, think: Option<f64>, enforce: bool) -> DecisionBandPolicy {
    let mut policy = DecisionBandPolicy::default();
    if let Some(threshold) = think {
        policy
            .set_think_threshold(threshold, 1)
            .expect("the think row");
    }
    if enforce {
        for reversibility in [Reversibility::ReversibleRead, Reversibility::OutboundEffect] {
            policy
                .learn_shadow(question, reversibility, DecisionBand::default(), 1)
                .expect("a learned band");
            policy
                .enforce(question, reversibility)
                .expect("an enforced band");
        }
    }
    policy
}

/// A rung that spends `spend` of the call's clock, then answers `reply` or fails.
struct Rung {
    rung: DecisionRung,
    spend: Duration,
    reply: Option<ProviderDecision>,
    /// The work time left each read saw when it started.
    seen: Mutex<Vec<Duration>>,
}

impl Rung {
    fn new(rung: DecisionRung, spend: Duration, reply: Option<ProviderDecision>) -> Self {
        Self {
            rung,
            spend,
            reply,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn reads(&self) -> Vec<Duration> {
        self.seen.lock().expect("reads").clone()
    }
}

impl DecisionProvider for Rung {
    fn pin(&self) -> ProviderPin {
        pin(self.rung)
    }

    fn decide(
        &self,
        _: &DecisionQuestion,
        _: &[EntityId],
        deadline: &RetrievalDeadline,
    ) -> Result<ProviderDecision> {
        self.seen
            .lock()
            .expect("reads")
            .push(deadline.decision_time_left());
        deadline.spend_for_test(self.spend);
        self.reply
            .clone()
            .ok_or_else(|| Error::InvalidConfig("the provider failed".into()))
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

/// A surface's ladder: its System One rung, the stronger escalation rung, and the person queue.
struct Ladder {
    first: Rung,
    stronger: Rung,
    queue: Queue,
}

impl Ladder {
    fn new(first: Rung, stronger: Rung) -> Self {
        Self {
            first,
            stronger,
            queue: Queue::default(),
        }
    }

    fn run(
        &self,
        question: &DecisionQuestion,
        policy: &DecisionBandPolicy,
        ceiling: DecisionRung,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<TypedDecision> {
        self.run_on(true, question, policy, ceiling, reversibility, deadline)
    }

    /// The ladder with its stronger rung's slot filled or empty.
    fn run_on(
        &self,
        stronger: bool,
        question: &DecisionQuestion,
        policy: &DecisionBandPolicy,
        ceiling: DecisionRung,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<TypedDecision> {
        DecisionLadder {
            rule: None,
            local: None,
            system_one: Some(&self.first),
            escalation: stronger.then_some(&self.stronger as &dyn DecisionProvider),
            big: None,
            human: &self.queue,
            human_pin: pin(DecisionRung::Human),
        }
        .run(
            question,
            EntityId::now(),
            &[],
            DecisionDial {
                first: DecisionRung::SystemOne,
                ceiling,
                band: DecisionBand::default(),
            },
            policy,
            reversibility,
            deadline,
        )
    }
}

const STEPS: [(Reversibility, DecisionRung); 4] = [
    (Reversibility::ReversibleRead, DecisionRung::Big),
    (Reversibility::ReversibleRead, DecisionRung::Human),
    (Reversibility::OutboundEffect, DecisionRung::Big),
    (Reversibility::OutboundEffect, DecisionRung::Human),
];

/// The cut rule on a held clear yes (0.9) from System One: a reversible step takes it; an
/// irreversible one abstains, and asks a person with it as the prior when its dial reaches one.
fn assert_cut_rule(
    ladder: &Ladder,
    decision: &TypedDecision,
    reversibility: Reversibility,
    ceiling: DecisionRung,
) {
    let takes = reversibility == Reversibility::ReversibleRead;
    let asks = !takes && ceiling == DecisionRung::Human;
    assert_eq!(
        decision.answer,
        if takes {
            DecisionAnswer::Noul(true)
        } else {
            DecisionAnswer::Abstain
        }
    );
    assert_eq!(decision.probability, takes.then_some(0.9));
    assert_eq!(
        decision.human_ask,
        (!takes).then_some(HumanAskReason::Deadline)
    );
    assert_eq!(time(decision).stop, StopCause::Deadline);
    assert_eq!(
        time(decision).answered,
        takes.then_some(DecisionRung::SystemOne)
    );
    let queued = ladder.queue.asks();
    assert_eq!(queued.len(), usize::from(asks));
    if let Some(ask) = queued.first() {
        assert_eq!(ask.reason, HumanAskReason::Deadline);
        let prior = ask.prior.as_ref().expect("the held answer is the prior");
        assert_eq!(
            (&prior.answer, prior.probability),
            (&DecisionAnswer::Noul(true), Some(0.9))
        );
        assert_eq!(ask.prior_provider, Some(pin(DecisionRung::SystemOne)));
    }
    let rungs: Vec<_> = decision.receipt.providers.iter().map(|p| p.rung).collect();
    let expected = if asks {
        vec![DecisionRung::SystemOne, DecisionRung::Human]
    } else {
        vec![DecisionRung::SystemOne]
    };
    assert_eq!(rungs, expected);
}

#[test]
fn with_no_work_time_left_no_read_starts_and_the_call_abstains() {
    for taken_early in [false, true] {
        for (reversibility, ceiling) in STEPS {
            let q = question();
            let ladder = Ladder::new(
                Rung::new(
                    DecisionRung::SystemOne,
                    ms(0),
                    Some(answer(true, 0.9, None)),
                ),
                Rung::new(
                    DecisionRung::Escalation,
                    ms(0),
                    Some(answer(true, 0.9, None)),
                ),
            );
            let deadline = clock();
            if taken_early {
                deadline.cancel();
            } else {
                deadline.spend_for_test(WORK);
            }
            let decision = ladder
                .run(
                    &q,
                    &policy(&q, None, false),
                    ceiling,
                    reversibility,
                    &deadline,
                )
                .expect("a cut is an outcome, not an error");
            assert!(ladder.first.reads().is_empty());
            assert_eq!(decision.answer, DecisionAnswer::Abstain);
            assert_eq!(decision.probability, None);
            assert_eq!(decision.human_ask, Some(HumanAskReason::Deadline));
            let queued = ladder.queue.asks();
            if ceiling == DecisionRung::Human {
                assert_eq!(queued.len(), 1);
                assert_eq!(queued[0].reason, HumanAskReason::Deadline);
                assert!(queued[0].prior.is_none());
                assert_eq!(decision.receipt.providers, vec![pin(DecisionRung::Human)]);
            } else {
                assert!(queued.is_empty());
                assert!(decision.receipt.providers.is_empty());
            }
            assert_eq!(
                time(&decision),
                DecisionTime {
                    budget_ms: 1000,
                    used_ms: if taken_early { 0 } else { 750 },
                    stop: StopCause::Deadline,
                    answered: None,
                    reasoning: Reasoning::NotNeeded,
                }
            );
        }
    }
    // A cut never changes provenance: a provenance question is refused before any read or ask.
    let mut q = question();
    q.class = DecisionClass::Provenance;
    let ladder = Ladder::new(
        Rung::new(
            DecisionRung::SystemOne,
            ms(0),
            Some(answer(true, 0.9, None)),
        ),
        Rung::new(DecisionRung::Escalation, ms(0), None),
    );
    let deadline = clock();
    deadline.spend_for_test(WORK);
    assert!(
        ladder
            .run(
                &q,
                &DecisionBandPolicy::default(),
                DecisionRung::Human,
                Reversibility::OutboundEffect,
                &deadline,
            )
            .is_err()
    );
    assert!(ladder.queue.asks().is_empty());
}

#[test]
fn a_stronger_rung_starts_only_for_a_cause_and_on_the_same_clock() {
    let cases = [
        // A paired reading at the think row steps up.
        (
            answer(true, 0.9, Some(0.8)),
            Some(0.7),
            false,
            Reasoning::Ran(ReasoningCause::PairedHigh),
        ),
        // A small margin under an enforced band steps up.
        (
            answer(true, 0.5, None),
            None,
            true,
            Reasoning::Ran(ReasoningCause::SmallMargin),
        ),
        // A clear answer with a low paired reading stands.
        (
            answer(true, 0.9, Some(0.2)),
            Some(0.7),
            false,
            Reasoning::NotNeeded,
        ),
        // With no think row a paired reading never steps.
        (
            answer(true, 0.9, Some(0.99)),
            None,
            false,
            Reasoning::NotNeeded,
        ),
        // A small margin in a shadow band stands.
        (answer(true, 0.5, None), None, false, Reasoning::NotNeeded),
    ];
    for (first, think, enforce, reasoning) in cases {
        let q = question();
        let ladder = Ladder::new(
            Rung::new(DecisionRung::SystemOne, ms(200), Some(first.clone())),
            Rung::new(
                DecisionRung::Escalation,
                ms(100),
                Some(answer(false, 0.95, Some(0.1))),
            ),
        );
        let decision = ladder
            .run(
                &q,
                &policy(&q, think, enforce),
                DecisionRung::Big,
                Reversibility::ReversibleRead,
                &clock(),
            )
            .expect("the call runs");
        let stepped = reasoning != Reasoning::NotNeeded;
        // One clock: the stronger rung sees the work time the first left, never a fresh budget.
        assert_eq!(ladder.first.reads(), vec![WORK]);
        let stronger: Vec<_> = stepped.then_some(WORK - ms(200)).into_iter().collect();
        assert_eq!(ladder.stronger.reads(), stronger);
        assert_eq!(
            time(&decision),
            DecisionTime {
                budget_ms: 1000,
                used_ms: if stepped { 300 } else { 200 },
                stop: StopCause::Done,
                answered: Some(if stepped {
                    DecisionRung::Escalation
                } else {
                    DecisionRung::SystemOne
                }),
                reasoning,
            }
        );
        let expected = if stepped {
            DecisionAnswer::Noul(false)
        } else {
            first.answer.clone()
        };
        assert_eq!(decision.answer, expected);
        // Every read's paired reading is on the receipt, bound to the rung that took it.
        let paired: Vec<_> = decision
            .receipt
            .paired
            .iter()
            .map(|reading| (reading.provider.rung, reading.probability))
            .collect();
        let expected: Vec<_> = first
            .paired
            .map(|reading| (DecisionRung::SystemOne, reading.probability))
            .into_iter()
            .chain(stepped.then_some((DecisionRung::Escalation, 0.1)))
            .collect();
        assert_eq!(paired, expected);
    }

    // A rung that abstains answered nothing: the receipt names no answering rung.
    let q = question();
    let abstains = ProviderDecision {
        answer: DecisionAnswer::Abstain,
        probability: None,
        paired: None,
        person: None,
    };
    let ladder = Ladder::new(
        Rung::new(DecisionRung::SystemOne, ms(200), Some(abstains)),
        Rung::new(DecisionRung::Escalation, ms(100), None),
    );
    let decision = ladder
        .run(
            &q,
            &policy(&q, None, false),
            DecisionRung::Big,
            Reversibility::ReversibleRead,
            &clock(),
        )
        .expect("the call runs");
    assert_eq!(decision.answer, DecisionAnswer::Abstain);
    assert_eq!(
        (time(&decision).stop, time(&decision).answered),
        (StopCause::Done, None)
    );
}

#[test]
fn a_reply_after_the_cut_is_never_taken_and_only_a_reversible_step_keeps_its_answer() {
    // The stronger rung replies after the answer is due, or fails once the work time is spent.
    let late = [
        (ms(950), Some(answer(false, 0.95, Some(0.1)))),
        (ms(700), None),
    ];
    for (spend, reply) in late {
        for (reversibility, ceiling) in STEPS {
            let q = question();
            let ladder = Ladder::new(
                Rung::new(
                    DecisionRung::SystemOne,
                    ms(100),
                    Some(answer(true, 0.9, Some(0.8))),
                ),
                Rung::new(DecisionRung::Escalation, spend, reply.clone()),
            );
            let decision = ladder
                .run(
                    &q,
                    &policy(&q, Some(0.7), false),
                    ceiling,
                    reversibility,
                    &clock(),
                )
                .expect("a cut is an outcome, not an error");
            assert_eq!(ladder.stronger.reads().len(), 1);
            assert_cut_rule(&ladder, &decision, reversibility, ceiling);
            assert_eq!(
                time(&decision).reasoning,
                Reasoning::Cut(ReasoningCause::PairedHigh)
            );
            assert_eq!(u128::from(time(&decision).used_ms), 100 + spend.as_millis());
            // The late read leaves nothing on the receipt; the held answer's reading stays.
            let paired: Vec<_> = decision
                .receipt
                .paired
                .iter()
                .map(|reading| (reading.provider.rung, reading.probability))
                .collect();
            assert_eq!(paired, vec![(DecisionRung::SystemOne, 0.8)]);
        }
    }

    // A failure with work time left still fails the call: the cut is not a fallback.
    let q = question();
    let ladder = Ladder::new(
        Rung::new(
            DecisionRung::SystemOne,
            ms(100),
            Some(answer(true, 0.9, Some(0.8))),
        ),
        Rung::new(DecisionRung::Escalation, ms(100), None),
    );
    assert!(
        ladder
            .run(
                &q,
                &policy(&q, Some(0.7), false),
                DecisionRung::Human,
                Reversibility::ReversibleRead,
                &clock(),
            )
            .is_err()
    );
    assert!(ladder.queue.asks().is_empty());

    // An answer inside its band is not eligible at the cut, even for a reversible step,
    // whether the band is enforced (a small margin steps up) or in shadow (a paired
    // reading at its row steps up).
    for (enforce, cause) in [
        (true, ReasoningCause::SmallMargin),
        (false, ReasoningCause::PairedHigh),
    ] {
        let q = question();
        let ladder = Ladder::new(
            Rung::new(
                DecisionRung::SystemOne,
                ms(100),
                Some(answer(true, 0.5, Some(0.8))),
            ),
            Rung::new(
                DecisionRung::Escalation,
                ms(950),
                Some(answer(true, 0.99, None)),
            ),
        );
        let decision = ladder
            .run(
                &q,
                &policy(&q, Some(0.7), enforce),
                DecisionRung::Big,
                Reversibility::ReversibleRead,
                &clock(),
            )
            .expect("a cut is an outcome, not an error");
        assert_eq!(decision.answer, DecisionAnswer::Abstain);
        assert_eq!(decision.probability, None);
        assert!(decision.in_band);
        assert_eq!(decision.human_ask, Some(HumanAskReason::Deadline));
        let cut = time(&decision);
        assert_eq!(
            (cut.stop, cut.answered, cut.reasoning),
            (StopCause::Deadline, None, Reasoning::Cut(cause))
        );
    }
}

#[test]
fn no_rung_starts_in_the_last_quarter_under_either_clock() {
    for raw in [false, true] {
        for (reversibility, ceiling) in STEPS {
            let q = question();
            // The first answer spends all the work time; its paired reading wants more.
            let ladder = Ladder::new(
                Rung::new(
                    DecisionRung::SystemOne,
                    WORK,
                    Some(answer(true, 0.9, Some(0.8))),
                ),
                Rung::new(
                    DecisionRung::Escalation,
                    ms(0),
                    Some(answer(false, 0.95, None)),
                ),
            );
            let deadline = if raw { raw_clock() } else { clock() };
            let decision = ladder
                .run(
                    &q,
                    &policy(&q, Some(0.7), false),
                    ceiling,
                    reversibility,
                    &deadline,
                )
                .expect("a cut is an outcome, not an error");
            assert!(ladder.stronger.reads().is_empty());
            assert_cut_rule(&ladder, &decision, reversibility, ceiling);
            assert_eq!(
                time(&decision).reasoning,
                Reasoning::Skipped(ReasoningCause::PairedHigh)
            );
        }
    }
    // With no stronger provider the step skips to the person, on the same clock: with
    // the work time spent it does not start, and the cut rule decides.
    for reversibility in [Reversibility::ReversibleRead, Reversibility::OutboundEffect] {
        let q = question();
        let ladder = Ladder::new(
            Rung::new(
                DecisionRung::SystemOne,
                WORK,
                Some(answer(true, 0.9, Some(0.8))),
            ),
            Rung::new(DecisionRung::Escalation, ms(0), None),
        );
        let decision = ladder
            .run_on(
                false,
                &q,
                &policy(&q, Some(0.7), false),
                DecisionRung::Human,
                reversibility,
                &clock(),
            )
            .expect("a cut is an outcome, not an error");
        assert_cut_rule(&ladder, &decision, reversibility, DecisionRung::Human);
        assert_eq!(
            time(&decision).reasoning,
            Reasoning::Skipped(ReasoningCause::PairedHigh)
        );
    }
}

/// A System One seat: each measurement spends its share of the call's clock, then replies or
/// its client gives up.
struct Seat<'c> {
    clock: &'c RetrievalDeadline,
    replies: Mutex<Vec<(Duration, Option<SeatAnswer>)>>,
    /// The work time left each measurement was given.
    seen: Mutex<Vec<Duration>>,
}

impl<'c> Seat<'c> {
    fn new(clock: &'c RetrievalDeadline, replies: Vec<(Duration, Option<SeatAnswer>)>) -> Self {
        Self {
            clock,
            replies: Mutex::new(replies),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn asks(&self) -> Vec<Duration> {
        self.seen.lock().expect("asks").clone()
    }
}

impl RemoteDecisionSeat for Seat<'_> {
    fn pin(&self) -> ProviderPin {
        pin(DecisionRung::SystemOne)
    }

    fn ask<'a>(
        &'a self,
        _: SeatRequest,
        _: &'a BudgetLease,
        time_left: Duration,
    ) -> SeatFuture<'a> {
        self.seen.lock().expect("asks").push(time_left);
        let (spend, reply) = self.replies.lock().expect("replies").remove(0);
        self.clock.spend_for_test(spend);
        Box::pin(std::future::ready(
            reply.ok_or(LlmError::Retryable(RetryableLlmError::Timeout)),
        ))
    }
}

/// A measurement that reports two units of usage.
fn measured(yes: bool, probability: f64) -> SeatAnswer {
    let mut usage = LlmUsage::zero();
    usage.input.total = 1;
    usage.output.total = 1;
    SeatAnswer {
        answer: DecisionAnswer::Noul(yes),
        probability,
        usage,
    }
}

fn guard() -> BudgetGuard {
    BudgetGuard::with_reserve_units(
        "decision-deadline",
        100,
        RESERVE,
        BudgetExhaustionPolicy::Suspend,
    )
}

/// One accept-type yes/no at the seat, polled once: the fakes reply at once.
fn at_seat(
    seat: &Seat<'_>,
    guard: &BudgetGuard,
    reversibility: Reversibility,
) -> LlmResult<TypedDecision> {
    let request = SeatRequest {
        question: DecisionQuestion {
            accept_type: true,
            ..question()
        },
        state: serde_json::json!({ "note": "bounded" }),
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
        DecisionDial {
            first: DecisionRung::Rule,
            ceiling: DecisionRung::SystemOne,
            band: DecisionBand::default(),
        },
        guard,
        reversibility,
        seat.clock,
    ));
    match call.poll(&mut std::task::Context::from_waker(std::task::Waker::noop())) {
        std::task::Poll::Ready(decision) => decision,
        std::task::Poll::Pending => panic!("the fake seat replies at once"),
    }
}

#[test]
fn the_seat_starts_no_measurement_without_time_and_a_failure_in_time_still_fails() {
    for taken_early in [false, true] {
        for reversibility in [Reversibility::ReversibleRead, Reversibility::OutboundEffect] {
            let deadline = clock();
            if taken_early {
                deadline.cancel();
            } else {
                deadline.spend_for_test(WORK);
            }
            let seat = Seat::new(&deadline, vec![(ms(0), Some(measured(true, 0.9)))]);
            let guard = guard();
            let decision = at_seat(&seat, &guard, reversibility).expect("a cut is an outcome");
            assert!(seat.asks().is_empty());
            assert_eq!(decision.answer, DecisionAnswer::Abstain);
            assert_eq!(decision.human_ask, Some(HumanAskReason::Deadline));
            assert!(decision.receipt.providers.is_empty());
            let time = time(&decision);
            assert_eq!(
                (time.stop, time.answered, time.reasoning),
                (StopCause::Deadline, None, Reasoning::NotNeeded)
            );
            // Nothing was admitted, so nothing is charged.
            assert_eq!(guard.read().used_units, 0);
        }
    }
    // A failure with work time left fails the call, and its lease is charged its reservation.
    let deadline = clock();
    let seat = Seat::new(&deadline, vec![(ms(100), None)]);
    let guard = guard();
    assert!(at_seat(&seat, &guard, Reversibility::ReversibleRead).is_err());
    assert_eq!(guard.read().used_units, RESERVE);
}

#[test]
fn the_second_measurement_shares_the_clock_and_a_cut_one_settles_its_spend() {
    let ran = Reasoning::Ran(ReasoningCause::SecondMeasurement);
    let skipped = Reasoning::Skipped(ReasoningCause::SecondMeasurement);
    let cut = Reasoning::Cut(ReasoningCause::SecondMeasurement);
    // (the first measurement's spend, the second's spend and reply, reasoning, units charged)
    let cases = [
        // It runs in time: the second confident negative stands.
        (
            ms(100),
            Some((ms(100), Some(measured(false, 0.05)))),
            ran,
            4,
        ),
        // The first spends the work time: the second does not start; the negative is unfinished.
        (WORK, None, skipped, 2),
        // Its client gives up at the time left; the provider may still bill, so the lease is
        // charged its reservation.
        (ms(100), Some((ms(650), None)), cut, 2 + RESERVE),
        // It replies after the answer is due: not an answer, charged the usage it reports.
        (
            ms(100),
            Some((ms(900), Some(measured(false, 0.05)))),
            cut,
            4,
        ),
    ];
    for (first, second, reasoning, units) in cases {
        for reversibility in [Reversibility::ReversibleRead, Reversibility::OutboundEffect] {
            let deadline = clock();
            let mut replies = vec![(first, Some(measured(false, 0.1)))];
            replies.extend(second.clone());
            let seat = Seat::new(&deadline, replies);
            let guard = guard();
            let decision = at_seat(&seat, &guard, reversibility).expect("a cut is an outcome");
            let finished = reasoning == ran;
            // At the cut a reversible step takes the unfinished negative; an irreversible one
            // never does.
            let takes = finished || reversibility == Reversibility::ReversibleRead;
            assert_eq!(
                decision.answer,
                if takes {
                    DecisionAnswer::Noul(false)
                } else {
                    DecisionAnswer::Abstain
                }
            );
            assert_eq!(
                decision.probability,
                takes.then_some(if finished { 0.05 } else { 0.1 })
            );
            assert_eq!(
                decision.human_ask,
                (!takes).then_some(HumanAskReason::Deadline)
            );
            let time = time(&decision);
            let stop = if finished {
                StopCause::Done
            } else {
                StopCause::Deadline
            };
            assert_eq!(
                (time.stop, time.answered, time.reasoning),
                (stop, takes.then_some(DecisionRung::SystemOne), reasoning)
            );
            // One clock: the second measurement is given the work time the first left.
            let given: Vec<_> = std::iter::once(WORK)
                .chain(second.as_ref().map(|_| WORK - first))
                .collect();
            assert_eq!(seat.asks(), given);
            // The receipt lists every measurement the call paid for.
            assert_eq!(decision.receipt.providers.len(), given.len());
            let budget = guard.read();
            assert_eq!((budget.used_units, budget.reserved_units), (units, 0));
        }
    }
}
