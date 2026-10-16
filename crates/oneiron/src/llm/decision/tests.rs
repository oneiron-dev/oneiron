use super::*;
use crate::llm::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, LabelReadModel, LabelReadRequest,
    LabelReadResponse, LabelSet, LlmResult, LlmUsage,
};
use crate::{EntityId, Result};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

fn question(class: DecisionClass) -> DecisionQuestion {
    DecisionQuestion {
        id: EntityId::now(),
        version: 1,
        text: "Does this fit the task and trace?".into(),
        class,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}
fn yes(p: f64) -> ProviderDecision {
    ProviderDecision {
        answer: DecisionAnswer::Noul(true),
        probability: Some(p),
        paired: None,
        person: None,
    }
}
fn pin(rung: DecisionRung, version: &str) -> ProviderPin {
    ProviderPin {
        rung,
        model: format!("test-{rung:?}"),
        version: version.into(),
    }
}
struct Scripted {
    pin: ProviderPin,
    result: ProviderDecision,
    calls: AtomicUsize,
}
impl DecisionProvider for Scripted {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }
    fn decide(&self, _: &DecisionQuestion, _: &[EntityId]) -> Result<ProviderDecision> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.result.clone())
    }
}
#[derive(Default)]
struct Queue(Mutex<Vec<HumanDecisionRequest>>);
impl HumanDecisionQueue for Queue {
    fn queue(&self, request: HumanDecisionRequest) -> Result<()> {
        self.0.lock().unwrap().push(request);
        Ok(())
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
fn provenance_and_invalid_provider_output_fail_before_queue_or_receipt() {
    let q = question(DecisionClass::Provenance);
    let rule = Scripted {
        pin: pin(DecisionRung::Rule, "v1"),
        result: yes(0.5),
        calls: AtomicUsize::new(0),
    };
    let queue = Queue::default();
    let ladder = DecisionLadder {
        rule: Some(&rule),
        local: None,
        system_one: None,
        escalation: None,
        big: None,
        human: &queue,
        human_pin: pin(DecisionRung::Human, "q1"),
    };
    assert!(
        ladder
            .run(
                &q,
                EntityId::now(),
                &[],
                dial(DecisionRung::Rule, DecisionRung::Human),
                &DecisionBandPolicy::default(),
                Reversibility::OutboundEffect
            )
            .is_err()
    );
    assert_eq!(rule.calls.load(Ordering::SeqCst), 0);
    assert!(queue.0.lock().unwrap().is_empty());
    let mut q = q;
    q.class = DecisionClass::Judgment;
    let bad = Scripted {
        pin: pin(DecisionRung::Rule, "v1"),
        result: yes(f64::NAN),
        calls: AtomicUsize::new(0),
    };
    let ladder = DecisionLadder {
        rule: Some(&bad),
        ..ladder
    };
    assert!(
        ladder
            .run(
                &q,
                EntityId::now(),
                &[],
                dial(DecisionRung::Rule, DecisionRung::Human),
                &DecisionBandPolicy::default(),
                Reversibility::OutboundEffect
            )
            .is_err()
    );
    assert!(queue.0.lock().unwrap().is_empty());
}

/// Primary text, primary labels, paired text and person text of one read.
type Seen = (String, Vec<String>, String, Option<String>);

struct Reader {
    revision: String,
    primary: Vec<f64>,
    paired_yes: f64,
    person_yes: Option<f64>,
    seen: Mutex<Vec<Seen>>,
}
impl Reader {
    fn new(primary: Vec<f64>, paired_yes: f64) -> Self {
        Self {
            revision: "r1".into(),
            primary,
            paired_yes,
            person_yes: None,
            seen: Mutex::default(),
        }
    }
}
impl LabelReadModel for Reader {
    fn model(&self) -> &str {
        "test-Escalation"
    }
    fn revision(&self) -> &str {
        &self.revision
    }
    fn read(
        &self,
        request: &LabelReadRequest<'_>,
        _: &BudgetLease,
    ) -> LlmResult<LabelReadResponse> {
        let labels = match request.primary.labels {
            LabelSet::Noul => vec!["yes".into(), "no".into()],
            LabelSet::Choice(options) => options.to_vec(),
        };
        self.seen.lock().unwrap().push((
            request.primary.text.to_owned(),
            labels,
            request.paired.to_owned(),
            request.person.map(str::to_owned),
        ));
        let mut usage = LlmUsage::zero();
        usage.input.total = 3;
        Ok(LabelReadResponse {
            primary: self.primary.clone(),
            paired_yes: self.paired_yes,
            person_yes: self.person_yes,
            usage,
        })
    }
}
fn choice_question() -> DecisionQuestion {
    DecisionQuestion {
        contract: AnswerContract::Choice {
            options: vec!["keep".into(), "merge".into(), "split".into()],
        },
        ..question(DecisionClass::Judgment)
    }
}
fn paired_question() -> DecisionQuestion {
    DecisionQuestion {
        version: 3,
        text: "Does this need more thinking?".into(),
        ..question(DecisionClass::Judgment)
    }
}
fn read_guard(limit: u64) -> BudgetGuard {
    BudgetGuard::with_reserve_units("read-test", limit, 4, BudgetExhaustionPolicy::Suspend)
}

/// PR B1 acceptance: an in-band System One answer under an enforced band steps to the
/// escalation rung, whose house-model read answers from the question's own labels and
/// records the paired reading on the receipt, bound to the escalation pin.
#[test]
fn enforced_band_escalates_to_the_house_read_and_records_its_paired_reading() {
    let q = choice_question();
    let paired = paired_question();
    let mut policy = DecisionBandPolicy::default();
    policy
        .learn_shadow(
            &q,
            Reversibility::ReversibleRead,
            DecisionBand::default(),
            1,
        )
        .unwrap();
    policy.enforce(&q, Reversibility::ReversibleRead).unwrap();
    let system_one = Scripted {
        pin: pin(DecisionRung::SystemOne, "s1"),
        result: ProviderDecision {
            answer: DecisionAnswer::Choice("merge".into()),
            probability: Some(0.5),
            paired: None,
            person: None,
        },
        calls: AtomicUsize::new(0),
    };
    let big = Scripted {
        pin: pin(DecisionRung::Big, "b1"),
        result: yes(0.9),
        calls: AtomicUsize::new(0),
    };
    let reader = Reader::new(vec![0.1, 0.2, 0.7], 0.8);
    let guard = read_guard(100);
    let evidence = vec![EntityId::now()];
    let state = serde_json::json!({"unit": "bounded"});
    let call = DecisionReadCall {
        question: &q,
        evidence: &evidence,
        state: &state,
    };
    let escalation = DecisionReadProvider::new(
        pin(DecisionRung::Escalation, "r1"),
        &reader,
        &guard,
        &paired,
        call,
    )
    .unwrap();
    let queue = Queue::default();
    let ladder = DecisionLadder {
        rule: None,
        local: None,
        system_one: Some(&system_one),
        escalation: Some(&escalation),
        big: Some(&big),
        human: &queue,
        human_pin: pin(DecisionRung::Human, "q1"),
    };
    let run = |ladder: &DecisionLadder<'_>| {
        ladder.run(
            &q,
            EntityId::now(),
            &evidence,
            dial(DecisionRung::SystemOne, DecisionRung::Big),
            &policy,
            Reversibility::ReversibleRead,
        )
    };
    let decision = run(&ladder).unwrap();

    assert_eq!(decision.answer, DecisionAnswer::Choice("split".into()));
    assert_eq!(decision.probability, Some(0.7));
    assert!(decision.in_band);
    assert_eq!(
        decision.receipt.providers,
        vec![
            pin(DecisionRung::SystemOne, "s1"),
            pin(DecisionRung::Escalation, "r1")
        ]
    );
    assert_eq!(
        decision.receipt.paired,
        vec![PairedReading {
            provider: pin(DecisionRung::Escalation, "r1"),
            question: paired.id,
            question_version: 3,
            probability: 0.8,
        }]
    );
    assert_eq!(big.calls.load(Ordering::SeqCst), 0);
    // One read over the question's own three labels; the paired question is no option.
    let labels: Vec<String> = vec!["keep".into(), "merge".into(), "split".into()];
    assert_eq!(
        *reader.seen.lock().unwrap(),
        vec![(q.text.clone(), labels, paired.text.clone(), None)]
    );
    let budget = guard.read();
    assert!(budget.used_units > 0);
    assert_eq!(budget.reserved_units, 0);

    // A ladder without the escalation slot fails; it never skips to the big model.
    let without = DecisionLadder {
        escalation: None,
        ..ladder
    };
    assert!(run(&without).is_err());
    assert_eq!(big.calls.load(Ordering::SeqCst), 0);
    assert!(queue.0.lock().unwrap().is_empty());
}

/// Q3 acceptance (owner ruling 10-16): when the read's P(ask a person) reaches the owner's
/// threshold row, the decision goes to the person rung at the start, carrying the read as its
/// prior. Below the row, with no row, or on a surface whose dial stops short of the person
/// rung, the answer stands as before. The person reading is on every receipt either way.
#[test]
fn person_reading_at_the_threshold_routes_to_the_person_rung_at_the_start() {
    let q = choice_question();
    let paired = paired_question();
    let person = DecisionQuestion {
        version: 2,
        text: "Should a person decide this?".into(),
        ..question(DecisionClass::Judgment)
    };
    let reader = Reader {
        person_yes: Some(0.97),
        ..Reader::new(vec![0.1, 0.2, 0.7], 0.3)
    };
    let guard = read_guard(100);
    let evidence = vec![EntityId::now()];
    let state = serde_json::json!({"unit": "bounded"});
    let call = DecisionReadCall {
        question: &q,
        evidence: &evidence,
        state: &state,
    };
    let provider = || {
        DecisionReadProvider::new(
            pin(DecisionRung::Escalation, "r1"),
            &reader,
            &guard,
            &paired,
            call,
        )
        .unwrap()
    };
    // The person question is neither the answered nor the paired question.
    assert!(provider().with_person(&paired).is_err());
    assert!(provider().with_person(&q).is_err());
    let escalation = provider().with_person(&person).unwrap();
    let queue = Queue::default();
    let ladder = DecisionLadder {
        rule: None,
        local: None,
        system_one: None,
        escalation: Some(&escalation),
        big: None,
        human: &queue,
        human_pin: pin(DecisionRung::Human, "q1"),
    };
    let run = |ceiling: DecisionRung, policy: &DecisionBandPolicy| {
        ladder
            .run(
                &q,
                EntityId::now(),
                &evidence,
                dial(DecisionRung::Escalation, ceiling),
                policy,
                Reversibility::ReversibleRead,
            )
            .unwrap()
    };
    let person_row = PairedReading {
        provider: pin(DecisionRung::Escalation, "r1"),
        question: person.id,
        question_version: 2,
        probability: 0.97,
    };
    let mut policy = DecisionBandPolicy::default();
    policy.set_person_threshold(0.95, 1).unwrap();

    let asked = run(DecisionRung::Human, &policy);
    assert_eq!(asked.answer, DecisionAnswer::Abstain);
    assert_eq!(asked.human_ask, Some(HumanAskReason::NeedsPerson));
    assert_eq!(
        asked.receipt.providers,
        vec![
            pin(DecisionRung::Escalation, "r1"),
            pin(DecisionRung::Human, "q1")
        ]
    );
    assert_eq!(asked.receipt.person, vec![person_row.clone()]);
    assert_eq!(asked.receipt.paired.len(), 1);
    {
        let queued = queue.0.lock().unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].reason, HumanAskReason::NeedsPerson);
        let prior = queued[0].prior.as_ref().unwrap();
        assert_eq!(prior.answer, DecisionAnswer::Choice("split".into()));
        // The person picks another option: the typed record carries the read that asked.
        let changed = queued[0]
            .changed_by(DecisionAnswer::Choice("keep".into()))
            .unwrap()
            .unwrap();
        assert_eq!(changed.reason, HumanAskReason::NeedsPerson);
        assert_eq!(changed.prior, DecisionAnswer::Choice("split".into()));
        assert_eq!(changed.prior_probability, Some(0.7));
        assert_eq!(changed.person, DecisionAnswer::Choice("keep".into()));
        assert_eq!(changed.person_reading, Some(0.97));
        assert_eq!(changed.paired_reading, Some(0.3));
        // The same answer changes nothing; an answer outside the labels is refused.
        let same = DecisionAnswer::Choice("split".into());
        assert_eq!(queued[0].changed_by(same).unwrap(), None);
        let outside = DecisionAnswer::Choice("nope".into());
        assert!(queued[0].changed_by(outside).is_err());
    }
    assert_eq!(
        reader.seen.lock().unwrap()[0].3.as_deref(),
        Some(person.text.as_str())
    );

    // A surface without a person rung, a row above the reading, and no row at all keep the
    // read's own answer, and still record the reading.
    let mut above = DecisionBandPolicy::default();
    above.set_person_threshold(0.99, 1).unwrap();
    for (ceiling, policy) in [
        (DecisionRung::Big, &policy),
        (DecisionRung::Human, &above),
        (DecisionRung::Human, &DecisionBandPolicy::default()),
    ] {
        let decision = run(ceiling, policy);
        assert_eq!(decision.answer, DecisionAnswer::Choice("split".into()));
        assert_eq!(decision.human_ask, None);
        assert_eq!(decision.receipt.person, vec![person_row.clone()]);
    }
    assert_eq!(queue.0.lock().unwrap().len(), 1);

    // The row only moves forward, and a read that drops the asked reading is refused,
    // never taken as P(yes) = 0.
    assert!(policy.set_person_threshold(0.9, 1).is_err());
    let silent = Reader::new(vec![0.1, 0.2, 0.7], 0.3);
    let dropped = DecisionReadProvider::new(
        pin(DecisionRung::Escalation, "r1"),
        &silent,
        &guard,
        &paired,
        call,
    )
    .unwrap()
    .with_person(&person)
    .unwrap();
    assert!(dropped.decide(&q, &evidence).is_err());
}

#[test]
fn decision_read_refuses_another_model_a_malformed_read_and_a_refused_budget() {
    let q = choice_question();
    let paired = paired_question();
    let evidence = vec![EntityId::now()];
    let state = serde_json::json!({"unit": "bounded"});
    let call = DecisionReadCall {
        question: &q,
        evidence: &evidence,
        state: &state,
    };
    let guard = read_guard(100);
    let reader = Reader::new(vec![0.1, 0.2, 0.7], 0.8);

    // The route bound another revision, or another rung.
    for bound in [
        pin(DecisionRung::Escalation, "r2"),
        pin(DecisionRung::SystemOne, "r1"),
    ] {
        assert!(DecisionReadProvider::new(bound, &reader, &guard, &paired, call).is_err());
    }

    let decide = |reader: &Reader, guard: &BudgetGuard| {
        DecisionReadProvider::new(
            pin(DecisionRung::Escalation, "r1"),
            reader,
            guard,
            &paired,
            call,
        )
        .unwrap()
        .decide(&q, &evidence)
    };
    // A paired reading outside [0, 1], a missing label, or labels that are no distribution.
    for (primary, paired_yes) in [
        (vec![0.1, 0.2, 0.7], f64::NAN),
        (vec![0.1, 0.2, 0.7], 1.5),
        (vec![0.3, 0.7], 0.8),
        (vec![0.3, 0.3, 0.3], 0.8),
    ] {
        assert!(decide(&Reader::new(primary, paired_yes), &guard).is_err());
    }

    // A refused admission never reaches the reader.
    let empty = read_guard(0);
    assert!(decide(&reader, &empty).is_err());
    assert!(reader.seen.lock().unwrap().is_empty());
}
