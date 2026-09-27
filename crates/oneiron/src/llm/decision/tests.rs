use super::*;
use crate::{EntityId, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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
fn rule_answers_offline_with_versioned_receipt_and_no_model_call() {
    let q = question(DecisionClass::Judgment);
    let mut rule = RuleDecisionProvider::new("offline-rules".into(), "rules@3".into()).unwrap();
    rule.insert(&q, yes(0.9)).unwrap();
    let model = Scripted {
        pin: pin(DecisionRung::Local, "model@7"),
        result: yes(0.9),
        calls: AtomicUsize::new(0),
    };
    let queue = Queue::default();
    let ladder = DecisionLadder {
        rule: Some(&rule),
        local: Some(&model),
        jev: None,
        big: None,
        human: &queue,
        human_pin: pin(DecisionRung::Human, "queue@2"),
    };
    let principal = EntityId::now();
    let evidence = [EntityId::now()];
    let result = ladder
        .run(
            &q,
            principal,
            &evidence,
            dial(DecisionRung::Rule, DecisionRung::Big),
            &DecisionBandPolicy::default(),
            Reversibility::ReversibleRead,
        )
        .unwrap();
    assert_eq!(result.answer, DecisionAnswer::Noul(true));
    assert_eq!(result.receipt.question_version, 1);
    assert_eq!(result.receipt.principal, principal);
    assert_eq!(result.receipt.providers, vec![rule.pin()]);
    assert_eq!(result.evidence, evidence);
    assert_eq!(result.receipt.band_version, 0);
    assert_eq!(model.calls.load(Ordering::SeqCst), 0);
    assert!(queue.0.lock().unwrap().is_empty());
}

#[test]
fn paired_read_and_send_same_probability_shadow_then_enforce_only_send() {
    let q = question(DecisionClass::Judgment);
    let rule = Scripted {
        pin: pin(DecisionRung::Rule, "r1"),
        result: yes(0.5),
        calls: AtomicUsize::new(0),
    };
    let local = Scripted {
        pin: pin(DecisionRung::Local, "l2"),
        result: yes(0.55),
        calls: AtomicUsize::new(0),
    };
    let jev = Scripted {
        pin: pin(DecisionRung::SystemOne, "j4"),
        result: yes(0.7),
        calls: AtomicUsize::new(0),
    };
    let queue = Queue::default();
    let ladder = DecisionLadder {
        rule: Some(&rule),
        local: Some(&local),
        jev: Some(&jev),
        big: None,
        human: &queue,
        human_pin: pin(DecisionRung::Human, "h1"),
    };
    let mut policy = DecisionBandPolicy::default();
    let read_band = DecisionBand {
        low: 0.1,
        high: 0.3,
    };
    let send_band = DecisionBand {
        low: 0.45,
        high: 0.6,
    };
    policy
        .learn_shadow(&q, Reversibility::ReversibleRead, read_band, 4)
        .unwrap();
    policy
        .learn_shadow(&q, Reversibility::OutboundEffect, send_band, 7)
        .unwrap();
    let principal = EntityId::now();
    let d = dial(DecisionRung::Rule, DecisionRung::Big);
    let shadow = ladder
        .run(
            &q,
            principal,
            &[],
            d,
            &policy,
            Reversibility::OutboundEffect,
        )
        .unwrap();
    assert!(shadow.in_band);
    assert_eq!(shadow.receipt.providers.len(), 1);
    assert_eq!(shadow.receipt.band_version, 7);
    assert_eq!(local.calls.load(Ordering::SeqCst), 0);
    assert!(
        policy
            .enforce(
                &question(DecisionClass::Judgment),
                Reversibility::OutboundEffect
            )
            .is_err()
    );
    policy.enforce(&q, Reversibility::ReversibleRead).unwrap();
    policy.enforce(&q, Reversibility::OutboundEffect).unwrap();
    let read = ladder
        .run(
            &q,
            principal,
            &[],
            d,
            &policy,
            Reversibility::ReversibleRead,
        )
        .unwrap();
    let send = ladder
        .run(
            &q,
            principal,
            &[],
            d,
            &policy,
            Reversibility::OutboundEffect,
        )
        .unwrap();
    assert!(!read.in_band);
    assert_eq!(read.receipt.providers.len(), 1);
    assert_eq!(read.receipt.band, read_band);
    assert!(send.in_band);
    assert_eq!(send.receipt.providers, vec![rule.pin(), local.pin()]);
    assert_eq!(send.receipt.band, send_band);
    assert_eq!(send.receipt.band_version, 7);
    assert_eq!(local.calls.load(Ordering::SeqCst), 1);
    assert_eq!(jev.calls.load(Ordering::SeqCst), 0); // no second climb
}

#[test]
fn human_rung_queues_question_explanation_and_prior_without_granting() {
    let q = question(DecisionClass::Judgment);
    let big = Scripted {
        pin: pin(DecisionRung::Big, "b9"),
        result: yes(0.5),
        calls: AtomicUsize::new(0),
    };
    let queue = Queue::default();
    let ladder = DecisionLadder {
        rule: None,
        local: None,
        jev: None,
        big: Some(&big),
        human: &queue,
        human_pin: pin(DecisionRung::Human, "q8"),
    };
    let mut policy = DecisionBandPolicy::default();
    policy
        .learn_shadow(
            &q,
            Reversibility::OutboundEffect,
            DecisionBand::default(),
            1,
        )
        .unwrap();
    policy.enforce(&q, Reversibility::OutboundEffect).unwrap();
    let principal = EntityId::now();
    let result = ladder
        .run(
            &q,
            principal,
            &[],
            dial(DecisionRung::Big, DecisionRung::Human),
            &policy,
            Reversibility::OutboundEffect,
        )
        .unwrap();
    assert_eq!(result.answer, DecisionAnswer::Abstain);
    assert_eq!(result.probability, None);
    assert_eq!(result.human_ask, Some(HumanAskReason::Uncertain));
    assert_eq!(result.receipt.providers, vec![big.pin(), ladder.human_pin]);
    let queued = queue.0.lock().unwrap();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].question.text, q.text);
    assert_eq!(queued[0].principal, principal);
    assert_eq!(queued[0].reason, HumanAskReason::Uncertain);
    assert_eq!(queued[0].prior, Some(yes(0.5)));
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
        jev: None,
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

struct FixedModel;
impl DecisionModel for FixedModel {
    fn decide(&self, _: &DecisionQuestion, _: &[EntityId]) -> Result<ProviderDecision> {
        Ok(yes(0.8))
    }
}
#[test]
fn model_adapters_restrict_rungs_and_missing_next_rung_fails_closed() {
    let model = Arc::new(FixedModel);
    for rung in [
        DecisionRung::Local,
        DecisionRung::SystemOne,
        DecisionRung::Big,
    ] {
        let adapter = ModelDecisionProvider::new(pin(rung, "revision-2"), model.clone()).unwrap();
        assert_eq!(adapter.pin().rung, rung);
    }
    assert!(ModelDecisionProvider::new(pin(DecisionRung::Human, "v1"), model).is_err());
    let q = question(DecisionClass::Judgment);
    let rule = Scripted {
        pin: pin(DecisionRung::Rule, "v1"),
        result: yes(0.5),
        calls: AtomicUsize::new(0),
    };
    let queue = Queue::default();
    let ladder = DecisionLadder {
        rule: Some(&rule),
        local: None,
        jev: None,
        big: None,
        human: &queue,
        human_pin: pin(DecisionRung::Human, "q1"),
    };
    let mut policy = DecisionBandPolicy::default();
    assert!(policy.enforce(&q, Reversibility::ReversibleRead).is_err());
    policy
        .learn_shadow(
            &q,
            Reversibility::ReversibleRead,
            DecisionBand::default(),
            1,
        )
        .unwrap();
    policy.enforce(&q, Reversibility::ReversibleRead).unwrap();
    assert!(
        ladder
            .run(
                &q,
                EntityId::now(),
                &[],
                dial(DecisionRung::Rule, DecisionRung::Human),
                &policy,
                Reversibility::ReversibleRead
            )
            .is_err()
    );
    assert!(queue.0.lock().unwrap().is_empty());
}

#[test]
fn intermediate_rungs_climb_exactly_once_at_inclusive_band_edges() {
    let q = question(DecisionClass::Judgment);
    let local = Scripted {
        pin: pin(DecisionRung::Local, "local@2"),
        result: yes(0.35),
        calls: AtomicUsize::new(0),
    };
    let jev = Scripted {
        pin: pin(DecisionRung::SystemOne, "jev@4"),
        result: yes(0.65),
        calls: AtomicUsize::new(0),
    };
    let big = Scripted {
        pin: pin(DecisionRung::Big, "big@6"),
        result: yes(0.95),
        calls: AtomicUsize::new(0),
    };
    let queue = Queue::default();
    let ladder = DecisionLadder {
        rule: None,
        local: Some(&local),
        jev: Some(&jev),
        big: Some(&big),
        human: &queue,
        human_pin: pin(DecisionRung::Human, "queue@1"),
    };
    let mut policy = DecisionBandPolicy::default();
    policy
        .learn_shadow(
            &q,
            Reversibility::ReversibleRead,
            DecisionBand::default(),
            2,
        )
        .unwrap();
    policy.enforce(&q, Reversibility::ReversibleRead).unwrap();
    let principal = EntityId::now();
    let local_first = ladder
        .run(
            &q,
            principal,
            &[],
            dial(DecisionRung::Local, DecisionRung::Big),
            &policy,
            Reversibility::ReversibleRead,
        )
        .unwrap();
    assert!(local_first.in_band);
    assert_eq!(local_first.receipt.providers, vec![local.pin(), jev.pin()]);
    assert_eq!(big.calls.load(Ordering::SeqCst), 0);
    let jev_first = ladder
        .run(
            &q,
            principal,
            &[],
            dial(DecisionRung::SystemOne, DecisionRung::Big),
            &policy,
            Reversibility::ReversibleRead,
        )
        .unwrap();
    assert!(jev_first.in_band);
    assert_eq!(jev_first.receipt.providers, vec![jev.pin(), big.pin()]);
    assert_eq!(big.calls.load(Ordering::SeqCst), 1);
    assert!(queue.0.lock().unwrap().is_empty());
}

#[test]
fn human_first_queues_owner_selected_without_model_output() {
    let q = question(DecisionClass::Judgment);
    let queue = Queue::default();
    let ladder = DecisionLadder {
        rule: None,
        local: None,
        jev: None,
        big: None,
        human: &queue,
        human_pin: pin(DecisionRung::Human, "queue@3"),
    };
    let decision = ladder
        .run(
            &q,
            EntityId::now(),
            &[],
            dial(DecisionRung::Human, DecisionRung::Human),
            &DecisionBandPolicy::default(),
            Reversibility::OutboundEffect,
        )
        .unwrap();
    assert_eq!(decision.answer, DecisionAnswer::Abstain);
    assert_eq!(decision.human_ask, Some(HumanAskReason::OwnerSelected));
    assert_eq!(decision.receipt.providers, vec![ladder.human_pin]);
    let requests = queue.0.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].reason, HumanAskReason::OwnerSelected);
    assert_eq!(requests[0].prior, None);
}
