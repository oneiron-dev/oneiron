use super::*;
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
