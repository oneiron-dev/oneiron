use super::*;
use crate::llm::decision::{DecisionBand, DecisionClass};
use crate::{BudgetExhaustionPolicy, RetryableLlmError};
use std::sync::Mutex;

struct Stub {
    answers: Mutex<Vec<LlmResult<SeatAnswer>>>,
    leases: Mutex<Vec<String>>,
}
impl Stub {
    fn new(answers: Vec<LlmResult<SeatAnswer>>) -> Self {
        Self {
            answers: Mutex::new(answers),
            leases: Mutex::new(Vec::new()),
        }
    }
}
impl DecisionSeat for Stub {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::SystemOne,
            model: "jev".into(),
            version: "1.13.0".into(),
        }
    }
    fn ask<'a>(&'a self, _request: SeatRequest, lease: &'a BudgetLease) -> SeatFuture<'a> {
        Box::pin(async move {
            self.leases.lock().unwrap().push(lease.id().to_owned());
            self.answers.lock().unwrap().remove(0)
        })
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    let mut f = Box::pin(f);
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match f.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => panic!("stub should be ready"),
    }
}
fn response(answer: DecisionAnswer, probability: f64) -> SeatAnswer {
    let mut usage = LlmUsage::zero();
    usage.input.total = 1;
    usage.output.total = 1;
    SeatAnswer {
        answer,
        probability,
        usage,
    }
}
fn request() -> SeatRequest {
    SeatRequest {
        question: DecisionQuestion {
            id: EntityId::now(),
            version: 2,
            text: "Caller-provided accept criterion".into(),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: true,
        },
        state: serde_json::json!({"unit":"bounded"}),
        score_levels: vec![],
        posture: HostingPrivacyPosture::Hosted,
        remote_opt_in: false,
        phase: SeatPhase::PreQuery,
    }
}
fn dial() -> DecisionDial {
    DecisionDial {
        first: DecisionRung::Rule,
        ceiling: DecisionRung::SystemOne,
        band: DecisionBand::default(),
    }
}
fn guard(limit: u64) -> BudgetGuard {
    BudgetGuard::with_reserve_units("seat-test", limit, 4, BudgetExhaustionPolicy::Suspend)
}
fn decide(stub: &Stub, req: SeatRequest, guard: &BudgetGuard) -> LlmResult<TypedDecision> {
    run(decide_at_remote_seat(
        stub,
        req,
        EntityId::now(),
        vec![],
        dial(),
        guard,
    ))
}
#[test]
fn confident_accept_no_is_measured_twice_with_distinct_leases_and_version_pins() {
    let stub = Stub::new(vec![
        Ok(response(DecisionAnswer::Noul(false), 0.12)),
        Ok(response(DecisionAnswer::Noul(false), 0.09)),
    ]);
    let guard = guard(8);
    let result = decide(&stub, request(), &guard).unwrap();
    assert_eq!(result.answer, DecisionAnswer::Noul(false));
    assert_eq!(result.receipt.providers.len(), 2);
    assert_eq!(result.receipt.providers[0].version, "1.13.0");
    assert_eq!(result.receipt.question_version, 2);
    let leases = stub.leases.lock().unwrap();
    assert_eq!(leases.len(), 2);
    assert_ne!(leases[0], leases[1]);
    assert_eq!(guard.read().used_units, 4);
    assert_eq!(guard.read().reserved_units, 0);
}
#[test]
fn no_budget_for_recheck_holds_without_second_call() {
    let stub = Stub::new(vec![Ok(response(DecisionAnswer::Noul(false), 0.12))]);
    let guard = guard(4);
    let result = decide(&stub, request(), &guard).unwrap();
    assert_eq!(result.answer, DecisionAnswer::Abstain);
    assert_eq!(result.human_ask, Some(HumanAskReason::ProviderUnavailable));
    assert_eq!(result.receipt.providers.len(), 1);
    assert_eq!(stub.leases.lock().unwrap().len(), 1);
    assert_eq!(guard.read().used_units, 2);
    assert_eq!(guard.read().reserved_units, 0);
}
#[test]
fn failed_recheck_settles_reserved_on_its_separate_lease() {
    let stub = Stub::new(vec![
        Ok(response(DecisionAnswer::Noul(false), 0.12)),
        Err(RetryableLlmError::ServerError.into()),
    ]);
    let guard = guard(8);
    let result = decide(&stub, request(), &guard).unwrap();
    assert_eq!(result.answer, DecisionAnswer::Abstain);
    assert_eq!(result.human_ask, Some(HumanAskReason::ProviderUnavailable));
    assert_eq!(stub.leases.lock().unwrap().len(), 2);
    assert_eq!(guard.read().used_units, 6);
    assert_eq!(guard.read().reserved_units, 0);
}
#[test]
fn disagreement_and_noul_uncertainty_hold() {
    let stub = Stub::new(vec![
        Ok(response(DecisionAnswer::Noul(false), 0.1)),
        Ok(response(DecisionAnswer::Noul(true), 0.9)),
    ]);
    let result = decide(&stub, request(), &guard(8)).unwrap();
    assert_eq!(result.answer, DecisionAnswer::Abstain);
    assert_eq!(result.human_ask, Some(HumanAskReason::Disagreement));
    let stub = Stub::new(vec![Ok(response(DecisionAnswer::Noul(true), 0.5))]);
    let result = decide(&stub, request(), &guard(4)).unwrap();
    assert!(result.in_band);
    assert_eq!(result.human_ask, Some(HumanAskReason::Uncertain));
}
#[test]
fn choice_and_score_confidence_hold_below_high_and_admit_at_or_above_it() {
    for answer_contract in [
        (
            AnswerContract::Choice {
                options: vec!["yes".into(), "no".into()],
            },
            DecisionAnswer::Choice("yes".into()),
            vec![],
        ),
        (
            AnswerContract::Score { min: 0.0, max: 2.0 },
            DecisionAnswer::Score(1.0),
            vec!["low".into(), "medium".into(), "high".into()],
        ),
    ] {
        for (confidence, hold) in [
            (0.1, true),
            (0.35, true),
            (0.649, true),
            (0.65, false),
            (0.9, false),
        ] {
            let mut req = request();
            req.question.contract = answer_contract.0.clone();
            req.question.accept_type = false;
            req.score_levels = answer_contract.2.clone();
            let stub = Stub::new(vec![Ok(response(answer_contract.1.clone(), confidence))]);
            let result = decide(&stub, req, &guard(4)).unwrap();
            assert_eq!(result.in_band, hold);
            assert_eq!(
                result.answer,
                if hold {
                    DecisionAnswer::Abstain
                } else {
                    answer_contract.1.clone()
                }
            );
            assert_eq!(result.human_ask, hold.then_some(HumanAskReason::Uncertain));
        }
    }
}
#[test]
fn relay_light_and_self_host_without_opt_in_never_call_remote() {
    for (posture, phase, opt_in) in [
        (HostingPrivacyPosture::Relay, SeatPhase::PreQuery, true),
        (HostingPrivacyPosture::Hosted, SeatPhase::Light, false),
        (
            HostingPrivacyPosture::SelfHostLocal,
            SeatPhase::Background,
            false,
        ),
    ] {
        let stub = Stub::new(vec![]);
        let mut req = request();
        req.posture = posture;
        req.phase = phase;
        req.remote_opt_in = opt_in;
        let guard = guard(4);
        assert!(decide(&stub, req, &guard).is_err());
        assert_eq!(guard.read().used_units, 0);
    }
    let stub = Stub::new(vec![Ok(response(DecisionAnswer::Noul(true), 0.9))]);
    let mut req = request();
    req.posture = HostingPrivacyPosture::SelfHostLocal;
    req.remote_opt_in = true;
    assert_eq!(
        decide(&stub, req, &guard(4)).unwrap().answer,
        DecisionAnswer::Noul(true)
    );
}
