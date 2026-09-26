use super::*;
use crate::llm::decision::{DecisionBand, DecisionClass};
use std::sync::Mutex;

struct Stub {
    answers: Mutex<Vec<SeatAnswer>>,
}
impl DecisionSeat for Stub {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::SystemOne,
            model: "jev".into(),
            version: "1.13.0".into(),
        }
    }
    fn ask<'a>(&'a self, _request: SeatRequest, _lease: &'a BudgetLease) -> SeatFuture<'a> {
        Box::pin(async move { Ok(self.answers.lock().unwrap().remove(0)) })
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
fn decide(stub: &Stub, req: SeatRequest) -> LlmResult<TypedDecision> {
    let principal = EntityId::now();
    run(decide_at_remote_seat(
        stub,
        req,
        principal,
        vec![],
        dial(),
        &BudgetLease::for_test("seat"),
    ))
}
#[test]
fn confident_accept_no_is_measured_twice_and_pins_each_version() {
    let stub = Stub {
        answers: Mutex::new(vec![
            SeatAnswer {
                answer: DecisionAnswer::Noul(false),
                probability: 0.12,
            },
            SeatAnswer {
                answer: DecisionAnswer::Noul(false),
                probability: 0.09,
            },
        ]),
    };
    let result = decide(&stub, request()).unwrap();
    assert_eq!(result.answer, DecisionAnswer::Noul(false));
    assert_eq!(result.receipt.providers.len(), 2);
    assert_eq!(result.receipt.providers[0].version, "1.13.0");
    assert_eq!(result.receipt.question_version, 2);
    assert!(stub.answers.lock().unwrap().is_empty());
}
#[test]
fn disagreement_and_uncertainty_hold_instead_of_accepting() {
    let stub = Stub {
        answers: Mutex::new(vec![
            SeatAnswer {
                answer: DecisionAnswer::Noul(false),
                probability: 0.1,
            },
            SeatAnswer {
                answer: DecisionAnswer::Noul(true),
                probability: 0.9,
            },
        ]),
    };
    let result = decide(&stub, request()).unwrap();
    assert_eq!(result.answer, DecisionAnswer::Abstain);
    assert_eq!(result.human_ask, Some(HumanAskReason::Disagreement));
    let stub = Stub {
        answers: Mutex::new(vec![SeatAnswer {
            answer: DecisionAnswer::Noul(true),
            probability: 0.5,
        }]),
    };
    let result = decide(&stub, request()).unwrap();
    assert!(result.in_band);
    assert_eq!(result.human_ask, Some(HumanAskReason::Uncertain));
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
        let stub = Stub {
            answers: Mutex::new(vec![]),
        };
        let mut req = request();
        req.posture = posture;
        req.phase = phase;
        req.remote_opt_in = opt_in;
        assert!(decide(&stub, req).is_err());
    }
    let stub = Stub {
        answers: Mutex::new(vec![SeatAnswer {
            answer: DecisionAnswer::Noul(true),
            probability: 0.9,
        }]),
    };
    let mut req = request();
    req.posture = HostingPrivacyPosture::SelfHostLocal;
    req.remote_opt_in = true;
    assert_eq!(
        decide(&stub, req).unwrap().answer,
        DecisionAnswer::Noul(true)
    );
}
