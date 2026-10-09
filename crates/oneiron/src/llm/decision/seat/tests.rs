use super::*;
use crate::BudgetExhaustionPolicy;
use crate::llm::decision::{DecisionBand, DecisionClass};
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
