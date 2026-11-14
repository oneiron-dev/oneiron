//! L9-19 (ARCH-0036 #decision-deadline part 4, #system-one-codec): a System
//! One server that takes a native budget gets the call's time left as that
//! budget, and a server that stopped at its token cap says so.
//!
//! Engine ruling L9-19-WIRE = A: the request key is `budget_ms`, whole
//! milliseconds of the time left rounded down, sent only when the binding
//! says `native_budget = true`; the reply key is `"stop": "token_cap"` at the
//! top level, read from every server. A capped read answers the house read's
//! own token-cap error, so the ladder steps up past it (L2-31).
//!
//! Every row drives the public seat over a capturing transport: the exact body
//! the seat built, and the reply a server would send.
//!
//! Red pin on main: the row that needs `SystemOneSeat::with_native_budget` (new API) is
//! left out; every other row is the head's, word for word.
//!
//! Fleet: `cargo test --locked -p oneiron-llm-systemone --all-features --test native_budget_wire`

use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneiron::llm::LabelReadFailure;
use oneiron::llm::decision::{
    AnswerContract, DecisionClass, DecisionQuestion, RemoteDecisionSeat, SeatPhase, SeatRequest,
};
use oneiron::{BudgetLease, EntityId, FatalLlmError, HostingPrivacyPosture, LlmError};
use oneiron_llm_systemone::{
    SystemOneHttpRequest, SystemOneHttpResponse, SystemOnePackQuestion, SystemOnePackRequest,
    SystemOneSeat, SystemOneTransport, SystemOneTransportFuture,
};
use serde_json::{Value, json};

const ENDPOINT: &str = "https://seat.example/v1/systemone";

/// Keeps every body the seat sends and answers each with `reply`.
struct Capture {
    sent: Arc<Mutex<Vec<Value>>>,
    reply: Value,
}

impl SystemOneTransport for Capture {
    fn send<'a>(
        &'a self,
        request: SystemOneHttpRequest,
        _lease: &'a BudgetLease,
    ) -> SystemOneTransportFuture<'a> {
        Box::pin(async move {
            let body: Value =
                serde_json::from_slice(&request.body).expect("the seat sends one JSON object");
            self.sent.lock().expect("capture lock").push(body);
            Ok(SystemOneHttpResponse {
                status: 200,
                body: serde_json::to_vec(&self.reply).expect("reply bytes"),
            })
        })
    }
}

/// A seat over a capturing transport answering `reply`, and what it sent.
fn seat(reply: Value) -> (SystemOneSeat, Arc<Mutex<Vec<Value>>>) {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let seat = SystemOneSeat::with_transport(
        ENDPOINT.to_owned(),
        "jev".to_owned(),
        "1.13.0".to_owned(),
        Box::new(Capture {
            sent: Arc::clone(&sent),
            reply,
        }),
    )
    .expect("a valid seat");
    (seat, sent)
}

fn question() -> DecisionQuestion {
    DecisionQuestion {
        id: EntityId::now(),
        version: 1,
        text: "Caller-owned question with criteria".into(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}

fn state() -> Value {
    json!({"unit":{"value":"example"}})
}

fn request() -> SeatRequest {
    SeatRequest {
        question: question(),
        state: state(),
        score_levels: Vec::new(),
        posture: HostingPrivacyPosture::Hosted,
        remote_opt_in: false,
        phase: SeatPhase::Background,
        images: Vec::new(),
        audio: Vec::new(),
    }
}

fn pack_request() -> SystemOnePackRequest {
    SystemOnePackRequest {
        questions: vec![SystemOnePackQuestion {
            question: question(),
            score_levels: Vec::new(),
        }],
        state: state(),
        images: Vec::new(),
        audio: Vec::new(),
        posture: HostingPrivacyPosture::Hosted,
        remote_opt_in: false,
        phase: SeatPhase::Background,
    }
}

/// A server's answer to the one-question call.
fn answered() -> Value {
    json!({
        "model": "jev-1.13.0",
        "answers": {"decision": {"type": "noul", "noul": 0.9}},
        "usage": {"input_tokens": 3, "output_tokens": 1},
    })
}

/// A server's answer to the one-question pack.
fn pack_answered() -> Value {
    json!({
        "model": "jev-1.13.0",
        "answers": {"q0": {"type": "noul", "noul": 0.9}},
        "usage": {"input_tokens": 3, "output_tokens": 1},
    })
}

/// A server whose read stopped at its token cap before an answer.
fn capped() -> Value {
    json!({
        "model": "jev-1.13.0",
        "stop": "token_cap",
        "usage": {"input_tokens": 3, "output_tokens": 64},
    })
}

fn is_token_cap(error: &LlmError) -> bool {
    matches!(
        error,
        LlmError::Fatal(FatalLlmError::LabelRead(LabelReadFailure::TokenCap))
    )
}

#[tokio::test]
async fn a_binding_without_the_flag_sends_no_budget_ms() {
    let lease = BudgetLease::for_test("seat");
    let (single, sent) = seat(answered());
    single
        .ask(request(), &lease, Duration::from_secs(2))
        .await
        .expect("the seat answers");
    let (pack, pack_sent) = seat(pack_answered());
    pack.ask_pack(pack_request(), &lease, Duration::from_secs(2))
        .await
        .expect("the pack answers");

    for (what, sent) in [("one question", sent), ("a pack", pack_sent)] {
        let sent = sent.lock().expect("capture lock");
        assert_eq!(sent.len(), 1, "{what}: one request");
        let mut keys: Vec<&str> = sent[0]
            .as_object()
            .expect("one JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["model", "questions", "state"],
            "{what}: a server that takes no native budget gets the body as before"
        );
    }
}

#[tokio::test]
async fn a_token_capped_reply_reads_as_the_token_cap() {
    let lease = BudgetLease::for_test("seat");
    let (single, _) = seat(capped());
    let error = single
        .ask(request(), &lease, Duration::from_secs(2))
        .await
        .err()
        .expect("a capped read is no answer");
    assert!(
        is_token_cap(&error),
        "one question: the cap, not a failure: {error:?}"
    );

    let (pack, _) = seat(capped());
    let error = pack
        .ask_pack(pack_request(), &lease, Duration::from_secs(2))
        .await
        .err()
        .expect("a capped pack read is no answer");
    assert!(
        is_token_cap(&error),
        "a pack: the cap, not a failure: {error:?}"
    );
}

#[tokio::test]
async fn another_stop_is_no_token_cap() {
    let lease = BudgetLease::for_test("seat");
    let mut reply = answered();
    reply["stop"] = json!("end");
    let (single, _) = seat(reply);
    let answer = single
        .ask(request(), &lease, Duration::from_secs(2))
        .await
        .expect("a reply with its answer and another stop still answers");
    assert!(answer.probability > 0.5, "the server's own answer stands");
}
