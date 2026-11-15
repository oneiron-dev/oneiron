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
//! The time left is read once the request is built, its images fitted (#7827
//! review round 1): the budget and the transport's timeout are both what is
//! left of the call then, and a call already out of time is never sent.
//!
//! Every row drives the public seat over a capturing transport: the exact body
//! the seat built, and the reply a server would send.
//!
//! Fleet: `cargo test --locked -p oneiron-llm-systemone --all-features --test native_budget_wire`

use std::sync::{Arc, Mutex};
use std::time::Duration;

use oneiron::llm::LabelReadFailure;
use oneiron::llm::decision::{
    AnswerContract, DecisionClass, DecisionImage, DecisionQuestion, EvidenceVersion,
    RemoteDecisionSeat, SeatPhase, SeatRequest,
};
use oneiron::llm::image::ImageBytes;
use oneiron::{
    BudgetLease, EntityId, FatalLlmError, HostingPrivacyPosture, LlmError, RetryableLlmError,
};
use oneiron_llm_systemone::{
    SystemOneHttpRequest, SystemOneHttpResponse, SystemOnePackQuestion, SystemOnePackRequest,
    SystemOneSeat, SystemOneTransport, SystemOneTransportFuture,
};
use serde_json::{Value, json};

const ENDPOINT: &str = "https://seat.example/v1/systemone";

/// What the seat sent: each body, and each transport timeout.
#[derive(Default)]
struct Sent {
    bodies: Mutex<Vec<Value>>,
    timeouts: Mutex<Vec<Duration>>,
}

/// Keeps every request the seat sends and answers each with `reply`.
struct Capture {
    sent: Arc<Sent>,
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
            self.sent.bodies.lock().expect("capture lock").push(body);
            self.sent
                .timeouts
                .lock()
                .expect("capture lock")
                .push(request.time_left);
            Ok(SystemOneHttpResponse {
                status: 200,
                body: serde_json::to_vec(&self.reply).expect("reply bytes"),
            })
        })
    }
}

/// A seat over a capturing transport answering `reply`, and what it sent.
fn seat(reply: Value) -> (SystemOneSeat, Arc<Sent>) {
    let sent = Arc::new(Sent::default());
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

/// A 2x2 PNG, which the seat fits up to the wire's shortest edge on a
/// blocking worker before it sends.
const PHOTO_PNG: [u8; 73] = [
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x08, 0x02, 0x00, 0x00, 0x00, 0xfd, 0xd4, 0x9a,
    0x73, 0x00, 0x00, 0x00, 0x10, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0x38, 0xa1, 0xa1, 0x01,
    0x44, 0x0c, 0x10, 0x0a, 0x00, 0x21, 0x2e, 0x04, 0x61, 0xf6, 0xe1, 0xc2, 0x4d, 0x00, 0x00, 0x00,
    0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

fn photo() -> DecisionImage {
    DecisionImage {
        name: "photo".to_owned(),
        evidence: EvidenceVersion {
            id: EntityId::now(),
            body_hash: [7; 32],
        },
        image: ImageBytes {
            bytes: PHOTO_PNG.to_vec(),
            media_type: "image/png".to_owned(),
        },
        frame: None,
    }
}

fn request_with_photo() -> SeatRequest {
    SeatRequest {
        images: vec![photo()],
        ..request()
    }
}

fn pack_request_with_photo() -> SystemOnePackRequest {
    SystemOnePackRequest {
        images: vec![photo()],
        ..pack_request()
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

fn is_timeout(error: &LlmError) -> bool {
    matches!(error, LlmError::Retryable(RetryableLlmError::Timeout))
}

#[tokio::test]
async fn systemone_body_carries_time_left_as_budget() {
    let lease = BudgetLease::for_test("seat");
    // 1234.9 ms left: the server gets at most 1234, never more than the call
    // has; less only by the moment the seat took to build the body.
    let time_left = Duration::from_micros(1_234_900);

    let (single, sent) = seat(answered());
    let single = single.with_native_budget(true);
    single
        .ask(request(), &lease, time_left)
        .await
        .expect("the seat answers");
    let (pack, pack_sent) = seat(pack_answered());
    let pack = pack.with_native_budget(true);
    pack.ask_pack(pack_request(), &lease, time_left)
        .await
        .expect("the pack answers");

    for (what, sent) in [("one question", sent), ("a pack", pack_sent)] {
        let sent = sent.bodies.lock().expect("capture lock");
        assert_eq!(sent.len(), 1, "{what}: one request");
        let budget = sent[0]["budget_ms"].as_u64();
        assert!(
            budget.is_some_and(|budget| (1_134..=1_234).contains(&budget)),
            "{what}: the body carries the time left as the server's budget: {}",
            sent[0]
        );
    }
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
        let sent = sent.bodies.lock().expect("capture lock");
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

#[tokio::test]
async fn the_budget_is_read_once_the_images_are_fitted() {
    let lease = BudgetLease::for_test("seat");
    let time_left = Duration::from_secs(5);

    let (single, sent) = seat(answered());
    let single = single.with_native_budget(true);
    single
        .ask(request_with_photo(), &lease, time_left)
        .await
        .expect("the seat answers");
    let (pack, pack_sent) = seat(pack_answered());
    let pack = pack.with_native_budget(true);
    pack.ask_pack(pack_request_with_photo(), &lease, time_left)
        .await
        .expect("the pack answers");

    for (what, sent) in [("one question", sent), ("a pack", pack_sent)] {
        let bodies = sent.bodies.lock().expect("capture lock");
        let timeouts = sent.timeouts.lock().expect("capture lock");
        assert_eq!(bodies.len(), 1, "{what}: one request");
        assert!(
            bodies[0]["assets"].is_object(),
            "{what}: the photo went as an asset"
        );
        let budget = bodies[0]["budget_ms"].as_u64().expect("a budget");
        assert!(
            budget < 5_000,
            "{what}: the time spent fitting the photo is spent from the server's budget: {budget}"
        );
        assert!(
            timeouts[0] < time_left,
            "{what}: and from the transport's timeout: {:?}",
            timeouts[0]
        );
        assert!(
            u128::from(budget) <= timeouts[0].as_millis(),
            "{what}: the server never gets more time than the transport waits"
        );
    }
}

#[tokio::test]
async fn a_call_out_of_time_once_its_images_are_fitted_is_never_sent() {
    let lease = BudgetLease::for_test("seat");
    // One microsecond: gone before the blocking worker has fitted the photo.
    let time_left = Duration::from_micros(1);

    let (single, sent) = seat(answered());
    let error = single
        .ask(request_with_photo(), &lease, time_left)
        .await
        .err()
        .expect("a call out of time is no answer");
    assert!(is_timeout(&error), "one question: timed out: {error:?}");
    let (pack, pack_sent) = seat(pack_answered());
    let error = pack
        .ask_pack(pack_request_with_photo(), &lease, time_left)
        .await
        .err()
        .expect("a pack out of time is no answer");
    assert!(is_timeout(&error), "a pack: timed out: {error:?}");

    for (what, sent) in [("one question", sent), ("a pack", pack_sent)] {
        assert!(
            sent.bodies.lock().expect("capture lock").is_empty(),
            "{what}: nothing is sent"
        );
    }
}
