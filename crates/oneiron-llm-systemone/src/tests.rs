use super::*;
use oneiron::llm::decision::{
    DecisionBand, DecisionClass, DecisionDial, DecisionQuestion, SeatPhase, decide_at_remote_seat,
};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, BudgetLease, EntityId, HostingPrivacyPosture};
use std::io::{Read, Write};
use std::net::TcpListener;

fn server(responses: Vec<Value>) -> (String, std::thread::JoinHandle<Vec<Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/v1/systemone", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut requests = vec![];
        for response in responses {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let end = loop {
                let mut chunk = [0u8; 4096];
                let n = socket.read(&mut chunk).unwrap();
                assert!(n > 0 && bytes.len() < 65_536);
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
            assert!(headers.starts_with("post /v1/systemone http/1.1"));
            assert!(headers.contains("authorization: bearer stub-key"));
            let length: usize = headers
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            while bytes.len() - end < length {
                let mut chunk = [0u8; 4096];
                let n = socket.read(&mut chunk).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
            }
            requests.push(serde_json::from_slice(&bytes[end..end + length]).unwrap());
            let payload = serde_json::to_vec(&response).unwrap();
            write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", payload.len()).unwrap();
            socket.write_all(&payload).unwrap();
        }
        requests
    });
    (endpoint, handle)
}
fn request(contract: AnswerContract, score_levels: Vec<String>) -> SeatRequest {
    SeatRequest {
        question: DecisionQuestion {
            id: EntityId::now(),
            version: 1,
            text: "Caller-owned question with criteria".into(),
            class: DecisionClass::Judgment,
            contract,
            accept_type: false,
        },
        state: json!({"unit":{"value":"example"}}),
        score_levels,
        posture: HostingPrivacyPosture::Hosted,
        remote_opt_in: false,
        phase: SeatPhase::Background,
    }
}
fn wire(answer: Value) -> Value {
    json!({"model":"jev-1.13.0","answers":{"decision":answer},"usage":{"input_tokens":3,"output_tokens":1}})
}
#[tokio::test]
async fn server_parses_all_three_primitives_and_pins_exact_revision() {
    let (endpoint, handle) = server(vec![
        wire(json!({"type":"noul","noul":0.9})),
        wire(
            json!({"type":"choice","choice":"keep","probabilities":{"keep":0.8,"drop":0.2},"confidence":0.8}),
        ),
        wire(
            json!({"type":"score","score":1.5,"legend":{"0":"low","1":"medium","2":"high"},"probabilities":{"0":0.0,"1":0.5,"2":0.5},"confidence":0.92}),
        ),
    ]);
    let seat =
        SystemOneSeat::new(endpoint, "stub-key".into(), "jev".into(), "1.13.0".into()).unwrap();
    let a = seat
        .ask(
            request(AnswerContract::Noul, vec![]),
            &BudgetLease::for_test("seat"),
        )
        .await
        .unwrap();
    assert_eq!(a.answer, DecisionAnswer::Noul(true));
    assert_eq!(a.usage.input.total, 3);
    assert_eq!(a.usage.output.total, 1);
    let b = seat
        .ask(
            request(
                AnswerContract::Choice {
                    options: vec!["keep".into(), "drop".into()],
                },
                vec![],
            ),
            &BudgetLease::for_test("seat"),
        )
        .await
        .unwrap();
    assert_eq!(b.answer, DecisionAnswer::Choice("keep".into()));
    let c = seat
        .ask(
            request(
                AnswerContract::Score {
                    min: 10.0,
                    max: 20.0,
                },
                vec!["low".into(), "medium".into(), "high".into()],
            ),
            &BudgetLease::for_test("seat"),
        )
        .await
        .unwrap();
    assert_eq!(c.answer, DecisionAnswer::Score(17.5));
    assert_eq!(c.probability, 0.92);
    let requests = handle.join().unwrap();
    assert_eq!(requests[0]["model"], "jev-1.13.0");
    assert_eq!(
        requests[0]["questions"]["decision"]["instructions"],
        "Caller-owned question with criteria"
    );
    assert_eq!(
        requests[1]["questions"]["decision"]["criteria"]["keep"],
        Value::Null
    );
    assert_eq!(
        requests[2]["questions"]["decision"]["criteria"],
        json!(["low", "medium", "high"])
    );
}
#[tokio::test]
async fn rechecks_negative_and_rejects_wrong_revision() {
    let (endpoint, handle) = server(vec![
        wire(json!({"type":"noul","noul":0.12})),
        wire(json!({"type":"noul","noul":0.08})),
    ]);
    let seat =
        SystemOneSeat::new(endpoint, "stub-key".into(), "jev".into(), "1.13.0".into()).unwrap();
    let mut req = request(AnswerContract::Noul, vec![]);
    req.question.accept_type = true;
    let result = decide_at_remote_seat(
        &seat,
        req,
        EntityId::now(),
        vec![],
        DecisionDial {
            first: DecisionRung::Rule,
            ceiling: DecisionRung::SystemOne,
            band: DecisionBand::default(),
        },
        &BudgetGuard::with_reserve_units("seat", 16, 8, BudgetExhaustionPolicy::Suspend),
    )
    .await
    .unwrap();
    assert_eq!(result.answer, DecisionAnswer::Noul(false));
    assert_eq!(result.receipt.providers.len(), 2);
    assert_eq!(result.receipt.providers[0].version, "1.13.0");
    assert_eq!(handle.join().unwrap().len(), 2);
    let (endpoint, handle) = server(vec![
        json!({"model":"jev-1.14.0","answers":{"decision":{"type":"noul","noul":0.9}}}),
    ]);
    let seat =
        SystemOneSeat::new(endpoint, "stub-key".into(), "jev".into(), "1.13.0".into()).unwrap();
    assert!(
        seat.ask(
            request(AnswerContract::Noul, vec![]),
            &BudgetLease::for_test("seat")
        )
        .await
        .is_err()
    );
    handle.join().unwrap();
}
#[tokio::test]
async fn relay_and_light_fail_before_http() {
    let (endpoint, _handle) = ("http://127.0.0.1:1/v1/systemone".to_string(), ());
    let seat =
        SystemOneSeat::new(endpoint, "stub-key".into(), "jev".into(), "1.13.0".into()).unwrap();
    let mut req = request(AnswerContract::Noul, vec![]);
    req.posture = HostingPrivacyPosture::Relay;
    req.remote_opt_in = true;
    assert!(seat.ask(req, &BudgetLease::for_test("seat")).await.is_err());
    let mut req = request(AnswerContract::Noul, vec![]);
    req.phase = SeatPhase::Light;
    assert!(seat.ask(req, &BudgetLease::for_test("seat")).await.is_err());
}

#[tokio::test]
async fn malformed_choice_probabilities_and_unpinned_endpoint_fail_closed() {
    assert!(
        SystemOneSeat::new(
            "http://example.com/v1/systemone".into(),
            "key".into(),
            "jev".into(),
            "1.13.0".into()
        )
        .is_err()
    );
    let (endpoint, handle) = server(vec![wire(json!({
        "type":"choice", "choice":"keep", "probabilities":{"keep":1.4,"drop":0.0}, "confidence":0.9
    }))]);
    let seat =
        SystemOneSeat::new(endpoint, "stub-key".into(), "jev".into(), "1.13.0".into()).unwrap();
    assert!(
        seat.ask(
            request(
                AnswerContract::Choice {
                    options: vec!["keep".into(), "drop".into()]
                },
                vec![]
            ),
            &BudgetLease::for_test("seat")
        )
        .await
        .is_err()
    );
    handle.join().unwrap();
}

#[tokio::test]
async fn one_call_budget_never_issues_second_http_request() {
    // The server accepts exactly one request and closes. A second attempt
    // would leave two provider pins even if connection refusal hid the call.
    let (endpoint, handle) = server(vec![wire(json!({"type":"noul","noul":0.1}))]);
    let seat =
        SystemOneSeat::new(endpoint, "stub-key".into(), "jev".into(), "1.13.0".into()).unwrap();
    let mut req = request(AnswerContract::Noul, vec![]);
    req.question.accept_type = true;
    let guard = BudgetGuard::with_reserve_units("one-call", 8, 8, BudgetExhaustionPolicy::Suspend);
    let result = decide_at_remote_seat(
        &seat,
        req,
        EntityId::now(),
        vec![],
        DecisionDial {
            first: DecisionRung::Rule,
            ceiling: DecisionRung::SystemOne,
            band: DecisionBand::default(),
        },
        &guard,
    )
    .await
    .unwrap();
    assert_eq!(result.answer, DecisionAnswer::Abstain);
    assert_eq!(result.receipt.providers.len(), 1);
    assert_eq!(
        result.human_ask,
        Some(oneiron::llm::decision::HumanAskReason::ProviderUnavailable)
    );
    assert_eq!(guard.read().used_units, 4);
    assert_eq!(guard.read().reserved_units, 0);
    assert_eq!(handle.join().unwrap().len(), 1);
}

#[tokio::test]
async fn failed_second_http_request_settles_its_reserved_lease() {
    let (endpoint, handle) = server(vec![
        wire(json!({"type":"noul","noul":0.1})),
        json!({"model":"jev-1.14.0","answers":{"decision":{"type":"noul","noul":0.1}}}),
    ]);
    let seat =
        SystemOneSeat::new(endpoint, "stub-key".into(), "jev".into(), "1.13.0".into()).unwrap();
    let mut req = request(AnswerContract::Noul, vec![]);
    req.question.accept_type = true;
    let guard =
        BudgetGuard::with_reserve_units("failed-recheck", 16, 8, BudgetExhaustionPolicy::Suspend);
    let result = decide_at_remote_seat(
        &seat,
        req,
        EntityId::now(),
        vec![],
        DecisionDial {
            first: DecisionRung::Rule,
            ceiling: DecisionRung::SystemOne,
            band: DecisionBand::default(),
        },
        &guard,
    )
    .await
    .unwrap();
    assert_eq!(result.answer, DecisionAnswer::Abstain);
    assert_eq!(result.receipt.providers.len(), 2);
    assert_eq!(guard.read().used_units, 12);
    assert_eq!(guard.read().reserved_units, 0);
    assert_eq!(handle.join().unwrap().len(), 2);
}

#[tokio::test]
async fn rejects_307_and_308_without_reposting_to_redirect_target() {
    for status in [307, 308] {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        target.set_nonblocking(true).unwrap();
        let source = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/v1/systemone", source.local_addr().unwrap());
        let location = format!("http://{}/v1/systemone", target.local_addr().unwrap());
        let sender = std::thread::spawn(move || {
            let (mut socket, _) = source.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut header = Vec::new();
            while !header.windows(4).any(|w| w == b"\r\n\r\n") {
                let mut chunk = [0u8; 4096];
                let n = socket.read(&mut chunk).unwrap();
                assert!(n > 0);
                header.extend_from_slice(&chunk[..n]);
            }
            write!(socket, "HTTP/1.1 {status} Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let seat =
            SystemOneSeat::new(endpoint, "stub-key".into(), "jev".into(), "1.13.0".into()).unwrap();
        assert!(
            seat.ask(
                request(AnswerContract::Noul, vec![]),
                &BudgetLease::for_test("seat")
            )
            .await
            .is_err()
        );
        sender.join().unwrap();
        assert!(matches!(target.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    }
}

#[tokio::test]
async fn maps_decimal_and_wide_finite_score_endpoints_and_interiors() {
    for (min, max, middle) in [(-0.1, 0.2, 0.05), (-1.0e308, 1.0e308, 0.0)] {
        let (endpoint, handle) = server(
            [0.0, 0.5, 1.0]
                .into_iter()
                .map(|score| {
                    wire(json!({
                        "type":"score", "score":score, "confidence":0.9,
                        "legend":{"0":"low","1":"high"},
                        "probabilities":{"0":0.5,"1":0.5}
                    }))
                })
                .collect(),
        );
        let seat =
            SystemOneSeat::new(endpoint, "stub-key".into(), "jev".into(), "1.13.0".into()).unwrap();
        for expected in [min, middle, max] {
            let answer = seat
                .ask(
                    request(
                        AnswerContract::Score { min, max },
                        vec!["low".into(), "high".into()],
                    ),
                    &BudgetLease::for_test("seat"),
                )
                .await
                .unwrap();
            match answer.answer {
                DecisionAnswer::Score(actual) if expected == min || expected == max => {
                    assert_eq!(actual, expected);
                }
                DecisionAnswer::Score(actual) => {
                    assert!((actual - expected).abs() <= f64::EPSILON * expected.abs().max(1.0));
                }
                _ => panic!("expected score"),
            }
        }
        assert_eq!(handle.join().unwrap().len(), 3);
    }
}
