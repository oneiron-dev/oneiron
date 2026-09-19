//! Own-server conformance through the shipped HTTP transport, not a trait-only fake.
use futures_core::Stream;
use oneiron::*;
use oneiron_llm_own_server::{OwnServerTransport, RemoteLlmClient};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::{Future, poll_fn},
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    thread,
    time::{Duration, Instant},
};

struct Notify(thread::Thread);
impl Wake for Notify {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}
fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(Notify(thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .expect("fixture timeout");
        thread::park_timeout(remaining);
    }
}
fn request() -> LlmRequest {
    LlmRequest {
        model: ModelId::new("own/model@1").unwrap(),
        envelope: CallEnvelope {
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
        },
        messages: vec![],
        tools: vec![],
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    }
}
fn response() -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: "answer".into(),
            }],
        },
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 2,
                ..Default::default()
            },
            output: LlmOutputUsage {
                total: 3,
                text: 3,
                reasoning: 0,
            },
            raw_provider: json!({}),
        },
        finish_reason: FinishReason::Stop,
    }
}
// The peer returns the received request so assertions cannot be lost in a background thread.
fn peer(
    status: u16,
    body: String,
) -> (
    RemoteLlmClient,
    thread::JoinHandle<(String, BTreeMap<String, String>, Value)>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = RemoteLlmClient::connect(
        &format!("http://{}", listener.local_addr().unwrap()),
        "fixture-bearer",
    )
    .unwrap();
    let handle = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(&mut socket);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let first = line.trim().to_owned();
        let mut headers = BTreeMap::new();
        loop {
            line.clear();
            assert!(reader.read_line(&mut line).unwrap() > 0);
            if line == "\r\n" {
                break;
            }
            let (key, value) = line.trim().split_once(':').unwrap();
            headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
        }
        let mut bytes = vec![0; headers["content-length"].parse::<usize>().unwrap()];
        reader.read_exact(&mut bytes).unwrap();
        let request = serde_json::from_slice(&bytes).unwrap();
        write!(
            socket,
            "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        (first, headers, request)
    });
    (client, handle)
}
fn assert_request(
    handle: thread::JoinHandle<(String, BTreeMap<String, String>, Value)>,
    stream: bool,
    lease: &BudgetLease,
) {
    let (line, headers, body) = handle.join().unwrap();
    assert_eq!(
        line,
        if stream {
            "POST /v1/llm/stream HTTP/1.1"
        } else {
            "POST /v1/llm/generate HTTP/1.1"
        }
    );
    assert_eq!(headers["authorization"], "Bearer fixture-bearer");
    assert_eq!(headers["x-oneiron-budget-lease"], lease.id());
    assert_eq!(
        headers["accept"],
        if stream {
            "application/x-ndjson"
        } else {
            "application/json"
        }
    );
    assert_eq!(body, serde_json::to_value(request()).unwrap());
}

#[test]
fn http_generate_and_ndjson_stream_carry_admission_and_settle_terminal_usage() {
    let guard = BudgetGuard::with_reserve_units("wire", 100, 10, BudgetExhaustionPolicy::Suspend);
    let expected = response();
    let (client, peer) = peer(200, serde_json::to_string(&expected).unwrap());
    let lease = guard.admit_for_request(&request()).unwrap().lease;
    let generated = block_on(client.generate(request(), &lease)).unwrap();
    assert_eq!(generated, expected);
    guard.settle_per_call(&lease, &generated.usage).unwrap();
    assert_request(peer, false, &lease);
    let events = vec![
        LlmStreamEvent::TextStart {
            part_id: "t".into(),
        },
        LlmStreamEvent::TextDelta {
            part_id: "t".into(),
            text: "answer".into(),
        },
        LlmStreamEvent::TextEnd {
            part_id: "t".into(),
        },
        LlmStreamEvent::Done {
            message: expected.message,
            usage: expected.usage,
            finish_reason: expected.finish_reason,
        },
    ];
    let body = events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap() + "\n")
        .collect::<String>();
    let (client, peer) = self::peer(200, body);
    let lease = guard.admit_for_request(&request()).unwrap().lease;
    let mut stream = client.stream(request(), &lease).unwrap();
    for expected in &events {
        let event = block_on(poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)))
            .unwrap()
            .unwrap();
        assert_eq!(&event, expected);
        if let LlmStreamEvent::Done { usage, .. } = event {
            guard.settle_per_call(&lease, &usage).unwrap();
        } else {
            assert_eq!(guard.read().reserved_units, 10);
        }
    }
    assert!(block_on(poll_fn(|cx| Pin::new(&mut stream).poll_next(cx))).is_none());
    assert_request(peer, true, &lease);
    assert_eq!(guard.read().reserved_units, 0);
    assert_eq!(guard.read().used_units, 10);
}

#[test]
fn http_status_failures_are_typed_for_both_verbs_and_do_not_retry() {
    for status in [401, 402, 429, 500] {
        for streaming in [false, true] {
            let guard = BudgetGuard::with_reserve_units(
                "failure",
                100,
                10,
                BudgetExhaustionPolicy::Suspend,
            );
            let lease = guard.admit_for_request(&request()).unwrap().lease;
            let (client, peer) = peer(status, "{}".into());
            let error = if streaming {
                let mut stream = client.stream(request(), &lease).unwrap();
                let error = block_on(poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)))
                    .unwrap()
                    .unwrap_err();
                assert!(block_on(poll_fn(|cx| Pin::new(&mut stream).poll_next(cx))).is_none());
                error
            } else {
                block_on(client.generate(request(), &lease)).unwrap_err()
            };
            match status {
                401 => assert!(matches!(error, LlmError::Fatal(FatalLlmError::Auth))),
                402 => assert!(matches!(error, LlmError::BudgetDenied(_))),
                429 => assert!(matches!(
                    error,
                    LlmError::Retryable(RetryableLlmError::RateLimited { .. })
                )),
                500 => assert!(matches!(
                    error,
                    LlmError::Retryable(RetryableLlmError::ServerError)
                )),
                _ => unreachable!(),
            }
            assert_request(peer, streaming, &lease);
            guard.abort(&lease).unwrap();
            assert_eq!(guard.read().reserved_units, 0);
            assert_eq!(guard.read().used_units, 0);
        }
    }
}

#[test]
fn truncated_ndjson_stream_never_becomes_successful_done() {
    let guard = BudgetGuard::with_reserve_units("cut", 100, 10, BudgetExhaustionPolicy::Suspend);
    let lease = guard.admit_for_request(&request()).unwrap().lease;
    let partial = LlmStreamEvent::TextStart {
        part_id: "t".into(),
    };
    let (client, peer) = peer(200, serde_json::to_string(&partial).unwrap() + "\n");
    let mut stream = client.stream(request(), &lease).unwrap();
    assert_eq!(
        block_on(poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)))
            .unwrap()
            .unwrap(),
        partial
    );
    assert!(matches!(
        block_on(poll_fn(|cx| Pin::new(&mut stream).poll_next(cx))),
        Some(Err(LlmError::Retryable(RetryableLlmError::StreamCut)))
    ));
    assert!(block_on(poll_fn(|cx| Pin::new(&mut stream).poll_next(cx))).is_none());
    drop(stream);
    assert_request(peer, true, &lease);
    guard.abort(&lease).unwrap();
    assert_eq!(guard.read().reserved_units, 0);
    assert_eq!(guard.read().used_units, 0);
}

#[test]
fn dropping_stalled_stream_closes_the_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = RemoteLlmClient::connect(
        &format!("http://{}", listener.local_addr().unwrap()),
        "fixture",
    )
    .unwrap();
    let (started, ready) = std::sync::mpsc::channel();
    let peer = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(&mut socket);
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some((key, value)) = line.split_once(':')
                && key.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().unwrap();
            }
        }
        reader.read_exact(&mut vec![0; length]).unwrap();
        write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n").unwrap();
        socket.flush().unwrap();
        started.send(()).unwrap();
        let mut byte = [0];
        match socket.read(&mut byte) {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            outcome => panic!("cancel must close peer socket, got {outcome:?}"),
        }
    });
    let guard = BudgetGuard::with_reserve_units("cancel", 100, 10, BudgetExhaustionPolicy::Suspend);
    let lease = guard.admit_for_request(&request()).unwrap().lease;
    let stream = client.stream(request(), &lease).unwrap();
    ready.recv_timeout(Duration::from_secs(5)).unwrap();
    drop(stream);
    peer.join().unwrap();
    guard.abort(&lease).unwrap();
}
