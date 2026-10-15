//! Own-server conformance through the shipped HTTP transport, not a trait-only fake.
use futures_core::Stream;
use oneiron::*;
use oneiron_llm_own_server::{OwnServerTransport, RemoteLlmClient};
use serde_json::Value;
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
        model: ModelId::new("own/model@1").expect("valid fixture model"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
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
type CapturedRequest = (String, BTreeMap<String, String>, Value);

// The peer returns the received request so assertions cannot be lost in a background thread.
fn peer(status: u16, body: String) -> (RemoteLlmClient, thread::JoinHandle<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture listener");
    let client = RemoteLlmClient::connect(
        &format!(
            "http://{}",
            listener
                .local_addr()
                .expect("read fixture listener address")
        ),
        "fixture-bearer",
    )
    .expect("connect fixture client");
    let handle = thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept fixture request");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set fixture read timeout");
        let mut reader = BufReader::new(&mut socket);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("read fixture request line");
        let first = line.trim().to_owned();
        let mut headers = BTreeMap::new();
        loop {
            line.clear();
            assert!(reader.read_line(&mut line).expect("read fixture header") > 0);
            if line == "\r\n" {
                break;
            }
            let (key, value) = line
                .trim()
                .split_once(':')
                .expect("fixture header has a colon");
            headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
        }
        let mut bytes = vec![
            0;
            headers["content-length"]
                .parse::<usize>()
                .expect("parse fixture content length")
        ];
        reader
            .read_exact(&mut bytes)
            .expect("read fixture request body");
        let request = serde_json::from_slice(&bytes).expect("decode fixture JSON request");
        write!(
            socket,
            "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("write fixture HTTP response");
        (first, headers, request)
    });
    (client, handle)
}
fn assert_request(handle: thread::JoinHandle<CapturedRequest>, stream: bool, lease: &BudgetLease) {
    let (line, headers, body) = handle.join().expect("join fixture peer");
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
    assert_eq!(
        body,
        serde_json::to_value(request()).expect("encode fixture JSON request")
    );
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
