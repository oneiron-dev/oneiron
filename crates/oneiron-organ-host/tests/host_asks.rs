//! Protocol 1.1 asks against a real organ process (the probe). Each test
//! pins a rule of the asks design (ARCH-0075 `#organ-host-design-asks`):
//! only an ask the grant names and the caller answers gets an answer, a
//! refusal leaves the call to the organ, an ask runs inside its call's
//! deadline, a flooding organ is cut off, a handler cannot nest a call, a
//! fetch reaches only its allowlist and redirects a POST as RFC 9110 says,
//! and an organ built for 1.0 still runs.
//! An answer goes only to a call still in flight under a live grant, counts
//! its value against the call's answer bytes, and every ask stays on record
//! however the call ends.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use oneiron::{Vault, VaultConfig};
use oneiron_organ_host::{
    Answered, AskGrant, AskHandler, AskHandlers, AskRequest, CallClass, FetchOrigin, GuardedFetch,
    HostConfig, HostError, OrganCall, OrganHost, OrganSpec, Unanswered,
};
use oneiron_organ_protocol::{
    ASK_NET_FETCH, AskCode, AskRefusal, ByteBuf, FetchAsk, FetchMethod, Hash32, PROTOCOL,
    ProtocolVersion, touch_fold,
};

const PROBE: &str = env!("CARGO_BIN_EXE_oneiron-organ-probe");
const ANSWER: &str = "probe.answer";

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config).expect("open vault");
    (dir, vault)
}

fn spec(asks: Vec<AskGrant>) -> OrganSpec {
    let mut spec = OrganSpec::first_party("probe", PROBE);
    spec.verbs = vec!["organ.echo".into(), "probe.ask".into()];
    spec.asks = asks;
    spec
}

fn host(spec: OrganSpec) -> OrganHost {
    let host = OrganHost::new(HostConfig::default());
    host.install(spec);
    host
}

fn ask_call(verb: &str, value: rmpv::Value, times: u64, deadline: Duration) -> OrganCall {
    OrganCall {
        organ: "probe".into(),
        verb: "probe.ask".into(),
        schema: 1,
        args: rmpv::Value::Map(vec![
            ("verb".into(), verb.into()),
            ("value".into(), value),
            ("times".into(), times.into()),
        ]),
        body: None,
        inputs: Vec::new(),
        class: CallClass::Agent,
        deadline,
        grant: "g".into(),
    }
}

fn field<'a>(value: &'a rmpv::Value, key: &str) -> Option<&'a rmpv::Value> {
    value
        .as_map()?
        .iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
}

/// What the probe saw for each of its asks: the answer's value, or the
/// refusal code's name.
fn lines(report: &rmpv::Value) -> Vec<rmpv::Value> {
    report.as_array().expect("one line per ask").clone()
}

fn refused(line: &rmpv::Value) -> Option<&str> {
    field(line, "refused").and_then(rmpv::Value::as_str)
}

/// Answers with a value and `bytes` bytes, counting its runs.
struct Bytes {
    bytes: Vec<u8>,
    runs: AtomicUsize,
}

impl AskHandler for Bytes {
    fn answer(&self, ask: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        Ok(Answered {
            value: ask.value.clone(),
            data: Some(self.bytes.clone()),
            fetch: None,
        })
    }
}

fn bytes(len: usize) -> Bytes {
    Bytes {
        bytes: (0..len).map(|n| (n % 251) as u8).collect(),
        runs: AtomicUsize::new(0),
    }
}

/// Sleeps, then answers, counting its runs.
struct Slow(Duration, AtomicUsize);

impl AskHandler for Slow {
    fn answer(&self, _: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        self.1.fetch_add(1, Ordering::SeqCst);
        thread::sleep(self.0);
        Ok(Answered::default())
    }
}

#[test]
fn a_granted_ask_is_answered_through_a_region_and_receipted() {
    let (_dir, vault) = vault();
    let host = host(spec(vec![AskGrant::new(ANSWER, 4)]));
    // Over 64 KiB, so the answer crosses as a region the host sealed.
    let handler = bytes(200 * 1024);
    let asks = AskHandlers::none().with(ANSWER, &handler);
    let outcome = host
        .call_with(
            &vault,
            ask_call(ANSWER, "hi".into(), 2, Duration::from_secs(10)),
            Vec::new(),
            &asks,
        )
        .expect("call");
    let seen = lines(&outcome.report);
    assert_eq!(seen.len(), 2);
    for line in &seen {
        assert_eq!(
            field(line, "answered").and_then(rmpv::Value::as_str),
            Some("hi")
        );
        assert_eq!(
            field(line, "len").and_then(rmpv::Value::as_u64),
            Some(200 * 1024)
        );
        assert_eq!(
            field(line, "fold").and_then(rmpv::Value::as_u64),
            Some(touch_fold(&handler.bytes))
        );
    }
    assert_eq!(handler.runs.load(Ordering::SeqCst), 2);
    let receipt = outcome.receipt;
    assert_eq!(receipt.protocol, PROTOCOL);
    assert_eq!(receipt.asks.len(), 2);
    for (n, line) in receipt.asks.iter().enumerate() {
        assert_eq!(line.id as usize, n + 1);
        assert_eq!(line.verb, ANSWER);
        assert_eq!(line.refused, None);
        assert_eq!(line.data_hash, Some(Hash32::of(&handler.bytes)));
        assert_eq!(line.data_len, 200 * 1024);
    }
}

#[test]
fn an_ungranted_ask_is_refused_and_the_call_goes_on() {
    let (_dir, vault) = vault();
    let handler = bytes(8);
    // A handler the grant does not name never runs.
    let host_without_grant = host(spec(Vec::new()));
    let asks = AskHandlers::none().with(ANSWER, &handler);
    let outcome = host_without_grant
        .call_with(
            &vault,
            ask_call(ANSWER, rmpv::Value::Nil, 1, Duration::from_secs(10)),
            Vec::new(),
            &asks,
        )
        .expect("the organ goes on past a refusal");
    assert_eq!(refused(&lines(&outcome.report)[0]), Some("not_granted"));
    assert_eq!(outcome.receipt.asks[0].refused, Some(AskCode::NotGranted));
    assert_eq!(handler.runs.load(Ordering::SeqCst), 0);
    // A verb the grant names, with no handler for this call.
    let host_without_handler = host(spec(vec![AskGrant::new(ANSWER, 4)]));
    let outcome = host_without_handler
        .call(
            &vault,
            ask_call(ANSWER, rmpv::Value::Nil, 1, Duration::from_secs(10)),
        )
        .expect("the organ goes on past a refusal");
    assert_eq!(refused(&lines(&outcome.report)[0]), Some("not_granted"));
}

#[test]
fn an_ask_past_the_deadline_is_cancelled_and_the_organ_lives() {
    let (_dir, vault) = vault();
    let host = host(spec(vec![AskGrant::new(ANSWER, 4)]));
    host.warm("probe").expect("warm");
    let pid = host.status("probe").expect("installed").pid;
    let slow = Slow(Duration::from_millis(600), AtomicUsize::new(0));
    let asks = AskHandlers::none().with(ANSWER, &slow);
    let started = Instant::now();
    let result = host.call_with(
        &vault,
        ask_call(ANSWER, rmpv::Value::Nil, 1, Duration::from_millis(200)),
        Vec::new(),
        &asks,
    );
    assert!(
        matches!(result, Err(HostError::DeadlineExceeded)),
        "{result:?}"
    );
    // The handler's own time plus the cancel grace, never a second ask.
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(slow.1.load(Ordering::SeqCst), 1);
    // The organ took the cancel: its ask woke, so it was not killed.
    assert_eq!(host.status("probe").expect("installed").pid, pid);
    let fast = bytes(4);
    let asks = AskHandlers::none().with(ANSWER, &fast);
    host.call_with(
        &vault,
        ask_call(ANSWER, rmpv::Value::Nil, 1, Duration::from_secs(10)),
        Vec::new(),
        &asks,
    )
    .expect("the next call runs");
}

/// Outlasts the call's deadline, then records whether the organ was still
/// running when it came back.
struct Outlasts<'a> {
    host: &'a OrganHost,
    sleep: Duration,
    pid_after: Mutex<Option<Option<u32>>>,
}

impl AskHandler for Outlasts<'_> {
    fn answer(&self, _: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        thread::sleep(self.sleep);
        let pid = self.host.status("probe").expect("installed").pid;
        *self.pid_after.lock().expect("pid") = Some(pid);
        Ok(Answered::default())
    }
}

#[test]
fn a_deadline_stops_an_organ_deaf_to_its_cancel_while_the_handler_runs() {
    let (_dir, vault) = vault();
    let host = rogue("--ask-once");
    // Started first: on a slow host a cold start alone can spend 200 ms.
    host.warm("probe").expect("warm");
    let handler = Outlasts {
        host: &host,
        sleep: Duration::from_millis(1500),
        pid_after: Mutex::new(None),
    };
    let asks = AskHandlers::none().with(ANSWER, &handler);
    let result = host.call_with(&vault, echo(Duration::from_millis(200)), Vec::new(), &asks);
    assert!(
        matches!(result, Err(HostError::DeadlineExceeded)),
        "{result:?}"
    );
    // Cancelled at the deadline and stopped after the grace, while the
    // handler still ran: the organ was gone before it came back.
    assert_eq!(*handler.pid_after.lock().expect("pid"), Some(None));
}

struct Panics;

impl AskHandler for Panics {
    fn answer(&self, _: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        panic!("a handler bug");
    }
}

#[test]
fn a_handler_that_panics_frees_its_call() {
    let (_dir, vault) = vault();
    let mut one = spec(vec![AskGrant::new(ANSWER, 4)]);
    one.threads = 1;
    let host = host(one);
    let asks = AskHandlers::none().with(ANSWER, &Panics);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        host.call_with(
            &vault,
            ask_call(ANSWER, rmpv::Value::Nil, 1, Duration::from_secs(10)),
            Vec::new(),
            &asks,
        )
    }));
    assert!(panicked.is_err());
    // The ask stays on record though its handler never returned.
    let asked = asks.asked();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].unanswered, Some(Unanswered::NotSent));
    // The one seat is free, and the cancel woke the organ's waiting ask, so
    // its one thread takes the next call.
    let fast = bytes(4);
    let asks = AskHandlers::none().with(ANSWER, &fast);
    host.call_with(
        &vault,
        ask_call(ANSWER, rmpv::Value::Nil, 1, Duration::from_secs(5)),
        Vec::new(),
        &asks,
    )
    .expect("the next call runs");
}

/// Outlasts the call's deadline, then panics.
struct PanicsLate(Duration);

impl AskHandler for PanicsLate {
    fn answer(&self, _: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        thread::sleep(self.0);
        panic!("a handler bug past the deadline");
    }
}

#[test]
fn a_handler_that_panics_in_the_grace_still_stops_a_deaf_organ() {
    let (_dir, vault) = vault();
    let host = rogue("--ask-once");
    host.warm("probe").expect("warm");
    // Back inside the grace: the deadline's cancel went out, unanswered.
    let handler = PanicsLate(Duration::from_millis(250));
    let asks = AskHandlers::none().with(ANSWER, &handler);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        host.call_with(&vault, echo(Duration::from_millis(200)), Vec::new(), &asks)
    }));
    assert!(panicked.is_err());
    // The grace ran out before the panic went on, and the organ was stopped.
    assert_eq!(host.status("probe").expect("installed").pid, None);
}

#[test]
fn an_organ_that_keeps_asking_is_refused_once_then_cut_off() {
    let (_dir, vault) = vault();
    let host = host(spec(vec![AskGrant::new(ANSWER, 4)]));
    let handler = bytes(4);
    let asks = AskHandlers::none().with(ANSWER, &handler);
    let started = Instant::now();
    let result = host.call_with(
        &vault,
        ask_call(ANSWER, rmpv::Value::Nil, 100_000, Duration::from_secs(30)),
        Vec::new(),
        &asks,
    );
    assert!(matches!(result, Err(HostError::AskBudget)), "{result:?}");
    assert_eq!(handler.runs.load(Ordering::SeqCst), 4);
    assert!(started.elapsed() < Duration::from_secs(5));
    // Ending the call cancelled it; the organ stopped and lives on.
    host.call(
        &vault,
        OrganCall {
            verb: "organ.echo".into(),
            args: 1.into(),
            ..ask_call(ANSWER, rmpv::Value::Nil, 0, Duration::from_secs(10))
        },
    )
    .expect("the next call runs");
}

fn rogue(mode: &str) -> OrganHost {
    let mut spec = spec(vec![AskGrant::new(ANSWER, 4)]);
    spec.args = vec![mode.into()];
    spec.verbs = vec!["organ.echo".into()];
    host(spec)
}

fn echo(deadline: Duration) -> OrganCall {
    OrganCall {
        organ: "probe".into(),
        verb: "organ.echo".into(),
        schema: 1,
        args: 7.into(),
        body: None,
        inputs: Vec::new(),
        class: CallClass::Agent,
        deadline,
        grant: "g".into(),
    }
}

#[test]
fn a_second_ask_in_flight_or_a_stale_ask_ends_the_organ() {
    let (_dir, vault) = vault();
    for mode in ["--ask-twice", "--stale-asks"] {
        let host = rogue(mode);
        let slow = Slow(Duration::from_millis(100), AtomicUsize::new(0));
        let asks = AskHandlers::none().with(ANSWER, &slow);
        let started = Instant::now();
        let result = host.call_with(&vault, echo(Duration::from_secs(30)), Vec::new(), &asks);
        assert!(
            matches!(result, Err(HostError::Crashed(_))),
            "{mode}: {result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(5), "{mode}");
        assert!(slow.1.load(Ordering::SeqCst) <= 1, "{mode}");
        assert_eq!(host.status("probe").expect("installed").pid, None, "{mode}");
    }
}

#[test]
fn an_organ_built_for_1_0_still_runs() {
    let (_dir, vault) = vault();
    let host = rogue("--v1-0");
    let handler = bytes(4);
    let asks = AskHandlers::none().with(ANSWER, &handler);
    for _ in 0..3 {
        let outcome = host
            .call_with(&vault, echo(Duration::from_secs(10)), Vec::new(), &asks)
            .expect("echo");
        assert_eq!(outcome.report.as_u64(), Some(7));
        assert_eq!(
            outcome.receipt.protocol,
            ProtocolVersion { major: 1, minor: 0 }
        );
        assert!(outcome.receipt.asks.is_empty());
    }
    assert_eq!(host.status("probe").expect("installed").spawns, 1);
}

/// Tries to call an organ from inside its handler.
struct Nested<'a> {
    host: &'a OrganHost,
    vault: &'a Vault,
    seen: Mutex<Option<String>>,
}

impl AskHandler for Nested<'_> {
    fn answer(&self, _: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        let inner = self.host.call(self.vault, echo(Duration::from_secs(5)));
        *self.seen.lock().expect("seen") = Some(format!("{inner:?}"));
        Err(AskRefusal::new(AskCode::Failed, "nested"))
    }
}

#[test]
fn a_handler_may_not_call_an_organ() {
    let (_dir, vault) = vault();
    let host = host(spec(vec![AskGrant::new(ANSWER, 4)]));
    let nested = Nested {
        host: &host,
        vault: &vault,
        seen: Mutex::new(None),
    };
    let asks = AskHandlers::none().with(ANSWER, &nested);
    let outcome = host
        .call_with(
            &vault,
            ask_call(ANSWER, rmpv::Value::Nil, 1, Duration::from_secs(10)),
            Vec::new(),
            &asks,
        )
        .expect("the organ goes on");
    assert_eq!(refused(&lines(&outcome.report)[0]), Some("failed"));
    let seen = nested.seen.lock().expect("seen").clone().expect("ran");
    assert!(seen.contains("Reentrant"), "{seen}");
}

/// A one-thread HTTP server on loopback: `/hop` redirects to `to`, `/drip`
/// drips its body, any other path answers `hello`. Returns its port and the
/// paths it was asked for.
fn serve(to: Option<String>) -> (u16, std::sync::Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let asked = std::sync::Arc::new(Mutex::new(Vec::new()));
    let log = std::sync::Arc::clone(&asked);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut first = String::new();
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            if reader.read_line(&mut first).is_err() {
                continue;
            }
            loop {
                let mut header = String::new();
                match reader.read_line(&mut header) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if header == "\r\n" => break,
                    Ok(_) => {}
                }
            }
            let path = first
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            log.lock().expect("log").push(path.clone());
            if path == "/drip" {
                // A hundred bytes, one every 100 ms: each read makes progress.
                let head = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n";
                if stream.write_all(head.as_bytes()).is_err() {
                    continue;
                }
                for _ in 0..100 {
                    thread::sleep(Duration::from_millis(100));
                    if stream.write_all(b"x").is_err() {
                        log.lock().expect("log").push("/drip:closed".into());
                        break;
                    }
                }
                continue;
            }
            let response = match (path.as_str(), &to) {
                ("/hop", Some(to)) => format!(
                    "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ),
                _ => "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".into(),
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (port, asked)
}

/// A fetch ask as an organ sends it: named fields, enums by name.
fn fetch(url: &str) -> rmpv::Value {
    let bytes = rmp_serde::to_vec_named(&FetchAsk {
        purpose: "test".into(),
        method: FetchMethod::Get,
        url: url.into(),
        content_type: None,
        body: None,
    })
    .expect("fetch encodes");
    rmpv::decode::read_value(&mut bytes.as_slice()).expect("fetch value")
}

#[test]
fn a_granted_fetch_reaches_only_its_allowlist() {
    let (_dir, vault) = vault();
    let (outside, outside_asked) = serve(None);
    let (port, asked) = serve(Some(format!("http://127.0.0.1:{outside}/ok")));
    let mut granted = spec(vec![AskGrant::new(ASK_NET_FETCH, 8)]);
    granted.fetch.origins = vec![FetchOrigin::new("http", "127.0.0.1", port)];
    granted.fetch.private_cidrs = vec!["127.0.0.1/32".parse().expect("cidr")];
    let host = host(granted);
    let asks = AskHandlers::none().with(ASK_NET_FETCH, &GuardedFetch);
    let run = |url: String| {
        host.call_with(
            &vault,
            ask_call(ASK_NET_FETCH, fetch(&url), 1, Duration::from_secs(10)),
            Vec::new(),
            &asks,
        )
        .expect("the organ goes on")
    };
    // On the allowlist, with loopback granted by CIDR: fetched.
    let outcome = run(format!("http://127.0.0.1:{port}/ok"));
    let line = &lines(&outcome.report)[0];
    let answer = field(line, "answered").expect("answered");
    assert_eq!(
        field(answer, "status").and_then(rmpv::Value::as_u64),
        Some(200)
    );
    assert_eq!(field(line, "len").and_then(rmpv::Value::as_u64), Some(5));
    let target = outcome.receipt.asks[0].fetch.clone().expect("target");
    assert_eq!(target.origin, format!("http://127.0.0.1:{port}"));
    assert_eq!(target.status, 200);
    // Another port is another origin: refused before any byte leaves.
    let outcome = run(format!("http://127.0.0.1:{outside}/ok"));
    assert_eq!(refused(&lines(&outcome.report)[0]), Some("not_granted"));
    // A redirect off the allowlist is refused at the hop.
    let outcome = run(format!("http://127.0.0.1:{port}/hop"));
    assert_eq!(refused(&lines(&outcome.report)[0]), Some("not_granted"));
    assert!(outside_asked.lock().expect("log").is_empty());
    assert_eq!(*asked.lock().expect("log"), vec!["/ok", "/hop"]);
    // Without the CIDR, loopback is not a global address: refused.
    let mut ungranted = spec(vec![AskGrant::new(ASK_NET_FETCH, 8)]);
    ungranted.fetch.origins = vec![FetchOrigin::new("http", "127.0.0.1", port)];
    let host = self::host(ungranted);
    let outcome = host
        .call_with(
            &vault,
            ask_call(
                ASK_NET_FETCH,
                fetch(&format!("http://127.0.0.1:{port}/ok")),
                1,
                Duration::from_secs(10),
            ),
            Vec::new(),
            &asks,
        )
        .expect("the organ goes on");
    assert_eq!(refused(&lines(&outcome.report)[0]), Some("not_granted"));
    assert_eq!(asked.lock().expect("log").len(), 2);
}

fn fetching(port: u16) -> OrganHost {
    let mut granted = spec(vec![AskGrant::new(ASK_NET_FETCH, 8)]);
    granted.fetch.origins = vec![FetchOrigin::new("http", "127.0.0.1", port)];
    granted.fetch.private_cidrs = vec!["127.0.0.1/32".parse().expect("cidr")];
    host(granted)
}

#[test]
fn a_fetch_that_drips_its_body_ends_at_the_deadline() {
    // Astra (#1378) P1: reqwest's blocking timeout restarts at every read,
    // so a body dripped a byte at a time held the call for ten seconds.
    let (_dir, vault) = vault();
    let (port, served) = serve(None);
    let host = fetching(port);
    let asks = AskHandlers::none().with(ASK_NET_FETCH, &GuardedFetch);
    let started = Instant::now();
    let result = host.call_with(
        &vault,
        ask_call(
            ASK_NET_FETCH,
            fetch(&format!("http://127.0.0.1:{port}/drip")),
            1,
            Duration::from_secs(1),
        ),
        Vec::new(),
        &asks,
    );
    assert!(
        matches!(result, Err(HostError::DeadlineExceeded)),
        "{result:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    let asked = asks.asked();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].unanswered, Some(Unanswered::NotSent));
    // The fetch was dropped with its connection: the server's next writes
    // fail, so nothing of the host's is left reading.
    let closed = (0..40).any(|_| {
        thread::sleep(Duration::from_millis(50));
        served
            .lock()
            .expect("log")
            .iter()
            .any(|path| path == "/drip:closed")
    });
    assert!(closed, "{:?}", served.lock().expect("log"));
}

/// A one-thread HTTP server on loopback: `/301`, `/302`, `/303`, `/307` and
/// `/308` redirect to `/landed` with that status; any other path answers
/// `hello`. Returns its port and each request as `METHOD path content-type
/// body`.
fn serve_redirects() -> (u16, std::sync::Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let asked = std::sync::Arc::new(Mutex::new(Vec::new()));
    let log = std::sync::Arc::clone(&asked);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut first = String::new();
            if reader.read_line(&mut first).is_err() {
                continue;
            }
            let (mut content_type, mut len) = ("-".to_owned(), 0);
            loop {
                let mut header = String::new();
                match reader.read_line(&mut header) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if header == "\r\n" => break,
                    Ok(_) => {}
                }
                let (name, value) = header.split_once(':').unwrap_or_default();
                match name.to_ascii_lowercase().as_str() {
                    "content-type" => value.trim().clone_into(&mut content_type),
                    "content-length" => len = value.trim().parse().unwrap_or_default(),
                    _ => {}
                }
            }
            let mut body = vec![0; len];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            let mut words = first.split_whitespace();
            let (method, path) = (
                words.next().unwrap_or_default(),
                words.next().unwrap_or_default(),
            );
            log.lock().expect("log").push(format!(
                "{method} {path} {content_type} {}",
                String::from_utf8_lossy(&body)
            ));
            let response = match path.trim_start_matches('/').parse::<u16>() {
                Ok(code) => format!(
                    "HTTP/1.1 {code} Moved\r\nLocation: /landed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ),
                Err(_) => "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".into(),
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (port, asked)
}

#[test]
fn a_redirected_post_keeps_its_body_only_on_307_and_308() {
    // CodeRabbit (#1378): every hop re-sent the POST and its body. A
    // timestamp request is the first POST an organ sends.
    let (_dir, vault) = vault();
    let (port, asked) = serve_redirects();
    let host = fetching(port);
    let asks = AskHandlers::none().with(ASK_NET_FETCH, &GuardedFetch);
    for (code, then) in [
        (301, "GET /landed - "),
        (302, "GET /landed - "),
        (303, "GET /landed - "),
        (307, "POST /landed application/timestamp-query query"),
        (308, "POST /landed application/timestamp-query query"),
    ] {
        asked.lock().expect("log").clear();
        let bytes = rmp_serde::to_vec_named(&FetchAsk {
            purpose: "test".into(),
            method: FetchMethod::Post,
            url: format!("http://127.0.0.1:{port}/{code}"),
            content_type: Some("application/timestamp-query".into()),
            body: Some(ByteBuf::from(b"query".to_vec())),
        })
        .expect("fetch encodes");
        let post = rmpv::decode::read_value(&mut bytes.as_slice()).expect("fetch value");
        let outcome = host
            .call_with(
                &vault,
                ask_call(ASK_NET_FETCH, post, 1, Duration::from_secs(10)),
                Vec::new(),
                &asks,
            )
            .expect("the organ goes on");
        let line = &lines(&outcome.report)[0];
        let answer = field(line, "answered").expect("answered");
        assert_eq!(
            field(answer, "status").and_then(rmpv::Value::as_u64),
            Some(200),
            "{code}"
        );
        assert_eq!(
            *asked.lock().expect("log"),
            vec![
                format!("POST /{code} application/timestamp-query query"),
                then.to_owned()
            ],
            "{code}"
        );
    }
}

#[test]
fn an_answer_value_counts_against_the_answer_bytes() {
    // Astra (#1378) P2: only an answer's data was charged, so a fetch's 4 KiB
    // final URL crossed under a 1 KiB cap.
    let (_dir, vault) = vault();
    let (port, asked) = serve(None);
    let mut granted = spec(vec![
        AskGrant::new(ASK_NET_FETCH, 4),
        AskGrant::new(ANSWER, 4),
    ]);
    granted.fetch.origins = vec![FetchOrigin::new("http", "127.0.0.1", port)];
    granted.fetch.private_cidrs = vec!["127.0.0.1/32".parse().expect("cidr")];
    granted.max_ask_bytes = 1024;
    let host = host(granted);
    let echoes = bytes(0);
    let asks = AskHandlers::none()
        .with(ASK_NET_FETCH, &GuardedFetch)
        .with(ANSWER, &echoes);
    let long = format!("http://127.0.0.1:{port}/{}", "a".repeat(4096));
    let calls = [
        ask_call(ASK_NET_FETCH, fetch(&long), 1, Duration::from_secs(10)),
        ask_call(ANSWER, "x".repeat(4096).into(), 1, Duration::from_secs(10)),
    ];
    for call in calls {
        let outcome = host
            .call_with(&vault, call, Vec::new(), &asks)
            .expect("the organ goes on");
        assert_eq!(refused(&lines(&outcome.report)[0]), Some("too_large"));
        assert_eq!(outcome.receipt.asks[0].refused, Some(AskCode::TooLarge));
    }
    // The fetch itself ran; only its answer was over the cap.
    assert_eq!(asked.lock().expect("log").len(), 1);
    assert_eq!(echoes.runs.load(Ordering::SeqCst), 1);
}

#[test]
fn an_ask_queued_behind_its_calls_reply_is_never_answered() {
    // Astra (#1378) P2: the organ asks and replies back to back; the host
    // ran the queued ask and sent its answer after the reply. This organ
    // exits if it is ever answered.
    let (_dir, vault) = vault();
    let host = rogue("--ask-then-reply");
    let slow = Slow(Duration::from_millis(200), AtomicUsize::new(0));
    let asks = AskHandlers::none().with(ANSWER, &slow);
    for _ in 0..2 {
        let outcome = host
            .call_with(&vault, echo(Duration::from_secs(10)), Vec::new(), &asks)
            .expect("the reply stands");
        assert_eq!(outcome.receipt.asks.len(), 1);
        assert!(outcome.receipt.asks[0].unanswered.is_some());
    }
    // Whether a handler started depends on which thread won the reply; its
    // answer never went, so the organ is the one it started as.
    assert!(slow.1.load(Ordering::SeqCst) <= 2);
    let status = host.status("probe").expect("installed");
    assert_eq!(status.spawns, 1);
    assert_eq!(status.recent_crashes, 0);
    assert!(status.pid.is_some());
}

/// On its run, lets a large call take the writer, then has the grant
/// revoked while this call's answer waits for that writer.
struct Racer {
    take_writer: Mutex<mpsc::Sender<()>>,
    revoke: Mutex<mpsc::Sender<()>>,
}

impl AskHandler for Racer {
    fn answer(&self, _: &AskRequest<'_>) -> Result<Answered, AskRefusal> {
        let _ = self.take_writer.lock().expect("sender").send(());
        thread::sleep(Duration::from_millis(300));
        let _ = self.revoke.lock().expect("sender").send(());
        Ok(Answered::default())
    }
}

#[test]
fn an_answer_that_waits_for_the_writer_never_follows_a_revoked_cancel() {
    // Astra (#1378) P2, as it wrote the race. The organ asks under grant `a`
    // and stops reading for 1.5 s. A large call under grant `b` takes the
    // writer; the answer waits for it; `a` is revoked, and its cancel waits
    // too. When the organ reads again, the answer must not go, whichever
    // thread takes the writer first. The organ exits if it is answered.
    let (_dir, vault) = vault();
    let mut racing = spec(vec![AskGrant::new(ANSWER, 4)]);
    racing.args = vec!["--ask-then-nap".into()];
    racing.verbs = vec!["organ.echo".into()];
    racing.threads = 2;
    let host = OrganHost::new(HostConfig {
        cancel_grace: Duration::from_secs(3),
        ..HostConfig::default()
    });
    host.install(racing);
    let (take_writer, writer_taken) = mpsc::channel();
    let (revoke, revoked) = mpsc::channel();
    let racer = Racer {
        take_writer: Mutex::new(take_writer),
        revoke: Mutex::new(revoke),
    };
    let asks = AskHandlers::none().with(ANSWER, &racer);
    let (host, vault) = (&host, &vault);
    let result = thread::scope(|scope| {
        scope.spawn(move || {
            if writer_taken.recv_timeout(Duration::from_secs(30)).is_ok() {
                let large = OrganCall {
                    args: "x".repeat(8 * 1024 * 1024).into(),
                    grant: "b".into(),
                    ..echo(Duration::from_secs(20))
                };
                let _ = host.call(vault, large);
            }
        });
        scope.spawn(move || {
            if revoked.recv_timeout(Duration::from_secs(30)).is_ok() {
                thread::sleep(Duration::from_millis(300));
                host.revoke_grant("a");
            }
        });
        let call = OrganCall {
            grant: "a".into(),
            ..echo(Duration::from_secs(20))
        };
        host.call_with(vault, call, Vec::new(), &asks)
    });
    assert!(matches!(result, Err(HostError::Revoked)), "{result:?}");
    let asked = asks.asked();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].unanswered, Some(Unanswered::NotSent));
    // The host stopped the organ for the revocation; it never exited on an
    // answer, which would count as a crash.
    assert_eq!(host.status("probe").expect("installed").recent_crashes, 0);
}

#[test]
fn a_failed_call_keeps_its_ask_lines() {
    // Astra (#1378) P2: an organ that asked, was answered, then failed
    // erased the record of what the handler did.
    let (_dir, vault) = vault();
    let host = host(spec(vec![AskGrant::new(ANSWER, 4)]));
    let handler = bytes(16);
    let asks = AskHandlers::none().with(ANSWER, &handler);
    let mut call = ask_call(ANSWER, "hi".into(), 1, Duration::from_secs(10));
    if let rmpv::Value::Map(args) = &mut call.args {
        args.push(("fail".into(), true.into()));
    }
    let result = host.call_with(&vault, call, Vec::new(), &asks);
    assert!(matches!(result, Err(HostError::Organ(_))), "{result:?}");
    let asked = asks.asked();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].verb, ANSWER);
    assert!(asked[0].answer_digest.is_some());
    assert_eq!(asked[0].data_hash, Some(Hash32::of(&handler.bytes)));
    assert_eq!(asked[0].unanswered, None);
}
