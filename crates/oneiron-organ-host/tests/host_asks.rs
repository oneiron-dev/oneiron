//! Protocol 1.1 asks against a real organ process (the probe). Each test
//! pins a rule of the asks design (ARCH-0075 `#organ-host-design-asks`):
//! only an ask the grant names and the caller answers gets an answer, a
//! refusal leaves the call to the organ, an ask runs inside its call's
//! deadline, a flooding organ is cut off, a handler cannot nest a call, a
//! fetch reaches only its allowlist, and an organ built for 1.0 still runs.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use oneiron::{Vault, VaultConfig};
use oneiron_organ_host::{
    Answered, AskGrant, AskHandler, AskHandlers, AskRequest, CallClass, FetchOrigin, GuardedFetch,
    HostConfig, HostError, OrganCall, OrganHost, OrganSpec,
};
use oneiron_organ_protocol::{
    ASK_NET_FETCH, AskCode, AskRefusal, FetchAsk, FetchMethod, Hash32, PROTOCOL, ProtocolVersion,
    touch_fold,
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

/// A one-thread HTTP server on loopback: `/ok` answers, `/hop` redirects to
/// `to`. Returns its port and the paths it was asked for.
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

fn fetch(url: &str) -> rmpv::Value {
    rmpv::ext::to_value(FetchAsk {
        purpose: "test".into(),
        method: FetchMethod::Get,
        url: url.into(),
        content_type: None,
        body: None,
    })
    .expect("fetch value")
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
