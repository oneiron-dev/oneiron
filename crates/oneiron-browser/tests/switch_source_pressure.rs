//! A switched engine's receipt names the pids pressure its source guest
//! showed before the switch dropped it (FIX
//! [BROWSER-SWITCH-SOURCE-PRESSURE-NO-RECEIPT], Engine ANSWER 20 Nov 20:41
//! = B): the source manifest goes with the source guest, so no later answer
//! can name those hits. The switch's own entry reads the source's pressure,
//! and the commit reads it once more before the source goes: the test's
//! starter raises the source's count while the target starts, and the
//! receipt carries the later count. An unchanged switch keeps its source and
//! names none.
//!
//! The source is Chromium on a scripted NUL-framed CDP pipe at about:blank,
//! the target Lightpanda on a scripted CDP WebSocket; each guest's lease
//! reports the pids-limit hits the test sets.
#![cfg(all(target_os = "linux", feature = "driver"))]

use oneiron_browser::{
    BrowserDriver, BrowserEngine, BrowserError, BrowserGuest, BrowserGuestStarter, BrowserSession,
    GuestLimits, HandleRetention, SendPolicy, StartedGuest, SwitchEngineInput,
};
use oneiron_container::{
    EgressRelay, GuestPressure, HostNetFloor, HttpRequest, HttpResponse, SessionLease,
    SessionManifest, SessionTransport, UnmeteredFloor,
};
use serde_json::{Value, json};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const IMAGE: &str = concat!(
    "example.invalid/guest@sha256:",
    "0000000000000000000000000000000000000000000000000000000000000000",
);
/// The source's hits after its last answer, read at the switch's entry.
const HITS_AT_ENTRY: u64 = 5;
/// The source's hits once the target starts, read at the commit.
const HITS_AT_COMMIT: u64 = 7;

/// A guest's lease that stays up and reports `hits` pids-limit refusals,
/// none while the count is zero.
struct CountedLease {
    hits: Arc<AtomicU64>,
}

impl SessionLease for CountedLease {
    fn is_running(&mut self) -> bool {
        true
    }

    fn observe_pressure(&self) -> Option<GuestPressure> {
        let hits = self.hits.load(Ordering::SeqCst);
        (hits > 0).then_some(GuestPressure::Processes { hits })
    }
}

/// A manifest that claims a proved fence, as an attach requires, and no
/// pressure.
fn manifest() -> SessionManifest {
    let manifest: SessionManifest = serde_json::from_value(json!({
        "backend": "test",
        "runtime": "test",
        "image": IMAGE,
        "argv_digest": "argv",
        "network": "none",
        "seccomp": "runtime_default",
        "generation": "generation-1",
        "fence_proof": {
            "ruleset_hash": "ruleset",
            "seccomp_hash": "seccomp",
            "network_routes": [],
            "network_evidence_digest": "evidence",
            "sandbox_generation": "generation-1",
            "launcher_digest": "launcher",
        },
    }))
    .expect("a test manifest");
    assert_eq!(manifest.guest_pressure, None, "nothing read before attach");
    manifest
}

fn transport(host_end: UnixStream, hits: &Arc<AtomicU64>) -> SessionTransport {
    SessionTransport {
        reader: Box::new(host_end.try_clone().expect("reader end")),
        writer: Box::new(host_end),
        manifest: manifest(),
        lease: Box::new(CountedLease {
            hits: Arc::clone(hits),
        }),
    }
}

/// The reply to one CDP call: the target list empty, a created target and
/// an attached session named, every other call an empty result; the call's
/// session echoed.
fn reply(message: &Value) -> Option<Value> {
    let id = message.get("id").cloned()?;
    let result = match message.get("method").and_then(Value::as_str) {
        Some("Target.getTargets") => json!({"targetInfos": []}),
        Some("Target.createTarget") => json!({"targetId": "page-1"}),
        Some("Target.attachToTarget") => json!({"sessionId": "session-1"}),
        Some("Target.getTargetInfo") => json!({"targetInfo": {"url": "about:blank", "title": ""}}),
        Some("Network.getAllCookies") => json!({"cookies": []}),
        _ => json!({}),
    };
    let mut reply = json!({"id": id, "result": result});
    if let Some(session) = message.get("sessionId") {
        reply["sessionId"] = session.clone();
    }
    Some(reply)
}

/// Answers Chromium's NUL-framed CDP pipe.
fn scripted_chromium(stream: UnixStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("cdp reader"));
    let mut writer = stream;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(0, &mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if buf.last() == Some(&0) {
            buf.pop();
        }
        let Some(answer) = serde_json::from_slice::<Value>(&buf)
            .ok()
            .as_ref()
            .and_then(reply)
        else {
            continue;
        };
        let mut bytes = serde_json::to_vec(&answer).expect("cdp reply");
        bytes.push(0);
        if writer
            .write_all(&bytes)
            .and_then(|()| writer.flush())
            .is_err()
        {
            return;
        }
    }
}

/// Reads one HTTP head from `stream`, byte by byte, so nothing past its
/// blank line is taken from the stream.
fn read_head(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    Ok(head)
}

/// Answers Lightpanda's CDP WebSocket: its discovery request, its upgrade,
/// then each text message's call.
fn scripted_lightpanda(mut stream: UnixStream) {
    let Ok(head) = read_head(&mut stream) else {
        return;
    };
    assert!(
        head.starts_with(b"GET /json/version "),
        "the host asks discovery first: {}",
        String::from_utf8_lossy(&head)
    );
    let body = r#"{"Browser":"Lightpanda/1.0","webSocketDebuggerUrl":"ws://localhost/"}"#;
    let answer = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    if stream.write_all(answer.as_bytes()).is_err() {
        return;
    }
    let Ok(mut socket) = tungstenite::accept(stream) else {
        return;
    };
    loop {
        let message = match socket.read() {
            Ok(tungstenite::Message::Text(text)) => text,
            Ok(tungstenite::Message::Close(_)) | Err(_) => return,
            Ok(_) => continue,
        };
        let Some(answer) = serde_json::from_str::<Value>(message.as_str())
            .ok()
            .as_ref()
            .and_then(reply)
        else {
            continue;
        };
        if socket
            .send(tungstenite::Message::text(answer.to_string()))
            .is_err()
        {
            return;
        }
    }
}

/// Holds nothing against any floor.
struct Unmetered;

impl HandleRetention for Unmetered {
    fn resize(&mut self, _bytes: usize) -> bool {
        true
    }
}

/// The session reaches nothing.
struct NoEgress;

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "this test has no egress")
}

impl EgressRelay for NoEgress {
    fn connect(&self, _target: SocketAddr) -> io::Result<TcpStream> {
        Err(refused())
    }

    fn authorize_datagram(&self, _target: SocketAddr) -> io::Result<()> {
        Err(refused())
    }

    fn record_session(&self, _manifest: &SessionManifest) -> io::Result<()> {
        Ok(())
    }

    fn record_abandoned(&self, _manifest: &SessionManifest) -> io::Result<()> {
        Ok(())
    }

    fn datagram(&self, _target: SocketAddr, _bytes: &[u8]) -> io::Result<Vec<u8>> {
        Err(refused())
    }

    fn fetch(&self, _request: HttpRequest) -> io::Result<HttpResponse> {
        Err(refused())
    }

    fn transferred(&self, _target: SocketAddr, _content_hash: [u8; 32], _bytes: u64) {}

    fn host_net_floor(&self) -> &dyn HostNetFloor {
        &UnmeteredFloor
    }
}

/// Starts the switch's Lightpanda target on a scripted WebSocket, with no
/// pressure of its own; while it starts, the source guest's count rises to
/// [`HITS_AT_COMMIT`].
struct ScriptedStarter {
    source_hits: Arc<AtomicU64>,
}

impl BrowserGuestStarter for ScriptedStarter {
    fn start(&mut self, engine: BrowserEngine) -> Result<StartedGuest, BrowserError> {
        assert_eq!(engine, BrowserEngine::Lightpanda, "the switch's target");
        self.source_hits.store(HITS_AT_COMMIT, Ordering::SeqCst);
        let (host_end, guest_end) = UnixStream::pair().expect("websocket pipe");
        std::thread::spawn(move || scripted_lightpanda(guest_end));
        Ok(StartedGuest {
            transport: transport(host_end, &Arc::new(AtomicU64::new(0))),
            relay: Arc::new(NoEgress),
            retention: Box::new(Unmetered),
        })
    }

    fn state_charge(&self) -> Box<dyn HandleRetention> {
        Box::new(Unmetered)
    }
}

fn switch(session: &mut BrowserSession, engine: BrowserEngine) -> Value {
    let output = session
        .switch_engine(SwitchEngineInput {
            engine,
            reason: "the page needs the other engine".to_owned(),
            snapshot_bounds: None,
        })
        .expect("an admitted switch answers with its receipt");
    let receipt = serde_json::to_value(&output.receipt).expect("receipt json");
    receipt["engine_switch"].clone()
}

#[test]
fn switched_receipt_names_the_source_guest_pressure() {
    let source_hits = Arc::new(AtomicU64::new(0));
    let (host_end, guest_end) = UnixStream::pair().expect("cdp pipe");
    std::thread::spawn(move || scripted_chromium(guest_end));
    let config = BrowserGuest {
        runtime: std::env::temp_dir().join("no-runtime"),
        image: IMAGE.to_owned(),
        limits: GuestLimits {
            memory_mib: 256,
            cpu_millis: 1000,
            pids: 64,
            tmpfs_mib: 64,
        },
        wait_cap: Duration::from_secs(5),
        policy: SendPolicy::default(),
        fixture: None,
        fixture_forward: None,
        engine: BrowserEngine::Chromium,
    };
    let starter = ScriptedStarter {
        source_hits: Arc::clone(&source_hits),
    };
    let mut session = BrowserSession::attach(
        &config,
        transport(host_end, &source_hits),
        Arc::new(NoEgress),
        Box::new(Unmetered),
        Some(Box::new(starter)),
        None,
    )
    .expect("the scripted browser attaches");

    // The source showed hits after its last answer.
    source_hits.store(HITS_AT_ENTRY, Ordering::SeqCst);

    // Unchanged: the source stays, with its own manifest, and the record
    // names no source pressure.
    let unchanged = switch(&mut session, BrowserEngine::Chromium);
    assert_eq!(unchanged["outcome"]["state"], "unchanged", "{unchanged}");
    assert_eq!(unchanged.get("source_guest_pressure"), None, "{unchanged}");

    let record = switch(&mut session, BrowserEngine::Lightpanda);
    assert_eq!(record["outcome"]["state"], "switched", "{record}");
    assert_eq!(
        record["source_guest_pressure"],
        json!({"processes": {"hits": HITS_AT_COMMIT}}),
        "the switched receipt names the source's hits, read as the switch commits: {record}"
    );
    assert_eq!(
        session.manifest().guest_pressure,
        None,
        "the target's own manifest names none of the source's hits"
    );
}
