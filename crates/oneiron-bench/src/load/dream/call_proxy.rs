//! The model-call timing proxy of `load dream` (FIX 21929). The server's
//! `[models]` provider points here; every byte goes on to the model gateway
//! unchanged, and each HTTP call is recorded when its response ends: its
//! request start, first response byte and end, its status and sizes, and
//! what tells calls apart without their text. A call's `schema` is the
//! digest of the JSON schema it asks for (one per role); `retry_of` names
//! an earlier call with the same body digest, and `extends` an earlier call
//! whose messages are a strict prefix of this one's (a corrective call).
//! Nothing records a header (the key rides in one) or a body: only digests
//! and counts. The engine puts no attempt or step id on the wire, so a call
//! joins its attempt by time: the stage lines' `call_ms` spans hold each
//! attempt's own extraction calls.
//!
//! It reads plain HTTP/1.1 only, so it runs for an `http://` gateway (as on
//! nelly, CPA over the tailnet) and stays off for `https://`.

use std::collections::{BTreeMap, VecDeque};
use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

/// One model call as the proxy saw it. Times are ms since the bench began.
#[derive(Clone, Debug, Serialize)]
pub(super) struct CallRecord {
    pub(super) seq: u64,
    pub(super) start_ms: f64,
    pub(super) first_byte_ms: Option<f64>,
    pub(super) end_ms: f64,
    pub(super) status: u16,
    pub(super) request_bytes: usize,
    pub(super) response_bytes: usize,
    pub(super) model: Option<String>,
    pub(super) stream: bool,
    pub(super) messages: usize,
    /// 16 hex of the requested JSON schema's digest; `None` without one.
    pub(super) schema: Option<String>,
    /// 16 hex of the whole body's digest.
    pub(super) body: String,
    pub(super) retry_of: Option<u64>,
    pub(super) extends: Option<u64>,
}

/// What a request carries that the record keeps.
#[derive(Clone, Debug, Default, PartialEq)]
struct RequestShape {
    model: Option<String>,
    stream: bool,
    messages: usize,
    schema: Option<String>,
    body: String,
    /// The digest of each message prefix, shortest first.
    prefixes: Vec<String>,
}

/// 16 hex of blake3 over `bytes`.
fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex()[..16].to_owned()
}

/// The shape of one request body. A body that is not JSON keeps only its
/// digest.
fn shape(body: &[u8]) -> RequestShape {
    let mut shape = RequestShape {
        body: digest(body),
        ..RequestShape::default()
    };
    let Ok(json) = serde_json::from_slice::<Value>(body) else {
        return shape;
    };
    shape.model = json["model"].as_str().map(str::to_owned);
    shape.stream = json["stream"].as_bool().unwrap_or(false);
    let format = &json["response_format"];
    let schema = [
        &format["json_schema"]["schema"],
        &format["json_schema"],
        &format["schema"],
    ]
    .into_iter()
    .find(|value| !value.is_null());
    shape.schema = schema.map(|schema| digest(schema.to_string().as_bytes()));
    if let Some(messages) = json["messages"].as_array() {
        shape.messages = messages.len();
        let mut running = blake3::Hasher::new();
        for message in messages {
            running.update(blake3::hash(message.to_string().as_bytes()).as_bytes());
            shape.prefixes.push(running.finalize().to_hex()[..16].to_owned());
        }
    }
    shape
}

/// The calls recorded so far, and the indexes that name retries and
/// corrective calls.
#[derive(Default)]
struct Ledger {
    calls: Vec<CallRecord>,
    by_body: BTreeMap<String, u64>,
    by_messages: BTreeMap<String, u64>,
}

impl Ledger {
    /// Records the call `seq` of `shape`: its retry and corrective links
    /// come from the calls that ended before it.
    fn record(&mut self, mut call: CallRecord, shape: &RequestShape) -> CallRecord {
        call.retry_of = self.by_body.get(&shape.body).copied();
        let strict = shape.prefixes.len().saturating_sub(1);
        call.extends = shape.prefixes[..strict]
            .iter()
            .rev()
            .find_map(|prefix| self.by_messages.get(prefix).copied());
        self.by_body.insert(shape.body.clone(), call.seq);
        if let Some(whole) = shape.prefixes.last() {
            self.by_messages.insert(whole.clone(), call.seq);
        }
        self.calls.push(call.clone());
        call
    }
}

/// Where one HTTP message's framing stands.
#[derive(Debug, PartialEq)]
enum Body {
    Length(usize),
    Chunked,
    /// Ends when the connection does.
    UntilClose,
}

/// The head of one HTTP message: its first line's status (responses only),
/// and how its body is framed.
#[derive(Debug, PartialEq)]
struct Head {
    status: u16,
    body: Body,
}

/// The head in `bytes[..end]`, `end` past its blank line.
fn head(bytes: &[u8], response: bool) -> Head {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("");
    let status = if response {
        first
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or(0)
    } else {
        0
    };
    let mut body = if response {
        Body::UntilClose
    } else {
        Body::Length(0)
    };
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
        if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            body = Body::Chunked;
        } else if name == "content-length"
            && body != Body::Chunked
            && let Ok(length) = value.parse()
        {
            body = Body::Length(length);
        }
    }
    // No body on 1xx, 204 and 304.
    if response && (status / 100 == 1 || status == 204 || status == 304) {
        body = Body::Length(0);
    }
    Head { status, body }
}

/// The end of the blank line closing a head in `bytes`, if it came.
fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n").map(|at| at + 4)
}

/// Where a chunked body that starts at `bytes[0]` ends, if all of it came.
fn chunked_end(bytes: &[u8]) -> Option<usize> {
    let mut at = 0;
    loop {
        let line = bytes[at..].windows(2).position(|w| w == b"\r\n")?;
        let size_text = String::from_utf8_lossy(&bytes[at..at + line]);
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        at += line + 2;
        if size == 0 {
            // Trailers, then the blank line.
            loop {
                let line = bytes[at..].windows(2).position(|w| w == b"\r\n")?;
                at += line + 2;
                if line == 0 {
                    return Some(at);
                }
            }
        }
        at += size + 2;
        if at > bytes.len() {
            return None;
        }
    }
}

/// Where the message starting at `bytes[0]` ends, if all of it came, and
/// its head.
fn message_end(bytes: &[u8], response: bool) -> Option<(usize, Head)> {
    let end = head_end(bytes)?;
    let parsed = head(&bytes[..end], response);
    let total = match parsed.body {
        Body::Length(length) => (bytes.len() >= end + length).then_some(end + length)?,
        Body::Chunked => end + chunked_end(&bytes[end..])?,
        Body::UntilClose => return None,
    };
    Some((total, parsed))
}

/// A request sent and not yet answered.
struct Pending {
    seq: u64,
    start: Instant,
    bytes: usize,
    shape: RequestShape,
}

/// The shared state of one proxy.
struct Shared {
    origin: Instant,
    next_seq: AtomicU64,
    ledger: Mutex<Ledger>,
    jsonl: Mutex<Option<std::fs::File>>,
}

impl Shared {
    fn ms(&self, at: Instant) -> f64 {
        at.saturating_duration_since(self.origin).as_secs_f64() * 1000.0
    }

    /// Records the answered `pending` and appends it to the JSONL file.
    fn answered(
        &self,
        pending: Pending,
        first_byte: Option<Instant>,
        status: u16,
        bytes: usize,
    ) {
        let call = CallRecord {
            seq: pending.seq,
            start_ms: self.ms(pending.start),
            first_byte_ms: first_byte.map(|at| self.ms(at)),
            end_ms: self.ms(Instant::now()),
            status,
            request_bytes: pending.bytes,
            response_bytes: bytes,
            model: pending.shape.model.clone(),
            stream: pending.shape.stream,
            messages: pending.shape.messages,
            schema: pending.shape.schema.clone(),
            body: pending.shape.body.clone(),
            retry_of: None,
            extends: None,
        };
        let call = match self.ledger.lock() {
            Ok(mut ledger) => ledger.record(call, &pending.shape),
            Err(_) => call,
        };
        if let Ok(mut file) = self.jsonl.lock()
            && let Some(file) = file.as_mut()
            && let Ok(line) = serde_json::to_string(&call)
        {
            let _ = writeln!(file, "{line}");
        }
    }
}

/// A running proxy: the base URL the server's config names, and its calls.
pub(super) struct CallProxy {
    pub(super) base_url: String,
    shared: Arc<Shared>,
    stop: Arc<AtomicBool>,
    port: u16,
}

impl CallProxy {
    /// Starts a proxy on loopback for the `http://` gateway at
    /// `upstream_base`; `None` for any other scheme. Calls append to
    /// `jsonl` as they end.
    pub(super) fn start(
        upstream_base: &str,
        origin: Instant,
        jsonl: PathBuf,
    ) -> Result<Option<Self>, String> {
        let Some(rest) = upstream_base.strip_prefix("http://") else {
            return Ok(None);
        };
        let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
        let upstream = if authority.contains(':') {
            authority.to_owned()
        } else {
            format!("{authority}:80")
        };
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|e| format!("call proxy bind: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("call proxy addr: {e}"))?
            .port();
        let file = std::fs::File::create(&jsonl)
            .map_err(|e| format!("call proxy log {}: {e}", jsonl.display()))?;
        let shared = Arc::new(Shared {
            origin,
            next_seq: AtomicU64::new(1),
            ledger: Mutex::new(Ledger::default()),
            jsonl: Mutex::new(Some(file)),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let (accept_shared, accept_stop) = (Arc::clone(&shared), Arc::clone(&stop));
        std::thread::spawn(move || {
            for client in listener.incoming() {
                if accept_stop.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(client) = client else { continue };
                let shared = Arc::clone(&accept_shared);
                let upstream = upstream.clone();
                std::thread::spawn(move || relay(client, &upstream, &shared));
            }
        });
        let base_url = if path.is_empty() {
            format!("http://127.0.0.1:{port}")
        } else {
            format!("http://127.0.0.1:{port}/{path}")
        };
        Ok(Some(Self {
            base_url,
            shared,
            stop,
            port,
        }))
    }

    /// Every call that ended so far, in the order they ended.
    pub(super) fn calls(&self) -> Vec<CallRecord> {
        self.shared
            .ledger
            .lock()
            .map(|ledger| ledger.calls.clone())
            .unwrap_or_default()
    }
}

impl Drop for CallProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Wakes the accept loop so it sees the stop.
        let _ = TcpStream::connect_timeout(
            &([127, 0, 0, 1], self.port).into(),
            Duration::from_millis(200),
        );
    }
}

/// Relays one server connection to the gateway and back.
fn relay(client: TcpStream, upstream: &str, shared: &Arc<Shared>) {
    let Ok(gateway) = TcpStream::connect(upstream) else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let _ = (client.set_nodelay(true), gateway.set_nodelay(true));
    let (Ok(client_back), Ok(gateway_back)) = (client.try_clone(), gateway.try_clone()) else {
        return;
    };
    let pending = Arc::new(Mutex::new(VecDeque::<Pending>::new()));
    let answers = {
        let (pending, shared) = (Arc::clone(&pending), Arc::clone(shared));
        std::thread::spawn(move || responses(gateway_back, client_back, &pending, &shared))
    };
    requests(client, gateway, &pending, shared);
    let _ = answers.join();
}

/// Server to gateway: forwards bytes and queues each request as it ends.
fn requests(
    mut client: TcpStream,
    mut gateway: TcpStream,
    pending: &Mutex<VecDeque<Pending>>,
    shared: &Shared,
) {
    let mut buffer = Vec::new();
    let mut started: Option<Instant> = None;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let read = match client.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        started.get_or_insert_with(Instant::now);
        if gateway.write_all(&chunk[..read]).is_err() {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        while let Some((end, _)) = message_end(&buffer, false) {
            let body_at = head_end(&buffer).unwrap_or(end);
            let call = Pending {
                seq: shared.next_seq.fetch_add(1, Ordering::Relaxed),
                start: started.take().unwrap_or_else(Instant::now),
                bytes: end,
                shape: shape(&buffer[body_at..end]),
            };
            if let Ok(mut queue) = pending.lock() {
                queue.push_back(call);
            }
            buffer.drain(..end);
            if !buffer.is_empty() {
                started = Some(Instant::now());
            }
        }
    }
    let _ = gateway.shutdown(Shutdown::Write);
}

/// Gateway to server: forwards bytes and records each answered request.
fn responses(
    mut gateway: TcpStream,
    mut client: TcpStream,
    pending: &Mutex<VecDeque<Pending>>,
    shared: &Shared,
) {
    let mut buffer = Vec::new();
    let mut first_byte: Option<Instant> = None;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let read = match gateway.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        first_byte.get_or_insert_with(Instant::now);
        if client.write_all(&chunk[..read]).is_err() {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        while let Some((end, parsed)) = message_end(&buffer, true) {
            buffer.drain(..end);
            // An interim 1xx answers nothing yet.
            if parsed.status / 100 != 1
                && let Some(call) = pending.lock().ok().and_then(|mut queue| queue.pop_front())
            {
                shared.answered(call, first_byte.take(), parsed.status, end);
            }
            if !buffer.is_empty() {
                first_byte = Some(Instant::now());
            }
        }
    }
    // A body framed by the close ends here.
    if let Some(end) = head_end(&buffer) {
        let parsed = head(&buffer[..end], true);
        if let Some(call) = pending.lock().ok().and_then(|mut queue| queue.pop_front()) {
            shared.answered(call, first_byte.take(), parsed.status, buffer.len());
        }
    }
    let _ = client.shutdown(Shutdown::Write);
}

/// The calls' summary for the report: counts, ms spread, the most calls
/// in flight at once and the ms with at least one in flight, over the
/// calls that started in `[from_ms, to_ms)`.
pub(super) fn summary(calls: &[CallRecord], from_ms: f64, to_ms: f64) -> Value {
    let inside: Vec<&CallRecord> = calls
        .iter()
        .filter(|call| (from_ms..to_ms).contains(&call.start_ms))
        .collect();
    let mut ms: Vec<f64> = inside.iter().map(|c| c.end_ms - c.start_ms).collect();
    ms.sort_by(f64::total_cmp);
    let pick = |q: f64| {
        (!ms.is_empty()).then(|| ms[((ms.len() - 1) as f64 * q).round() as usize])
    };
    let mut edges: Vec<(f64, i64)> = inside
        .iter()
        .flat_map(|c| [(c.start_ms, 1), (c.end_ms, -1)])
        .collect();
    edges.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
    let (mut open, mut most, mut busy, mut since) = (0_i64, 0_i64, 0.0, 0.0);
    for (at, step) in edges {
        if open > 0 {
            busy += at - since;
        }
        open += step;
        most = most.max(open);
        since = at;
    }
    serde_json::json!({
        "calls": inside.len(),
        "failed": inside.iter().filter(|c| c.status >= 400 || c.status == 0).count(),
        "retries": inside.iter().filter(|c| c.retry_of.is_some()).count(),
        "corrective": inside.iter().filter(|c| c.extends.is_some()).count(),
        "p50_ms": pick(0.5),
        "p95_ms": pick(0.95),
        "max_ms": ms.last(),
        "sum_ms": ms.iter().sum::<f64>(),
        "most_in_flight": most,
        "busy_ms": busy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_end_frames_length_chunked_and_interim() {
        let request = b"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 4\r\n\r\nbodyNEXT";
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nX";
        let interim = b"HTTP/1.1 100 Continue\r\n\r\n";
        assert_eq!(
            (
                message_end(request, false).map(|(end, _)| end),
                message_end(&request[..60], false).map(|(end, _)| end),
                message_end(chunked, true).map(|(end, head)| (end, head.status)),
                message_end(&chunked[..55], true).map(|(end, _)| end),
                message_end(interim, true).map(|(end, head)| (end, head.status)),
            ),
            (
                Some(request.len() - 4),
                None,
                Some((chunked.len() - 1, 200)),
                None,
                Some((interim.len(), 100)),
            )
        );
    }

    #[test]
    fn ledger_names_retries_and_corrective_calls() {
        let first = br#"{"model":"m","messages":[{"role":"user","content":"a"}],"response_format":{"type":"json_schema","schema":{"type":"object"}}}"#;
        let corrective = br#"{"model":"m","messages":[{"role":"user","content":"a"},{"role":"assistant","content":"b"},{"role":"user","content":"fix"}],"response_format":{"type":"json_schema","schema":{"type":"object"}}}"#;
        let mut ledger = Ledger::default();
        let call = |seq| CallRecord {
            seq,
            start_ms: 0.0,
            first_byte_ms: None,
            end_ms: 1.0,
            status: 200,
            request_bytes: 0,
            response_bytes: 0,
            model: None,
            stream: false,
            messages: 0,
            schema: None,
            body: String::new(),
            retry_of: None,
            extends: None,
        };
        let a = ledger.record(call(1), &shape(first));
        let b = ledger.record(call(2), &shape(first));
        let c = ledger.record(call(3), &shape(corrective));
        assert_eq!(
            (
                a.retry_of,
                a.extends,
                b.retry_of,
                c.retry_of,
                c.extends,
                shape(first).schema == shape(corrective).schema,
                shape(first).schema.is_some(),
            ),
            (None, None, Some(1), None, Some(2), true, true)
        );
    }
}
