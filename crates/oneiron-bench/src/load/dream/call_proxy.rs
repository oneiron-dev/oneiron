//! The model-call timing proxy of `load dream` (FIX 21929). The server's
//! `[models]` provider points here; every byte goes on to the model gateway
//! unchanged but each request's `Host` line, which names the gateway's own
//! authority again (a virtual-host gateway routes by it). Each HTTP call is
//! recorded when its response ends: its request start, first response byte
//! and end, its status and sizes, and what tells calls apart without their
//! text. A call that fails in transport (no connection, a reset or close
//! before its response ended) is recorded with status 0 when its connection
//! ends, so a lost call still counts as a failed one. A request cut off after
//! its head (the server gave up, or the gateway refused it early and closed)
//! is a call too, recorded with the bytes that came and the early answer's
//! status, if one came. When the server's side of a connection ends, no
//! answer can reach it any more: the proxy ends the gateway connection whole,
//! so nothing waits on a silent gateway. A call's `schema` is the
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
    /// The response status; 0 when the call failed in transport (no
    /// response, or one cut off before its end).
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
            shape
                .prefixes
                .push(running.finalize().to_hex()[..16].to_owned());
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
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| at + 4)
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

/// `head` (a request head, through its blank line) with its `Host` line
/// naming `host`; every other byte stays as it came.
fn with_host(head: &[u8], host: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(head.len() + host.len());
    let mut rest = head;
    while let Some(at) = rest.windows(2).position(|w| w == b"\r\n") {
        let line = &rest[..at];
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"host:") {
            out.extend_from_slice(b"Host: ");
            out.extend_from_slice(host.as_bytes());
        } else {
            out.extend_from_slice(line);
        }
        out.extend_from_slice(b"\r\n");
        rest = &rest[at + 2..];
    }
    out.extend_from_slice(rest);
    out
}

/// A request from the server: whole, or cut off after its head when its
/// connection ended.
struct Pending {
    seq: u64,
    start: Instant,
    bytes: usize,
    shape: RequestShape,
}

/// How one call's response ended.
struct Answer {
    first_byte: Option<Instant>,
    end: Instant,
    status: u16,
    bytes: usize,
}

impl Answer {
    /// The answer of a call whose connection ended with no response.
    fn failed() -> Self {
        Self {
            first_byte: None,
            end: Instant::now(),
            status: 0,
            bytes: 0,
        }
    }
}

/// One connection's requests and responses. HTTP/1.1 answers in request
/// order, so the n-th response answers the n-th request; either one may end
/// first (a gateway may answer before a request's body is all in).
#[derive(Default)]
struct Exchange {
    unanswered: VecDeque<Pending>,
    early: VecDeque<Answer>,
    /// The proxy ended the gateway connection itself, so the gateway's end
    /// of it is no clean close.
    upstream_cancelled: bool,
}

impl Exchange {
    /// Queues `call`; the pair at once if its response already ended.
    fn request(&mut self, call: Pending) -> Option<(Pending, Answer)> {
        match self.early.pop_front() {
            Some(answer) => Some((call, answer)),
            None => {
                self.unanswered.push_back(call);
                None
            }
        }
    }

    /// Pairs `answer` with the oldest unanswered request, or keeps it until
    /// that request ends.
    fn response(&mut self, answer: Answer) -> Option<(Pending, Answer)> {
        match self.unanswered.pop_front() {
            Some(call) => Some((call, answer)),
            None => {
                self.early.push_back(answer);
                None
            }
        }
    }
}

/// Records the pair, if both halves of the call ended.
fn settle(shared: &Shared, pair: Option<(Pending, Answer)>) {
    if let Some((call, answer)) = pair {
        shared.answered(call, answer);
    }
}

/// Records every request still unanswered as a failed call: no response
/// can come for it any more.
fn fail_unanswered(exchange: &Mutex<Exchange>, shared: &Shared) {
    let left: Vec<Pending> = exchange
        .lock()
        .map(|mut exchange| exchange.unanswered.drain(..).collect())
        .unwrap_or_default();
    for call in left {
        shared.answered(call, Answer::failed());
    }
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

    /// Records `pending` with its `answer` and appends it to the JSONL file.
    fn answered(&self, pending: Pending, answer: Answer) {
        let call = CallRecord {
            seq: pending.seq,
            start_ms: self.ms(pending.start),
            first_byte_ms: answer.first_byte.map(|at| self.ms(at)),
            end_ms: self.ms(answer.end),
            status: answer.status,
            request_bytes: pending.bytes,
            response_bytes: answer.bytes,
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
        // The gateway's own authority, as its URL names it, for each `Host`.
        let host = authority.to_owned();
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
                let (upstream, host) = (upstream.clone(), host.clone());
                std::thread::spawn(move || relay(client, &upstream, &host, &shared));
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

/// Relays one server connection to the gateway and back. Whatever request
/// is still unanswered when both directions end failed in transport.
fn relay(client: TcpStream, upstream: &str, host: &str, shared: &Arc<Shared>) {
    let _ = client.set_nodelay(true);
    let exchange = Arc::new(Mutex::new(Exchange::default()));
    match TcpStream::connect(upstream) {
        Ok(gateway) => {
            let _ = gateway.set_nodelay(true);
            let (Ok(client_back), Ok(gateway_back)) = (client.try_clone(), gateway.try_clone())
            else {
                let _ = client.shutdown(Shutdown::Both);
                return;
            };
            let answers = {
                let (exchange, shared) = (Arc::clone(&exchange), Arc::clone(shared));
                std::thread::spawn(move || responses(gateway_back, client_back, &exchange, &shared))
            };
            requests(client, Some(gateway), host, &exchange, shared);
            let _ = answers.join();
        }
        // No gateway: the server's first request is read, and fails.
        Err(_) => requests(client, None, host, &exchange, shared),
    }
    fail_unanswered(&exchange, shared);
}

/// Server to gateway: forwards each request with its `Host` line naming the
/// gateway. A request is queued as soon as all of it came and before its
/// last bytes go on, so its response always finds it; one whose head came
/// and whose rest never did is queued when the server's side ends. Then the
/// gateway connection ends whole (the server never half-closes, so its end
/// means it gave up on what is in flight, as at its timeout), which ends
/// `responses` and fails what is still unanswered. Without a gateway it
/// reads the first request only, and closes.
fn requests(
    mut client: TcpStream,
    mut gateway: Option<TcpStream>,
    host: &str,
    exchange: &Mutex<Exchange>,
    shared: &Shared,
) {
    // The bytes from the current request's first on; `sent` of them went on
    // (0 until its head is all in).
    let mut buffer = Vec::new();
    let mut sent = 0;
    let mut started: Option<Instant> = None;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let read = match client.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        started.get_or_insert_with(Instant::now);
        buffer.extend_from_slice(&chunk[..read]);
        let mut out = Vec::new();
        let mut queued = false;
        loop {
            if sent == 0 {
                let Some(head_at) = head_end(&buffer) else {
                    break;
                };
                out.extend_from_slice(&with_host(&buffer[..head_at], host));
                sent = head_at;
            }
            let Some((end, _)) = message_end(&buffer, false) else {
                out.extend_from_slice(&buffer[sent..]);
                sent = buffer.len();
                break;
            };
            let body_at = head_end(&buffer).unwrap_or(end);
            let call = Pending {
                seq: shared.next_seq.fetch_add(1, Ordering::Relaxed),
                start: started.take().unwrap_or_else(Instant::now),
                bytes: end,
                shape: shape(&buffer[body_at..end]),
            };
            settle(
                shared,
                exchange
                    .lock()
                    .ok()
                    .and_then(|mut exchange| exchange.request(call)),
            );
            queued = true;
            out.extend_from_slice(&buffer[sent..end]);
            buffer.drain(..end);
            sent = 0;
            if !buffer.is_empty() {
                started = Some(Instant::now());
            }
        }
        let stop = match gateway.as_mut() {
            Some(gateway) => gateway.write_all(&out).is_err(),
            None => queued,
        };
        if stop {
            break;
        }
    }
    // A request cut off after its head: an answer that already ended (an
    // early refusal) is its own, else it fails with the connection.
    if sent > 0 {
        let body_at = head_end(&buffer).unwrap_or(buffer.len());
        let call = Pending {
            seq: shared.next_seq.fetch_add(1, Ordering::Relaxed),
            start: started.take().unwrap_or_else(Instant::now),
            bytes: buffer.len(),
            shape: shape(&buffer[body_at..]),
        };
        settle(
            shared,
            exchange
                .lock()
                .ok()
                .and_then(|mut exchange| exchange.request(call)),
        );
    }
    match gateway {
        Some(gateway) => {
            if let Ok(mut exchange) = exchange.lock() {
                exchange.upstream_cancelled = true;
            }
            let _ = gateway.shutdown(Shutdown::Both);
        }
        None => {
            let _ = client.shutdown(Shutdown::Both);
        }
    }
}

/// Gateway to server: forwards bytes and records each response with the
/// request it answers. When the gateway's side ends no response can come
/// any more: the requests still unanswered failed, and the server's side
/// closes too, so the server sees the failure at once.
fn responses(
    mut gateway: TcpStream,
    mut client: TcpStream,
    exchange: &Mutex<Exchange>,
    shared: &Shared,
) {
    let mut buffer = Vec::new();
    let mut first_byte: Option<Instant> = None;
    let mut chunk = [0_u8; 64 * 1024];
    let mut closed = false;
    loop {
        let read = match gateway.read(&mut chunk) {
            Ok(0) => {
                closed = true;
                break;
            }
            Err(_) => break,
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
            if parsed.status / 100 != 1 {
                let answer = Answer {
                    first_byte: first_byte.take(),
                    end: Instant::now(),
                    status: parsed.status,
                    bytes: end,
                };
                settle(
                    shared,
                    exchange
                        .lock()
                        .ok()
                        .and_then(|mut exchange| exchange.response(answer)),
                );
            }
            if !buffer.is_empty() {
                first_byte = Some(Instant::now());
            }
        }
    }
    // A response begun and not ended: a body framed by the close ends here
    // if the gateway closed cleanly (not the proxy, for a server that gave
    // up); any other was cut off, and failed.
    let cancelled = exchange
        .lock()
        .map(|exchange| exchange.upstream_cancelled)
        .unwrap_or(false);
    if let Some(end) = head_end(&buffer) {
        let parsed = head(&buffer[..end], true);
        let whole = closed && !cancelled && parsed.body == Body::UntilClose;
        let answer = Answer {
            first_byte: first_byte.take(),
            end: Instant::now(),
            status: if whole { parsed.status } else { 0 },
            bytes: buffer.len(),
        };
        settle(
            shared,
            exchange
                .lock()
                .ok()
                .and_then(|mut exchange| exchange.response(answer)),
        );
    }
    fail_unanswered(exchange, shared);
    let _ = client.shutdown(Shutdown::Both);
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
    let pick = |q: f64| (!ms.is_empty()).then(|| ms[((ms.len() - 1) as f64 * q).round() as usize]);
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
    fn with_host_names_the_gateway_and_keeps_every_other_byte() {
        let head = b"POST /v1/chat/completions HTTP/1.1\r\nhost: 127.0.0.1:5555\r\nContent-Length: 2\r\n\r\n";
        assert_eq!(
            with_host(head, "models.example:8080"),
            b"POST /v1/chat/completions HTTP/1.1\r\nHost: models.example:8080\r\nContent-Length: 2\r\n\r\n"
                .to_vec()
        );
    }

    #[test]
    fn exchange_pairs_a_response_that_ended_before_its_request() {
        let call = |seq| Pending {
            seq,
            start: Instant::now(),
            bytes: 0,
            shape: RequestShape::default(),
        };
        let answer = |status| Answer {
            status,
            ..Answer::failed()
        };
        let mut exchange = Exchange::default();
        let early = exchange.response(answer(429)).is_none();
        let first = exchange.request(call(1)).map(|(c, a)| (c.seq, a.status));
        let second_waits = exchange.request(call(2)).is_none();
        let second = exchange
            .response(answer(200))
            .map(|(c, a)| (c.seq, a.status));
        assert_eq!(
            (early, first, second_waits, second),
            (true, Some((1, 429)), true, Some((2, 200)))
        );
    }

    /// One connection through the proxy: a fast 429, then a request the
    /// gateway reads and drops with no answer. Both calls are recorded, in
    /// order, and the gateway sees its own authority in each `Host`.
    #[test]
    fn proxy_records_a_fast_answer_and_a_dropped_call_and_names_the_gateway_host() {
        let gateway = TcpListener::bind("127.0.0.1:0").expect("gateway bind");
        let gateway_port = gateway.local_addr().expect("gateway addr").port();
        let seen = std::thread::spawn(move || {
            let (mut socket, _) = gateway.accept().expect("gateway accept");
            let (mut heads, mut buffer, mut chunk) = (Vec::new(), Vec::new(), [0_u8; 4096]);
            let fast: &[u8] = b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n";
            for answer in [Some(fast), None] {
                let end = loop {
                    if let Some((end, _)) = message_end(&buffer, false) {
                        break end;
                    }
                    let read = socket.read(&mut chunk).expect("gateway read");
                    assert!(read > 0, "the request came whole");
                    buffer.extend_from_slice(&chunk[..read]);
                };
                let head_at = head_end(&buffer).expect("request head");
                heads.push(String::from_utf8_lossy(&buffer[..head_at]).into_owned());
                buffer.drain(..end);
                if let Some(answer) = answer {
                    socket.write_all(answer).expect("gateway write");
                }
            }
            // Drops the socket: the second request is never answered.
            heads
        });
        let (proxy, proxy_authority, jsonl) = start_proxy(gateway_port, "dropped");
        let mut server = TcpStream::connect(&proxy_authority).expect("connect to the proxy");
        let body: &[u8] = br#"{"model":"m","messages":[]}"#;
        let request = [
            format!(
                "POST /v1/chat/completions HTTP/1.1\r\nHost: {proxy_authority}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
            body,
        ]
        .concat();
        server.write_all(&request).expect("send the first request");
        let (mut answer, mut chunk) = (Vec::new(), [0_u8; 4096]);
        while message_end(&answer, true).is_none() {
            let read = server.read(&mut chunk).expect("read the first answer");
            assert!(read > 0, "the first answer came");
            answer.extend_from_slice(&chunk[..read]);
        }
        server.write_all(&request).expect("send the second request");
        let mut rest = Vec::new();
        let _ = server.read_to_end(&mut rest);
        let heads = seen.join().expect("gateway thread");
        let calls = wait_for_calls(&proxy, 2);
        let _ = std::fs::remove_file(&jsonl);
        let (gateway_host, proxy_host) = (
            format!("\r\nHost: 127.0.0.1:{gateway_port}\r\n"),
            format!("\r\nHost: {proxy_authority}\r\n"),
        );
        assert_eq!(
            (
                calls,
                heads.len(),
                heads.iter().all(|head| head.contains(&gateway_host)),
                heads.iter().any(|head| head.contains(&proxy_host)),
                rest.is_empty(),
            ),
            (vec![(1, 429), (2, 0)], 2, true, false, true)
        );
    }

    /// A proxy for the gateway on loopback `gateway_port`, the authority the
    /// server dials, and the proxy's calls file (`tag` keeps it apart from
    /// the other tests' files).
    fn start_proxy(gateway_port: u16, tag: &str) -> (CallProxy, String, PathBuf) {
        let jsonl =
            std::env::temp_dir().join(format!("call-proxy-{tag}-{}.jsonl", std::process::id()));
        let proxy = CallProxy::start(
            &format!("http://127.0.0.1:{gateway_port}/v1"),
            Instant::now(),
            jsonl.clone(),
        )
        .expect("proxy start")
        .expect("an http gateway is proxied");
        let authority = proxy
            .base_url
            .trim_start_matches("http://")
            .trim_end_matches("/v1")
            .to_owned();
        (proxy, authority, jsonl)
    }

    /// Each recorded call's seq and status, once `count` calls ended or 5 s
    /// went by.
    fn wait_for_calls(proxy: &CallProxy, count: usize) -> Vec<(u64, u16)> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while proxy.calls().len() < count && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        proxy
            .calls()
            .iter()
            .map(|call| (call.seq, call.status))
            .collect()
    }

    /// The gateway refuses a request from its head alone with a whole 413
    /// and closes while the server is still sending the body. The cut-off
    /// call is recorded with the refusal's status (review round 2, P1 1).
    #[test]
    fn proxy_records_an_early_refusal_that_closes_during_the_upload() {
        let gateway = TcpListener::bind("127.0.0.1:0").expect("gateway bind");
        let gateway_port = gateway.local_addr().expect("gateway addr").port();
        let refusing = std::thread::spawn(move || {
            let (mut socket, _) = gateway.accept().expect("gateway accept");
            let (mut buffer, mut chunk) = (Vec::new(), [0_u8; 4096]);
            while head_end(&buffer).is_none() {
                let read = socket.read(&mut chunk).expect("gateway read");
                assert!(read > 0, "the request head came");
                buffer.extend_from_slice(&chunk[..read]);
            }
            socket
                .write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .expect("gateway write");
            socket.shutdown(Shutdown::Write).expect("gateway close");
            // Reads on until the proxy closes: an unread byte would turn the
            // close into a reset.
            while socket.read(&mut chunk).is_ok_and(|read| read > 0) {}
        });
        let (proxy, authority, jsonl) = start_proxy(gateway_port, "refused");
        let mut server = TcpStream::connect(&authority).expect("connect to the proxy");
        let head_and_part = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 1000\r\n\r\n{{\"model\":"
        );
        server
            .write_all(head_and_part.as_bytes())
            .expect("send the head and a part of the body");
        let mut answer = Vec::new();
        let _ = server.read_to_end(&mut answer);
        let calls = wait_for_calls(&proxy, 1);
        drop(server);
        refusing.join().expect("gateway thread");
        let _ = std::fs::remove_file(&jsonl);
        assert_eq!(calls, vec![(1, 413)]);
    }

    /// The gateway takes a whole request and never answers, its side left
    /// open; the server gives up (as at its timeout) and closes. The proxy
    /// ends the gateway connection and records the call as failed (review
    /// round 2, P1 2).
    #[test]
    fn proxy_fails_a_call_the_server_gave_up_on() {
        let gateway = TcpListener::bind("127.0.0.1:0").expect("gateway bind");
        let gateway_port = gateway.local_addr().expect("gateway addr").port();
        let (release, held) = std::sync::mpsc::channel::<()>();
        let silent = std::thread::spawn(move || {
            let (mut socket, _) = gateway.accept().expect("gateway accept");
            let (mut buffer, mut chunk) = (Vec::new(), [0_u8; 4096]);
            while message_end(&buffer, false).is_none() {
                let read = socket.read(&mut chunk).expect("gateway read");
                assert!(read > 0, "the request came whole");
                buffer.extend_from_slice(&chunk[..read]);
            }
            // No answer, and the write side stays open until the test ends.
            let _ = held.recv_timeout(Duration::from_secs(30));
            drop(socket);
        });
        let (proxy, authority, jsonl) = start_proxy(gateway_port, "abandoned");
        let mut server = TcpStream::connect(&authority).expect("connect to the proxy");
        let body: &[u8] = br#"{"model":"m","messages":[]}"#;
        let request = [
            format!(
                "POST /v1/chat/completions HTTP/1.1\r\nHost: {authority}\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
            body,
        ]
        .concat();
        server.write_all(&request).expect("send the request");
        drop(server);
        let calls = wait_for_calls(&proxy, 1);
        let _ = release.send(());
        silent.join().expect("gateway thread");
        let _ = std::fs::remove_file(&jsonl);
        assert_eq!(calls, vec![(1, 0)]);
    }

    #[test]
    fn message_end_frames_length_chunked_and_interim() {
        let request = b"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 4\r\n\r\nbodyNEXT";
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nX";
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
