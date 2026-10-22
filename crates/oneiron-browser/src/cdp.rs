//! The Chrome DevTools Protocol over Chromium's `--remote-debugging-pipe`:
//! JSON messages, each ended by a NUL byte, on one reader and one writer;
//! or, for Lightpanda, over a WebSocket its guest's relay carries on the
//! same two halves (`websocket`). Replies are matched to calls by id.
//! Network events cross the host proxy, for every page the guest opens; the
//! DOM driver still polls for its observations and its tabs. Each page
//! session's navigation events are counted, for the driver's change check
//! (FIX 6680), and a JavaScript dialog a page opens is answered at once, as
//! before its Page domain was on. The pages' committed top-level origins
//! and an engine switch's one-shot seed document ride the same routing
//! (`state`), as do the storage reads a Chromium document sends as it is
//! left, kept in the session's snapshots (`storage`). A message past the
//! pipe's bound, or a reply it cannot parse, fails only its own call, and
//! the pipe reads on (`overrun`, FIX 6851). Each paused request goes to the
//! host's request handler where the session has one, in place of the relay
//! (`requests`, FIX 7122).

mod overrun;
pub(crate) mod recorder;
mod requests;
mod state;
mod storage;
mod websocket;

pub(crate) use state::{Visits, web_origin};

use crate::request::Custody;
use crate::session::storage::Sink;
use crate::{BrowserEngine, BrowserError};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

/// The largest message the pipe reads. A 1,366 px PNG screenshot in base64
/// is a few MiB; a message past this fails only its own call, or is
/// dropped as an event, and the pipe reads on (`overrun`).
const MAX_MESSAGE: u64 = 32 << 20;

/// The Page events that start or make a navigation, of any frame of a
/// page: the main frame's and every in-page frame's. Each one moves its
/// session's navigation count.
const NAVIGATION_EVENTS: [&str; 4] = [
    "Page.frameRequestedNavigation",
    "Page.frameStartedLoading",
    "Page.frameNavigated",
    "Page.navigatedWithinDocument",
];

type Reply = Result<Value, String>;
type Pending = Arc<Mutex<Option<HashMap<u64, Sender<Reply>>>>>;
/// Each watched page session's navigation events so far.
type Navigations = Arc<Mutex<HashMap<String, u64>>>;

/// The half of a transport that takes one whole message to the browser.
trait Outbound: Send {
    fn send(&mut self, message: Vec<u8>) -> io::Result<()>;
}

/// Chromium's pipe: each message ended by a NUL byte.
struct Nul<W>(W);

impl<W: Write + Send> Outbound for Nul<W> {
    fn send(&mut self, mut message: Vec<u8>) -> io::Result<()> {
        message.push(0);
        self.0.write_all(&message)?;
        self.0.flush()
    }
}

#[derive(Clone)]
pub(crate) struct Pipe {
    writer: Arc<Mutex<Box<dyn Outbound>>>,
    pending: Pending,
    next: Arc<AtomicU64>,
    egress: bool,
    /// The targets one session already routes through the proxy: another
    /// session on one of them (the driver's own, or the browser's auto-attach
    /// finding a page again) only lets it run.
    routed: Arc<Mutex<HashSet<String>>>,
    navigations: Navigations,
    /// Each watched page's binding and committed top-level origins.
    pages: Arc<Mutex<state::Pages>>,
    /// The one-shot seed document an engine switch armed, if any.
    seed: Arc<Mutex<Option<state::Seed>>>,
    /// Where the pages' storage reads are kept, once the session gave one.
    sink: Arc<OnceLock<Sink>>,
    /// The session's custody of its requests: the host's handler, if any,
    /// and the refusal not yet delivered (`requests`).
    custody: Custody,
    /// Each page session's main-document answers, by frame (`requests`).
    documents: requests::Documents,
    /// The running demonstration's capture, if one records (`recorder`).
    recorder: Arc<Mutex<Option<recorder::Live>>>,
}

impl Pipe {
    pub(crate) fn with_egress(
        reader: impl Read + Send + 'static,
        writer: impl Write + Send + 'static,
        relay: Option<Arc<dyn oneiron_container::EgressRelay>>,
        custody: Custody,
    ) -> Self {
        let pipe = Self::routed(Box::new(Nul(writer)), relay.is_some(), custody);
        let handle = pipe.clone();
        std::thread::spawn(move || {
            read_replies(BufReader::new(reader), &handle, relay.as_ref());
            handle.end();
        });
        pipe
    }

    /// The pipe to a guest's browser on `engine`: Chromium's NUL-framed
    /// pipe, or Lightpanda's WebSocket once its upgrade answered. It holds
    /// the session's `custody` before it reads a message.
    pub(crate) fn for_engine(
        engine: BrowserEngine,
        reader: impl Read + Send + 'static,
        writer: impl Write + Send + 'static,
        relay: Option<Arc<dyn oneiron_container::EgressRelay>>,
        custody: Custody,
    ) -> Result<Self, BrowserError> {
        match engine {
            BrowserEngine::Chromium => Ok(Self::with_egress(reader, writer, relay, custody)),
            BrowserEngine::Lightpanda => websocket::open(reader, writer, relay, custody),
        }
    }

    /// A pipe whose calls go out through `outbound`; its transport routes
    /// each message it reads.
    fn routed(outbound: Box<dyn Outbound>, egress: bool, custody: Custody) -> Self {
        Self {
            writer: Arc::new(Mutex::new(outbound)),
            pending: Arc::new(Mutex::new(Some(HashMap::new()))),
            next: Arc::new(AtomicU64::new(1)),
            egress,
            routed: Arc::default(),
            navigations: Arc::default(),
            pages: Arc::default(),
            seed: Arc::default(),
            sink: Arc::default(),
            custody,
            documents: Arc::default(),
            recorder: Arc::default(),
        }
    }

    /// Ends the pipe once its transport ended: every call waiting, and
    /// every call after, answers that the guest is gone.
    fn end(&self) {
        if let Ok(mut routes) = self.pending.lock() {
            routes.take();
        }
    }

    pub(crate) fn mediated(&self) -> bool {
        self.egress
    }

    /// Claims `target`'s routing through the proxy for the caller's session;
    /// false when another session already routes it.
    pub(crate) fn claim_network(&self, target: &str) -> bool {
        self.routed
            .lock()
            .map(|mut routed| routed.insert(target.to_owned()))
            .unwrap_or(false)
    }

    /// Counts page `session`'s navigation events from now on, and keeps the
    /// web origins its page `target` commits at its top level: its Page
    /// domain is enabled.
    pub(crate) fn watch_navigations(&self, session: &str, target: &str) {
        if let Ok(mut navigations) = self.navigations.lock() {
            navigations.entry(session.to_owned()).or_default();
        }
        self.bind_page(session, target);
    }

    /// Page `session`'s navigation events so far; none for a session whose
    /// events are not counted.
    pub(crate) fn navigations(&self, session: &str) -> Option<u64> {
        self.navigations.lock().ok()?.get(session).copied()
    }

    /// Sends one command and waits for its reply until `deadline`.
    pub(crate) fn call(
        &self,
        session: Option<&str>,
        method: &str,
        params: Value,
        deadline: Instant,
    ) -> Result<Value, BrowserError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel();
        {
            let mut routes = self.pending.lock().map_err(|_| BrowserError::GuestLost)?;
            routes
                .as_mut()
                .ok_or(BrowserError::GuestLost)?
                .insert(id, tx);
        }
        let mut message = json!({"id": id, "method": method, "params": params});
        if let Some(session) = session {
            message["sessionId"] = Value::from(session);
        }
        let bytes =
            serde_json::to_vec(&message).map_err(|e| BrowserError::Protocol(e.to_string()))?;
        {
            let mut writer = self.writer.lock().map_err(|_| BrowserError::GuestLost)?;
            writer.send(bytes).map_err(|_| BrowserError::GuestLost)?;
        }
        let wait = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(message)) => Err(BrowserError::Protocol(format!("{method}: {message}"))),
            Err(RecvTimeoutError::Disconnected) => Err(BrowserError::GuestLost),
            Err(RecvTimeoutError::Timeout) => {
                if let Ok(mut routes) = self.pending.lock()
                    && let Some(routes) = routes.as_mut()
                {
                    routes.remove(&id);
                }
                Err(BrowserError::Timeout(method.to_owned()))
            }
        }
    }
}

fn read_replies(
    mut reader: impl BufRead,
    pipe: &Pipe,
    relay: Option<&Arc<dyn oneiron_container::EgressRelay>>,
) {
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match (&mut reader).take(MAX_MESSAGE).read_until(0, &mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) if buf.last() == Some(&0) => {}
            // A message that reached the bound before its end fails only its
            // own call, and the pipe reads on past it.
            Ok(read) if u64::try_from(read) == Ok(MAX_MESSAGE) => {
                let prefix = &buf[..buf.len().min(overrun::PREFIX)];
                if !overrun::oversize_message_policy(pipe, prefix) || !skip_message(&mut reader) {
                    return;
                }
                continue;
            }
            Ok(_) => return,
        }
        buf.pop();
        if !route(pipe, relay, &buf) {
            return;
        }
    }
}

/// Reads past the rest of a message, through its NUL end, keeping none of
/// it: false once the pipe ended first.
fn skip_message(reader: &mut impl BufRead) -> bool {
    loop {
        let (used, ended) = match reader.fill_buf() {
            Ok([]) => return false,
            Ok(bytes) => match bytes.iter().position(|byte| *byte == 0) {
                Some(at) => (at + 1, true),
                None => (bytes.len(), false),
            },
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return false,
        };
        reader.consume(used);
        if ended {
            return true;
        }
    }
}

/// Routes one message the browser sent, on either transport: a reply goes
/// to its call, an event to its handling. False once the routes are lost.
fn route(
    pipe: &Pipe,
    relay: Option<&Arc<dyn oneiron_container::EgressRelay>>,
    bytes: &[u8],
) -> bool {
    let message = match serde_json::from_slice::<Value>(bytes) {
        Ok(message) => message,
        Err(error) => return overrun::unreadable(pipe, bytes, &error),
    };
    let Some(id) = message.get("id").and_then(Value::as_u64) else {
        count_navigation(&pipe.navigations, &message);
        pipe.note_page(&message);
        pipe.note_storage(&message);
        pipe.note_recording(&message);
        answer_dialog(pipe, &message);
        if let Some(relay) = relay {
            network_event(pipe.clone(), Arc::clone(relay), message);
        }
        return true;
    };
    let reply = match message.get("error") {
        Some(error) => Err(error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("error")
            .to_owned()),
        None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
    };
    let Ok(mut routes) = pipe.pending.lock() else {
        return false;
    };
    if let Some(tx) = routes.as_mut().and_then(|routes| routes.remove(&id)) {
        let _ = tx.send(reply);
    }
    true
}

/// Counts `event` for its page session when it is a navigation event of a
/// session whose events are counted.
fn count_navigation(navigations: &Navigations, event: &Value) {
    let method = event["method"].as_str().unwrap_or("");
    if !NAVIGATION_EVENTS.contains(&method) {
        return;
    }
    let Some(session) = event["sessionId"].as_str() else {
        return;
    };
    if let Ok(mut navigations) = navigations.lock()
        && let Some(count) = navigations.get_mut(session)
    {
        *count += 1;
    }
}

/// Answers a JavaScript dialog a page opened, at once, as headless Chromium
/// answers one when no client holds the page's Page domain: an alert,
/// confirm or prompt is dismissed (`accept: false`), and a beforeunload is
/// accepted, so the page is left. Called on the pipe reader, which must
/// never wait for its own CDP reply: the answer goes from its own thread,
/// and one that fails changes nothing.
fn answer_dialog(pipe: &Pipe, event: &Value) {
    if event["method"].as_str() != Some("Page.javascriptDialogOpening") {
        return;
    }
    let Some(session) = event["sessionId"].as_str().map(str::to_owned) else {
        return;
    };
    let accept = event.pointer("/params/type").and_then(Value::as_str) == Some("beforeunload");
    let pipe = pipe.clone();
    std::thread::spawn(move || {
        let _ = pipe.call(
            Some(&session),
            "Page.handleJavaScriptDialog",
            json!({"accept": accept}),
            Instant::now() + std::time::Duration::from_secs(30),
        );
    });
}

/// Called on the pipe reader, which must never wait for its own CDP reply.
fn network_event(pipe: Pipe, relay: Arc<dyn oneiron_container::EgressRelay>, event: Value) {
    let method = event["method"].as_str().unwrap_or("");
    if method == "Target.attachedToTarget" {
        let Some(session) = event
            .pointer("/params/sessionId")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return;
        };
        // Claimed here, on the reader, so a later reply never finds a page
        // unclaimed whose attach came first.
        let routed = event
            .pointer("/params/targetInfo/targetId")
            .and_then(Value::as_str)
            .is_some_and(|target| !pipe.claim_network(target));
        let attached = recorder::Attached::of(&event);
        std::thread::spawn(move || {
            let deadline = Instant::now() + std::time::Duration::from_secs(30);
            if routed || enable_network(&pipe, &session, deadline).is_ok() {
                pipe.record_attached(&session, &attached, deadline);
                let _ = pipe.call(
                    Some(&session),
                    "Runtime.runIfWaitingForDebugger",
                    json!({}),
                    deadline,
                );
            }
        });
    } else if method == "Fetch.requestPaused" {
        let Some(session) = event["sessionId"].as_str().map(str::to_owned) else {
            return;
        };
        let Some(id) = event
            .pointer("/params/requestId")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            return;
        };
        // An engine switch's seed document is answered here, never fetched.
        if let Some(seed) = pipe.take_seed(&session, &event) {
            state::fulfill_seed(pipe, session, id, seed, &event);
            return;
        }
        std::thread::spawn(move || {
            let request = &event["params"]["request"];
            let headers = request["headers"]
                .as_object()
                .map(|h| {
                    h.iter()
                        .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
                        .collect()
                })
                .unwrap_or_default();
            use base64::Engine as _;
            let body = if let Some(entries) = request["postDataEntries"].as_array() {
                let mut body = Vec::new();
                for entry in entries {
                    if let Some(bytes) = entry["bytes"].as_str() {
                        match base64::engine::general_purpose::STANDARD.decode(bytes) {
                            Ok(bytes) => body.extend(bytes),
                            Err(_) => {
                                let _ = pipe.call(
                                    Some(&session),
                                    "Fetch.failRequest",
                                    json!({"requestId": id, "errorReason": "Failed"}),
                                    Instant::now() + std::time::Duration::from_secs(30),
                                );
                                return;
                            }
                        }
                    } else {
                        let _ = pipe.call(
                            Some(&session),
                            "Fetch.failRequest",
                            json!({"requestId": id, "errorReason": "Failed"}),
                            Instant::now() + std::time::Duration::from_secs(30),
                        );
                        return;
                    }
                }
                body
            } else if let Some(data) = request["postData"].as_str() {
                data.as_bytes().to_vec()
            } else if request["hasPostData"].as_bool() == Some(true) {
                let network_id = event.pointer("/params/networkId").and_then(Value::as_str);
                match network_id
                    .and_then(|network_id| {
                        pipe.call(
                            Some(&session),
                            "Network.getRequestPostData",
                            json!({"requestId": network_id}),
                            Instant::now() + std::time::Duration::from_secs(30),
                        )
                        .ok()
                    })
                    .and_then(|data| data["postData"].as_str().map(|s| s.as_bytes().to_vec()))
                {
                    Some(bytes) => bytes,
                    None => {
                        let _ = pipe.call(
                            Some(&session),
                            "Fetch.failRequest",
                            json!({"requestId": id, "errorReason": "Failed"}),
                            Instant::now() + std::time::Duration::from_secs(30),
                        );
                        return;
                    }
                }
            } else {
                Vec::new()
            };
            let asked = oneiron_container::HttpRequest {
                url: request["url"].as_str().unwrap_or("").to_owned(),
                method: request["method"].as_str().unwrap_or("GET").to_owned(),
                headers,
                body,
                follow_redirects: false,
            };
            // The host's handler takes it where the session has one, else the
            // relay; a refusal it gave is kept before the request fails.
            let response = pipe.fetch_paused(&relay, &session, &event, asked);
            let deadline = Instant::now() + std::time::Duration::from_secs(30);
            match response {
                Some(response) => {
                    use base64::Engine as _;
                    let headers: Vec<_> = response
                        .headers
                        .into_iter()
                        .map(|(name, value)| json!({"name": name, "value": value}))
                        .collect();
                    let _ = pipe.call(
                        Some(&session),
                        "Fetch.fulfillRequest",
                        json!({"requestId": id,
                        "responseCode": response.status, "responseHeaders": headers,
                        "body": base64::engine::general_purpose::STANDARD.encode(response.body)}),
                        deadline,
                    );
                }
                None => {
                    let _ = pipe.call(
                        Some(&session),
                        "Fetch.failRequest",
                        json!({"requestId": id, "errorReason": "BlockedByClient"}),
                        deadline,
                    );
                }
            }
        });
    }
}

/// Has the browser attach every page it opens from now on (a popup, a tab a
/// link opens), paused at its start until [`network_event`] routed its
/// network through the proxy, as the first page's is. Frames and workers
/// stay each page's own auto-attach.
pub(crate) fn follow_pages(pipe: &Pipe, deadline: Instant) -> Result<(), BrowserError> {
    pipe.call(
        None,
        "Target.setAutoAttach",
        json!({"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true,
        "filter": [{"type": "page"}]}),
        deadline,
    )?;
    Ok(())
}

pub(crate) fn enable_network(
    pipe: &Pipe,
    session: &str,
    deadline: Instant,
) -> Result<(), BrowserError> {
    pipe.call(Some(session), "Network.enable", json!({}), deadline)?;
    pipe.call(
        Some(session),
        "Network.setBypassServiceWorker",
        json!({"bypass": true}),
        deadline,
    )?;
    pipe.call(
        Some(session),
        "Fetch.enable",
        json!({"patterns": [
            {"urlPattern": "http://*", "requestStage": "Request"},
            {"urlPattern": "https://*", "requestStage": "Request"}
        ]}),
        deadline,
    )?;
    pipe.call(
        Some(session),
        "Target.setAutoAttach",
        json!({"autoAttach": true,
        "waitForDebuggerOnStart": true, "flatten": true}),
        deadline,
    )?;
    Ok(())
}
