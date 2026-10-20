//! The Chrome DevTools Protocol over Chromium's `--remote-debugging-pipe`:
//! JSON messages, each ended by a NUL byte, on one reader and one writer.
//! Replies are matched to calls by id. Network events cross the host proxy,
//! for every page the guest opens; the DOM driver still polls for its
//! observations and its tabs. Each page session's navigation events are
//! counted, for the driver's change check (FIX 6680).

use crate::BrowserError;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The largest message the pipe reads. A 1,366 px PNG screenshot in base64
/// is a few MiB; a message past this closes the pipe.
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

#[derive(Clone)]
pub(crate) struct Pipe {
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    pending: Pending,
    next: Arc<AtomicU64>,
    egress: bool,
    /// The targets one session already routes through the proxy: another
    /// session on one of them (the driver's own, or the browser's auto-attach
    /// finding a page again) only lets it run.
    routed: Arc<Mutex<HashSet<String>>>,
    navigations: Navigations,
}

impl Pipe {
    pub(crate) fn new(
        reader: impl Read + Send + 'static,
        writer: impl Write + Send + 'static,
    ) -> Self {
        Self::with_egress(reader, writer, None)
    }

    pub(crate) fn with_egress(
        reader: impl Read + Send + 'static,
        writer: impl Write + Send + 'static,
        relay: Option<Arc<dyn oneiron_container::EgressRelay>>,
    ) -> Self {
        let pending: Pending = Arc::new(Mutex::new(Some(HashMap::new())));
        let pipe = Self {
            writer: Arc::new(Mutex::new(Box::new(writer))),
            pending,
            next: Arc::new(AtomicU64::new(1)),
            egress: relay.is_some(),
            routed: Arc::default(),
            navigations: Arc::default(),
        };
        let handle = pipe.clone();
        std::thread::spawn(move || {
            read_replies(BufReader::new(reader), &handle, relay);
            if let Ok(mut routes) = handle.pending.lock() {
                routes.take();
            }
        });
        pipe
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

    /// Counts page `session`'s navigation events from now on: its Page
    /// domain is enabled.
    pub(crate) fn watch_navigations(&self, session: &str) {
        if let Ok(mut navigations) = self.navigations.lock() {
            navigations.entry(session.to_owned()).or_default();
        }
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
        let mut bytes =
            serde_json::to_vec(&message).map_err(|e| BrowserError::Protocol(e.to_string()))?;
        bytes.push(0);
        {
            let mut writer = self.writer.lock().map_err(|_| BrowserError::GuestLost)?;
            writer
                .write_all(&bytes)
                .and_then(|()| writer.flush())
                .map_err(|_| BrowserError::GuestLost)?;
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
    relay: Option<Arc<dyn oneiron_container::EgressRelay>>,
) {
    let routes = &pipe.pending;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match (&mut reader).take(MAX_MESSAGE).read_until(0, &mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) if buf.last() != Some(&0) => return,
            Ok(_) => {}
        }
        buf.pop();
        let Ok(message) = serde_json::from_slice::<Value>(&buf) else {
            continue;
        };
        let Some(id) = message.get("id").and_then(Value::as_u64) else {
            count_navigation(&pipe.navigations, &message);
            if let Some(relay) = &relay {
                network_event(pipe.clone(), Arc::clone(relay), message);
            }
            continue;
        };
        let reply = match message.get("error") {
            Some(error) => Err(error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("error")
                .to_owned()),
            None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
        };
        let Ok(mut routes) = routes.lock() else {
            return;
        };
        if let Some(tx) = routes.as_mut().and_then(|routes| routes.remove(&id)) {
            let _ = tx.send(reply);
        }
    }
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
        std::thread::spawn(move || {
            let deadline = Instant::now() + std::time::Duration::from_secs(30);
            if routed || enable_network(&pipe, &session, deadline).is_ok() {
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
            let response = relay.fetch(oneiron_container::HttpRequest {
                url: request["url"].as_str().unwrap_or("").to_owned(),
                method: request["method"].as_str().unwrap_or("GET").to_owned(),
                headers,
                body,
                follow_redirects: false,
            });
            let deadline = Instant::now() + std::time::Duration::from_secs(30);
            match response {
                Ok(response) => {
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
                Err(_) => {
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
