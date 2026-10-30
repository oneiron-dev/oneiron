//! The house EXL3 worker's native channel, host side (DESIGN-V2 §8, V2-R1):
//! a managed EXL3 worker whose launch has a native socket is called over it,
//! through the same OpenAI-compatible adapter as any chat provider, so the
//! request mapping, stream decoding, output cap and schema policy are the
//! ones HTTP uses.
//!
//! [`NativeExl3Transport`] is the provider's transport when a managed EXL3
//! worker this process launches is bound to it. A call whose wire model that
//! worker serves, while its current launch has a socket, goes over the
//! socket: with a lease of its own on the incarnation it was sent to, the
//! epoch that incarnation answered its qualification with, and the
//! conversation in a sealed shared region (`buffer.rs`, `transport.rs`,
//! codec v1 in `wire.rs`). Every other call on the provider goes over its
//! HTTP route exactly as before. A call that may have been admitted is never
//! sent again over HTTP: a fault after `generate` left is a cut stream, for
//! the caller's own retry authority, which never replays a tool's effects.
//!
//! The worker's `final` carries the HTTP reply's fields, its usage with the
//! same inference receipt R1 defined; it goes through the same reply
//! evidence as an HTTP answer (`openai::carry_reply_evidence`). A receipt
//! that claims verified artifacts keeps the claim only when it echoes the
//! manifest of the launch this host started and the epoch the call went to
//! (FIX 9195); otherwise its build is unknown. The cheap stats in each
//! `final` feed the worker's activity (FIX 9190), as the supervisor's own
//! poll ([`activity`]) does.
mod buffer;
mod session_ops;
mod transport;
mod updates;
mod wire;

pub(super) use session_ops::{OpFault, capability as session_capability, send as session_send};
pub(super) use transport::next_request_id;
// Codec v1.2's snapshot ops (R3), for the session coordinator's park and
// restore paths.
pub(super) use buffer::SnapshotRegion;
pub(super) use session_ops::{export as session_export, import as session_import};

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::BudgetLease;
use oneiron::llm::run_admission::WorkContext;
use oneiron::llm::{
    INFERENCE_CALLS_KEY, InferenceCallReceipt, SchedulingReceipt, SegmentManifest,
    WorkerBuildEvidence, WorkerFailure,
};
use oneiron_driver::{WorkEnvelope, WorkerActivity};
use oneiron_llm_openai::{
    OpenAiCompatFuture, OpenAiCompatHttpRequest, OpenAiCompatHttpResponse,
    OpenAiCompatProviderStream, OpenAiCompatStreamFrame, OpenAiCompatTransport,
    OpenAiCompatTransportError,
};
use serde::Deserialize;
use serde_json::{Map as JsonMap, Value as JsonValue, json};

use super::openai::{OpenAiHttp, carry_reply_evidence, send_format};
use super::worker_host::{self, NativeRoute};
use transport::{Call, Channel, Cut, Event, Start};

/// The usage key a worker's answer echoes its launch manifest's digest
/// under, as the worker probe reads it.
const LAUNCH_MANIFEST_KEY: &str = "launch_manifest";

/// What a worker's `resident_mib` must say it measures to be its resident
/// memory: this process's CUDA allocator reservations.
const RESIDENT_SOURCE: &str = "cuda_allocator_reserved";

/// The stats detail the supervisor's activity poll asks for: allocator
/// counters, pages and queue, with no walk over the live tensors.
const POLL_DETAIL: &str = "cheap";

/// A provider's chat transport when a managed EXL3 worker is bound to it.
pub(super) struct NativeExl3Transport {
    provider: String,
    http: OpenAiHttp,
}

impl NativeExl3Transport {
    /// The transport for provider `name`, when a managed EXL3 worker this
    /// process launches is bound to it and the provider holds no Responses
    /// socket; otherwise `http` back, to serve as it always has.
    pub(super) fn bind(
        name: &str,
        responses_socket: bool,
        http: OpenAiHttp,
    ) -> Result<Self, OpenAiHttp> {
        if responses_socket || !worker_host::serves_native(name) {
            return Err(http);
        }
        Ok(Self {
            provider: name.to_owned(),
            http,
        })
    }

    /// The native route of the worker the call's wire model is bound to,
    /// when its current launch has a socket.
    fn route(&self, body: &JsonValue) -> Option<NativeRoute> {
        let wire_model = body.get("model").and_then(JsonValue::as_str)?;
        worker_host::native_route(&self.provider, wire_model)
    }

    /// The body as HTTP would send it: its output cap and response format.
    fn shaped(&self, mut body: JsonValue) -> JsonValue {
        self.http.cap.apply(&mut body);
        send_format(self.http.response_format, &mut body);
        body
    }
}

/// One native `generate` per call, never resent; a call no native route
/// serves is one HTTP send, as before.
impl oneiron::llm::SingleSend for NativeExl3Transport {}

impl OpenAiCompatTransport for NativeExl3Transport {
    fn execute<'a>(
        &'a self,
        request: OpenAiCompatHttpRequest,
        lease: &'a BudgetLease,
    ) -> OpenAiCompatFuture<'a> {
        let Some(route) = self.route(&request.body) else {
            return self.http.execute(request, lease);
        };
        let segments = request.host_segments;
        let body = self.shaped(request.body);
        Box::pin(execute(route, body, segments))
    }

    fn stream<'a>(
        &'a self,
        request: OpenAiCompatHttpRequest,
        lease: &'a BudgetLease,
    ) -> Result<OpenAiCompatProviderStream<'a>, OpenAiCompatTransportError> {
        let Some(route) = self.route(&request.body) else {
            return self.http.stream(request, lease);
        };
        let segments = request.host_segments;
        let body = self.shaped(request.body);
        Ok(Box::pin(futures_util::stream::unfold(
            Streaming::Start {
                route,
                body,
                segments,
            },
            Streaming::step,
        )))
    }
}

/// What a sent call answers to: its manifest and epoch check (FIX 9195).
struct Tie {
    manifest_sha256: String,
    epoch: String,
}

impl Tie {
    /// Keeps each receipt's verified-artifacts claim only when the answer
    /// echoes this launch's manifest and the receipt names this epoch;
    /// otherwise the receipt's build is unknown.
    fn apply(&self, body: &mut JsonValue) {
        let Some(usage) = body.get_mut("usage").and_then(JsonValue::as_object_mut) else {
            return;
        };
        let echoed = usage.get(LAUNCH_MANIFEST_KEY).and_then(JsonValue::as_str)
            == Some(self.manifest_sha256.as_str());
        let Some(JsonValue::Array(calls)) = usage.get_mut(INFERENCE_CALLS_KEY) else {
            return;
        };
        for call in calls {
            let Some(worker) = call.get_mut("worker").and_then(JsonValue::as_object_mut) else {
                continue;
            };
            let claimed = worker
                .get("build_evidence")
                .and_then(|evidence| WorkerBuildEvidence::deserialize(evidence).ok())
                == Some(WorkerBuildEvidence::VerifiedArtifacts);
            let epoch = worker
                .get("identity")
                .and_then(|identity| identity.get("backend_epoch"))
                .and_then(JsonValue::as_str);
            if claimed
                && !(echoed && epoch == Some(self.epoch.as_str()))
                && let Ok(unknown) = serde_json::to_value(WorkerBuildEvidence::Unknown)
            {
                worker.insert("build_evidence".to_owned(), unknown);
            }
        }
    }
}

/// A call that went out, and what its answer must tie to.
struct Sent {
    call: Call,
    tie: Tie,
    #[expect(
        dead_code,
        reason = "its Drop unregisters the call's device update row"
    )]
    registration: Option<updates::Registration>,
    /// Holds non-updates foreground presence until the call itself ends.
    _foreground: Option<updates::Foreground>,
}

/// How a call's start ended.
enum Begun {
    Sent(Sent),
    /// The worker refused the request itself: the reply HTTP gives for it.
    Answered(OpenAiCompatHttpResponse),
}

/// Sends the call on `route`: a lease of its own on the ready incarnation,
/// the epoch it answered its qualification with, and the current launch's
/// socket. A call whose `segments` the session coordinator takes runs on
/// its session's working branch (DESIGN-V2 R2, `worker_host::session`);
/// every other call, and one whose session op failed, as a plain `generate`.
async fn begin(
    route: &NativeRoute,
    body: &JsonValue,
    stream: bool,
    segments: Option<&SegmentManifest>,
    context: WorkContext,
) -> Result<Begun, OpenAiCompatTransportError> {
    // The ticket precedes demand; an early exit cancels it without touching
    // the worker. Foreground arrival yields only update-capable background
    // calls on the same device. EXL3's steady declaration covers its weights,
    // KV pool and workspace, so a call's incremental host charge is qualified
    // zero; an unknown steady commitment still fails the ledger's room check.
    let envelope = WorkEnvelope {
        kv_increment_mib: Some(0),
        workspace_mib: Some(0),
    };
    let mut work = worker_host::admit_bound_work(&route.worker, context, envelope);
    let foreground = if work.is_foreground() {
        match work.device() {
            Some(device) => Some(updates::foreground_arrival(device).await),
            None => None,
        }
    } else {
        None
    };
    work.wait_runnable()
        .await
        .map_err(|_| OpenAiCompatTransportError::Connection)?;
    let lease = route
        .worker
        .acquire()
        .await
        .map_err(|_| OpenAiCompatTransportError::Connection)?;
    let epoch = lease
        .observed()
        .and_then(|observed| observed.identity.backend_epoch.as_ref())
        .map(|epoch| epoch.as_str().to_owned())
        .ok_or(OpenAiCompatTransportError::Connection)?;
    let (socket, manifest_sha256) = route
        .launch()
        .ok_or(OpenAiCompatTransportError::Connection)?;
    if lease.revoked() {
        return Err(OpenAiCompatTransportError::Connection);
    }
    // Readiness is now proved, so take the execution grant before any
    // session op or generate. It and the worker lease share release custody.
    let grant = work
        .execution_grant()
        .await
        .map_err(|_| OpenAiCompatTransportError::Connection)?;
    let schedule = work.schedule(grant.as_ref());
    let (conversation, params) = wire::split_request(body);
    let session = match segments {
        Some(manifest) => {
            worker_host::open_turn(
                route,
                &socket,
                &epoch,
                lease.observed(),
                manifest,
                &conversation,
                &params,
            )
            .await
        }
        None => None,
    };
    let plain = session.is_some().then(|| params.clone());
    // A plain retry after a refused session is the same call: it reuses the
    // ticket, grant, class, priority and deadline.
    let mut started = Call::start(
        &socket,
        &epoch,
        &conversation,
        params,
        stream,
        Some(lease),
        session,
        Some(&schedule),
    )
    .await;
    let refused = matches!(
        &started,
        Err(Start::Refused(refusal)) if !wire::refusal_is_request(wire::refusal_code(refusal))
    );
    if let (true, Some(params)) = (refused, plain) {
        let lease = route
            .worker
            .acquire()
            .await
            .map_err(|_| OpenAiCompatTransportError::Connection)?;
        started = Call::start(
            &socket,
            &epoch,
            &conversation,
            params,
            stream,
            Some(lease),
            None,
            Some(&schedule),
        )
        .await;
    }
    match started {
        Ok(call) => {
            let mut call = call;
            let registration = grant.as_ref().and_then(|grant| {
                work.device().and_then(|device| {
                    updates::register(
                        device.to_owned(),
                        grant.grant_id(),
                        grant.revision(),
                        schedule.work_class,
                        route.scheduling_capability(),
                        call.updates(),
                    )
                })
            });
            call.set_grant(grant);
            // A registration carries updates-capable foreground presence.
            // Otherwise keep the arrival guard in Sent until the call ends.
            let foreground = if registration.is_none() {
                foreground
            } else {
                None
            };
            Ok(Begun::Sent(Sent {
                call,
                tie: Tie {
                    manifest_sha256,
                    epoch,
                },
                registration,
                _foreground: foreground,
            }))
        }
        Err(Start::Refused(refusal)) => {
            let code = wire::refusal_code(&refusal);
            if wire::refusal_is_request(code) {
                Ok(Begun::Answered(refused_reply(&refusal)))
            } else {
                // Another incarnation answered, or the worker drains: the
                // call ran nowhere.
                Err(transport::refusal(&refusal))
            }
        }
        Err(Start::NotSent(error) | Start::Cut(error)) => Err(error),
    }
}

/// A buffered call over the native route.
async fn execute(
    route: NativeRoute,
    body: JsonValue,
    segments: Option<Arc<SegmentManifest>>,
) -> Result<OpenAiCompatHttpResponse, OpenAiCompatTransportError> {
    let target = body
        .get("model")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    let mut sent = match begin(
        &route,
        &body,
        false,
        segments.as_deref(),
        WorkContext::default(),
    )
    .await?
    {
        Begun::Sent(sent) => sent,
        Begun::Answered(reply) => return Ok(reply),
    };
    let last = loop {
        match sent.call.next().await {
            Ok(Event::Final(last)) => break last,
            Ok(Event::Admitted(mark)) => report(&route, &mark),
            Ok(Event::Scheduled(ack)) => report_stats(&route, ack.stats.as_ref()),
            Ok(Event::FirstToken | Event::Token { .. }) => {}
            Err(Cut(error)) => {
                refresh_after_cut(&route);
                return Err(error);
            }
        }
    };
    report(&route, &last);
    record_receipt(&route, &sent, &last);
    Ok(buffered_reply(last, target.as_deref(), Some(&sent.tie)))
}

/// A `refused` request as the 400 reply HTTP gives for an invalid one.
fn refused_reply(refusal: &JsonValue) -> OpenAiCompatHttpResponse {
    let mut error = JsonMap::new();
    error.insert(
        "message".to_owned(),
        refusal.get("message").cloned().unwrap_or(JsonValue::Null),
    );
    error.insert(
        "type".to_owned(),
        JsonValue::String("invalid_request_error".to_owned()),
    );
    error.insert(
        "code".to_owned(),
        JsonValue::String(wire::refusal_code(refusal).to_owned()),
    );
    OpenAiCompatHttpResponse {
        status: 400,
        headers: BTreeMap::new(),
        body: json!({ "error": error }),
    }
}

/// A `final` that is not done, as the error reply HTTP gives.
fn error_reply(last: &JsonValue) -> OpenAiCompatHttpResponse {
    let error = last.get("error").cloned().unwrap_or_else(|| json!({}));
    OpenAiCompatHttpResponse {
        status: wire::error_status(&error),
        headers: BTreeMap::new(),
        body: json!({ "error": error }),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn take(object: &mut JsonValue, key: &str) -> JsonValue {
    object.get_mut(key).map(JsonValue::take).unwrap_or_default()
}

/// A done `final` as the buffered chat reply HTTP gives, through the same
/// reply evidence, and tied to its launch when `tie` names one.
fn buffered_reply(
    mut last: JsonValue,
    target: Option<&str>,
    tie: Option<&Tie>,
) -> OpenAiCompatHttpResponse {
    if last.get("outcome").and_then(JsonValue::as_str) != Some("done") {
        return error_reply(&last);
    }
    let mut body = json!({
        "id": format!("chatcmpl-native-{}", transport::next_request_id()),
        "object": "chat.completion",
        "created": now_secs(),
        "model": take(&mut last, "model"),
        "choices": [{
            "index": 0,
            "message": take(&mut last, "message"),
            "finish_reason": take(&mut last, "finish_reason"),
        }],
        "usage": take(&mut last, "usage"),
        "timings": take(&mut last, "timings"),
    });
    carry_reply_evidence(200, &mut body, target, None);
    if let Some(tie) = tie {
        tie.apply(&mut body);
    }
    OpenAiCompatHttpResponse {
        status: 200,
        headers: BTreeMap::new(),
        body,
    }
}

/// The activity a worker's stats report: its queue depth (submits waiting
/// for a place plus its ingress queue), what else it has open, and its
/// resident memory when the stats say it is the allocator's reservation.
fn activity_of(stats: &JsonValue) -> Option<WorkerActivity> {
    let queue = stats.get("queue")?;
    let queued = queue.get("queue_depth")?.as_u64()?;
    let open = queue.get("open_calls")?.as_u64()?;
    let resident_mib = (stats.get("resident_source").and_then(JsonValue::as_str)
        == Some(RESIDENT_SOURCE))
    .then(|| stats.get("resident_mib").and_then(JsonValue::as_u64))
    .flatten();
    Some(WorkerActivity {
        queued,
        active: open.saturating_sub(queued),
        resident_mib,
    })
}

/// Retains the physical receipt a terminal carried, with its launch epoch.
fn record_receipt(route: &NativeRoute, sent: &Sent, last: &JsonValue) {
    let scheduling = last
        .get("scheduling")
        .and_then(|value| serde_json::from_value::<SchedulingReceipt>(value.clone()).ok());
    let receipt = last
        .get("usage")
        .and_then(|usage| usage.get(INFERENCE_CALLS_KEY))
        .and_then(JsonValue::as_array)
        .and_then(|calls| {
            calls
                .iter()
                .find_map(|call| serde_json::from_value::<InferenceCallReceipt>(call.clone()).ok())
        });
    if let Some(mut receipt) = receipt {
        receipt.scheduling = scheduling;
        worker_host::report_receipt(&route.worker.spec().worker_id, &sent.tie.epoch, receipt);
    }
}

/// Feeds the cheap stats of a `final`, or of an `admitted`, to the worker's
/// supervisor.
fn report(route: &NativeRoute, last: &JsonValue) {
    report_stats(route, last.get("stats"));
}

/// Feeds cheap `stats` the worker took at an event (an admission, a
/// `schedule` applied, a terminal) to its supervisor: reports between its
/// polls.
fn report_stats(route: &NativeRoute, stats: Option<&JsonValue>) {
    if let Some(stats) = stats {
        worker_host::report_device_stats(&route.worker.spec().worker_id, stats);
    }
    if let Some(activity) = stats.and_then(activity_of) {
        worker_host::report_device_activity(&route.worker, activity);
    }
}

/// Re-polls after a Cut so a stale mid-call busy row cannot block idle-stop
/// or pressure victim discovery. A dead worker's supervisor owns its truth.
fn refresh_after_cut(route: &NativeRoute) {
    let Some((socket, _)) = route.launch() else {
        return;
    };
    let route = route.clone();
    tokio::spawn(async move {
        if let Some(activity) = activity(&socket).await {
            worker_host::report_device_activity(&route.worker, activity);
        }
    });
}

/// What the worker holds now, from a cheap `stats` on its socket: the
/// supervisor's activity poll. `None` when it does not answer.
pub(super) async fn activity(socket: &Path) -> Option<WorkerActivity> {
    let mut channel = Channel::connect(socket).await.ok()?;
    let stats = channel
        .ask("stats", json!({ "detail": POLL_DETAIL }))
        .await
        .ok()?;
    activity_of(&stats)
}

/// Asks the worker at `socket` to stop (FIX 9298): `drain`, answered once
/// every call it accepted has ended, with no deadline, then `shutdown`. A
/// worker that does not answer is left to the caller's signals.
pub(super) async fn drain_and_shutdown(socket: &Path) {
    let Ok(mut channel) = Channel::connect(socket).await else {
        return;
    };
    if channel
        .exchange("drain", None, json!({}), None)
        .await
        .is_err()
    {
        return;
    }
    let _ = channel.ask("shutdown", json!({})).await;
}

/// One qualification over the worker's socket: its `hello`, then `request`
/// sent once, buffered, with the epoch the hello named. Returns the hello
/// and the reply in the HTTP reply's shape.
pub(super) async fn qualify(
    socket: &Path,
    request: &JsonValue,
) -> Result<(JsonValue, JsonValue), WorkerFailure> {
    let mut channel = Channel::connect(socket)
        .await
        .map_err(|_| WorkerFailure::Unreachable)?;
    let hello = channel
        .ask("hello", json!({}))
        .await
        .map_err(|_| WorkerFailure::Unreachable)?;
    drop(channel);
    let epoch = hello
        .get("epoch")
        .and_then(JsonValue::as_str)
        .ok_or(WorkerFailure::InvalidReply)?
        .to_owned();
    let (conversation, params) = wire::split_request(request);
    let mut call = Call::start(
        socket,
        &epoch,
        &conversation,
        params,
        false,
        None,
        None,
        None,
    )
    .await
    .map_err(|start| match start {
        Start::Refused(_) => WorkerFailure::InvalidReply,
        Start::NotSent(_) | Start::Cut(_) => WorkerFailure::Unreachable,
    })?;
    let last = loop {
        match call.next().await {
            Ok(Event::Final(last)) => break last,
            Ok(
                Event::Admitted(_) | Event::FirstToken | Event::Token { .. } | Event::Scheduled(_),
            ) => {}
            Err(Cut(_)) => return Err(WorkerFailure::Unreachable),
        }
    };
    let target = request.get("model").and_then(JsonValue::as_str);
    let reply = buffered_reply(last, target, None);
    if !(200..300).contains(&reply.status) {
        return Err(WorkerFailure::InvalidReply);
    }
    Ok((hello, reply.body))
}

type Frame = Result<OpenAiCompatStreamFrame, OpenAiCompatTransportError>;

/// A streamed call over the native route.
enum Streaming {
    Start {
        route: NativeRoute,
        body: JsonValue,
        segments: Option<Arc<SegmentManifest>>,
    },
    Live(Box<Live>),
    Done,
}

/// A streamed call in flight: the chunks it owes, in order.
struct Live {
    route: NativeRoute,
    sent: Sent,
    target: Option<String>,
    id: String,
    created: u64,
    model: JsonValue,
    pending: VecDeque<Frame>,
    /// A piece of the reply went out already.
    streamed: bool,
    finished: bool,
}

impl Streaming {
    async fn step(self) -> Option<(Frame, Self)> {
        match self {
            Self::Start {
                route,
                body,
                segments,
            } => {
                let target = body
                    .get("model")
                    .and_then(JsonValue::as_str)
                    .map(str::to_owned);
                match begin(
                    &route,
                    &body,
                    true,
                    segments.as_deref(),
                    WorkContext::default(),
                )
                .await
                {
                    Ok(Begun::Sent(sent)) => Box::new(Live::over(route, sent, target)).next().await,
                    Ok(Begun::Answered(reply)) => {
                        Some((Ok(OpenAiCompatStreamFrame::Status(reply)), Self::Done))
                    }
                    Err(error) => Some((Err(error), Self::Done)),
                }
            }
            Self::Live(live) => live.next().await,
            Self::Done => None,
        }
    }
}

impl Live {
    fn over(route: NativeRoute, sent: Sent, target: Option<String>) -> Self {
        Self {
            route,
            sent,
            model: target.clone().map_or(JsonValue::Null, JsonValue::String),
            target,
            id: format!("chatcmpl-native-{}", transport::next_request_id()),
            created: now_secs(),
            pending: VecDeque::new(),
            streamed: false,
            finished: false,
        }
    }

    fn chunk(&self, delta: JsonValue, finish: JsonValue) -> JsonValue {
        json!({
            "id": self.id,
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
        })
    }

    fn piece(&self, field: &str, text: String) -> JsonValue {
        let mut delta = JsonMap::new();
        delta.insert(field.to_owned(), JsonValue::String(text));
        self.chunk(JsonValue::Object(delta), JsonValue::Null)
    }

    async fn next(mut self: Box<Self>) -> Option<(Frame, Streaming)> {
        loop {
            if let Some(frame) = self.pending.pop_front() {
                return Some((frame, Streaming::Live(self)));
            }
            if self.finished {
                return None;
            }
            match self.sent.call.next().await {
                Ok(Event::FirstToken) => {}
                Ok(Event::Admitted(mark)) => report(&self.route, &mark),
                Ok(Event::Scheduled(ack)) => report_stats(&self.route, ack.stats.as_ref()),
                Ok(Event::Token { reasoning, text }) => {
                    if text.is_empty() {
                        continue;
                    }
                    self.streamed = true;
                    let field = if reasoning {
                        "reasoning_content"
                    } else {
                        "content"
                    };
                    let chunk = self.piece(field, text);
                    self.pending
                        .push_back(Ok(OpenAiCompatStreamFrame::Chunk(chunk)));
                }
                Ok(Event::Final(last)) => {
                    self.finished = true;
                    report(&self.route, &last);
                    record_receipt(&self.route, &self.sent, &last);
                    self.finish(last);
                }
                Err(Cut(error)) => {
                    refresh_after_cut(&self.route);
                    self.finished = true;
                    self.pending.push_back(Err(error));
                }
            }
        }
    }

    /// The chunks a `final` owes: what the worker held back, the tool calls,
    /// and the last chunk with its finish, usage and timings. An error is the
    /// error reply when nothing went out yet, else a cut stream, as an HTTP
    /// stream's would be.
    fn finish(&mut self, mut last: JsonValue) {
        if last.get("outcome").and_then(JsonValue::as_str) != Some("done") {
            let frame = if self.streamed {
                let error = last.get("error").cloned().unwrap_or_default();
                tracing::warn!(%error, "native EXL3 call ended with an error mid-reply");
                Err(OpenAiCompatTransportError::EndedWithError(
                    error.to_string(),
                ))
            } else {
                Ok(OpenAiCompatStreamFrame::Status(error_reply(&last)))
            };
            self.pending.push_back(frame);
            return;
        }
        if let Some(model) = last.get("model").filter(|model| model.is_string()) {
            self.model = model.clone();
        }
        if let Some(tail) = last
            .get("tail")
            .and_then(JsonValue::as_str)
            .filter(|tail| !tail.is_empty())
        {
            let chunk = self.piece("content", tail.to_owned());
            self.pending
                .push_back(Ok(OpenAiCompatStreamFrame::Chunk(chunk)));
        }
        if let Some(calls) = last.get("tool_calls").filter(|calls| calls.is_array()) {
            let chunk = self.chunk(json!({ "tool_calls": calls }), JsonValue::Null);
            self.pending
                .push_back(Ok(OpenAiCompatStreamFrame::Chunk(chunk)));
        }
        let mut chunk = self.chunk(json!({}), take(&mut last, "finish_reason"));
        if let Some(object) = chunk.as_object_mut() {
            object.insert("usage".to_owned(), take(&mut last, "usage"));
            object.insert("timings".to_owned(), take(&mut last, "timings"));
        }
        carry_reply_evidence(200, &mut chunk, self.target.as_deref(), None);
        self.sent.tie.apply(&mut chunk);
        self.pending
            .push_back(Ok(OpenAiCompatStreamFrame::Chunk(chunk)));
    }
}
