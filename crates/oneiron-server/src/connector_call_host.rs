//! The served [`ConnectorCallHost`] (ONE-2510): the generic connector call's
//! transport, credential and reply, beneath the catalog name.
//!
//! The engine routes a guest's call by catalog name, finds the caller's
//! standing grant, prepares the call against the governing key's approved
//! schema, and runs it through the gate and the intent ledger. This host is
//! the send: MCP streamable HTTP to the endpoint `[connectors.<name>]`
//! installed, with the connector key's credential presented only inside the
//! credential door. One send is one `tools/call`: `initialize` at the key's
//! pinned protocol revision, `notifications/initialized`, then the call
//! itself. No proxy, no redirects, a complete reply and short timeouts.
//!
//! The reply is foreign data. The host keeps its own copy of the
//! `tools/call` result for the caller; the ledger's scrub still destroys the
//! raw bytes before anything durable is written. Sampling and roots are not
//! served: any such server request on the reply stream is refused.
//!
//! A connector may ask for input mid-call (elicitation). `initialize`
//! declares the capability only when the governing key's elicitation setting,
//! read before the exchange starts, is not `never allow`, the engine bound
//! the call's caller and grant, and the pinned revision has an elicitation
//! shape: 2025-06-18 declares `{}`, 2025-11-25 and 2026-07-28 form mode
//! alone. A question is a form-mode
//! `elicitation/create` request on the reply stream (2025-06-18,
//! 2025-11-25), or a 2026-07-28 `tools/call` result that asks for input,
//! each of its requests a form `elicitation/create`. Either way the call
//! reached the connector: the send is acknowledged, the host keeps the
//! questions for its caller in place of a result, and a worker thread takes
//! the open exchange, registered in the server's
//! [`ConnectorElicitationRegistry`]. It sends the caller's checked answer,
//! reads what the connector says next, and ends the session when the call
//! ends or its exchange does. Any other server request is refused as
//! before, and any other result is the tool's.
//!
//! A `self.use` call (OF-560) presents the custody record its handle names
//! in place of the route's own secret, through the same door for the same
//! effector; the door rechecks the record's binding at each send. A call under
//! a secret grant (FIX 4313) redeems the grant at its door at each send.
//! Every door reads the call's durable issuer binding again before the
//! credential leaves, and a row an issuer change holds sends nothing (FIX 9303).
//! Whatever selected it, everything the connector says is cleared of the
//! value a send presented inside its door, with those bytes (`presenting`):
//! a `self.use` send declares elicitation as any other does, and its
//! questions and every later reply are cleared the same way (FIX 3843).

use std::collections::BTreeMap;
use std::io::{BufRead, Read};
use std::sync::{Arc, Weak, mpsc};
use std::time::{Duration, Instant};

use oneiron::connector_key::{ConnectorCallRoute, SlateDisposition};
use oneiron::outbound_consent::{
    ConnectorAwaitingInput, ConnectorCallCaller, ConnectorCallHost, ConnectorQuestion,
    FrozenToolCallView, OutboundResultSender, OutboundTransportResult, RawOutboundResult,
    UntrustedToolResult, zeroize_json,
};
use oneiron::outbound_intent_ledger::{
    FrozenOutboundCall, OutboundFailureKind, OutboundSendFailure, OutboundSendOutcome,
    RemoteTaskHandle,
};
use oneiron::secret_custody::{KeptSentValue, RunSecretHolder, SentPresentation, SentValue};
use oneiron::secret_lease::{SecretGrantRef, SecretGrantTarget};
use oneiron::task_verb::sdk::ConnectorAnswerAction;
use oneiron::{EntityId, Vault};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde_json::{Map, Value, json};

use crate::config::connectors::normalize_name;
use crate::config::{ConnectorHostConfig, ConnectorTransport};
use crate::connector_elicitation::{
    AnswerCommand, ConnectorElicitationRegistry, QuestionBinding, Registered, WorkerEvent,
};
use crate::server::SyncServer;

mod json_wire;
mod live_exchange;
mod presenting;
mod remote_task;
mod reply_read;
mod resume;
mod sent;
mod stream_pump;
use json_wire::{KeptWire, post_json};
use live_exchange::{Continuation, LiveSession, hand_over};
use presenting::{KeptRound, KeyAliases, clear_event, clear_questions};
use reply_read::{Reply, StreamEvent, open_reply, read_reply, tool_result};
use resume::RoundResume;
pub(crate) use resume::resume_exchanges;
use sent::Sent;

/// Connecting to a connector's endpoint.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// `initialize`, `notifications/initialized`, a refusal, an answer's POST
/// and the session's end.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// The `tools/call` itself, until its reply is read; on a stream that may
/// carry questions, each read and each round of reading.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

const INITIALIZE_ID: u64 = 1;
const CALL_ID: u64 = 2;
const SESSION_HEADER: &str = "mcp-session-id";
const PROTOCOL_HEADER: &str = "mcp-protocol-version";
const ACCEPT_BOTH: &str = "application/json, text/event-stream";

/// The elicitation wire names this host speaks (ONE-2510): the 2025-06-18 /
/// 2025-11-25 request on the reply stream and its result, and the
/// 2026-07-28 multi round-trip result and its retry. None of these shapes is
/// vendored in tree, so every name lives here, once.
mod wire {
    pub(super) const ELICIT: &str = "elicitation/create";
    pub(super) const MODE: &str = "mode";
    pub(super) const FORM: &str = "form";
    pub(super) const MESSAGE: &str = "message";
    pub(super) const REQUESTED_SCHEMA: &str = "requestedSchema";
    pub(super) const ACTION: &str = "action";
    pub(super) const CONTENT: &str = "content";
    pub(super) const RESULT_TYPE: &str = "resultType";
    pub(super) const INPUT_REQUIRED: &str = "input_required";
    pub(super) const INPUT_REQUESTS: &str = "inputRequests";
    pub(super) const INPUT_RESPONSES: &str = "inputResponses";
    pub(super) const REQUEST_STATE: &str = "requestState";
    /// The key the one question of a stream request takes.
    pub(super) const STREAM_KEY: &str = "0";
}

/// The generic connector call's send on this host.
pub struct ServedConnectorCallHost {
    vault: Arc<Vault>,
    /// Installed transports by normalized catalog name.
    connectors: BTreeMap<String, ConnectorHostConfig>,
    client: reqwest::blocking::Client,
    reply: Option<UntrustedToolResult>,
    /// The custody record a `self.use` call presents, in place of the
    /// route's own secret.
    credential: Option<EntityId>,
    /// The secret grant a lease-aware `self.use` call redeems at each send.
    grant: Option<SecretGrantRef>,
    /// The use's own run, when its seat found that record (FIX 8334).
    run: Option<RunSecretHolder>,
    /// The server's live connector questions, shared by every host it
    /// builds and read by `connector.answer`.
    elicitations: Arc<ConnectorElicitationRegistry>,
    /// The caller and grant the next send runs for, as the engine bound
    /// them.
    caller: Option<ConnectorCallCaller>,
    /// The questions the last send's connector asked, kept for the caller.
    awaiting: Option<ConnectorAwaitingInput>,
    /// The custody record the last send presented, as its door resolved it.
    presented: Option<EntityId>,
    /// The last send's custody presentation, until taken (FIX 7646).
    presentation: Option<SentPresentation>,
    /// The resume state of the last send's first round, until the engine
    /// binds that round to its call's row (FIX 9157).
    resume: Option<RoundResume>,
    /// The remote task the last send's connector accepted it as (FIX 7960).
    remote_task: Option<RemoteTaskHandle>,
    /// The hold the last send met at its door, until taken (FIX 9303).
    held: Option<&'static str>,
}

impl ServedConnectorCallHost {
    /// The host for this server's `[connectors]` and vault. Build it on a
    /// blocking worker: it holds a blocking HTTP client.
    pub fn new(server: &SyncServer) -> oneiron::Result<Self> {
        Self::with_connectors(
            Arc::clone(server.vault()),
            server.config.connectors.clone(),
            Arc::clone(&server.connector_elicitations),
        )
    }

    /// The host for an explicit set of installed transports, keeping its
    /// connectors' questions in `elicitations`: the server's own registry,
    /// the one `connector.answer` reads.
    pub(crate) fn with_connectors(
        vault: Arc<Vault>,
        connectors: BTreeMap<String, ConnectorHostConfig>,
        elicitations: Arc<ConnectorElicitationRegistry>,
    ) -> oneiron::Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(CALL_TIMEOUT)
            .build()
            .map_err(|_| {
                oneiron::Error::InvalidConfig(
                    "the connector HTTP client could not be built".to_owned(),
                )
            })?;
        Ok(Self {
            vault,
            connectors: connectors
                .into_iter()
                .map(|(name, connector)| (normalize_name(&name), connector))
                .collect(),
            client,
            reply: None,
            credential: None,
            grant: None,
            run: None,
            elicitations,
            caller: None,
            awaiting: None,
            presented: None,
            presentation: None,
            resume: None,
            remote_task: None,
            held: None,
        })
    }

    fn send_call(
        &self,
        call: &FrozenOutboundCall,
        presented: &mut Option<SentPresentation>,
    ) -> Sent {
        let Ok(view) = FrozenToolCallView::read(call) else {
            return Sent::not_sent(OutboundFailureKind::InvalidRequest, None);
        };
        let Some(connector) = self.connectors.get(view.server()) else {
            return Sent::not_sent(OutboundFailureKind::TransportNotStarted, None);
        };
        match connector.transport {
            ConnectorTransport::McpHttp => {}
        }
        // The grant admitted the frozen endpoint; this host sends only to
        // the one it installed under the same name.
        if connector.endpoint != view.endpoint() {
            return Sent::not_sent(OutboundFailureKind::EndpointChanged, None);
        }
        // The route and the credential its send presents are known before
        // the exchange is declared (FIX 7646); a failure answers as before.
        let presenting = match self.vault.route_connector_call(view.server()) {
            Ok(Some(route)) => Some(self.presenting(route)),
            _ => None,
        };
        // The setting is read before the exchange starts.
        let elicitation = self.declared(call, &view);
        let Some(exchange) = Exchange::new(&self.client, &view, elicitation) else {
            return Sent::not_sent(OutboundFailureKind::InvalidRequest, None);
        };
        let Some(presenting) = presenting else {
            return Sent::not_sent(OutboundFailureKind::Rejected, None);
        };
        // The door reads the call's issuer binding again (FIX 9303).
        let key_ref = view.key_ref().and_then(|hex| EntityId::from_hex(hex).ok());
        let row = key_ref.as_ref().map(|key_ref| (key_ref, view.tool()));
        // A grant the send refuses answers as its typed refusal, not TransportNotStarted (FIX 6673).
        presenting.send(&self.vault, &exchange, row, presented)
    }

    /// The elicitation this send declares, or `None`: a call the engine
    /// bound no caller to, a revision with no elicitation shape, an
    /// unreadable key ref or setting, and a key set to `never allow` all
    /// declare none. A call that names a custody record declares it too: its
    /// door clears the presented value from each question and every later
    /// reply (FIX 3843).
    fn declared<'a>(
        &'a self,
        call: &'a FrozenOutboundCall,
        view: &FrozenToolCallView,
    ) -> Option<Declared<'a>> {
        let caller = self.caller.as_ref()?;
        let revision = view.protocol_revision()?;
        let capability = elicitation_capability(revision)?;
        let intake = Intake::of(revision)?;
        let key_ref = EntityId::from_hex(view.key_ref()?).ok()?;
        let principal = EntityId::from_hex(&caller.principal_ref).ok()?;
        match self.vault.connector_elicitation_setting(&key_ref) {
            Ok(setting) if setting != SlateDisposition::NeverAllow => {}
            _ => return None,
        }
        Some(Declared {
            capability,
            intake,
            call,
            vault: &self.vault,
            registry: &self.elicitations,
            binding: QuestionBinding {
                principal,
                grant_id: caller.grant_id,
                key_ref,
                parent_intent: call.intent_id().copied(),
                name: caller.name.clone(),
                server: view.server().to_owned(),
                tool: view.tool().to_owned(),
                endpoint: view.endpoint().to_owned(),
                revision: revision.to_owned(),
            },
        })
    }
}

impl ServedConnectorCallHost {
    /// Ends the questions the last send kept that nobody took: no caller
    /// holds their handle, so their worker cancels them now (FIX 3844).
    fn abandon_untaken(&mut self) {
        self.resume = None;
        if let Some(left) = self.awaiting.take() {
            self.elicitations.finish(Some(&*self.vault), &left.handle);
        }
    }
}

impl Drop for ServedConnectorCallHost {
    fn drop(&mut self) {
        self.abandon_untaken();
    }
}

impl OutboundResultSender for ServedConnectorCallHost {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundTransportResult {
        self.reply = None;
        self.abandon_untaken();
        let mut presented = None;
        let sent = self.send_call(call, &mut presented);
        self.presented = presented.map(|presented| presented.custody);
        self.presentation = presented;
        self.reply = sent.reply;
        self.awaiting = sent.awaiting;
        self.resume = sent.resume;
        self.remote_task = sent.remote_task;
        self.held = sent.held;
        OutboundTransportResult {
            outcome: sent.outcome,
            raw_result: RawOutboundResult::new(sent.body, sent.error, None, None),
        }
    }

    fn remote_task(&self) -> Option<RemoteTaskHandle> {
        self.remote_task.clone()
    }
}

impl ConnectorCallHost for ServedConnectorCallHost {
    fn tool_endpoint(&self, route: &ConnectorCallRoute) -> Option<String> {
        self.connectors
            .get(&route.name)
            .map(|connector| connector.endpoint.clone())
    }

    fn take_result(&mut self) -> Option<UntrustedToolResult> {
        self.reply.take()
    }

    fn present_credential(
        &mut self,
        credential: Option<EntityId>,
        grant: Option<SecretGrantRef>,
        run: Option<RunSecretHolder>,
    ) -> bool {
        self.credential = credential;
        self.grant = grant;
        self.run = run;
        true
    }

    fn bind_caller(&mut self, caller: Option<ConnectorCallCaller>) {
        self.caller = caller;
    }

    fn take_sent_custody(&mut self) -> Option<Vec<EntityId>> {
        Some(self.presented.take().into_iter().collect())
    }

    fn clears_at_door(&self) -> bool {
        true
    }

    fn take_sent_presentation(&mut self) -> Option<SentPresentation> {
        self.presentation.take()
    }

    fn take_send_hold(&mut self) -> Option<&'static str> {
        self.held.take()
    }

    fn take_awaiting_input(&mut self) -> Option<ConnectorAwaitingInput> {
        self.awaiting.take()
    }

    fn abandon_awaiting_input(&mut self, handle: &str) {
        self.elicitations.finish(Some(&*self.vault), handle);
    }

    fn bind_awaiting_call(&mut self, handle: &str, call_ref: EntityId) {
        let bound = self.elicitations.bind_call(&self.vault, handle, call_ref);
        // The row kept the round; its resume state goes beside it (FIX 9157).
        if let Some(resume) = self.resume.take().filter(|_| bound) {
            resume.keep(&self.vault, handle, &call_ref);
        }
    }
}

/// The client capability one pinned revision declares for elicitation:
/// 2025-06-18 an empty object, 2025-11-25 and 2026-07-28 form mode alone,
/// so URL mode stays undeclared; `None` for any other revision.
fn elicitation_capability(revision: &str) -> Option<Value> {
    match revision {
        "2025-06-18" => Some(json!({})),
        "2025-11-25" | "2026-07-28" => {
            let mut modes = Map::new();
            modes.insert(wire::FORM.to_owned(), json!({}));
            Some(Value::Object(modes))
        }
        _ => None,
    }
}

/// How a revision carries a connector's questions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Intake {
    /// `elicitation/create` requests on the reply stream.
    Stream,
    /// A `tools/call` result that asks for input, answered by the same call
    /// again.
    Retry,
}

impl Intake {
    fn of(revision: &str) -> Option<Self> {
        match revision {
            "2025-06-18" | "2025-11-25" => Some(Self::Stream),
            "2026-07-28" => Some(Self::Retry),
            _ => None,
        }
    }
}

/// One answer as the connector's wire takes it: its action, and its content
/// when it carries one.
pub(crate) fn elicitation_response(
    action: ConnectorAnswerAction,
    content: Option<&Value>,
) -> Value {
    let action = match action {
        ConnectorAnswerAction::Accept => "accept",
        ConnectorAnswerAction::Decline => "decline",
        ConnectorAnswerAction::Cancel => "cancel",
    };
    let mut response = Map::new();
    response.insert(wire::ACTION.to_owned(), Value::from(action));
    if let Some(content) = content {
        response.insert(wire::CONTENT.to_owned(), content.clone());
    }
    Value::Object(response)
}

/// One form-mode `elicitation/create`'s params as the question `key`;
/// `None` for URL mode, any other mode, or a malformed request.
fn form_question(key: &str, params: &Value) -> Option<ConnectorQuestion> {
    match params.get(wire::MODE) {
        None => {}
        Some(Value::String(mode)) if mode == wire::FORM => {}
        Some(_) => return None,
    }
    let message = params.get(wire::MESSAGE)?.as_str()?.to_owned();
    let requested_schema = params
        .get(wire::REQUESTED_SCHEMA)
        .filter(|schema| schema.is_object())?
        .clone();
    Some(ConnectorQuestion {
        key: key.to_owned(),
        message,
        requested_schema,
    })
}

/// A stream request's one question: a form `elicitation/create`.
fn stream_question(request: &Value) -> Option<ConnectorQuestion> {
    if request.get("method").and_then(Value::as_str) != Some(wire::ELICIT) {
        return None;
    }
    form_question(wire::STREAM_KEY, request.get("params")?)
}

/// The questions of a `tools/call` result that asks for input, each a form
/// `elicitation/create`, and its opaque request state, kept zeroized
/// (FIX 8054). `None` when the result asks for none, or for anything else:
/// then it is the tool's terminal result.
fn retry_questions(message: &Value) -> Option<(Vec<ConnectorQuestion>, Option<KeptWire>)> {
    let result = message.get("result")?;
    if result.get(wire::RESULT_TYPE).and_then(Value::as_str) != Some(wire::INPUT_REQUIRED) {
        return None;
    }
    let requests = result.get(wire::INPUT_REQUESTS)?.as_object()?;
    if requests.is_empty() {
        return None;
    }
    let questions = requests
        .iter()
        .map(|(key, request)| {
            if request.get("method").and_then(Value::as_str) != Some(wire::ELICIT) {
                return None;
            }
            form_question(key, request.get("params")?)
        })
        .collect::<Option<Vec<_>>>()?;
    Some((
        questions,
        result.get(wire::REQUEST_STATE).map(KeptWire::keep),
    ))
}

/// What a send that declares elicitation keeps a question with.
struct Declared<'a> {
    capability: Value,
    intake: Intake,
    /// The authenticated call, which every re-send of its payload rechecks.
    call: &'a FrozenOutboundCall,
    binding: QuestionBinding,
    /// The vault whose `[limits]` row measures the live question sets, and
    /// whose gate ledger keeps each answer's receipt (FIX 3840).
    vault: &'a Arc<Vault>,
    registry: &'a Arc<ConnectorElicitationRegistry>,
}

/// One MCP session's worth of requests for one frozen call.
struct Exchange<'a> {
    client: &'a reqwest::blocking::Client,
    endpoint: &'a str,
    revision: &'a str,
    protocol: HeaderValue,
    tool: &'a str,
    arguments: Value,
    tool_headers: HeaderMap,
    /// The elicitation this send declares, if any.
    elicitation: Option<Declared<'a>>,
}

impl<'a> Exchange<'a> {
    /// Everything the requests need, checked before any of them leaves.
    fn new(
        client: &'a reqwest::blocking::Client,
        view: &'a FrozenToolCallView,
        elicitation: Option<Declared<'a>>,
    ) -> Option<Self> {
        let revision = view.protocol_revision()?;
        let protocol = HeaderValue::from_str(revision).ok()?;
        let mut tool_headers = HeaderMap::new();
        for (name, value) in view.headers() {
            // A tool header never stands in for the session's own.
            if name == "accept" || name.starts_with("mcp-") {
                return None;
            }
            tool_headers.insert(
                HeaderName::from_bytes(name.as_bytes()).ok()?,
                HeaderValue::from_str(value).ok()?,
            );
        }
        Some(Self {
            client,
            endpoint: view.endpoint(),
            revision,
            protocol,
            tool: view.tool(),
            arguments: Value::Object(
                view.arguments()
                    .iter()
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect(),
            ),
            tool_headers,
            elicitation,
        })
    }

    /// The client capabilities `initialize` declares: elicitation alone,
    /// when this send declares it.
    fn capabilities(&self) -> Value {
        match &self.elicitation {
            Some(declared) => json!({ "elicitation": declared.capability }),
            None => json!({}),
        }
    }

    /// One send, its answer cleared of `value` when it presents one.
    fn run(&self, auth: Option<HeaderValue>, value: Option<&SentValue<'_>>) -> Sent {
        // Everything before `tools/call` leaves is certain non-delivery.
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": INITIALIZE_ID,
            "method": "initialize",
            "params": {
                "protocolVersion": self.revision,
                "capabilities": self.capabilities(),
                "clientInfo": { "name": "oneiron", "version": env!("CARGO_PKG_VERSION") },
            },
        });
        let posted = post_json(
            self.client,
            self.endpoint,
            &initialize,
            auth.as_ref(),
            None,
            Some(HANDSHAKE_TIMEOUT),
        )
        .send();
        let response = match posted {
            Ok(response) => response,
            Err(_) => return Sent::not_sent(OutboundFailureKind::TransportNotStarted, None),
        };
        if !response.status().is_success() {
            return Sent::not_sent(
                OutboundFailureKind::Rejected,
                Some(response.status().as_u16()),
            );
        }
        let session = response.headers().get(SESSION_HEADER).cloned();
        let initialized = match read_reply(response, INITIALIZE_ID) {
            Ok(Some((message, _))) => message,
            _ => return Sent::not_sent(OutboundFailureKind::Rejected, None),
        };
        // The key pinned one revision; a server that answers another is not
        // the connector the owner approved.
        if initialized.get("error").is_some()
            || initialized
                .pointer("/result/protocolVersion")
                .and_then(Value::as_str)
                != Some(self.revision)
        {
            return Sent::not_sent(OutboundFailureKind::Rejected, None);
        }
        let live = LiveSession {
            client: self.client.clone(),
            endpoint: self.endpoint.to_owned(),
            protocol: self.protocol.clone(),
            session,
            auth,
        };
        let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        match live.post(&notification, Some(HANDSHAKE_TIMEOUT)).send() {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                return Sent::not_sent(
                    OutboundFailureKind::Rejected,
                    Some(response.status().as_u16()),
                );
            }
            Err(_) => return Sent::not_sent(OutboundFailureKind::TransportNotStarted, None),
        }

        let call = json!({
            "jsonrpc": "2.0",
            "id": CALL_ID,
            "method": "tools/call",
            "params": { "name": self.tool, "arguments": self.arguments },
        });
        // A question on the reply stream outlives the call's own timeout, so
        // that stream reads under the client's per-read bound and a deadline
        // per round of reading instead of one bound on the whole reply.
        let asks_on_stream = self
            .elicitation
            .as_ref()
            .is_some_and(|declared| declared.intake == Intake::Stream);
        let posted = live
            .post(&call, (!asks_on_stream).then_some(CALL_TIMEOUT))
            .headers(self.tool_headers.clone())
            .send();
        let mut live = Some(live);
        let sent = match posted {
            Ok(response) => self.read_call_reply(response, &mut live, asks_on_stream, value),
            // A refused connection never reached the connector.
            Err(error) if error.is_connect() || error.is_builder() => {
                Sent::not_sent(OutboundFailureKind::TransportNotStarted, None)
            }
            Err(_) => Sent::ambiguous("connector_no_reply"),
        };
        // The session ends with the call; a live question's worker took it
        // and ends it with the questions.
        if let Some(live) = live {
            live.end();
        }
        sent
    }

    /// Reads the `tools/call` reply. A question this send declared for
    /// hands `live` to a worker; any other server request on the stream is
    /// refused.
    fn read_call_reply(
        &self,
        response: reqwest::blocking::Response,
        live: &mut Option<LiveSession>,
        asks_on_stream: bool,
        value: Option<&SentValue<'_>>,
    ) -> Sent {
        let status = response.status();
        if status.is_server_error() {
            // The connector may have acted before it failed.
            return Sent::ambiguous("connector_server_error");
        }
        if !status.is_success() {
            // A refusal at the door: the tool never ran.
            return Sent::not_sent(OutboundFailureKind::Rejected, Some(status.as_u16()));
        }
        let deadline = asks_on_stream.then(|| Instant::now() + CALL_TIMEOUT);
        let mut stream = match open_reply(response, CALL_ID, deadline) {
            Ok(Reply::Json(Some((message, body)))) => {
                return self.call_answered(&message, body, live, value);
            }
            Ok(Reply::Json(None)) | Err(()) => {
                return Sent::ambiguous("connector_reply_unreadable");
            }
            Ok(Reply::Stream(stream)) => stream,
        };
        loop {
            match stream.next(CALL_ID) {
                Ok(StreamEvent::Answer(message, body)) => {
                    return self.call_answered(&message, body, live, value);
                }
                Ok(StreamEvent::Request(request)) => {
                    let declared = self
                        .elicitation
                        .as_ref()
                        .filter(|declared| declared.intake == Intake::Stream);
                    let question = declared.and_then(|_| stream_question(&request));
                    let (Some(declared), Some(question)) = (declared, question) else {
                        match live.as_ref() {
                            Some(live) => match self.elicitation.as_ref() {
                                Some(declared) => live.refuse_unless_held(
                                    request,
                                    declared.vault,
                                    &declared.binding.key_ref,
                                    &declared.binding.tool,
                                ),
                                None => live.refuse(request),
                            },
                            None => zeroize_json(request),
                        }
                        continue;
                    };
                    let round = declared.keep_questions(vec![question], value);
                    // The request's id waits zeroized (FIX 8054).
                    let request_id = KeptWire::keep(request.get("id").unwrap_or(&Value::Null));
                    // The stream reattaches after this event (FIX 9157).
                    let last_event_id = stream
                        .last_event_id()
                        .map(|id| zeroize::Zeroizing::new(id.to_owned()));
                    let continuation = Continuation::Stream {
                        stream: Some(stream),
                        request_id,
                        last_event_id,
                    };
                    let body = request.to_string().into_bytes();
                    // Its question, id and body are read out (FIX 11861).
                    zeroize_json(request);
                    let kept = value.map(SentValue::keep);
                    return hand_over(declared, round, continuation, live, body, kept);
                }
                Ok(StreamEvent::End) | Err(()) => {
                    return Sent::ambiguous("connector_reply_unreadable");
                }
            }
        }
    }

    /// The connector's answer to `tools/call`. A 2026-07-28 result that asks
    /// for input, on a send that declared it, hands `live` to a worker; any
    /// other result is the tool's.
    fn call_answered(
        &self,
        message: &Value,
        body: Vec<u8>,
        live: &mut Option<LiveSession>,
        value: Option<&SentValue<'_>>,
    ) -> Sent {
        if let Some(declared) = self
            .elicitation
            .as_ref()
            .filter(|declared| declared.intake == Intake::Retry)
            && let Some((questions, request_state)) = retry_questions(message)
        {
            let round = declared.keep_questions(questions, value);
            let continuation = Continuation::Retry {
                tool: self.tool.to_owned(),
                arguments: self.arguments.clone(),
                tool_headers: self.tool_headers.clone(),
                request_state,
                next_id: CALL_ID + 1,
                original: declared.call.clone(),
            };
            let kept = value.map(SentValue::keep);
            return hand_over(declared, round, continuation, live, body, kept);
        }
        // FIX 7960: a connector that takes the call as a remote task answers
        // with its task, not the tool's result.
        if let Some(handle) = remote_task::remote_task_from_result(message) {
            return Sent::deferred(handle, body);
        }
        match tool_result(message) {
            Some(reply) => Sent::acked(Some(reply), body),
            None => Sent::ambiguous("connector_reply_unreadable"),
        }
    }
}
