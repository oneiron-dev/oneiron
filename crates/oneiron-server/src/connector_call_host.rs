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
//! itself. No proxy, no redirects, a bounded reply and short timeouts.
//!
//! The reply is foreign data. The host keeps its own bounded copy of the
//! `tools/call` result for the caller; the ledger's scrub still destroys the
//! raw bytes before anything durable is written. Sampling and roots are not
//! served: any such server request on the reply stream is refused.
//!
//! A connector may ask for input mid-call (elicitation). `initialize`
//! declares the capability only when the governing key's elicitation setting,
//! read before the exchange starts, is not `never allow`, the engine bound
//! the call's caller and grant, the send presents no custody record, and the
//! pinned revision has an elicitation shape: 2025-06-18 declares `{}`,
//! 2025-11-25 and 2026-07-28 form mode alone. A question is a form-mode
//! `elicitation/create` request on the reply stream (2025-06-18,
//! 2025-11-25), or a 2026-07-28 `tools/call` result that asks for input,
//! each of its requests a form `elicitation/create`. Either way the call
//! reached the connector: the send is acknowledged, the host keeps the
//! questions for its caller in place of a result, and a worker thread takes
//! the open exchange, registered in the server's
//! [`ConnectorElicitationRegistry`]. It sends the caller's checked answer,
//! reads what the connector says next, and ends the session when the call
//! ends or its questions lapse. Any other server request is refused as
//! before, and any other result is the tool's.
//!
//! A `self.use` call (OF-560) presents the custody record its handle names
//! in place of the route's own secret, through the same door for the same
//! effector; the door rechecks the record's binding at each send.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::sync::{Arc, Weak, mpsc};
use std::time::{Duration, Instant};

use oneiron::connector_key::{ConnectorCallRoute, SlateDisposition};
use oneiron::outbound_consent::{
    CONNECTOR_REPLY_MAX_BYTES, ConnectorAwaitingInput, ConnectorCallCaller, ConnectorCallHost,
    ConnectorQuestion, FrozenToolCallView, OutboundResultSender, OutboundTransportResult,
    RawOutboundResult, UntrustedToolResult,
};
use oneiron::outbound_intent_ledger::{
    FrozenOutboundCall, OutboundFailureKind, OutboundSendFailure, OutboundSendOutcome,
};
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
    /// The server's live connector questions, shared by every host it
    /// builds and read by `connector.answer`.
    elicitations: Arc<ConnectorElicitationRegistry>,
    /// The caller and grant the next send runs for, as the engine bound
    /// them.
    caller: Option<ConnectorCallCaller>,
    /// The questions the last send's connector asked, kept for the caller.
    awaiting: Option<ConnectorAwaitingInput>,
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
            elicitations,
            caller: None,
            awaiting: None,
        })
    }

    fn send_call(&self, call: &FrozenOutboundCall) -> Sent {
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
            return Sent::not_sent(OutboundFailureKind::Rejected, None);
        }
        // The setting is read before the exchange starts.
        let elicitation = self.declared(call, &view);
        let Some(exchange) = Exchange::new(&self.client, &view, elicitation) else {
            return Sent::not_sent(OutboundFailureKind::InvalidRequest, None);
        };
        let route = match self.vault.route_connector_call(view.server()) {
            Ok(Some(route)) => route,
            _ => return Sent::not_sent(OutboundFailureKind::Rejected, None),
        };
        let effector = format!("connector:{}", route.connector);
        let mut sent = None;
        let mut present = |value: &[u8]| -> oneiron::Result<()> {
            let header = authorization_header(value)?;
            sent = Some(exchange.run(Some(header)));
            Ok(())
        };
        let _door = match (self.credential, route.secret_ref.as_deref()) {
            (Some(custody), _) => {
                self.vault
                    .inject_secret_record_at_door(&custody, &effector, &mut present)
            }
            (None, Some(secret_ref)) => {
                self.vault
                    .inject_secret_at_door(secret_ref, &effector, &mut present)
            }
            (None, None) => return exchange.run(None),
        };
        // Once the exchange ran, what the connector said is the delivery
        // fact, whatever the door reports after it.
        sent.unwrap_or_else(|| Sent::not_sent(OutboundFailureKind::TransportNotStarted, None))
    }

    /// The elicitation this send declares, or `None`: a send that presents
    /// a custody record, one the engine bound no caller to, a revision with
    /// no elicitation shape, an unreadable key ref or setting, and a key set
    /// to `never allow` all declare none.
    fn declared(
        &self,
        call: &FrozenOutboundCall,
        view: &FrozenToolCallView,
    ) -> Option<Declared<'_>> {
        if self.credential.is_some() {
            return None;
        }
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

impl OutboundResultSender for ServedConnectorCallHost {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundTransportResult {
        self.reply = None;
        self.awaiting = None;
        let sent = self.send_call(call);
        self.reply = sent.reply;
        self.awaiting = sent.awaiting;
        OutboundTransportResult {
            outcome: sent.outcome,
            raw_result: RawOutboundResult::new(sent.body, sent.error, None, None),
        }
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

    fn present_credential(&mut self, credential: Option<EntityId>) -> bool {
        self.credential = credential;
        true
    }

    fn bind_caller(&mut self, caller: Option<ConnectorCallCaller>) {
        self.caller = caller;
    }

    fn take_awaiting_input(&mut self) -> Option<ConnectorAwaitingInput> {
        self.awaiting.take()
    }
}

/// The stored value is a whole `Authorization` header (`Basic ...` or
/// `Bearer ...`) or a bare bearer token, as the native mail check reads it.
fn authorization_header(value: &[u8]) -> oneiron::Result<HeaderValue> {
    let value = std::str::from_utf8(value)
        .map_err(|_| oneiron::Error::InvalidConfig("the stored credential is not text".to_owned()))?
        .trim();
    let header = if value.starts_with("Basic ") || value.starts_with("Bearer ") {
        value.to_owned()
    } else {
        format!("Bearer {value}")
    };
    let mut header = HeaderValue::from_str(&header).map_err(|_| {
        oneiron::Error::InvalidConfig("the stored credential is not a header value".to_owned())
    })?;
    header.set_sensitive(true);
    Ok(header)
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
/// `elicitation/create`, and its opaque request state. `None` when the
/// result asks for none, or for anything else: then it is the tool's
/// terminal result.
fn retry_questions(message: &Value) -> Option<(Vec<ConnectorQuestion>, Option<Value>)> {
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
    Some((questions, result.get(wire::REQUEST_STATE).cloned()))
}

/// A `tools/call` answer as the tool's reply: its result, or the JSON-RPC
/// error it answered with; `None` when it carries neither.
fn tool_result(message: &Value) -> Option<UntrustedToolResult> {
    if let Some(error) = message.get("error") {
        return Some(UntrustedToolResult {
            content: Value::Array(Vec::new()),
            structured_content: None,
            is_error: true,
            rpc_error: Some(error.clone()),
        });
    }
    let result = message.get("result")?;
    Some(UntrustedToolResult {
        content: result
            .get("content")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new())),
        structured_content: result.get("structuredContent").cloned(),
        is_error: result.get("isError").and_then(Value::as_bool) == Some(true),
        rpc_error: None,
    })
}

/// What one send came to, before the ledger scrubs its raw fields.
struct Sent {
    outcome: OutboundSendOutcome,
    reply: Option<UntrustedToolResult>,
    /// The questions the connector answered with, in place of a reply.
    awaiting: Option<ConnectorAwaitingInput>,
    body: Option<Vec<u8>>,
    error: Option<String>,
}

impl Sent {
    /// Certain non-delivery: the `tools/call` request never left.
    fn not_sent(kind: OutboundFailureKind, code: Option<u16>) -> Self {
        Self {
            outcome: OutboundSendOutcome::Failed(OutboundSendFailure { kind, code }),
            reply: None,
            awaiting: None,
            body: None,
            error: None,
        }
    }

    /// The request went and no readable answer came back.
    fn ambiguous(error: &str) -> Self {
        Self {
            outcome: OutboundSendOutcome::Ambiguous,
            reply: None,
            awaiting: None,
            body: None,
            error: Some(error.to_owned()),
        }
    }

    /// The connector answered the call.
    fn acked(reply: Option<UntrustedToolResult>, body: Vec<u8>) -> Self {
        Self {
            outcome: OutboundSendOutcome::Acked,
            reply,
            awaiting: None,
            body: Some(body),
            error: None,
        }
    }
}

/// What a send that declares elicitation keeps a question with.
struct Declared<'a> {
    capability: Value,
    intake: Intake,
    binding: QuestionBinding,
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

    fn run(&self, auth: Option<HeaderValue>) -> Sent {
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
            Ok(response) => self.read_call_reply(response, &mut live, asks_on_stream),
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
                return self.call_answered(&message, body, live);
            }
            Ok(Reply::Json(None)) | Err(()) => {
                return Sent::ambiguous("connector_reply_unreadable");
            }
            Ok(Reply::Stream(stream)) => stream,
        };
        loop {
            match stream.next(CALL_ID) {
                Ok(StreamEvent::Answer(message, body)) => {
                    return self.call_answered(&message, body, live);
                }
                Ok(StreamEvent::Request(request)) => {
                    let declared = self
                        .elicitation
                        .as_ref()
                        .filter(|declared| declared.intake == Intake::Stream);
                    let question = declared.and_then(|_| stream_question(&request));
                    let (Some(declared), Some(question)) = (declared, question) else {
                        if let Some(live) = live.as_ref() {
                            live.refuse(&request);
                        }
                        continue;
                    };
                    let request_id = request.get("id").cloned().unwrap_or(Value::Null);
                    let questions = vec![question];
                    if let Some(registered) = declared
                        .registry
                        .register(declared.binding.clone(), &questions)
                    {
                        let continuation = Continuation::Stream { stream, request_id };
                        let body = request.to_string().into_bytes();
                        return hand_over(
                            declared,
                            registered,
                            questions,
                            continuation,
                            live,
                            body,
                        );
                    }
                    // A full registry: the question is cancelled at once,
                    // and the call goes on without it.
                    if let Some(live) = live.as_ref() {
                        let cancel = elicitation_response(ConnectorAnswerAction::Cancel, None);
                        let _ = live.respond(&request_id, "result", cancel);
                    }
                }
                Ok(StreamEvent::End) | Err(()) => {
                    return Sent::ambiguous("connector_reply_unreadable");
                }
            }
        }
    }

    /// The connector's answer to `tools/call`. A 2026-07-28 result that asks
    /// for input, on a send that declared it, hands `live` to a worker; any
    /// other result is the tool's, and so is that one when the registry is
    /// full.
    fn call_answered(
        &self,
        message: &Value,
        body: Vec<u8>,
        live: &mut Option<LiveSession>,
    ) -> Sent {
        if let Some(declared) = self
            .elicitation
            .as_ref()
            .filter(|declared| declared.intake == Intake::Retry)
            && let Some((questions, request_state)) = retry_questions(message)
            && let Some(registered) = declared
                .registry
                .register(declared.binding.clone(), &questions)
        {
            let continuation = Continuation::Retry {
                tool: self.tool.to_owned(),
                arguments: self.arguments.clone(),
                tool_headers: self.tool_headers.clone(),
                request_state,
                next_id: CALL_ID + 1,
            };
            return hand_over(declared, registered, questions, continuation, live, body);
        }
        match tool_result(message) {
            Some(reply) => Sent::acked(Some(reply), body),
            None => Sent::ambiguous("connector_reply_unreadable"),
        }
    }
}

/// Hands one live exchange to a worker thread, which owns it from here, and
/// keeps its questions for the caller. The call reached the connector, so
/// the send is acknowledged either way; a worker that could not start drops
/// the questions.
fn hand_over(
    declared: &Declared<'_>,
    registered: Registered,
    questions: Vec<ConnectorQuestion>,
    continuation: Continuation,
    live: &mut Option<LiveSession>,
    body: Vec<u8>,
) -> Sent {
    let Some(session) = live.take() else {
        declared.registry.finish(&registered.handle);
        return Sent::acked(None, body);
    };
    let awaiting = ConnectorAwaitingInput {
        handle: registered.handle.clone(),
        questions,
        expires_at_ms: registered.expires_at_ms,
    };
    let worker = Worker {
        session,
        continuation,
        commands: registered.commands,
        registry: Arc::downgrade(declared.registry),
        handle: registered.handle,
        deadline: registered.deadline,
        generation: 0,
    };
    let started = std::thread::Builder::new()
        .name("connector-elicitation".to_owned())
        .spawn(move || worker.run());
    if started.is_err() {
        declared.registry.finish(&awaiting.handle);
        return Sent::acked(None, body);
    }
    Sent {
        awaiting: Some(awaiting),
        ..Sent::acked(None, body)
    }
}

/// A POST of `body` to `endpoint`; `timeout` bounds the whole request, and
/// `None` leaves each read to the client's own bound.
fn post_json(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    body: &Value,
    auth: Option<&HeaderValue>,
    session: Option<&HeaderValue>,
    timeout: Option<Duration>,
) -> reqwest::blocking::RequestBuilder {
    let mut request = client
        .post(endpoint)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, ACCEPT_BOTH)
        .body(body.to_string());
    if let Some(timeout) = timeout {
        request = request.timeout(timeout);
    }
    if let Some(auth) = auth {
        request = request.header(AUTHORIZATION, auth.clone());
    }
    if let Some(session) = session {
        request = request.header(SESSION_HEADER, session.clone());
    }
    request
}

/// The MCP session one send opened, owned: what a live question's worker
/// keeps once the send returned. No borrow of the host or the frozen call.
struct LiveSession {
    client: reqwest::blocking::Client,
    endpoint: String,
    protocol: HeaderValue,
    session: Option<HeaderValue>,
    /// The credential the door presented for the send, kept until the
    /// session ends.
    auth: Option<HeaderValue>,
}

/// How one POST of an answer or a refusal went.
enum Posted {
    Accepted,
    Refused,
    Unsent,
    Uncertain,
}

impl LiveSession {
    /// A POST of `body` in this session, with its protocol header.
    fn post(&self, body: &Value, timeout: Option<Duration>) -> reqwest::blocking::RequestBuilder {
        post_json(
            &self.client,
            &self.endpoint,
            body,
            self.auth.as_ref(),
            self.session.as_ref(),
            timeout,
        )
        .header(PROTOCOL_HEADER, self.protocol.clone())
    }

    /// Answers the server request `id` with `member` (`result` or `error`):
    /// a new POST to the endpoint, its status checked.
    fn respond(&self, id: &Value, member: &str, value: Value) -> Posted {
        let mut message = Map::new();
        message.insert("jsonrpc".to_owned(), Value::from("2.0"));
        message.insert("id".to_owned(), id.clone());
        message.insert(member.to_owned(), value);
        match self
            .post(&Value::Object(message), Some(HANDSHAKE_TIMEOUT))
            .send()
        {
            Ok(response) if response.status().is_success() => Posted::Accepted,
            Ok(response) if response.status().is_server_error() => Posted::Uncertain,
            Ok(_) => Posted::Refused,
            Err(error) if error.is_connect() || error.is_builder() => Posted::Unsent,
            Err(_) => Posted::Uncertain,
        }
    }

    /// Refuses one server request this client does not serve.
    fn refuse(&self, request: &Value) {
        let Some(id) = request.get("id") else {
            return;
        };
        let refusal =
            json!({ "code": -32601, "message": "this client does not serve this request" });
        let _ = self.respond(id, "error", refusal);
    }

    /// Ends the session: a courtesy, whose outcome changes nothing.
    fn end(&self) {
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let mut end = self
            .client
            .delete(self.endpoint.as_str())
            .timeout(HANDSHAKE_TIMEOUT)
            .header(SESSION_HEADER, session.clone())
            .header(PROTOCOL_HEADER, self.protocol.clone());
        if let Some(auth) = &self.auth {
            end = end.header(AUTHORIZATION, auth.clone());
        }
        drop(end.send());
    }
}

/// What a live question set's worker continues the exchange with.
enum Continuation {
    /// A request on the reply stream: answered by a JSON-RPC response POSTed
    /// to the endpoint, then the same stream read on.
    Stream {
        stream: EventStream,
        request_id: Value,
    },
    /// A result that asked for input: answered by the same `tools/call`
    /// again, with the responses and the opaque request state.
    Retry {
        tool: String,
        arguments: Value,
        tool_headers: HeaderMap,
        request_state: Option<Value>,
        next_id: u64,
    },
}

/// What one answer led to.
enum Next {
    /// Another round of questions.
    Asked(Vec<ConnectorQuestion>),
    /// The exchange is over.
    Over(WorkerEvent),
}

/// The thread that owns one live exchange once its send returned: it waits
/// for an answer to each round until the round's deadline, sends it, and
/// reads what the connector says next.
struct Worker {
    session: LiveSession,
    continuation: Continuation,
    commands: mpsc::Receiver<AnswerCommand>,
    /// The registry, held weakly: a server going away drops it, and with it
    /// every question set's channel.
    registry: Weak<ConnectorElicitationRegistry>,
    handle: String,
    deadline: Instant,
    generation: u64,
}

impl Worker {
    fn run(mut self) {
        loop {
            let left = self.deadline.saturating_duration_since(Instant::now());
            // A round that lapsed, or a server going away, cancels the
            // questions.
            let Ok(command) = self.commands.recv_timeout(left) else {
                self.cancel();
                break;
            };
            match self.answer(&command.responses) {
                Next::Asked(questions) => {
                    self.generation += 1;
                    let advanced = self.registry.upgrade().and_then(|registry| {
                        registry.advance(&self.handle, self.generation, &questions)
                    });
                    let Some((deadline, expires_at_ms)) = advanced else {
                        let _ = command.reply.send(WorkerEvent::Failed {
                            sent: true,
                            reason: "connector_question_lapsed",
                        });
                        self.cancel();
                        break;
                    };
                    self.deadline = deadline;
                    let _ = command.reply.send(WorkerEvent::Question {
                        questions,
                        expires_at_ms,
                    });
                }
                Next::Over(event) => {
                    let _ = command.reply.send(event);
                    break;
                }
            }
        }
        self.session.end();
        if let Some(registry) = self.registry.upgrade() {
            registry.finish(&self.handle);
        }
    }

    /// Sends one frozen answer and reads what the connector says next.
    fn answer(&mut self, responses: &BTreeMap<String, Value>) -> Next {
        match &mut self.continuation {
            Continuation::Stream { stream, request_id } => {
                let Some(result) = responses.get(wire::STREAM_KEY) else {
                    return Next::Over(WorkerEvent::Failed {
                        sent: false,
                        reason: "connector_answer_unmatched",
                    });
                };
                match self.session.respond(request_id, "result", result.clone()) {
                    Posted::Accepted => {}
                    Posted::Refused | Posted::Unsent => {
                        return Next::Over(WorkerEvent::Failed {
                            sent: false,
                            reason: "connector_answer_not_taken",
                        });
                    }
                    Posted::Uncertain => {
                        return Next::Over(WorkerEvent::Failed {
                            sent: true,
                            reason: "connector_answer_unconfirmed",
                        });
                    }
                }
                stream.renew(CALL_TIMEOUT);
                read_stream_round(&self.session, stream, request_id)
            }
            Continuation::Retry {
                tool,
                arguments,
                tool_headers,
                request_state,
                next_id,
            } => {
                let id = *next_id;
                *next_id += 1;
                let mut params = Map::new();
                params.insert("name".to_owned(), Value::from(tool.as_str()));
                params.insert("arguments".to_owned(), arguments.clone());
                params.insert(
                    wire::INPUT_RESPONSES.to_owned(),
                    Value::Object(responses.clone().into_iter().collect()),
                );
                if let Some(state) = request_state.as_ref() {
                    params.insert(wire::REQUEST_STATE.to_owned(), state.clone());
                }
                let call = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": Value::Object(params),
                });
                let posted = self
                    .session
                    .post(&call, Some(CALL_TIMEOUT))
                    .headers(tool_headers.clone())
                    .send();
                let message = match posted {
                    Ok(response) => read_retry_reply(&self.session, response, id),
                    Err(error) if error.is_connect() || error.is_builder() => {
                        Err(WorkerEvent::Failed {
                            sent: false,
                            reason: "connector_answer_not_taken",
                        })
                    }
                    Err(_) => Err(WorkerEvent::Failed {
                        sent: true,
                        reason: "connector_no_reply",
                    }),
                };
                let message = match message {
                    Ok(message) => message,
                    Err(event) => return Next::Over(event),
                };
                if let Some((questions, state)) = retry_questions(&message) {
                    *request_state = state;
                    return Next::Asked(questions);
                }
                Next::Over(terminal(&message))
            }
        }
    }

    /// Cancels the current round: a stream request is answered `cancel`; a
    /// result that asked for input takes no reply.
    fn cancel(&self) {
        if let Continuation::Stream { request_id, .. } = &self.continuation {
            let cancel = elicitation_response(ConnectorAnswerAction::Cancel, None);
            let _ = self.session.respond(request_id, "result", cancel);
        }
    }
}

/// The tool's terminal reply in `message`, or the failure an unreadable one
/// is.
fn terminal(message: &Value) -> WorkerEvent {
    match tool_result(message) {
        Some(result) => WorkerEvent::Result(result),
        None => WorkerEvent::Failed {
            sent: true,
            reason: "connector_reply_unreadable",
        },
    }
}

/// Reads the stream on after an answer: the call's reply ends it, another
/// form `elicitation/create` opens the next round under its own request id,
/// and any other server request is refused.
fn read_stream_round(
    session: &LiveSession,
    stream: &mut EventStream,
    request_id: &mut Value,
) -> Next {
    loop {
        match stream.next(CALL_ID) {
            Ok(StreamEvent::Answer(message, _)) => return Next::Over(terminal(&message)),
            Ok(StreamEvent::Request(request)) => match stream_question(&request) {
                Some(question) => {
                    *request_id = request.get("id").cloned().unwrap_or(Value::Null);
                    return Next::Asked(vec![question]);
                }
                None => session.refuse(&request),
            },
            Ok(StreamEvent::End) | Err(()) => {
                return Next::Over(WorkerEvent::Failed {
                    sent: true,
                    reason: "connector_reply_unreadable",
                });
            }
        }
    }
}

/// Reads the reply to a retried `tools/call` (`id`), refusing any server
/// request on its stream.
fn read_retry_reply(
    session: &LiveSession,
    response: reqwest::blocking::Response,
    id: u64,
) -> Result<Value, WorkerEvent> {
    let unreadable = WorkerEvent::Failed {
        sent: true,
        reason: "connector_reply_unreadable",
    };
    let status = response.status();
    if status.is_server_error() {
        return Err(WorkerEvent::Failed {
            sent: true,
            reason: "connector_server_error",
        });
    }
    if !status.is_success() {
        return Err(WorkerEvent::Failed {
            sent: false,
            reason: "connector_answer_not_taken",
        });
    }
    let mut stream = match open_reply(response, id, None) {
        Ok(Reply::Json(Some((message, _)))) => return Ok(message),
        Ok(Reply::Json(None)) | Err(()) => return Err(unreadable),
        Ok(Reply::Stream(stream)) => stream,
    };
    loop {
        match stream.next(id) {
            Ok(StreamEvent::Answer(message, _)) => return Ok(message),
            Ok(StreamEvent::Request(request)) => session.refuse(&request),
            Ok(StreamEvent::End) | Err(()) => return Err(unreadable),
        }
    }
}

/// One reply body: a JSON body read whole, or an event stream still open.
enum Reply {
    /// The message that answers the request, if the body holds one, and its
    /// bytes.
    Json(Option<(Value, Vec<u8>)>),
    Stream(EventStream),
}

/// One event of a reply stream.
enum StreamEvent {
    /// The response that answers the request, and its own bytes.
    Answer(Value, Vec<u8>),
    /// A server request.
    Request(Value),
    /// The stream ended without answering.
    End,
}

/// A reply stream read event by event. More than
/// [`CONNECTOR_REPLY_MAX_BYTES`] of it is unreadable; past `deadline`, so is
/// the rest of a round.
struct EventStream {
    reader: BufReader<std::io::Take<reqwest::blocking::Response>>,
    read: usize,
    data: String,
    deadline: Option<Instant>,
}

impl EventStream {
    /// The next answer to `id` or server request; notifications are
    /// dropped.
    fn next(&mut self, id: u64) -> Result<StreamEvent, ()> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.reader.read_line(&mut line).map_err(|_| ())?;
            self.read = self.read.saturating_add(n);
            if self.read > CONNECTOR_REPLY_MAX_BYTES
                || self
                    .deadline
                    .is_some_and(|deadline| Instant::now() > deadline)
            {
                return Err(());
            }
            let end = n == 0;
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if end || trimmed.is_empty() {
                if !self.data.is_empty() {
                    let event = std::mem::take(&mut self.data);
                    if let Ok(message) = serde_json::from_str::<Value>(&event) {
                        if answers(&message, id) {
                            return Ok(StreamEvent::Answer(message, event.into_bytes()));
                        }
                        if message.get("method").is_some() && message.get("id").is_some() {
                            return Ok(StreamEvent::Request(message));
                        }
                    }
                }
                if end {
                    return Ok(StreamEvent::End);
                }
                continue;
            }
            if let Some(field) = trimmed.strip_prefix("data:") {
                if !self.data.is_empty() {
                    self.data.push('\n');
                }
                self.data.push_str(field.strip_prefix(' ').unwrap_or(field));
            }
        }
    }

    /// Starts a new round of reading, bounded by `timeout`.
    fn renew(&mut self, timeout: Duration) {
        self.deadline = Some(Instant::now() + timeout);
    }
}

/// Opens one reply body, JSON or an event stream. A JSON body is read whole,
/// and more than [`CONNECTOR_REPLY_MAX_BYTES`] of it is unreadable.
fn open_reply(
    response: reqwest::blocking::Response,
    id: u64,
    deadline: Option<Instant>,
) -> Result<Reply, ()> {
    let stream = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim_start().starts_with("text/event-stream"));
    let limit = u64::try_from(CONNECTOR_REPLY_MAX_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut body = response.take(limit);
    if stream {
        return Ok(Reply::Stream(EventStream {
            reader: BufReader::new(body),
            read: 0,
            data: String::new(),
            deadline,
        }));
    }
    let mut bytes = Vec::new();
    body.read_to_end(&mut bytes).map_err(|_| ())?;
    if bytes.len() > CONNECTOR_REPLY_MAX_BYTES {
        return Err(());
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| ())?;
    let found = match value {
        Value::Array(batch) => batch.into_iter().find(|message| answers(message, id)),
        message => answers(&message, id).then_some(message),
    };
    Ok(Reply::Json(found.map(|message| (message, bytes))))
}

/// Reads one reply body until the response that answers `id`; server
/// requests and notifications on a stream are dropped. Returns the message
/// and its own bytes.
fn read_reply(
    response: reqwest::blocking::Response,
    id: u64,
) -> Result<Option<(Value, Vec<u8>)>, ()> {
    let mut stream = match open_reply(response, id, None)? {
        Reply::Json(found) => return Ok(found),
        Reply::Stream(stream) => stream,
    };
    loop {
        match stream.next(id)? {
            StreamEvent::Answer(message, bytes) => return Ok(Some((message, bytes))),
            StreamEvent::Request(_) => {}
            StreamEvent::End => return Ok(None),
        }
    }
}

/// A response (not a request) carrying exactly this id.
fn answers(message: &Value, id: u64) -> bool {
    message.get("method").is_none()
        && message.get("id").and_then(Value::as_u64) == Some(id)
        && (message.get("result").is_some() || message.get("error").is_some())
}
