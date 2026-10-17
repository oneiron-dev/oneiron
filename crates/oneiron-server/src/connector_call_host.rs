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
//! raw bytes before anything durable is written. Foreign mid-call requests
//! (elicitation, sampling) are not served: `initialize` declares no client
//! capabilities and any server request on the reply stream is refused.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::sync::Arc;
use std::time::Duration;

use oneiron::Vault;
use oneiron::connector_key::ConnectorCallRoute;
use oneiron::outbound_consent::{
    CONNECTOR_REPLY_MAX_BYTES, ConnectorCallHost, FrozenToolCallView, OutboundResultSender,
    OutboundTransportResult, RawOutboundResult, UntrustedToolResult,
};
use oneiron::outbound_intent_ledger::{
    FrozenOutboundCall, OutboundFailureKind, OutboundSendFailure, OutboundSendOutcome,
};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde_json::{Value, json};

use crate::config::connectors::normalize_name;
use crate::config::{ConnectorHostConfig, ConnectorTransport};
use crate::server::SyncServer;

/// Connecting to a connector's endpoint.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// `initialize`, `notifications/initialized`, a refusal and the session's end.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// The `tools/call` itself, until its reply is read.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

const INITIALIZE_ID: u64 = 1;
const CALL_ID: u64 = 2;
const SESSION_HEADER: &str = "mcp-session-id";
const PROTOCOL_HEADER: &str = "mcp-protocol-version";
const ACCEPT_BOTH: &str = "application/json, text/event-stream";

/// The generic connector call's send on this host.
pub struct ServedConnectorCallHost {
    vault: Arc<Vault>,
    /// Installed transports by normalized catalog name.
    connectors: BTreeMap<String, ConnectorHostConfig>,
    client: reqwest::blocking::Client,
    reply: Option<UntrustedToolResult>,
}

impl ServedConnectorCallHost {
    /// The host for this server's `[connectors]` and vault. Build it on a
    /// blocking worker: it holds a blocking HTTP client.
    pub fn new(server: &SyncServer) -> oneiron::Result<Self> {
        Self::with_connectors(Arc::clone(server.vault()), server.config.connectors.clone())
    }

    /// The host for an explicit set of installed transports.
    pub fn with_connectors(
        vault: Arc<Vault>,
        connectors: BTreeMap<String, ConnectorHostConfig>,
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
        let Some(exchange) = Exchange::new(&self.client, &view) else {
            return Sent::not_sent(OutboundFailureKind::InvalidRequest, None);
        };
        let route = match self.vault.route_connector_call(view.server()) {
            Ok(Some(route)) => route,
            _ => return Sent::not_sent(OutboundFailureKind::Rejected, None),
        };
        let Some(secret_ref) = route.secret_ref.as_deref() else {
            return exchange.run(None);
        };
        let effector = format!("connector:{}", route.connector);
        let mut sent = None;
        let _door =
            self.vault
                .inject_secret_at_door(secret_ref, &effector, &mut |value: &[u8]| {
                    let header = authorization_header(value)?;
                    sent = Some(exchange.run(Some(header)));
                    Ok(())
                });
        // Once the exchange ran, what the connector said is the delivery
        // fact, whatever the door reports after it.
        sent.unwrap_or_else(|| Sent::not_sent(OutboundFailureKind::TransportNotStarted, None))
    }
}

impl OutboundResultSender for ServedConnectorCallHost {
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundTransportResult {
        self.reply = None;
        let sent = self.send_call(call);
        self.reply = sent.reply;
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

/// What one send came to, before the ledger scrubs its raw fields.
struct Sent {
    outcome: OutboundSendOutcome,
    reply: Option<UntrustedToolResult>,
    body: Option<Vec<u8>>,
    error: Option<String>,
}

impl Sent {
    /// Certain non-delivery: the `tools/call` request never left.
    fn not_sent(kind: OutboundFailureKind, code: Option<u16>) -> Self {
        Self {
            outcome: OutboundSendOutcome::Failed(OutboundSendFailure { kind, code }),
            reply: None,
            body: None,
            error: None,
        }
    }

    /// The request went and no readable answer came back.
    fn ambiguous(error: &str) -> Self {
        Self {
            outcome: OutboundSendOutcome::Ambiguous,
            reply: None,
            body: None,
            error: Some(error.to_owned()),
        }
    }
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
}

impl<'a> Exchange<'a> {
    /// Everything the requests need, checked before any of them leaves.
    fn new(client: &'a reqwest::blocking::Client, view: &'a FrozenToolCallView) -> Option<Self> {
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
        })
    }

    fn post(
        &self,
        body: &Value,
        auth: Option<&HeaderValue>,
        session: Option<&HeaderValue>,
        timeout: Duration,
    ) -> reqwest::blocking::RequestBuilder {
        let mut request = self
            .client
            .post(self.endpoint)
            .timeout(timeout)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, ACCEPT_BOTH)
            .body(body.to_string());
        if let Some(auth) = auth {
            request = request.header(AUTHORIZATION, auth.clone());
        }
        if let Some(session) = session {
            request = request.header(SESSION_HEADER, session.clone());
        }
        request
    }

    fn run(&self, auth: Option<HeaderValue>) -> Sent {
        let auth = auth.as_ref();
        // Everything before `tools/call` leaves is certain non-delivery.
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": INITIALIZE_ID,
            "method": "initialize",
            "params": {
                "protocolVersion": self.revision,
                "capabilities": {},
                "clientInfo": { "name": "oneiron", "version": env!("CARGO_PKG_VERSION") },
            },
        });
        let response = match self.post(&initialize, auth, None, HANDSHAKE_TIMEOUT).send() {
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
        let initialized = match read_reply(response, INITIALIZE_ID, &mut |_: &Value| {}) {
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
        let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        match self
            .post(&notification, auth, session.as_ref(), HANDSHAKE_TIMEOUT)
            .header(PROTOCOL_HEADER, self.protocol.clone())
            .send()
        {
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
        let sent = match self
            .post(&call, auth, session.as_ref(), CALL_TIMEOUT)
            .header(PROTOCOL_HEADER, self.protocol.clone())
            .headers(self.tool_headers.clone())
            .send()
        {
            Ok(response) => self.read_call_reply(response, auth, session.as_ref()),
            // A refused connection never reached the connector.
            Err(error) if error.is_connect() || error.is_builder() => {
                Sent::not_sent(OutboundFailureKind::TransportNotStarted, None)
            }
            Err(_) => Sent::ambiguous("connector_no_reply"),
        };
        if let Some(session) = session.as_ref() {
            // The session's end is a courtesy; its outcome changes nothing.
            let mut end = self
                .client
                .delete(self.endpoint)
                .timeout(HANDSHAKE_TIMEOUT)
                .header(SESSION_HEADER, session.clone())
                .header(PROTOCOL_HEADER, self.protocol.clone());
            if let Some(auth) = auth {
                end = end.header(AUTHORIZATION, auth.clone());
            }
            drop(end.send());
        }
        sent
    }

    fn read_call_reply(
        &self,
        response: reqwest::blocking::Response,
        auth: Option<&HeaderValue>,
        session: Option<&HeaderValue>,
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
        let mut refuse = |request: &Value| self.refuse_server_request(request, auth, session);
        let (message, body) = match read_reply(response, CALL_ID, &mut refuse) {
            Ok(Some(reply)) => reply,
            Ok(None) | Err(()) => return Sent::ambiguous("connector_reply_unreadable"),
        };
        let reply = if let Some(error) = message.get("error") {
            UntrustedToolResult {
                content: Value::Array(Vec::new()),
                structured_content: None,
                is_error: true,
                rpc_error: Some(error.clone()),
            }
        } else if let Some(result) = message.get("result") {
            UntrustedToolResult {
                content: result
                    .get("content")
                    .cloned()
                    .unwrap_or_else(|| Value::Array(Vec::new())),
                structured_content: result.get("structuredContent").cloned(),
                is_error: result.get("isError").and_then(Value::as_bool) == Some(true),
                rpc_error: None,
            }
        } else {
            return Sent::ambiguous("connector_reply_unreadable");
        };
        Sent {
            outcome: OutboundSendOutcome::Acked,
            reply: Some(reply),
            body: Some(body),
            error: None,
        }
    }

    /// Answers one server-initiated request on the reply stream with a
    /// refusal: this client serves no elicitation, sampling or roots.
    fn refuse_server_request(
        &self,
        request: &Value,
        auth: Option<&HeaderValue>,
        session: Option<&HeaderValue>,
    ) {
        let Some(id) = request.get("id") else {
            return;
        };
        let refusal = json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": "this client serves no server requests" },
        });
        let refused = self
            .post(&refusal, auth, session, HANDSHAKE_TIMEOUT)
            .header(PROTOCOL_HEADER, self.protocol.clone())
            .send();
        drop(refused);
    }
}

/// Reads one reply body, JSON or an event stream, until the response that
/// answers `id`. Server requests on a stream go to `refuse`; notifications
/// are dropped. More than [`CONNECTOR_REPLY_MAX_BYTES`] is unreadable.
/// Returns the message and its own bytes.
fn read_reply(
    response: reqwest::blocking::Response,
    id: u64,
    refuse: &mut dyn FnMut(&Value),
) -> Result<Option<(Value, Vec<u8>)>, ()> {
    let stream = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim_start().starts_with("text/event-stream"));
    let limit = u64::try_from(CONNECTOR_REPLY_MAX_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut body = response.take(limit);
    if !stream {
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
        return Ok(found.map(|message| (message, bytes)));
    }
    let mut reader = BufReader::new(body);
    let mut read = 0usize;
    let mut data = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).map_err(|_| ())?;
        read = read.saturating_add(n);
        if read > CONNECTOR_REPLY_MAX_BYTES {
            return Err(());
        }
        let end = n == 0;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if end || trimmed.is_empty() {
            if !data.is_empty() {
                let event = std::mem::take(&mut data);
                if let Ok(message) = serde_json::from_str::<Value>(&event) {
                    if answers(&message, id) {
                        return Ok(Some((message, event.into_bytes())));
                    }
                    if message.get("method").is_some() && message.get("id").is_some() {
                        refuse(&message);
                    }
                }
            }
            if end {
                return Ok(None);
            }
            continue;
        }
        if let Some(field) = trimmed.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(field.strip_prefix(' ').unwrap_or(field));
        }
    }
}

/// A response (not a request) carrying exactly this id.
fn answers(message: &Value, id: u64) -> bool {
    message.get("method").is_none()
        && message.get("id").and_then(Value::as_u64) == Some(id)
        && (message.get("result").is_some() || message.get("error").is_some())
}
