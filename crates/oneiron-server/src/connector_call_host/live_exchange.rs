//! The live half of the call host: the worker that owns an exchange once its
//! send returned, and the reply readers both halves share.
//!
//! The worker receipts each answer it sends at its POST, and each round it
//! ends unanswered, on the gate ledger (FIX 3840): receipt-only, ids,
//! digests and dispositions, never an answer. A receipt that cannot be
//! written is logged; the answer has gone or not either way.

use std::sync::mpsc::RecvTimeoutError;

use oneiron::outbound_consent::{
    ConnectorElicitationReceipt, ElicitationDisposition, ElicitationEgress,
};
use zeroize::Zeroizing;

use super::*;

/// Hands one live exchange to a worker thread, which owns it from here, and
/// keeps its questions for the caller. The call reached the connector, so
/// the send is acknowledged either way; a worker that could not start drops
/// the questions. `kept` is the value the send presented, which the worker
/// clears what the connector says next of (FIX 7646); the round's aliases go
/// with it (FIX 8051).
pub(super) fn hand_over(
    declared: &Declared<'_>,
    round: KeptRound,
    continuation: Continuation,
    live: &mut Option<LiveSession>,
    body: Vec<u8>,
    kept: Option<KeptSentValue>,
) -> Sent {
    let KeptRound {
        registered,
        questions,
        aliases,
    } = round;
    let Some(session) = live.take() else {
        declared.registry.finish(&registered.handle);
        return Sent::acked(None, body);
    };
    let awaiting = ConnectorAwaitingInput {
        handle: registered.handle.clone(),
        questions,
        expires_at_ms: registered.expires_at_ms,
    };
    let receipts = AnswerReceipts {
        vault: Arc::downgrade(declared.vault),
        binding: declared.binding.clone(),
        question_set: *blake3::hash(registered.handle.as_bytes()).as_bytes(),
    };
    let worker = Worker {
        session,
        continuation,
        commands: registered.commands,
        registry: Arc::downgrade(declared.registry),
        handle: registered.handle,
        deadline: registered.deadline,
        generation: 0,
        asked: awaiting.questions.len(),
        kept,
        aliases,
        receipts,
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
pub(super) fn post_json(
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
pub(super) struct LiveSession {
    pub(super) client: reqwest::blocking::Client,
    pub(super) endpoint: String,
    pub(super) protocol: HeaderValue,
    pub(super) session: Option<HeaderValue>,
    /// The credential the door presented for the send, kept until the
    /// session ends.
    pub(super) auth: Option<HeaderValue>,
}

/// How one POST of an answer or a refusal went.
pub(super) enum Posted {
    Accepted,
    Refused,
    Unsent,
    Uncertain,
}

impl Posted {
    /// What an answer's receipt says of this POST.
    fn egress(&self) -> ElicitationEgress {
        match self {
            Self::Accepted => ElicitationEgress::Accepted,
            Self::Refused => ElicitationEgress::Refused,
            Self::Unsent => ElicitationEgress::Unsent,
            Self::Uncertain => ElicitationEgress::Uncertain,
        }
    }
}

/// Where a worker receipts each answer it sends, and each round it ends
/// unanswered (FIX 3840): the call's binding, the vault held weakly, and
/// the digest of the question set's handle, never the handle.
pub(super) struct AnswerReceipts {
    vault: Weak<Vault>,
    binding: QuestionBinding,
    question_set: [u8; 32],
}

impl AnswerReceipts {
    /// Receipts round `generation`: each question's disposition, the exact
    /// `responses` sent (or none) and how their POST went.
    fn record(
        &self,
        generation: u64,
        dispositions: &[ElicitationDisposition],
        responses: &BTreeMap<String, Value>,
        egress: ElicitationEgress,
    ) {
        let Some(vault) = self.vault.upgrade() else {
            return;
        };
        let binding = self.binding.authority();
        let text = Value::Object(responses.clone().into_iter().collect()).to_string();
        let receipt = ConnectorElicitationReceipt {
            binding: &binding,
            parent_intent: self.binding.parent_intent,
            question_set: self.question_set,
            generation,
            dispositions,
            answer_digest: *blake3::hash(text.as_bytes()).as_bytes(),
            egress,
        };
        if let Err(error) = vault.append_connector_elicitation_receipt(&receipt) {
            tracing::warn!(%error, "connector answer receipt not written");
        }
    }
}

/// Each answer's disposition, in the order of its key, as `responses` say.
fn dispositions(responses: &BTreeMap<String, Value>) -> Vec<ElicitationDisposition> {
    responses
        .values()
        .map(
            |response| match response.get(wire::ACTION).and_then(Value::as_str) {
                Some("accept") => ElicitationDisposition::Accept,
                Some("decline") => ElicitationDisposition::Decline,
                _ => ElicitationDisposition::Cancel,
            },
        )
        .collect()
}

impl LiveSession {
    /// A POST of `body` in this session, with its protocol header.
    pub(super) fn post(
        &self,
        body: &Value,
        timeout: Option<Duration>,
    ) -> reqwest::blocking::RequestBuilder {
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
    pub(super) fn respond(&self, id: &Value, member: &str, value: Value) -> Posted {
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
    pub(super) fn refuse(&self, request: &Value) {
        let Some(id) = request.get("id") else {
            return;
        };
        let refusal =
            json!({ "code": -32601, "message": "this client does not serve this request" });
        let _ = self.respond(id, "error", refusal);
    }

    /// Ends the session: a courtesy, whose outcome changes nothing.
    pub(super) fn end(&self) {
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

/// A foreign value the exchange hands back exactly as the connector sent it:
/// a stream request's id, a retried call's request state. A connector may
/// put the presented value in it, so while it waits for the next answer it
/// is kept serialized in zeroizing storage, scrubbed once replaced or
/// dropped, and never cleared or rewritten (FIX 8054).
pub(super) struct KeptWire(Zeroizing<String>);

impl KeptWire {
    pub(super) fn keep(value: &Value) -> Self {
        Self(Zeroizing::new(value.to_string()))
    }

    /// The kept value, for one message: its own serialization parses back
    /// to the same value, key order included.
    pub(super) fn value(&self) -> Value {
        serde_json::from_str(&self.0).unwrap_or(Value::Null)
    }
}

/// What a live question set's worker continues the exchange with.
pub(super) enum Continuation {
    /// A request on the reply stream: answered by a JSON-RPC response POSTed
    /// to the endpoint, then the same stream read on.
    Stream {
        stream: EventStream,
        request_id: KeptWire,
    },
    /// A result that asked for input: answered by the same `tools/call`
    /// again, with the responses and the opaque request state.
    Retry {
        tool: String,
        arguments: Value,
        tool_headers: HeaderMap,
        request_state: Option<KeptWire>,
        next_id: u64,
    },
}

/// What one answer led to.
pub(super) enum Next {
    /// Another round of questions.
    Asked(Vec<ConnectorQuestion>),
    /// The exchange is over.
    Over(WorkerEvent),
}

/// The thread that owns one live exchange once its send returned: it waits
/// for an answer to each round until the round's deadline, sends it, and
/// reads what the connector says next.
pub(super) struct Worker {
    session: LiveSession,
    continuation: Continuation,
    commands: mpsc::Receiver<AnswerCommand>,
    /// The registry, held weakly: a server going away drops it, and with it
    /// every question set's channel.
    registry: Weak<ConnectorElicitationRegistry>,
    handle: String,
    deadline: Instant,
    generation: u64,
    /// How many questions the current round asks.
    asked: usize,
    /// The value the send presented, kept as the session keeps its header:
    /// each later question and the terminal reply are cleared of it.
    kept: Option<KeptSentValue>,
    /// The current round's aliases: its answer goes on the wire under the
    /// connector's own keys (FIX 8051).
    aliases: KeyAliases,
    /// Where each answer and each round ended unanswered is receipted.
    receipts: AnswerReceipts,
}

impl Worker {
    fn run(mut self) {
        loop {
            let left = self.deadline.saturating_duration_since(Instant::now());
            // A round that lapsed, or a server going away (or a call that
            // left no one to answer, FIX 3844), cancels the questions.
            let command = match self.commands.recv_timeout(left) {
                Ok(command) => command,
                Err(RecvTimeoutError::Timeout) => {
                    self.cancel(ElicitationDisposition::Expired);
                    break;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.cancel(ElicitationDisposition::Cancel);
                    break;
                }
            };
            match self.answer(&command.responses) {
                Next::Asked(mut questions) => {
                    // Cleared before the registry or the caller sees them;
                    // this round's aliases replace the last round's.
                    self.aliases = match &self.kept {
                        Some(kept) => clear_questions(&mut questions, &kept.sent()),
                        None => KeyAliases::default(),
                    };
                    self.generation += 1;
                    self.asked = questions.len();
                    let advanced = self.registry.upgrade().and_then(|registry| {
                        registry.advance(&self.handle, self.generation, &questions)
                    });
                    let Some((deadline, expires_at_ms)) = advanced else {
                        let _ = command.reply.send(WorkerEvent::Failed {
                            sent: true,
                            reason: "connector_question_lapsed",
                        });
                        self.cancel(ElicitationDisposition::Cancel);
                        break;
                    };
                    self.deadline = deadline;
                    let _ = command.reply.send(WorkerEvent::Question {
                        questions,
                        expires_at_ms,
                    });
                }
                Next::Over(mut event) => {
                    if let Some(kept) = &self.kept {
                        clear_event(&mut event, &kept.sent());
                    }
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

    /// Sends one frozen answer and reads what the connector says next. The
    /// answer is receipted at its POST (FIX 3840).
    fn answer(&mut self, responses: &BTreeMap<String, Value>) -> Next {
        let (generation, answered) = (self.generation, dispositions(responses));
        match &mut self.continuation {
            Continuation::Stream { stream, request_id } => {
                let Some(result) = self.aliases.response(responses, wire::STREAM_KEY) else {
                    self.receipts.record(
                        generation,
                        &answered,
                        responses,
                        ElicitationEgress::NotSent,
                    );
                    return Next::Over(WorkerEvent::Failed {
                        sent: false,
                        reason: "connector_answer_unmatched",
                    });
                };
                let posted = self
                    .session
                    .respond(&request_id.value(), "result", result.clone());
                self.receipts
                    .record(generation, &answered, responses, posted.egress());
                match posted {
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
                // The connector's own keys go back only here, on the wire.
                params.insert(
                    wire::INPUT_RESPONSES.to_owned(),
                    Value::Object(self.aliases.restore(responses)),
                );
                if let Some(state) = request_state.as_ref() {
                    params.insert(wire::REQUEST_STATE.to_owned(), state.value());
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
                let egress = match &posted {
                    Ok(response) if response.status().is_success() => ElicitationEgress::Accepted,
                    Ok(response) if response.status().is_server_error() => {
                        ElicitationEgress::Uncertain
                    }
                    Ok(_) => ElicitationEgress::Refused,
                    Err(error) if error.is_connect() || error.is_builder() => {
                        ElicitationEgress::Unsent
                    }
                    Err(_) => ElicitationEgress::Uncertain,
                };
                self.receipts
                    .record(generation, &answered, responses, egress);
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
    /// result that asked for input takes no reply. Each of its questions is
    /// receipted `disposition` (FIX 3840).
    fn cancel(&self, disposition: ElicitationDisposition) {
        let mut sent = BTreeMap::new();
        let egress = match &self.continuation {
            Continuation::Stream { request_id, .. } => {
                let cancel = elicitation_response(ConnectorAnswerAction::Cancel, None);
                sent.insert(wire::STREAM_KEY.to_owned(), cancel.clone());
                self.session
                    .respond(&request_id.value(), "result", cancel)
                    .egress()
            }
            Continuation::Retry { .. } => ElicitationEgress::NotSent,
        };
        self.receipts.record(
            self.generation,
            &vec![disposition; self.asked],
            &sent,
            egress,
        );
    }
}

/// The tool's terminal reply in `message`, or the failure an unreadable one
/// is.
pub(super) fn terminal(message: &Value) -> WorkerEvent {
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
pub(super) fn read_stream_round(
    session: &LiveSession,
    stream: &mut EventStream,
    request_id: &mut KeptWire,
) -> Next {
    loop {
        match stream.next(CALL_ID) {
            Ok(StreamEvent::Answer(message, _)) => return Next::Over(terminal(&message)),
            Ok(StreamEvent::Request(request)) => match stream_question(&request) {
                Some(question) => {
                    *request_id = KeptWire::keep(request.get("id").unwrap_or(&Value::Null));
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
#[allow(
    clippy::result_large_err,
    reason = "the error is the worker's terminal event, handed on as is"
)]
pub(super) fn read_retry_reply(
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
pub(super) enum Reply {
    /// The message that answers the request, if the body holds one, and its
    /// bytes.
    Json(Option<(Value, Vec<u8>)>),
    Stream(EventStream),
}

/// One event of a reply stream.
pub(super) enum StreamEvent {
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
pub(super) struct EventStream {
    reader: BufReader<std::io::Take<reqwest::blocking::Response>>,
    read: usize,
    data: String,
    deadline: Option<Instant>,
}

impl EventStream {
    /// The next answer to `id` or server request; notifications are
    /// dropped.
    pub(super) fn next(&mut self, id: u64) -> Result<StreamEvent, ()> {
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
pub(super) fn open_reply(
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
pub(super) fn read_reply(
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
pub(super) fn answers(message: &Value, id: u64) -> bool {
    message.get("method").is_none()
        && message.get("id").and_then(Value::as_u64) == Some(id)
        && (message.get("result").is_some() || message.get("error").is_some())
}
