//! The live half of the call host: the worker that owns an exchange once its
//! send returned. The reply readers both halves share are in `reply_read`.
//!
//! The worker receipts each answer it sends at its POST, and each round it
//! ends unanswered, on the gate ledger (FIX 3840): receipt-only, ids,
//! digests and dispositions, never an answer. A receipt that cannot be
//! written is logged; the answer has gone or not either way.
//!
//! The worker keeps the call's row current (FIX 3837): each next round (its
//! generation and count, never the questions' text), the delivery once the
//! connector answers the call, and, when the exchange ends unanswered, the
//! round standing with its delivery uncertain. A round never lapses: the worker waits for its answer as long
//! as the exchange lives. A stream's worker reads the stream on while it
//! waits (FIX 9286, [`super::stream_pump`]), so a stream that ends ends the
//! exchange then, and its kept owner ask is withdrawn.
//!
//! Each round's resume state goes on the call's row beside it, and a server
//! going away suspends the exchange rather than ending it, so a restart
//! takes it up again (`super::resume`, FIX 9157).
//!
//! Before the session's kept header goes out again (an answer, a cancel, the
//! session's end), the worker reads the call's durable issuer binding again.
//! While an issuer change the owner has not accepted holds the row, it drops
//! the header, ends the session here and settles the call with the hold
//! (FIX 9303).

use oneiron::connector_key::CONNECTOR_ISSUER_HOLD_REASON;
use oneiron::outbound_consent::{
    ConnectorElicitationReceipt, ElicitationDisposition, ElicitationEgress,
    OutboundBindingAuthority, OutboundBindingValidation,
};
use oneiron::outbound_intent_ledger::IntentLedgerError;
use zeroize::Zeroizing;

use super::reply_read::{EventStream, read_retry_reply, terminal};
use super::stream_pump::{Pump, Waited};
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
    mut continuation: Continuation,
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
        declared
            .registry
            .finish(Some(&**declared.vault), &registered.handle);
        return Sent::acked(None, body);
    };
    let awaiting = ConnectorAwaitingInput {
        handle: registered.handle.clone(),
        questions,
        live_until_ms: registered.live_until_ms,
    };
    let receipts = AnswerReceipts {
        vault: Arc::downgrade(declared.vault),
        binding: declared.binding.clone(),
        question_set: *blake3::hash(registered.handle.as_bytes()).as_bytes(),
    };
    // A stream is read on while its round waits (FIX 9286).
    let inbox = match &mut continuation {
        Continuation::Stream { stream, .. } => {
            match stream
                .take()
                .and_then(|stream| Pump::start(stream, registered.commands))
            {
                Some(pump) => Inbox::Pumped(pump),
                None => {
                    declared
                        .registry
                        .finish(Some(&**declared.vault), &awaiting.handle);
                    return Sent::acked(None, body);
                }
            }
        }
        Continuation::Retry { .. } => Inbox::Commands(registered.commands),
    };
    let worker = Worker {
        session,
        continuation,
        inbox,
        registry: Arc::downgrade(declared.registry),
        handle: registered.handle,
        generation: 0,
        asked: awaiting.questions.len(),
        kept,
        aliases,
        receipts,
    };
    // The first round's resume state waits for the engine to bind the round
    // to its call's row (FIX 9157).
    let resume = worker.round_resume(&awaiting.questions);
    if !worker.start() {
        declared
            .registry
            .finish(Some(&**declared.vault), &awaiting.handle);
        return Sent::acked(None, body);
    }
    Sent {
        awaiting: Some(awaiting),
        resume,
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
    pub(super) vault: Weak<Vault>,
    pub(super) binding: QuestionBinding,
    pub(super) question_set: [u8; 32],
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

    /// Refuses one server request this client does not serve once the
    /// call's issuer binding is read again (FIX 9303): while a hold stands
    /// the kept header does not go out and the request goes unanswered; the
    /// worker's next answer, cancel or end settles the hold.
    pub(super) fn refuse_unheld(&self, request: &Value, receipts: &AnswerReceipts) {
        if self.issuer_hold(receipts).is_none() {
            self.refuse(request);
        }
    }

    /// The hold the call `receipts` names meets, its durable issuer binding
    /// read again before the kept `Authorization` header would go out again
    /// (FIX 9303): an issuer change the owner has not accepted, or a binding
    /// that cannot be read. A session that keeps no header meets none.
    pub(super) fn issuer_hold(&self, receipts: &AnswerReceipts) -> Option<&'static str> {
        if self.auth.is_none() {
            return None;
        }
        let Some(vault) = receipts.vault.upgrade() else {
            return Some(ISSUER_BINDING_UNREAD);
        };
        let binding = &receipts.binding;
        vault
            .connector_issuer_hold(&binding.key_ref, &binding.tool)
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "connector issuer binding not read");
                Some(ISSUER_BINDING_UNREAD)
            })
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

    /// Drops the kept credential, and the session with it, here (FIX 9303):
    /// an issuer change holds the call's row, so the header never goes out
    /// again, and the session ends without a word to the connector.
    pub(super) fn forget_credential(&mut self) {
        self.auth = None;
        self.session = None;
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

    /// The kept serialization, for a round's resume state (FIX 9157).
    pub(super) fn text(&self) -> &str {
        self.0.as_str()
    }

    /// A value a round's resume state kept, as its serialization.
    pub(super) const fn of_text(text: Zeroizing<String>) -> Self {
        Self(text)
    }
}

/// The reason an answer gets when the original call's grant no longer
/// admits the re-send it would make (FIX 8226): the ledger's own word for a
/// frozen binding its grant no longer admits.
const RETRY_NOT_ADMITTED: &str = "binding_invalid";

/// The reason an answer gets when the call's issuer binding could not be
/// read again before the kept header would go out (FIX 9303): it does not
/// go unread.
const ISSUER_BINDING_UNREAD: &str = "connector_issuer_binding_unread";

/// Whether the original call's grant still admits `original`, checked as
/// the first send and a ledger recovery check it; a vault gone or a check
/// that fails admits nothing.
fn still_admitted(vault: &Weak<Vault>, original: &FrozenOutboundCall) -> bool {
    let Some(vault) = vault.upgrade() else {
        return false;
    };
    OutboundBindingAuthority::for_vault(&vault)
        .and_then(|authority| authority.validate_frozen_call(&vault, original))
        .is_ok_and(|validation| matches!(validation, OutboundBindingValidation::Valid))
}

/// What a live question set's worker continues the exchange with.
pub(super) enum Continuation {
    /// A request on the reply stream: answered by a JSON-RPC response POSTed
    /// to the endpoint, then the same stream read on. The worker's pump
    /// takes the stream (FIX 9286).
    Stream {
        stream: Option<EventStream>,
        request_id: KeptWire,
        /// The stream's last event id as the round's request was read: what
        /// a restart reattaches after (FIX 9157).
        last_event_id: Option<Zeroizing<String>>,
    },
    /// A result that asked for input: answered by the same `tools/call`
    /// again, with the responses and the opaque request state.
    Retry {
        tool: String,
        arguments: Value,
        tool_headers: HeaderMap,
        request_state: Option<KeptWire>,
        next_id: u64,
        /// The authenticated call whose payload each answer re-sends: its
        /// grant is checked again before every re-send (FIX 8226).
        original: FrozenOutboundCall,
    },
}

/// What one answer led to.
pub(super) enum Next {
    /// Another round of questions.
    Asked(Vec<ConnectorQuestion>),
    /// The exchange is over.
    Over(WorkerEvent),
}

/// Where a worker waits for each round's answer.
pub(super) enum Inbox {
    /// The answers alone: a retried call holds no stream between rounds.
    Commands(mpsc::Receiver<AnswerCommand>),
    /// The answers and the stream together (FIX 9286).
    Pumped(Pump),
}

/// The thread that owns one live exchange once its send returned: it waits
/// for an answer to each round as long as the exchange lives, sends it, and
/// reads what the connector says next.
pub(super) struct Worker {
    pub(super) session: LiveSession,
    pub(super) continuation: Continuation,
    pub(super) inbox: Inbox,
    /// The registry, held weakly: a server going away drops it, and with it
    /// every question set's channel.
    pub(super) registry: Weak<ConnectorElicitationRegistry>,
    pub(super) handle: String,
    pub(super) generation: u64,
    /// How many questions the current round asks.
    pub(super) asked: usize,
    /// The value the send presented, kept as the session keeps its header:
    /// each later question and the terminal reply are cleared of it.
    pub(super) kept: Option<KeptSentValue>,
    /// The current round's aliases: its answer goes on the wire under the
    /// connector's own keys (FIX 8051).
    pub(super) aliases: KeyAliases,
    /// Where each answer and each round ended unanswered is receipted.
    pub(super) receipts: AnswerReceipts,
}

impl Worker {
    /// Runs the worker on its own thread; `false` when it could not start.
    pub(super) fn start(self) -> bool {
        std::thread::Builder::new()
            .name("connector-elicitation".to_owned())
            .spawn(move || self.run())
            .is_ok()
    }

    fn run(mut self) {
        // The connector answered the call: its row keeps the delivery.
        let mut delivered = false;
        loop {
            // A call that left no one to answer (FIX 3844) cancels the
            // questions; a server going away suspends a round a restart can
            // take up again, and cancels any other (FIX 9157). A round never
            // lapses (FIX 3837).
            let waited = match &mut self.inbox {
                Inbox::Commands(commands) => commands.recv().map_or(Waited::Closed, Waited::Answer),
                Inbox::Pumped(pump) => pump.wait_answer(&self.session, &self.receipts),
            };
            let command = match waited {
                Waited::Answer(command) => command,
                Waited::Closed if self.suspends() => return,
                Waited::Closed => {
                    self.cancel(ElicitationDisposition::Cancel);
                    break;
                }
                Waited::Ended => {
                    // The stream ended while the round waited: nothing is
                    // left to answer, so its questions end unanswered, their
                    // delivery uncertain (FIX 9286).
                    self.receipts.record(
                        self.generation,
                        &vec![ElicitationDisposition::Cancel; self.asked],
                        &BTreeMap::new(),
                        ElicitationEgress::NotSent,
                    );
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
                    let Some((live_until_ms, call_ref)) = advanced else {
                        let _ = command.reply.send(WorkerEvent::Failed {
                            sent: true,
                            reason: "connector_question_gone",
                        });
                        self.cancel(ElicitationDisposition::Cancel);
                        break;
                    };
                    // The row keeps the round before its caller sees it.
                    let (handle, generation, asked) =
                        (self.handle.as_str(), self.generation, questions.len());
                    self.keep_row(call_ref, |vault, call_ref| {
                        vault.keep_connector_input_round(
                            call_ref,
                            handle,
                            generation,
                            asked,
                            live_until_ms,
                        )
                    });
                    self.keep_resume(call_ref, &questions);
                    let _ = command.reply.send(WorkerEvent::Question {
                        questions,
                        live_until_ms,
                    });
                }
                Next::Over(mut event) => {
                    if let Some(kept) = &self.kept {
                        clear_event(&mut event, &kept.sent());
                    }
                    let (call_ref, handle) = (self.bound_call(), self.handle.as_str());
                    if matches!(event, WorkerEvent::Result(_)) {
                        self.keep_row(call_ref, |vault, call_ref| {
                            vault.settle_connector_input(call_ref, handle)
                        });
                        delivered = true;
                    } else if let WorkerEvent::Failed {
                        sent: false,
                        reason:
                            reason @ (RETRY_NOT_ADMITTED
                            | CONNECTOR_ISSUER_HOLD_REASON
                            | ISSUER_BINDING_UNREAD),
                    } = event
                    {
                        // Definitely never re-sent, and never will be.
                        self.keep_row(call_ref, |vault, call_ref| {
                            vault.refuse_connector_input(call_ref, handle, reason)
                        });
                        delivered = true;
                    }
                    let _ = command.reply.send(event);
                    break;
                }
            }
        }
        // An exchange that ended unanswered leaves the questions standing,
        // their delivery uncertain (FIX 3837).
        if !delivered {
            let (call_ref, handle) = (self.bound_call(), self.handle.as_str());
            self.keep_row(call_ref, |vault, call_ref| {
                vault.mark_connector_input_uncertain(call_ref, handle)
            });
        }
        // The courtesy end carries the kept header too (FIX 9303).
        if self.issuer_hold().is_some() {
            self.session.forget_credential();
        }
        self.session.end();
        if let Some(registry) = self.registry.upgrade() {
            registry.finish(self.receipts.vault.upgrade().as_deref(), &self.handle);
        }
    }

    /// The hold the call's row meets before the kept header goes out again
    /// (FIX 9303).
    fn issuer_hold(&self) -> Option<&'static str> {
        self.session.issuer_hold(&self.receipts)
    }

    /// The call whose row keeps this exchange's questions, once bound.
    fn bound_call(&self) -> Option<EntityId> {
        self.registry
            .upgrade()
            .and_then(|registry| registry.call_ref(&self.handle))
    }

    /// Writes the call `call_ref`'s row through `write`, when the row is
    /// bound and the vault still stands; a write that fails is logged.
    pub(super) fn keep_row(
        &self,
        call_ref: Option<EntityId>,
        write: impl FnOnce(&Vault, &EntityId) -> Result<bool, IntentLedgerError>,
    ) {
        let (Some(vault), Some(call_ref)) = (self.receipts.vault.upgrade(), call_ref) else {
            return;
        };
        if let Err(error) = write(&vault, &call_ref) {
            tracing::warn!(%error, "connector call questions not kept");
        }
    }

    /// Sends one frozen answer and reads what the connector says next. The
    /// answer is receipted at its POST (FIX 3840).
    fn answer(&mut self, responses: &BTreeMap<String, Value>) -> Next {
        let (generation, answered) = (self.generation, dispositions(responses));
        // The kept header goes out again only while the call's row meets no
        // issuer change the owner has not accepted (FIX 9303).
        if let Some(reason) = self.issuer_hold() {
            self.session.forget_credential();
            self.receipts
                .record(generation, &answered, responses, ElicitationEgress::NotSent);
            return Next::Over(WorkerEvent::Failed {
                sent: false,
                reason,
            });
        }
        match &mut self.continuation {
            Continuation::Stream {
                request_id,
                last_event_id,
                ..
            } => {
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
                match &mut self.inbox {
                    Inbox::Pumped(pump) => pump.read_round(
                        &self.session,
                        &self.receipts,
                        request_id,
                        last_event_id,
                        CALL_TIMEOUT,
                    ),
                    Inbox::Commands(_) => Next::Over(WorkerEvent::Failed {
                        sent: true,
                        reason: "connector_reply_unreadable",
                    }),
                }
            }
            Continuation::Retry {
                tool,
                arguments,
                tool_headers,
                request_state,
                next_id,
                original,
            } => {
                // The original grant must still admit the call this answer
                // re-sends, a decline or a cancel too; one that no longer
                // does (or cannot be checked) sends nothing (FIX 8226).
                if !still_admitted(&self.receipts.vault, original) {
                    self.receipts.record(
                        generation,
                        &answered,
                        responses,
                        ElicitationEgress::NotSent,
                    );
                    return Next::Over(WorkerEvent::Failed {
                        sent: false,
                        reason: RETRY_NOT_ADMITTED,
                    });
                }
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
                    Ok(response) => read_retry_reply(&self.session, &self.receipts, response, id),
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
    /// result that asked for input takes no reply, nor does a round whose
    /// row an issuer change holds (FIX 9303). Each of its questions is
    /// receipted `disposition` (FIX 3840).
    fn cancel(&mut self, disposition: ElicitationDisposition) {
        let held = self.issuer_hold().is_some();
        if held {
            self.session.forget_credential();
        }
        let mut sent = BTreeMap::new();
        let egress = match &self.continuation {
            Continuation::Stream { request_id, .. } if !held => {
                let cancel = elicitation_response(ConnectorAnswerAction::Cancel, None);
                sent.insert(wire::STREAM_KEY.to_owned(), cancel.clone());
                self.session
                    .respond(&request_id.value(), "result", cancel)
                    .egress()
            }
            Continuation::Stream { .. } | Continuation::Retry { .. } => ElicitationEgress::NotSent,
        };
        self.receipts.record(
            self.generation,
            &vec![disposition; self.asked],
            &sent,
            egress,
        );
    }
}
