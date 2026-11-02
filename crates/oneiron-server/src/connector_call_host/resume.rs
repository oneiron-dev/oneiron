//! A live exchange taken up again after a restart (FIX 9157, ruled by the
//! Engine 07:49).
//!
//! Each round, once the call's row keeps it, the host seals beside it what a
//! restart needs: the question set's binding, the round's questions as the
//! caller sees them (foreign text, so only in the sealed state, never on the
//! row), its key aliases, the session, and the protocol's own continuation.
//! For a 2026-07-28 Retry that is the opaque request state and the next
//! request id; for a 2025-06-18 or 2025-11-25 stream, the outstanding
//! request's id and the stream's last event id. A stream that set no event
//! id has nothing to reattach to, so it keeps no state. Copies in memory
//! stay zeroized (FIX 8051, FIX 8054).
//!
//! A server starting marks every round uncertain. The settler's pass then
//! takes each round with a state up again, once per call each run: the
//! credential is presented again through its own door, the session is
//! rebuilt, a stream is reattached by a `GET` naming its last event id, and
//! the same handle is registered again under its call and round with a new
//! worker. A Retry re-sends nothing until the round is answered, and then
//! only while the original grant still admits the call (FIX 8226). Only then
//! is the round taken out of uncertain. A round whose state cannot be
//! opened, whose connector moved, or whose credential or stream is refused
//! stands uncertain, as before. Keeping a state never holds up a live round:
//! a state that cannot be kept is logged, and that round is not resumable.
//!
//! The calls (canon silent), each in one place:
//! - [`RESUME_TRIES_PER_START`]: how often one server run tries one call.
//! - [`Worker::suspends`]: a server going away suspends an exchange a
//!   restart can take up again; no cancel goes and its session stays open.
//! - [`resumes_at`]: only where the connector is still installed at the
//!   endpoint the call was admitted to.
//! - [`Worker::round_resume`]: a stream that set no event id keeps no state.
//! - The credential is presented again through its own door
//!   (`Presenting::present_again`), so a secret grant counts the
//!   redemption as a send.

use std::collections::HashMap;

use oneiron::limit_ask::EngineLimit;
use oneiron::outbound_consent::{ConnectorResumeProtocol, OpenedConnectorResume};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::live_exchange::{AnswerReceipts, Inbox, Worker};
use super::reply_read::EventStream;
use super::stream_pump::Pump;
use super::*;

/// The header a stream's reattachment names the last event it read by.
const LAST_EVENT_ID_HEADER: &str = "last-event-id";

/// What a stream's reattachment accepts.
const EVENT_STREAM: &str = "text/event-stream";

/// How many times one server run tries to take one call's exchange up
/// again: once, at the settler's first pass after a start. A round it could
/// not take up stands uncertain until the next start tries again.
const RESUME_TRIES_PER_START: u32 = 1;

/// Whether an exchange admitted to `binding`'s endpoint may be taken up
/// again on the connector `installed` there now: only at the same endpoint.
fn resumes_at(installed: Option<&ConnectorHostConfig>, binding: &QuestionBinding) -> bool {
    installed.is_some_and(|connector| connector.endpoint == binding.endpoint)
}

/// One round's resume state, as the host seals it. `S` is the text a
/// presented secret may hide in: borrowed while it is sealed, and owned and
/// zeroized again at once when it is opened.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeState<S> {
    binding: QuestionBinding,
    /// The round's questions as the caller sees them, cleared.
    questions: Vec<ConnectorQuestion>,
    /// Each alias beside the original key it stands for (FIX 8051).
    aliases: Vec<(S, S)>,
    /// The MCP session the exchange runs in.
    session: Option<S>,
    next: ResumeNext<S>,
}

/// What the protocol continues the exchange with.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum ResumeNext<S> {
    /// 2026-07-28: the opaque request state and the next request id.
    Retry {
        request_state: Option<S>,
        next_id: u64,
    },
    /// 2025-06-18 and 2025-11-25: the outstanding request's id and the
    /// stream's last event id as that request was read.
    Stream { request_id: S, last_event_id: S },
}

/// One round's sealed resume state, until the call's row keeps it.
pub(super) struct RoundResume {
    generation: u64,
    protocol: ConnectorResumeProtocol,
    state: Zeroizing<Vec<u8>>,
}

impl RoundResume {
    /// Keeps this state on the call `call_ref`'s row, beside its round of
    /// the questions `handle` names; a write that fails is logged.
    pub(super) fn keep(&self, vault: &Vault, handle: &str, call_ref: &EntityId) {
        if let Err(error) = vault.keep_connector_input_resume(
            call_ref,
            handle,
            self.generation,
            self.protocol,
            &self.state,
        ) {
            tracing::warn!(%error, "connector call resume state not kept");
        }
    }
}

impl Worker {
    /// This round's resume state, its questions as the caller sees them;
    /// `None` when there is none to keep: a stream that set no event id
    /// (nothing to reattach after), or a session header that is not text.
    pub(super) fn round_resume(&self, questions: &[ConnectorQuestion]) -> Option<RoundResume> {
        let session = self
            .session
            .session
            .as_ref()
            .map(HeaderValue::to_str)
            .transpose()
            .ok()?;
        let (protocol, next) = match &self.continuation {
            Continuation::Stream {
                request_id,
                last_event_id,
                ..
            } => (
                ConnectorResumeProtocol::Stream,
                ResumeNext::Stream {
                    request_id: request_id.text(),
                    last_event_id: last_event_id.as_deref()?.as_str(),
                },
            ),
            Continuation::Retry {
                request_state,
                next_id,
                ..
            } => (
                ConnectorResumeProtocol::Retry,
                ResumeNext::Retry {
                    request_state: request_state.as_ref().map(KeptWire::text),
                    next_id: *next_id,
                },
            ),
        };
        let state = ResumeState {
            binding: self.receipts.binding.clone(),
            questions: questions.to_vec(),
            aliases: self.aliases.pairs(),
            session,
            next,
        };
        let mut sealed = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *sealed, &state).ok()?;
        Some(RoundResume {
            generation: self.generation,
            protocol,
            state: sealed,
        })
    }

    /// Keeps this round's resume state on the call `call_ref`'s row, once
    /// the row kept the round.
    pub(super) fn keep_resume(&self, call_ref: Option<EntityId>, questions: &[ConnectorQuestion]) {
        if let Some(resume) = self.round_resume(questions) {
            self.keep_row(call_ref, |vault, call_ref| {
                vault.keep_connector_input_resume(
                    call_ref,
                    &self.handle,
                    resume.generation,
                    resume.protocol,
                    &resume.state,
                )
            });
        }
    }

    /// Whether this exchange is suspended rather than ended now that its
    /// answers' channel closed: the server went away (its registry is
    /// gone), and a restart can take the round up again, a Retry always and
    /// a stream that set an event id. Nothing is sent and the session stays
    /// open.
    pub(super) fn suspends(&self) -> bool {
        self.registry.strong_count() == 0
            && match &self.continuation {
                Continuation::Stream { last_event_id, .. } => last_event_id.is_some(),
                Continuation::Retry { .. } => true,
            }
    }
}

impl LiveSession {
    /// Reattaches this session's reply stream after the event
    /// `last_event_id`: a `GET` the server answers with the events it still
    /// holds after that one. `None` when it answers with no stream.
    fn reattach(&self, last_event_id: &str) -> Option<EventStream> {
        let mut last = HeaderValue::from_str(last_event_id).ok()?;
        last.set_sensitive(true);
        let mut get = self
            .client
            .get(self.endpoint.as_str())
            .header(ACCEPT, EVENT_STREAM)
            .header(PROTOCOL_HEADER, self.protocol.clone())
            .header(LAST_EVENT_ID_HEADER, last);
        if let Some(session) = &self.session {
            get = get.header(SESSION_HEADER, session.clone());
        }
        if let Some(auth) = &self.auth {
            get = get.header(AUTHORIZATION, auth.clone());
        }
        let response = get.send().ok()?;
        if !response.status().is_success() {
            return None;
        }
        match open_reply(response, CALL_ID, None) {
            Ok(Reply::Stream(stream)) => Some(stream),
            Ok(Reply::Json(_)) | Err(()) => None,
        }
    }
}

/// Takes up again each live exchange a restart left with a resume state on
/// its call's row, up to [`RESUME_TRIES_PER_START`] times per call this run:
/// `tries` counts them. Blocking: it presents credentials and reattaches
/// streams, so run it on a blocking worker.
pub(crate) fn resume_exchanges(server: &SyncServer, tries: &mut HashMap<EntityId, u32>) {
    let registry = &server.connector_elicitations;
    let opened = server
        .vault()
        .open_connector_input_resumes(|call_ref, handle| {
            tries.get(call_ref).copied().unwrap_or(0) < RESUME_TRIES_PER_START
                && !registry.holds(handle)
        });
    let opened = match opened {
        Ok(opened) if opened.is_empty() => return,
        Ok(opened) => opened,
        Err(error) => {
            tracing::warn!(%error, "connector call resume states not read");
            return;
        }
    };
    let mut host = match ServedConnectorCallHost::new(server) {
        Ok(host) => host,
        Err(error) => {
            tracing::warn!(%error, "connector call host not built to resume");
            return;
        }
    };
    for opened in opened {
        let call_ref = opened.call_ref;
        *tries.entry(call_ref).or_default() += 1;
        match host.resume(opened) {
            Ok(()) => {
                tracing::debug!(call_ref = %call_ref.to_hex(), "connector exchange taken up again");
            }
            Err(reason) => {
                tracing::info!(
                    call_ref = %call_ref.to_hex(),
                    reason,
                    "connector exchange not taken up again; its round stays uncertain"
                );
            }
        }
    }
}

impl ServedConnectorCallHost {
    /// Takes up again the exchange `opened` keeps the state of: its
    /// credential presented again, its session rebuilt, a stream
    /// reattached, and its handle registered again under its call and
    /// round with a new worker. The round leaves uncertain only then.
    fn resume(&mut self, opened: OpenedConnectorResume) -> Result<(), &'static str> {
        let OpenedConnectorResume {
            call_ref,
            handle,
            generation,
            state,
            credential,
            grant,
            run,
            original,
            ..
        } = opened;
        let ResumeState {
            binding,
            questions,
            aliases,
            session,
            next,
        } = serde_json::from_slice::<ResumeState<String>>(&state)
            .map_err(|_| "resume_state_unreadable")?;
        let aliases = KeyAliases::of_pairs(aliases);
        if !resumes_at(self.connectors.get(&binding.server), &binding) {
            return Err("connector_endpoint_changed");
        }
        let protocol =
            HeaderValue::from_str(&binding.revision).map_err(|_| "revision_unreadable")?;
        let session = session
            .as_deref()
            .map(HeaderValue::from_str)
            .transpose()
            .map_err(|_| "session_unreadable")?;
        // The credential the call presents, through its own door again.
        self.credential = credential;
        self.grant = grant;
        self.run = run;
        let route = self
            .vault
            .route_connector_call(&binding.server)
            .ok()
            .flatten()
            .ok_or("connector_route_gone")?;
        let presented = self
            .presenting(route)
            .present_again(&self.vault)
            .ok_or("credential_not_presented")?;
        let live = LiveSession {
            client: self.client.clone(),
            endpoint: binding.endpoint.clone(),
            protocol,
            session,
            auth: presented.auth,
        };
        let (continuation, stream) = match next {
            ResumeNext::Retry {
                request_state,
                next_id,
            } => {
                let original = original.ok_or("original_call_unread")?;
                let (tool, arguments, tool_headers) = {
                    let view =
                        FrozenToolCallView::read(&original).map_err(|_| "original_call_unread")?;
                    let exchange =
                        Exchange::new(&self.client, &view, None).ok_or("original_call_unread")?;
                    (
                        exchange.tool.to_owned(),
                        exchange.arguments,
                        exchange.tool_headers,
                    )
                };
                let continuation = Continuation::Retry {
                    tool,
                    arguments,
                    tool_headers,
                    request_state: request_state
                        .map(|state| KeptWire::of_text(Zeroizing::new(state))),
                    next_id,
                    original,
                };
                (continuation, None)
            }
            ResumeNext::Stream {
                request_id,
                last_event_id,
            } => {
                let last_event_id = Zeroizing::new(last_event_id);
                let stream = live
                    .reattach(&last_event_id)
                    .ok_or("stream_not_reattached")?;
                let continuation = Continuation::Stream {
                    stream: None,
                    request_id: KeptWire::of_text(Zeroizing::new(request_id)),
                    last_event_id: Some(last_event_id),
                };
                (continuation, Some(stream))
            }
        };
        let registry = &self.elicitations;
        let registered = registry
            .restore(&handle, call_ref, generation, binding.clone(), &questions)
            .ok_or("question_set_live")?;
        let live_sets = u64::try_from(registered.live).unwrap_or(u64::MAX);
        let _ = self
            .vault
            .measure_limit(EngineLimit::ConnectorLiveQuestions, live_sets);
        let inbox = match stream {
            Some(stream) => match Pump::start(stream, registered.commands) {
                Some(pump) => Inbox::Pumped(pump),
                None => {
                    registry.finish(None, &handle);
                    return Err("stream_pump_not_started");
                }
            },
            None => Inbox::Commands(registered.commands),
        };
        // The round is live again before its worker can end it.
        if !matches!(
            self.vault.resume_connector_input(&call_ref, &handle),
            Ok(true)
        ) {
            registry.finish(None, &handle);
            return Err("round_not_resumed");
        }
        let worker = Worker {
            session: live,
            continuation,
            inbox,
            registry: Arc::downgrade(registry),
            handle: handle.clone(),
            generation,
            asked: questions.len(),
            kept: presented.kept,
            aliases,
            receipts: AnswerReceipts {
                vault: Arc::downgrade(&self.vault),
                binding,
                question_set: *blake3::hash(handle.as_bytes()).as_bytes(),
            },
        };
        if !worker.start() {
            registry.finish(None, &handle);
            if let Err(error) = self
                .vault
                .mark_connector_input_uncertain(&call_ref, &handle)
            {
                tracing::warn!(%error, "connector call questions not marked uncertain");
            }
            return Err("worker_not_started");
        }
        Ok(())
    }
}
