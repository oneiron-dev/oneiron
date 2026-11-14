//! The served poll of remote MCP tasks (FIX 11023; MCP 2025-11-25 tasks): one
//! `tasks/get` per Deferred row its pass finds due, in the session the task
//! was created in, under the row's own frozen endpoint and binding, with the
//! credential its send presented, through the same door. It never sends the
//! row's `tools/call` again, and it reads the row again just before each
//! `tasks/get`, so a row erased or settled since the pass began sends nothing.
//! A reply counts only when it names the task asked about. `completed` settles
//! the send Done; `failed` and `cancelled`, and a task the connector no longer
//! knows (`-32602`), stop it with its delivery uncertain; `working` polls
//! again later. An `input_required` task has its requests read through
//! `tasks/result` in its session (FIX 16029), and the result's own answer
//! settles the task; a stream that ends or runs out of time first polls
//! again later.
//!
//! Nobody is at a deferred call, so the vault owner answers a task's form
//! question: a form `elicitation/create` of this task, in a session whose
//! send declared form elicitation, is cleared of the value the poll's door
//! presented (FIX 3843) and parked in the ledger with its owner Ask, and
//! nothing answers it on the stream, so the task stays `input_required`.
//! Once the owner answered that question (values, Decline or Cancel), the
//! task is due on the next pass whenever it was last read; when the
//! connector asks the same question again, the answer is claimed (Sending,
//! before its POST) and sent in reply under the request's own id with the
//! task's metadata, then recorded Sent, or Uncertain when its POST's outcome
//! is unknown. A claimed answer is never sent twice. A changed question never
//! takes the answer: it is parked as the next round. Every other request is
//! refused as one this client does not serve: an elicitation in URL mode, in
//! a session that declared none, of another task, or one the ledger cannot
//! park, with `-32602`; any other method with `-32601`. A keyed call's issuer
//! binding is read again just before each answer or refusal goes out, after
//! any writer it waited on: while a hold stands (FIX 12166), or the binding
//! does not read, nothing is sent, and a claimed answer that was not sent is
//! Uncertain, never sent again. Every pass, whether it polled or not and
//! whether or not its host was built, ends by forgetting the parked
//! questions whose task ended with their Asks, reconciling the Asks with the
//! rows, and carrying out the task-input key retirements committed writers
//! staged.
//!
//! When the owner asked the task to stop (L8-29: the owner's cancel of the
//! call, or the owner's Stop of its try), the poll first sends one
//! `tasks/cancel` in the task's session, which undoes nothing already done:
//! the stop is claimed in the ledger (Sending) before its POST, the keyed
//! call's issuer binding is read again after that writer, and the POST's
//! outcome is recorded (Sent for a 2xx, Uncertain when unknown or held). A
//! claimed stop is never sent again. It carries no content and is the
//! owner's own act, so it goes out whether or not the grant still admits the
//! send; the `tasks/get` that follows in the same pass does not. Its answer
//! is not read: the send stays Deferred until a poll reads the task's end.
//!
//! A `tasks/get` or `tasks/cancel` answered HTTP 404 in its session is the
//! connector ending that session: the poll opens a new one under the same
//! endpoint, revision and credential, declaring what the send's session
//! declared, the ledger keeps its id, and the poll asks again in it (FIX
//! 16028). The session ends
//! only after the ledger holds the settlement. A session whose handle went
//! before it ended (an erase took the request) is owed its end: each pass
//! ends those, under the connector's own endpoint and the credential the
//! polls presented. Only the status word and a parked question's seal are
//! kept: the reply's other text never leaves this pass, so nothing it echoes
//! of the credential is stored.

use oneiron::outbound_consent::{OutboundBindingAuthority, OutboundBindingValidation};
use oneiron::outbound_intent_ledger::{
    DueRemoteTask, IntentLedgerError, IntentLedgerResult, RemoteTaskAnswer, RemoteTaskCredential,
    RemoteTaskEnd, RemoteTaskFormQuestion, RemoteTaskSessionEnd,
};

use super::live_exchange::Posted;
use super::*;

/// The JSON-RPC id of a poll's one request.
const POLL_ID: u64 = 7;
/// The JSON-RPC id of the `tasks/result` an `input_required` poll sends.
const RESULT_ID: u64 = 8;
/// The JSON-RPC id of the `tasks/cancel` the owner's stop sends (L8-29).
const CANCEL_ID: u64 = 9;
/// The most tasks one pass polls.
const POLLS_PER_PASS: usize = 32;
/// JSON-RPC "Invalid params": MCP's answer for a task id it does not know,
/// or one whose time to live ran out.
const INVALID_PARAMS: i64 = -32602;

/// What one poll read of a task.
enum Polled {
    /// Still running: `status` as the connector named it, and its hint.
    Running {
        status: &'static str,
        poll_after_ms: Option<u64>,
    },
    /// Done, one way or the other: its session ends once the ledger holds
    /// it.
    Ended(RemoteTaskEnd, LiveSession),
    /// The row is no longer a Deferred send of this task: nothing was sent.
    Gone,
}

/// What one POST in a task's session came to.
enum InSession {
    /// The connector's answer, or the send's error, and the session it came
    /// in.
    Answered(LiveSession, reqwest::Result<reqwest::blocking::Response>),
    /// The connector ended the session, and the row is no longer a Deferred
    /// send of this task: the session renewed for it is ended.
    Gone,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// One pass over the Deferred rows whose tasks are due a poll, then the
/// parked questions' reconciliation. Blocking: it sends, so run it on a
/// blocking worker (the connector settler does).
pub(crate) fn poll_remote_tasks(server: &SyncServer) {
    poll_due_remote_tasks(server);
    // FIX 16029: on every pass, however the poll went (nothing due, only
    // sessions owed their end, no host built): the parked question of a task
    // that ended, in this pass or another way, goes with its owner Ask; the
    // Asks are reconciled with the rows a restore can leave apart; and every
    // task-input key retirement a committed writer staged is carried out.
    let vault = server.vault();
    if let Err(error) = vault.forget_ended_remote_task_inputs() {
        tracing::warn!(%error, "the questions of ended remote tasks not forgotten");
        vault.finish_remote_task_input_retirements();
    }
}

/// The polls of one pass, and the sessions owed their end.
fn poll_due_remote_tasks(server: &SyncServer) {
    let vault = server.vault();
    // FIX 16029: a task whose parked question the owner answered is due now,
    // however recently its last poll read it, so this pass sends the answer.
    let ready = vault.remote_task_inputs_ready().unwrap_or_else(|error| {
        tracing::warn!(%error, "remote task questions the owner answered not read");
        Vec::new()
    });
    if let Err(error) = vault.remote_task_polls_due_at(&ready, now_ms()) {
        tracing::warn!(%error, "remote tasks the owner answered not made due");
    }
    let due = vault
        .remote_tasks_due(now_ms(), POLLS_PER_PASS)
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "remote tasks due a poll not read");
            Vec::new()
        });
    let owed = vault
        .remote_task_sessions_to_end(POLLS_PER_PASS)
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "remote task sessions owed their end not read");
            Vec::new()
        });
    if due.is_empty() && owed.is_empty() {
        return;
    }
    let mut host = match ServedConnectorCallHost::new(server) {
        Ok(host) => host,
        Err(error) => {
            tracing::warn!(%error, "connector call host not built to poll remote tasks");
            return;
        }
    };
    for task in due {
        // The intent id's first bytes name the row in the log.
        let intent: String = task.intent[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let recorded = match host.poll_remote_task(&task) {
            Ok(Polled::Running {
                status,
                poll_after_ms,
            }) => vault.remote_task_polled(
                &task.intent,
                poll_after_ms,
                status,
                now_ms(),
                task.cancel_requested,
            ),
            Ok(Polled::Ended(end, mut live)) => {
                vault.settle_polled_remote_task(&task.intent, end).map(|_| {
                    // The ledger holds the end: the task's session ends. Its
                    // kept header goes out only while no issuer hold stands
                    // over the call (FIX 12166); under one the session ends
                    // without a word to the connector.
                    if issuer_held(vault, &task) {
                        live.forget_credential();
                    }
                    live.end();
                })
            }
            // The next pass drops its poll row.
            Ok(Polled::Gone) => Ok(()),
            Err(reason) => {
                tracing::info!(%intent, reason, "remote task not polled; it waits for the next pass");
                vault.remote_task_polled(
                    &task.intent,
                    None,
                    reason,
                    now_ms(),
                    task.cancel_requested,
                )
            }
        };
        if let Err(error) = recorded {
            tracing::warn!(%intent, %error, "remote task poll not recorded");
        }
    }
    for (intent, end) in owed {
        // An end that cannot be sent (the connector gone or moved, its
        // credential no longer presented) is dropped: no session of it can
        // be reached.
        if let Err(reason) = host.end_remote_session(&end) {
            tracing::info!(reason, "a remote task's session was not ended");
        }
        if let Err(error) = vault.remote_task_session_ended(&intent) {
            tracing::warn!(%error, "a remote task session's end not recorded");
        }
    }
}

/// Whether an issuer hold stands over `task`'s keyed call, read again from
/// its durable binding (FIX 12166), or the binding cannot be read. A keyless
/// call meets none.
fn issuer_held(vault: &Vault, task: &DueRemoteTask) -> bool {
    let Ok(view) = FrozenToolCallView::read(&task.call) else {
        return true;
    };
    let Some(key_ref) = view.key_ref().and_then(|hex| EntityId::from_hex(hex).ok()) else {
        return false;
    };
    !matches!(vault.connector_issuer_hold(&key_ref, view.tool()), Ok(None))
}

impl ServedConnectorCallHost {
    /// Ends one session a remote task's polls kept open (`DELETE`), under
    /// the connector's endpoint, as long as the connector still answers
    /// there, with the credential its polls presented, through its own door
    /// (FIX 16028).
    fn end_remote_session(&mut self, end: &RemoteTaskSessionEnd) -> Result<(), &'static str> {
        let connector = self
            .connectors
            .get(end.server.as_str())
            .ok_or("connector_not_installed")?;
        if connector.endpoint != end.endpoint {
            return Err("connector_endpoint_changed");
        }
        let protocol = HeaderValue::from_str(&end.protocol).map_err(|_| "revision_unreadable")?;
        let session = HeaderValue::from_str(&end.session).map_err(|_| "session_unreadable")?;
        self.grant = None;
        self.run = None;
        self.credential = match end.credential {
            RemoteTaskCredential::Record(custody) => Some(custody),
            RemoteTaskCredential::Route => None,
        };
        let route = self
            .vault
            .route_connector_call(&end.server)
            .ok()
            .flatten()
            .ok_or("connector_route_gone")?;
        let key_ref = end
            .key_ref
            .as_deref()
            .and_then(|hex| EntityId::from_hex(hex).ok());
        let row = key_ref.as_ref().map(|key_ref| (key_ref, end.tool.as_str()));
        let auth = self
            .presenting(route)
            .present_again(&self.vault, row)
            .ok_or("credential_not_presented")?
            .auth;
        LiveSession {
            client: self.client.clone(),
            endpoint: end.endpoint.clone(),
            protocol,
            session: Some(session),
            auth,
        }
        .end();
        Ok(())
    }

    /// Polls `task` once: its credential presented again through its own
    /// door, then, when the owner asked the task to stop, one `tasks/cancel`
    /// (L8-29), then one `tasks/get` in its session.
    fn poll_remote_task(&mut self, task: &DueRemoteTask) -> Result<Polled, &'static str> {
        let view = FrozenToolCallView::read(&task.call).map_err(|_| "frozen_call_unread")?;
        let connector = self
            .connectors
            .get(view.server())
            .ok_or("connector_not_installed")?;
        if connector.endpoint != view.endpoint() {
            return Err("connector_endpoint_changed");
        }
        // The grant that admitted the send still admits it. The owner's stop
        // carries no content and is the owner's own act, so it goes out
        // whether or not the grant still admits the send (L8-29); the poll
        // does not.
        let admitted = OutboundBindingAuthority::for_vault(&self.vault)
            .and_then(|authority| authority.validate_frozen_call(&self.vault, &task.call))
            .is_ok_and(|validation| matches!(validation, OutboundBindingValidation::Valid));
        if !admitted && !task.cancel_requested {
            return Err("binding_not_admitted");
        }
        let protocol =
            HeaderValue::from_str(&task.poll.protocol).map_err(|_| "revision_unreadable")?;
        let session = task
            .poll
            .session
            .as_deref()
            .map(HeaderValue::from_str)
            .transpose()
            .map_err(|_| "session_unreadable")?;
        // The credential the send presented, through its own door again.
        self.grant = None;
        self.run = None;
        self.credential = match task.poll.credential {
            RemoteTaskCredential::Record(custody) => Some(custody),
            RemoteTaskCredential::Route => None,
        };
        let route = self
            .vault
            .route_connector_call(view.server())
            .ok()
            .flatten()
            .ok_or("connector_route_gone")?;
        let key_ref = view.key_ref().and_then(|hex| EntityId::from_hex(hex).ok());
        let row = key_ref.as_ref().map(|key_ref| (key_ref, view.tool()));
        let presented = self
            .presenting(route)
            .present_again(&self.vault, row)
            .ok_or("credential_not_presented")?;
        let live = LiveSession {
            client: self.client.clone(),
            endpoint: view.endpoint().to_owned(),
            protocol,
            session,
            auth: presented.auth,
        };
        // An erase or a settlement since the pass read the row sends nothing.
        let still_due = self
            .vault
            .remote_task_still_due(&task.intent, &task.task_id)
            .map_err(|_| "row_unread")?;
        if !still_due {
            return Ok(Polled::Gone);
        }
        let live = if task.cancel_requested {
            match self.cancel_remote_task(live, task)? {
                Some(live) => live,
                None => return Ok(Polled::Gone),
            }
        } else {
            live
        };
        if !admitted {
            return Err("binding_not_admitted");
        }
        let request = json!({
            "jsonrpc": "2.0",
            "id": POLL_ID,
            "method": "tasks/get",
            "params": { "taskId": task.task_id },
        });
        let (live, response) = match self.post_in_task_session(live, task, &request)? {
            InSession::Answered(live, sent) => (live, sent.map_err(|_| "poll_unsent")?),
            InSession::Gone => return Ok(Polled::Gone),
        };
        if !response.status().is_success() {
            return Err("poll_http_refused");
        }
        let Some((message, _)) =
            read_reply(response, POLL_ID).map_err(|_| "poll_reply_unreadable")?
        else {
            return Err("poll_unanswered");
        };
        Ok(match read_of(&message, &task.task_id)? {
            // MCP 2025-11-25 tasks: a requestor that meets `input_required`
            // asks for the result, and the task's requests come before it.
            Read::Running {
                status: "input_required",
                poll_after_ms,
            } => {
                let input = TaskInput {
                    vault: self.vault.as_ref(),
                    task,
                    issuer: key_ref.as_ref().map(|key_ref| (key_ref, view.tool())),
                    form: declared_elicitation(&task.poll).is_some(),
                    cleared: presented.kept.as_ref(),
                };
                match answer_task_input(&live, &input)? {
                    Some(end) => Polled::Ended(end, live),
                    None => Polled::Running {
                        status: "input_required",
                        poll_after_ms,
                    },
                }
            }
            Read::Running {
                status,
                poll_after_ms,
            } => Polled::Running {
                status,
                poll_after_ms,
            },
            Read::Ended(end) => Polled::Ended(end, live),
        })
    }

    /// Sends the owner's stop of `task` in its session `live` (L8-29): the
    /// stop is claimed first (Sending, in a writer that commits before the
    /// POST), the keyed call's issuer binding is read again after that
    /// writer (FIX 12166), then one `tasks/cancel` goes out, in a renewed
    /// session when the connector ended this one, and how it went is
    /// recorded: Sent when the connector took it (a 2xx), Uncertain when that
    /// is unknown or an issuer hold stood after the claim. A refused or
    /// unsent stop stays Sending. None is ever sent again. Its answer is not
    /// read: a stop undoes nothing already done, and only the end a poll
    /// reads settles the send. The session the poll goes on in; `None` when
    /// the row is no longer this task's Deferred send; `Err` when an issuer
    /// hold stood after the claim, so the pass sends nothing more.
    fn cancel_remote_task(
        &self,
        live: LiveSession,
        task: &DueRemoteTask,
    ) -> Result<Option<LiveSession>, &'static str> {
        match self
            .vault
            .claim_remote_task_cancel(&task.intent, &task.task_id)
        {
            Ok(true) => {}
            // Claimed before, and the task still runs: the poll goes on. A
            // row no longer this task's Deferred send (settled or erased
            // since the pass read it) sends nothing more.
            Ok(false) => {
                let still_due = self
                    .vault
                    .remote_task_still_due(&task.intent, &task.task_id)
                    .map_err(|_| "row_unread")?;
                return Ok(still_due.then_some(live));
            }
            Err(_) => return Err("cancel_unclaimed"),
        }
        if issuer_held(&self.vault, task) {
            tracing::info!(
                reason = "remote_task_cancel_issuer_held",
                "an issuer hold stands over a remote task's claimed stop; it is not sent, and \
                 never sent again"
            );
            if let Err(error) = self.vault.record_remote_task_cancel_uncertain(&task.intent) {
                tracing::warn!(%error, "a remote task stop's outcome not recorded");
            }
            // The hold stands: this pass presents the credential no more,
            // so no tasks/get goes out either (FIX 12166).
            return Err("issuer_held");
        }
        let request = json!({
            "jsonrpc": "2.0",
            "id": CANCEL_ID,
            "method": "tasks/cancel",
            "params": { "taskId": task.task_id },
        });
        // A session the connector ended and that could not be renewed: the
        // stop was not taken, and it stays Sending.
        let (live, sent) = match self.post_in_task_session(live, task, &request)? {
            InSession::Answered(live, sent) => (live, sent),
            InSession::Gone => return Ok(None),
        };
        let recorded = match Posted::of_send(&sent) {
            Posted::Accepted => self.vault.record_remote_task_cancel_sent(&task.intent),
            Posted::Uncertain => self.vault.record_remote_task_cancel_uncertain(&task.intent),
            Posted::Refused | Posted::Unsent => {
                tracing::info!(
                    reason = "remote_task_cancel_not_taken",
                    "the connector did not take a remote task's stop; it is not sent again"
                );
                Ok(())
            }
        };
        drop(sent);
        if let Err(error) = recorded {
            tracing::warn!(%error, "a remote task stop's outcome not recorded");
        }
        Ok(Some(live))
    }

    /// POSTs `request` in `task`'s session `live`. MCP (Streamable HTTP): a
    /// 404 to a request that carries a session id is the server ending that
    /// session, and the client starts a new one. A task binds to its
    /// authorization context, not its session (MCP 2025-11-25 tasks), so its
    /// requests go on in a new session under the row's own endpoint and
    /// credential (FIX 16028): the ledger keeps the new session's id, and
    /// `request` is sent again in it. The connector took nothing it answered
    /// 404, so that POST is the request's first that counts.
    fn post_in_task_session(
        &self,
        live: LiveSession,
        task: &DueRemoteTask,
        request: &Value,
    ) -> Result<InSession, &'static str> {
        let sent = live.post(request, Some(CALL_TIMEOUT)).send();
        let ended = live.session.is_some()
            && matches!(&sent, Ok(response) if response.status() == reqwest::StatusCode::NOT_FOUND);
        if !ended {
            return Ok(InSession::Answered(live, sent));
        }
        drop(sent);
        let renewed = renew_session(&live, &task.poll)?;
        // The new session is this request's until the ledger keeps it: every
        // way short of that ends it, so no retry leaves one open on the
        // connector.
        let Ok(session) = renewed
            .session
            .as_ref()
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()
        else {
            renewed.end();
            return Err("session_unreadable");
        };
        match self
            .vault
            .remote_task_session_renewed(&task.intent, &task.task_id, session)
        {
            Ok(true) => {}
            // Erased or settled since the pass read it.
            Ok(false) => {
                renewed.end();
                return Ok(InSession::Gone);
            }
            Err(_) => {
                renewed.end();
                return Err("session_unrecorded");
            }
        }
        let sent = renewed.post(request, Some(CALL_TIMEOUT)).send();
        Ok(InSession::Answered(renewed, sent))
    }
}

/// What the requests of one `input_required` task are served with.
struct TaskInput<'a> {
    vault: &'a Vault,
    /// The task's Deferred send: its intent, its task id and its frozen
    /// call, whose ledger row names the connector and the tool.
    task: &'a DueRemoteTask,
    /// A keyed call's issuer binding: its key and its tool.
    issuer: Option<(&'a EntityId, &'a str)>,
    /// Whether the task's session declared form elicitation.
    form: bool,
    /// The value the poll's door presented: what the connector asks is
    /// cleared of it before it is parked or matched, as a live call's
    /// questions are (FIX 3843).
    cleared: Option<&'a KeptSentValue>,
}

impl TaskInput<'_> {
    /// Whether the kept header must stay in: an issuer hold stands over the
    /// keyed call, read again from its durable binding (FIX 12166), or the
    /// binding cannot be read. A keyless call meets none.
    fn held(&self) -> bool {
        let Some((key_ref, tool)) = self.issuer else {
            return false;
        };
        match self.vault.connector_issuer_hold(key_ref, tool) {
            Ok(None) => false,
            Ok(Some(_)) => true,
            Err(error) => {
                tracing::warn!(%error, "connector issuer binding not read");
                true
            }
        }
    }
}

/// How one request on a task's `tasks/result` stream was served.
enum Served {
    /// Answered, refused, or left unanswered under an issuer hold: the
    /// stream is read on.
    ReadOn,
    /// Its question is parked for the owner, or could not be parked now:
    /// the stream is left, and the task is polled again.
    Leave,
}

/// What the writer of a form question did with it.
enum Turned {
    /// The owner's answer to this same question, claimed: its row is
    /// Sending.
    Claimed(RemoteTaskAnswer),
    /// The question is parked for the owner (or was already).
    Parked,
}

/// Reads the requests a task that needs input sends while its `tasks/result`
/// is open in `live`, the task's own session (FIX 16029), and serves each
/// ([`serve_request`]). A form question of this task, in a session that
/// declared form elicitation, is the owner's: when the owner answered that
/// same question, the answer is sent in reply and the stream read on;
/// otherwise it is parked for the owner, nothing answers it, and the stream
/// is left, so the task stays `input_required`. Every other request is
/// refused as one this client does not serve (`-32602` for an elicitation it
/// does not take, `-32601` for any other method). The result's own answer
/// settles the task. `None` when the stream ends, its time runs out or a
/// question is parked first: the task is polled again, and leaving the
/// stream does not cancel it. Nothing the requests or the result carry is
/// kept outside the parked question's seal. A keyed call meets its issuer
/// hold before the `tasks/result` and just before each answer or refusal,
/// after the writer that claims or parks its question committed.
fn answer_task_input(
    live: &LiveSession,
    input: &TaskInput<'_>,
) -> Result<Option<RemoteTaskEnd>, &'static str> {
    // A keyed call's issuer binding is read again before the kept header
    // goes out (FIX 12166): while a hold stands nothing more is sent.
    if let Some((key_ref, tool)) = input.issuer {
        match input.vault.connector_issuer_hold(key_ref, tool) {
            Ok(None) => {}
            Ok(Some(_)) => return Err("issuer_held"),
            Err(_) => return Err("issuer_binding_unread"),
        }
    }
    let request = json!({
        "jsonrpc": "2.0",
        "id": RESULT_ID,
        "method": "tasks/result",
        "params": { "taskId": input.task.task_id },
    });
    // The task's requests wait on the connector already: a short read, so
    // one task that goes on working after them does not hold the pass.
    let response = live
        .post(&request, Some(HANDSHAKE_TIMEOUT))
        .send()
        .map_err(|_| "result_unsent")?;
    if !response.status().is_success() {
        return Err("result_http_refused");
    }
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let mut stream = match open_reply(response, RESULT_ID, Some(deadline))
        .map_err(|()| "result_unreadable")?
    {
        Reply::Json(found) => return Ok(found.map(|(message, bytes)| settled_by(message, bytes))),
        Reply::Stream(stream) => stream,
    };
    loop {
        match stream.next(RESULT_ID) {
            Ok(StreamEvent::Request(request)) => {
                if matches!(serve_request(live, input, request), Served::Leave) {
                    return Ok(None);
                }
            }
            Ok(StreamEvent::Answer(message, bytes)) => {
                return Ok(Some(settled_by(message, bytes.into())));
            }
            Ok(StreamEvent::End) | Err(()) => return Ok(None),
        }
    }
}

/// Serves one request of `input`'s task on its `tasks/result` stream in
/// `live` (FIX 16029), as [`answer_task_input`] says. A form question,
/// cleared of the value the poll's door presented, is parked or answered in
/// one writer: the owner's answer to this same question (the same digest) is
/// claimed there, its row Sending before the POST, or else the question is
/// parked with its owner Ask. The request is wiped once served.
fn serve_request(live: &LiveSession, input: &TaskInput<'_>, request: Value) -> Served {
    // Each answer and refusal reads the issuer binding again, as a live
    // call's does: a hold that stood since keeps it from going out.
    if input.held() {
        zeroize_json(request);
        return Served::ReadOn;
    }
    if request.get("method").and_then(Value::as_str) != Some(wire::ELICIT) {
        live.refuse(request);
        return Served::ReadOn;
    }
    // MCP: a mode the session did not declare, URL mode here, answers
    // `-32602`; so does a question of another task.
    let question = if input.form && related_to(&request, &input.task.task_id) {
        stream_question(&request)
    } else {
        None
    };
    let (Some(mut question), Some(request_id)) = (question, request.get("id").cloned()) else {
        live.refuse_params(request);
        return Served::ReadOn;
    };
    // The same question asked again is cleared the same way, so its digest
    // still matches the parked one.
    if let Some(kept) = input.cleared {
        let sent = kept.sent();
        sent.clear_string(&mut question.message);
        sent.clear_json(&mut question.requested_schema);
    }
    let question = RemoteTaskFormQuestion {
        session: live
            .session
            .as_ref()
            .and_then(|session| session.to_str().ok())
            .map(str::to_owned),
        request_id: request_id.clone(),
        message: question.message,
        requested_schema: question.requested_schema,
        connector: input.task.call.server().to_owned(),
        tool: input.task.call.tool().to_owned(),
    };
    let (vault, intent) = (input.vault, &input.task.intent);
    let digest = question.digest();
    let turned = vault.try_with_write_txn(|txn| -> IntentLedgerResult<Turned> {
        if let Some(answer) = vault.claim_remote_task_answer_in_txn(
            txn,
            intent,
            &digest,
            question.session.as_deref(),
        )? {
            return Ok(Turned::Claimed(answer));
        }
        vault.park_remote_task_input_in_txn(txn, intent, &question)?;
        Ok(Turned::Parked)
    });
    wipe_question(question);
    match turned {
        Ok(Turned::Claimed(answer)) => {
            zeroize_json(request);
            send_answer(live, input, answer, request_id);
            Served::ReadOn
        }
        Ok(Turned::Parked) => {
            // A new round staged its last round's retirement.
            vault.finish_remote_task_input_retirements();
            zeroize_json(request_id);
            zeroize_json(request);
            Served::Leave
        }
        // A schema that is not a flat form, or a row that is no longer this
        // task's Deferred send: a question this client cannot take. The
        // writer may have waited behind one that committed an issuer hold,
        // so the binding is read again before the refusal goes out.
        Err(IntentLedgerError::InvalidInput(_)) => {
            zeroize_json(request_id);
            if input.held() {
                zeroize_json(request);
            } else {
                live.refuse_params(request);
            }
            Served::ReadOn
        }
        Err(error) => {
            tracing::warn!(
                %error,
                "a remote task's question was not parked; the task is polled again"
            );
            zeroize_json(request_id);
            zeroize_json(request);
            Served::Leave
        }
    }
}

/// Sends the owner's claimed `answer` in reply to the task's request
/// `request_id`, the related-task metadata with it, in `live`, and records
/// how its POST went (FIX 16029): taken (a 2xx), the answer is Sent and its
/// sealed round retired; an outcome unknown, it is Uncertain. The keyed
/// call's issuer binding is read again just before the POST, after the
/// claim's writer committed: while a hold stands over it (FIX 12166), or
/// the binding does not read, nothing goes out and the claimed answer is
/// Uncertain. A refused or unsent answer stays Sending. None is ever sent
/// again.
fn send_answer(
    live: &LiveSession,
    input: &TaskInput<'_>,
    answer: RemoteTaskAnswer,
    request_id: Value,
) {
    let RemoteTaskAnswer {
        generation,
        request_id: parked_id,
        session,
        result,
    } = answer;
    // The answer goes out under the request's own id; the parked one's
    // place is wiped.
    zeroize_json(parked_id);
    zeroize_json(Value::from(session));
    // `None`: an issuer hold stood, or the binding did not read, just before
    // the POST, so nothing went out.
    let posted = if input.held() {
        zeroize_json(request_id);
        None
    } else if let Ok(elicit_result) = serde_json::from_slice::<Map<String, Value>>(&result) {
        Some(live.respond_in_task(request_id, &input.task.task_id, elicit_result))
    } else {
        zeroize_json(request_id);
        Some(Posted::Unsent)
    };
    drop(result);
    if posted.is_none() {
        tracing::info!(
            reason = "remote_task_answer_issuer_held",
            "an issuer hold stands over a remote task's claimed answer; it is not sent, and \
             never sent again"
        );
    }
    let (vault, intent) = (input.vault, &input.task.intent);
    let recorded = match posted {
        Some(Posted::Accepted) => vault.try_with_write_txn(|txn| {
            vault.record_remote_task_answer_sent_in_txn(txn, intent, generation)
        }),
        None | Some(Posted::Uncertain) => vault.try_with_write_txn(|txn| {
            vault.record_remote_task_answer_uncertain_in_txn(txn, intent, generation)
        }),
        Some(Posted::Refused | Posted::Unsent) => {
            tracing::info!(
                reason = "remote_task_answer_not_taken",
                "the connector did not take a remote task's answer; it is not sent again"
            );
            return;
        }
    };
    if let Err(error) = recorded {
        tracing::warn!(%error, "a remote task answer's outcome not recorded");
    }
    vault.finish_remote_task_input_retirements();
}

/// Whether `request` is task `task_id`'s: its related-task metadata names
/// that task, or it carries none (MCP 2025-11-25 tasks).
fn related_to(request: &Value, task_id: &str) -> bool {
    match request
        .get("params")
        .and_then(|params| params.get(wire::META))
        .and_then(|meta| meta.get(wire::RELATED_TASK))
    {
        None => true,
        Some(related) => related.get(wire::TASK_ID).and_then(Value::as_str) == Some(task_id),
    }
}

/// Wipes what `question` carries of the connector's request once its
/// writer is done with it.
fn wipe_question(question: RemoteTaskFormQuestion) {
    let RemoteTaskFormQuestion {
        session,
        request_id,
        message,
        requested_schema,
        connector: _,
        tool: _,
    } = question;
    zeroize_json(Value::from(session));
    zeroize_json(request_id);
    zeroize_json(Value::String(message));
    zeroize_json(requested_schema);
}

/// The elicitation capability the task's session declared: what its send's
/// `initialize` declared, read again from the revision it pinned, when that
/// send declared form elicitation; `None` when it declared none (FIX
/// 16029).
fn declared_elicitation(poll: &RemoteTaskPoll) -> Option<Value> {
    if poll.form_elicitation {
        elicitation_capability(&poll.protocol)
    } else {
        None
    }
}

/// What a `tasks/result` answer says of its task: it carries what the task's
/// `tools/call` would have answered (MCP 2025-11-25 tasks), so a result is a
/// completed send and an error one whose delivery the connector has not
/// shown. The answer is wiped here.
fn settled_by(message: Value, bytes: RawOutboundBody) -> RemoteTaskEnd {
    let end = if message.get("error").is_some() {
        RemoteTaskEnd::Unconfirmed
    } else {
        RemoteTaskEnd::Completed
    };
    zeroize_json(message);
    drop(bytes);
    end
}

/// A new MCP session in place of the one the connector ended, under
/// `live`'s endpoint, the protocol revision `poll` pinned and `live`'s
/// credential (FIX 16028): `initialize` with no session, declaring the
/// capabilities the send's session declared (FIX 16029: form elicitation
/// when it did, else none), so the new session asks nothing the first could
/// not, its revision checked as the send checked it, then
/// `notifications/initialized` in the new session. A renewal that fails once
/// the server opened a session ends that session.
fn renew_session(live: &LiveSession, poll: &RemoteTaskPoll) -> Result<LiveSession, &'static str> {
    let revision = poll.protocol.as_str();
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": INITIALIZE_ID,
        "method": "initialize",
        "params": {
            "protocolVersion": revision,
            "capabilities": client_capabilities(declared_elicitation(poll).as_ref()),
            "clientInfo": { "name": "oneiron", "version": env!("CARGO_PKG_VERSION") },
        },
    });
    let response = post_json(
        &live.client,
        &live.endpoint,
        &initialize,
        live.auth.as_ref(),
        None,
        Some(HANDSHAKE_TIMEOUT),
    )
    .send()
    .map_err(|_| "session_renewal_unsent")?;
    if !response.status().is_success() {
        return Err("session_renewal_refused");
    }
    let renewed = LiveSession {
        client: live.client.clone(),
        endpoint: live.endpoint.clone(),
        protocol: live.protocol.clone(),
        session: response.headers().get(SESSION_HEADER).cloned(),
        auth: live.auth.clone(),
    };
    // The key pinned one revision; a server that answers another is not
    // the connector the owner approved.
    let refusal = match read_reply(response, INITIALIZE_ID) {
        Ok(Some((initialized, _))) => (initialized.get("error").is_some()
            || initialized
                .pointer("/result/protocolVersion")
                .and_then(Value::as_str)
                != Some(revision))
        .then_some("session_renewal_rejected"),
        _ => Some("session_renewal_unreadable"),
    };
    if let Some(refusal) = refusal {
        renewed.end();
        return Err(refusal);
    }
    let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    match renewed.post(&notification, Some(HANDSHAKE_TIMEOUT)).send() {
        Ok(response) if response.status().is_success() => Ok(renewed),
        _ => {
            renewed.end();
            Err("session_renewal_unconfirmed")
        }
    }
}

/// What one `tasks/get` answer says of its task.
enum Read {
    Running {
        status: &'static str,
        poll_after_ms: Option<u64>,
    },
    Ended(RemoteTaskEnd),
}

/// What a `tasks/get` answer to the poll of `task_id` says of that task.
/// A result that names another task, or none, is no answer.
fn read_of(message: &Value, task_id: &str) -> Result<Read, &'static str> {
    if let Some(error) = message.get("error") {
        return if error.get("code").and_then(Value::as_i64) == Some(INVALID_PARAMS) {
            // The connector no longer knows the task: it has not shown
            // whether the send took effect.
            Ok(Read::Ended(RemoteTaskEnd::Unconfirmed))
        } else {
            Err("poll_refused")
        };
    }
    let result = message.get("result").ok_or("poll_reply_unreadable")?;
    if result.get("taskId").and_then(Value::as_str) != Some(task_id) {
        return Err("poll_reply_other_task");
    }
    let poll_after_ms = result.get("pollInterval").and_then(Value::as_u64);
    match result.get("status").and_then(Value::as_str) {
        Some("completed") => Ok(Read::Ended(RemoteTaskEnd::Completed)),
        Some("failed" | "cancelled") => Ok(Read::Ended(RemoteTaskEnd::Unconfirmed)),
        Some("working") => Ok(Read::Running {
            status: "working",
            poll_after_ms,
        }),
        Some("input_required") => Ok(Read::Running {
            status: "input_required",
            poll_after_ms,
        }),
        Some(_) => Err("poll_status_unknown"),
        None => Err("poll_status_missing"),
    }
}
