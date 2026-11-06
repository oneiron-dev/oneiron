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
//! `tasks/result` in its session (FIX 16029): nobody is at a deferred call to
//! answer them, so each is refused as one this client does not serve, and the
//! result's own answer settles the task; a stream that ends or runs out of
//! time first polls again later. A `tasks/get` answered HTTP 404 in its
//! session is the connector ending that session: the poll opens a new one
//! under the same endpoint, revision and credential, the ledger keeps its id,
//! and the poll asks again in it (FIX 16028). The session ends only after the
//! ledger holds the settlement. A session whose handle went before it ended
//! (an erase took the request) is owed its end: each pass ends those, under
//! the connector's own endpoint and the credential the polls presented. Only
//! the status word is kept: the reply's other text never leaves this pass, so
//! nothing it echoes of the credential is stored.

use oneiron::outbound_consent::{OutboundBindingAuthority, OutboundBindingValidation};
use oneiron::outbound_intent_ledger::{
    DueRemoteTask, RemoteTaskCredential, RemoteTaskEnd, RemoteTaskSessionEnd,
};

use super::*;

/// The JSON-RPC id of a poll's one request.
const POLL_ID: u64 = 7;
/// The JSON-RPC id of the `tasks/result` an `input_required` poll sends.
const RESULT_ID: u64 = 8;
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

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// One pass over the Deferred rows whose tasks are due a poll. Blocking: it
/// sends, so run it on a blocking worker (the connector settler does).
pub(crate) fn poll_remote_tasks(server: &SyncServer) {
    let vault = server.vault();
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
            }) => vault.remote_task_polled(&task.intent, poll_after_ms, status, now_ms()),
            Ok(Polled::Ended(end, live)) => {
                vault.settle_polled_remote_task(&task.intent, end).map(|_| {
                    // The ledger holds the end: the task's session ends.
                    live.end();
                })
            }
            // The next pass drops its poll row.
            Ok(Polled::Gone) => Ok(()),
            Err(reason) => {
                tracing::info!(%intent, reason, "remote task not polled; it waits for the next pass");
                vault.remote_task_polled(&task.intent, None, reason, now_ms())
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
    /// door, then one `tasks/get` in its session.
    fn poll_remote_task(&mut self, task: &DueRemoteTask) -> Result<Polled, &'static str> {
        let view = FrozenToolCallView::read(&task.call).map_err(|_| "frozen_call_unread")?;
        let connector = self
            .connectors
            .get(view.server())
            .ok_or("connector_not_installed")?;
        if connector.endpoint != view.endpoint() {
            return Err("connector_endpoint_changed");
        }
        // The grant that admitted the send still admits it.
        let admitted = OutboundBindingAuthority::for_vault(&self.vault)
            .and_then(|authority| authority.validate_frozen_call(&self.vault, &task.call))
            .is_ok_and(|validation| matches!(validation, OutboundBindingValidation::Valid));
        if !admitted {
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
        let auth = self
            .presenting(route)
            .present_again(&self.vault, row)
            .ok_or("credential_not_presented")?
            .auth;
        let live = LiveSession {
            client: self.client.clone(),
            endpoint: view.endpoint().to_owned(),
            protocol,
            session,
            auth,
        };
        // An erase or a settlement since the pass read the row sends nothing.
        let still_due = self
            .vault
            .remote_task_still_due(&task.intent, &task.task_id)
            .map_err(|_| "row_unread")?;
        if !still_due {
            return Ok(Polled::Gone);
        }
        let request = json!({
            "jsonrpc": "2.0",
            "id": POLL_ID,
            "method": "tasks/get",
            "params": { "taskId": task.task_id },
        });
        let response = live
            .post(&request, Some(CALL_TIMEOUT))
            .send()
            .map_err(|_| "poll_unsent")?;
        // MCP (Streamable HTTP): a 404 to a request that carries a session id
        // is the server ending that session, and the client starts a new
        // one. A task binds to its authorization context, not its session
        // (MCP 2025-11-25 tasks), so its poll goes on in a new session under
        // the row's own endpoint and credential.
        let (live, response) =
            if response.status() == reqwest::StatusCode::NOT_FOUND && live.session.is_some() {
                drop(response);
                let renewed = renew_session(&live, &task.poll.protocol)?;
                // The new session is this poll's until the ledger keeps it:
                // every way short of that ends it, so no retry leaves one
                // open on the connector.
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
                        return Ok(Polled::Gone);
                    }
                    Err(_) => {
                        renewed.end();
                        return Err("session_unrecorded");
                    }
                }
                let response = renewed
                    .post(&request, Some(CALL_TIMEOUT))
                    .send()
                    .map_err(|_| "poll_unsent")?;
                (renewed, response)
            } else {
                (live, response)
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
            } => match answer_task_input(
                &live,
                &task.task_id,
                key_ref
                    .as_ref()
                    .map(|key_ref| (&self.vault, key_ref, view.tool())),
            )? {
                Some(end) => Polled::Ended(end, live),
                None => Polled::Running {
                    status: "input_required",
                    poll_after_ms,
                },
            },
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
}

/// Reads the requests a task that needs input sends while its `tasks/result`
/// is open in `live`, the task's own session (FIX 16029). Nobody is at a
/// deferred call to answer them: each is refused as one this client does not
/// serve, so the task goes on or ends at once instead of waiting on input
/// until its provider drops it. The result's own answer settles the task.
/// `None` when the stream ends or its time runs out first: the task is polled
/// again, and leaving the stream does not cancel it. Nothing the requests or
/// the result carry is kept. A keyed call (`issuer`) meets its issuer hold
/// before the `tasks/result` and before each refusal.
fn answer_task_input(
    live: &LiveSession,
    task_id: &str,
    issuer: Option<(&Vault, &EntityId, &str)>,
) -> Result<Option<RemoteTaskEnd>, &'static str> {
    // A keyed call's issuer binding is read again before the kept header
    // goes out (FIX 12166): while a hold stands nothing more is sent.
    if let Some((vault, key_ref, tool)) = issuer {
        match vault.connector_issuer_hold(key_ref, tool) {
            Ok(None) => {}
            Ok(Some(_)) => return Err("issuer_held"),
            Err(_) => return Err("issuer_binding_unread"),
        }
    }
    let request = json!({
        "jsonrpc": "2.0",
        "id": RESULT_ID,
        "method": "tasks/result",
        "params": { "taskId": task_id },
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
            // Each refusal reads the issuer binding again, as a live call's
            // does: a hold that stood since keeps it from going out.
            Ok(StreamEvent::Request(request)) => match issuer {
                Some((vault, key_ref, tool)) => {
                    live.refuse_unless_held(request, vault, key_ref, tool);
                }
                None => live.refuse(request),
            },
            Ok(StreamEvent::Answer(message, bytes)) => return Ok(Some(settled_by(message, bytes))),
            Ok(StreamEvent::End) | Err(()) => return Ok(None),
        }
    }
}

/// What a `tasks/result` answer says of its task: it carries what the task's
/// `tools/call` would have answered (MCP 2025-11-25 tasks), so a result is a
/// completed send and an error one whose delivery the connector has not
/// shown. The answer is wiped here.
fn settled_by(message: Value, bytes: Vec<u8>) -> RemoteTaskEnd {
    let end = if message.get("error").is_some() {
        RemoteTaskEnd::Unconfirmed
    } else {
        RemoteTaskEnd::Completed
    };
    zeroize_json(message);
    drop(zeroize::Zeroizing::new(bytes));
    end
}

/// A new MCP session in place of the one the connector ended, under
/// `live`'s endpoint, protocol revision and credential (FIX 16028):
/// `initialize` with no session, declaring no capabilities (a poll answers
/// no task input), its revision checked as the send checked it, then
/// `notifications/initialized` in the new session. A renewal that fails once
/// the server opened a session ends that session.
fn renew_session(live: &LiveSession, revision: &str) -> Result<LiveSession, &'static str> {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": INITIALIZE_ID,
        "method": "initialize",
        "params": {
            "protocolVersion": revision,
            "capabilities": {},
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
