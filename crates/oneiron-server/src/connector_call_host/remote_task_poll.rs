//! The served poll of remote MCP tasks (FIX 11023; MCP 2025-11-25 tasks):
//! one `tasks/get` per Deferred row its pass finds due, in the session the
//! task was created in, under the row's own frozen endpoint and binding,
//! with the credential its send presented, through the same door. It never
//! sends the row's `tools/call` again, and it reads the row again just
//! before each `tasks/get`, so a row erased or settled since the pass began
//! sends nothing. A reply counts only when it names the task asked about.
//! `completed` settles the send Done; `failed` and `cancelled`, and a task
//! the connector no longer knows (`-32602`), stop it with its delivery
//! uncertain; `working` and `input_required` poll again later (this host
//! answers no task input). The session ends only after the ledger holds the
//! settlement. Only the status word is kept: the reply's other text never
//! leaves this pass, so nothing it echoes of the credential is stored.

use oneiron::outbound_consent::{OutboundBindingAuthority, OutboundBindingValidation};
use oneiron::outbound_intent_ledger::{DueRemoteTask, RemoteTaskCredential, RemoteTaskEnd};

use super::*;

/// The JSON-RPC id of a poll's one request.
const POLL_ID: u64 = 7;
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
    let due = match vault.remote_tasks_due(now_ms(), POLLS_PER_PASS) {
        Ok(due) if due.is_empty() => return,
        Ok(due) => due,
        Err(error) => {
            tracing::warn!(%error, "remote tasks due a poll not read");
            return;
        }
    };
    let mut host = match ServedConnectorCallHost::new(server) {
        Ok(host) => host,
        Err(error) => {
            tracing::warn!(%error, "connector call host not built to poll remote tasks");
            return;
        }
    };
    for task in due {
        // The intent id's first bytes name the row in the log.
        let intent: String = task.intent[..8].iter().map(|byte| format!("{byte:02x}")).collect();
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
}

impl ServedConnectorCallHost {
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
        if !response.status().is_success() {
            return Err("poll_http_refused");
        }
        let Some((message, _)) =
            read_reply(response, POLL_ID).map_err(|_| "poll_reply_unreadable")?
        else {
            return Err("poll_unanswered");
        };
        Ok(match read_of(&message, &task.task_id)? {
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
