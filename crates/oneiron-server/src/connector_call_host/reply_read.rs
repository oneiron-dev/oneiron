//! The reply readers both halves of the call host share: one reply body,
//! JSON read whole or an event stream read event by event, and the tool's
//! reply a `tools/call` answer carries.

use std::sync::atomic::{AtomicBool, Ordering};

use super::live_exchange::AnswerReceipts;
use super::*;

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

/// A reply stream read event by event, each event whole whatever its size
/// (FIX 8227): only a message that does not parse is unreadable. Past
/// `deadline`, so is the rest of a round.
pub(super) struct EventStream {
    reader: BufReader<reqwest::blocking::Response>,
    data: String,
    deadline: Option<Instant>,
    /// The line being read, kept across a read that timed out (FIX 9286).
    line: String,
    /// The last event id buffer: the latest `id:` field read (FIX 9157).
    id_buffer: String,
    /// The last event id, set from the buffer as each event is dispatched:
    /// what a reattachment after a restart sends as `Last-Event-ID`.
    last_event_id: String,
}

impl EventStream {
    /// The next answer to `id` or server request; notifications are
    /// dropped.
    pub(super) fn next(&mut self, id: u64) -> Result<StreamEvent, ()> {
        self.read_event(id, None)
    }

    /// [`Self::next`] for a stream read while its round waits for an answer
    /// (FIX 9286): a quiet stream is not an ended one, so a read that timed
    /// out reads on, its partial line kept, as long as `waiting` holds.
    pub(super) fn next_while(&mut self, id: u64, waiting: &AtomicBool) -> Result<StreamEvent, ()> {
        self.read_event(id, Some(waiting))
    }

    /// Reads on with no deadline of its own: whoever waits on the stream
    /// keeps the round's (FIX 9286).
    pub(super) fn read_on(&mut self) {
        self.deadline = None;
    }

    fn read_event(&mut self, id: u64, waiting: Option<&AtomicBool>) -> Result<StreamEvent, ()> {
        loop {
            let n = match self.reader.read_line(&mut self.line) {
                Ok(n) => n,
                Err(error)
                    if timed_out(&error)
                        && waiting.is_some_and(|waiting| waiting.load(Ordering::Acquire)) =>
                {
                    continue;
                }
                Err(_) => return Err(()),
            };
            let line = std::mem::take(&mut self.line);
            if self
                .deadline
                .is_some_and(|deadline| Instant::now() > deadline)
            {
                return Err(());
            }
            let end = n == 0;
            let trimmed = line.trim_end_matches(['\r', '\n']);
            if end || trimmed.is_empty() {
                self.last_event_id.clone_from(&self.id_buffer);
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
            } else if let Some(field) = id_field(trimmed) {
                field.clone_into(&mut self.id_buffer);
            }
        }
    }

    /// The stream's last event id, once an event that set one was
    /// dispatched (FIX 9157).
    pub(super) fn last_event_id(&self) -> Option<&str> {
        (!self.last_event_id.is_empty()).then_some(self.last_event_id.as_str())
    }
}

/// The value of an event-stream `id` field line, its one leading space
/// dropped; a bare `id` line has the empty value, which clears the id. A
/// value holding a NUL is ignored, as the format says.
fn id_field(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("id")?;
    let value = if rest.is_empty() {
        rest
    } else {
        let value = rest.strip_prefix(':')?;
        value.strip_prefix(' ').unwrap_or(value)
    };
    (!value.contains('\0')).then_some(value)
}

/// Whether a read failed only because nothing came within the client's
/// per-read bound: the body itself is still readable.
fn timed_out(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::TimedOut {
        return true;
    }
    match error.get_ref() {
        Some(inner) => inner
            .downcast_ref::<reqwest::Error>()
            .is_some_and(reqwest::Error::is_timeout),
        None => false,
    }
}

/// Opens one reply body, JSON or an event stream. A JSON body is read whole,
/// whatever its size (FIX 8227): only a body that does not parse is
/// unreadable, and the complete result goes on as the call's reply.
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
    let mut body = response;
    if stream {
        return Ok(Reply::Stream(EventStream {
            reader: BufReader::new(body),
            data: String::new(),
            deadline,
            line: String::new(),
            id_buffer: String::new(),
            last_event_id: String::new(),
        }));
    }
    let mut bytes = Vec::new();
    body.read_to_end(&mut bytes).map_err(|_| ())?;
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

/// A `tools/call` answer as the tool's reply: its result, or the JSON-RPC
/// error it answered with; `None` when it carries neither.
pub(super) fn tool_result(message: &Value) -> Option<UntrustedToolResult> {
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

/// Reads the reply to a retried `tools/call` (`id`), refusing any server
/// request on its stream once the call's issuer binding is read again (FIX
/// 9303).
#[allow(
    clippy::result_large_err,
    reason = "the error is the worker's terminal event, handed on as is"
)]
pub(super) fn read_retry_reply(
    session: &LiveSession,
    receipts: &AnswerReceipts,
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
            Ok(StreamEvent::Request(request)) => session.refuse_unheld(&request, receipts),
            Ok(StreamEvent::End) | Err(()) => return Err(unreadable),
        }
    }
}
